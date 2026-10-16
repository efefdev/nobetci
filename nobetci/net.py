"""
Resilience policies for every outbound HTTP call, built on nopanic
(https://github.com/dagdelenemre/nopanic, pinned with hashes in
requirements.txt). Adapted from Emre Kadir Dağdelen's soc_resilience.py
(efefdev/nobetci#1).

Errors are never wrapped: callers see the original urllib exception, or
nopanic.CircuitOpen while Telegram is known to be down.
"""
import json
import math
import sys
import urllib.error
import urllib.request
from datetime import datetime

from nopanic import backoff, circuit_breaker, compose, rate_limit, retry, time_remaining

USER_AGENT = "nobetci"


def _log(msg):
    print(f"[{datetime.now()}] {msg}", file=sys.stderr)


def _before_sleep(what):
    return lambda a: _log(f"{what} attempt {a.attempt} failed ({type(a.exception).__name__}). "
                          f"Retrying in {a.delay:.1f}s...")


# ERROR CLASSIFICATION

def is_transient(exc):
    """Network failures, timeouts, HTTP 429 and 5xx. Other 4xx are permanent."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code == 429 or exc.code >= 500
    # URLError, TimeoutError and ConnectionError are all OSError subclasses
    return isinstance(exc, OSError)


def is_timeout(exc):
    return isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError)


def is_safe_to_resend(exc):
    """is_transient minus timeouts: a request that timed out may already have been applied."""
    return is_transient(exc) and not is_timeout(exc)


def is_auth_error(exc):
    return isinstance(exc, urllib.error.HTTPError) and exc.code in (401, 403)


def _attach_retry_after(exc):
    """
    Copy a 429's Retry-After hint onto the exception as `retry_after`, which
    nopanic's retry honors. Groq sends a header, Telegram a JSON body field.
    """
    if exc.code != 429:
        return
    hint = exc.headers.get("Retry-After") if exc.headers else None
    if hint is None:
        try:
            hint = json.loads(exc.read().decode()).get("parameters", {}).get("retry_after")
        except Exception:
            hint = None
    try:
        value = float(hint)
    except (TypeError, ValueError):
        return
    if math.isfinite(value) and value >= 0:
        exc.retry_after = value


# TRANSPORT

def _request(url, payload=None, headers=None, method=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    all_headers = {"User-Agent": USER_AGENT}
    if data is not None:
        all_headers["Content-Type"] = "application/json; charset=utf-8"
    all_headers.update(headers or {})
    return urllib.request.Request(url, data=data, headers=all_headers, method=method)


def _open(req, timeout):
    """One round trip. Inside a nopanic deadline the socket timeout is clamped to the time left."""
    remaining = time_remaining()
    if remaining is not None:
        if remaining <= 0:
            raise TimeoutError("time budget exhausted")
        timeout = min(timeout, remaining)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        _attach_retry_after(exc)
        raise


def _open_json(req, timeout):
    body = _open(req, timeout).decode()
    return json.loads(body) if body else {}


# TELEGRAM

# One breaker per process: once Telegram is clearly down, callers fail fast
# for reset_timeout seconds instead of stacking retries.
telegram_breaker = circuit_breaker(
    failure_threshold=0.5,
    min_calls=5,
    window=60.0,
    reset_timeout=30.0,
    on=is_transient,
    name="telegram",
    on_state_change=lambda b, old, new: _log(f"Telegram circuit: {old} -> {new}"),
)

# Telegram allows roughly one message per second per chat; faster bursts get 429.
telegram_rate = rate_limit(1, per=1.0, burst=3, name="telegram")

_telegram_retry_idempotent = retry(
    attempts=3, on=is_transient, backoff=backoff.full_jitter(base=0.5, cap=10.0),
    retry_after_cap=30.0, before_sleep=_before_sleep("Telegram"))
_telegram_retry_send = retry(
    attempts=4, on=is_safe_to_resend, backoff=backoff.full_jitter(base=0.5, cap=10.0),
    retry_after_cap=30.0, before_sleep=_before_sleep("Telegram"))

_rate_limited_open_json = telegram_rate(_open_json)
_telegram_send = compose(_telegram_retry_send, telegram_breaker)(_rate_limited_open_json)
_telegram_edit = compose(_telegram_retry_idempotent, telegram_breaker)(_rate_limited_open_json)
_telegram_other = compose(_telegram_retry_idempotent, telegram_breaker)(_open_json)

_TELEGRAM_CALLS = {"sendMessage": _telegram_send, "editMessageText": _telegram_edit}


def telegram_api(token, method, payload=None, timeout=30):
    """Call a Bot API method; raises the original error once retries are exhausted."""
    req = _request(f"https://api.telegram.org/bot{token}/{method}", payload)
    return _TELEGRAM_CALLS.get(method, _telegram_other)(req, timeout)


# AI (Groq, Ollama, OpenAI-compatible)

def _ai_worth_retrying(exc):
    """
    Retry the same model on network errors and 5xx. A 429 is retried only for
    a short wait: limits are per model, so on a longer one the caller moves
    to the next model instead.
    """
    if isinstance(exc, urllib.error.HTTPError) and exc.code == 429:
        return getattr(exc, "retry_after", None) is not None and exc.retry_after <= 5
    return is_transient(exc)


_ai_post = retry(attempts=3, on=_ai_worth_retrying, backoff=backoff.full_jitter(base=1.0, cap=8.0),
                 before_sleep=_before_sleep("AI"))(_open_json)


def ai_chat(url, payload, headers=None, timeout=45):
    """POST a chat completion. Run inside nopanic.deadline(...) to bound the total time."""
    return _ai_post(_request(url, payload, headers), timeout)


# GENERIC (Cloudflare API, Cloudflare IP lists)

_get_retry = retry(attempts=4, on=is_transient, backoff=backoff.full_jitter(base=1.0, cap=15.0),
                   before_sleep=_before_sleep("HTTP"))
_json_retry = retry(attempts=3, on=is_transient, backoff=backoff.full_jitter(base=1.0, cap=10.0),
                    retry_after_cap=30.0, before_sleep=_before_sleep("HTTP"))
_json_retry_no_resend = retry(attempts=3, on=is_safe_to_resend, backoff=backoff.full_jitter(base=1.0, cap=10.0),
                              retry_after_cap=30.0, before_sleep=_before_sleep("HTTP"))
_json_call = _json_retry(_open_json)
_json_call_no_resend = _json_retry_no_resend(_open_json)
_get_call = _get_retry(_open)


def request_json(url, payload=None, headers=None, method=None, timeout=30, resend=True):
    """
    JSON request with retries on transient errors. resend=False never repeats
    a request that timed out (e.g. creating a Cloudflare rule).
    """
    call = _json_call if resend else _json_call_no_resend
    return call(_request(url, payload, headers, method), timeout)


def get_text(url, timeout=10):
    return _get_call(_request(url), timeout).decode()
