"""
Outbound HTTP with plain urllib. One place for timeouts and a small retry
on transient errors, so every caller behaves the same.
"""
import json
import time
import urllib.error
import urllib.request

USER_AGENT = "nobetci"


def is_transient(exc):
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code == 429 or exc.code >= 500
    return isinstance(exc, OSError)


def _retry_after(exc):
    if not isinstance(exc, urllib.error.HTTPError) or exc.code != 429:
        return None
    hint = exc.headers.get("Retry-After") if exc.headers else None
    if hint is None:
        try:
            hint = json.loads(exc.read().decode()).get("parameters", {}).get("retry_after")
        except Exception:
            hint = None
    try:
        return max(0.0, float(hint))
    except (TypeError, ValueError):
        return None


def request_json(url, payload=None, headers=None, method=None, timeout=30, attempts=3, resend=True):
    """
    Send a JSON request and decode the JSON reply. Transient errors are retried
    with backoff; resend=False never repeats a request that timed out, because
    it may already have been applied (e.g. sendMessage).
    """
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    all_headers = {"User-Agent": USER_AGENT}
    if data is not None:
        all_headers["Content-Type"] = "application/json; charset=utf-8"
    all_headers.update(headers or {})
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(url, data=data, headers=all_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode()
                return json.loads(body) if body else {}
        except Exception as exc:
            timed_out = isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError)
            if attempt == attempts or not is_transient(exc) or (timed_out and not resend):
                raise
            wait = _retry_after(exc)
            if wait is None:
                wait = min(2 ** attempt, 10)
            if wait > 30:
                raise
            time.sleep(wait)


def get_text(url, timeout=10, attempts=3):
    for attempt in range(1, attempts + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode()
        except Exception as exc:
            if attempt == attempts or not is_transient(exc):
                raise
            time.sleep(min(2 ** attempt, 10))
