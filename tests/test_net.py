"""
Failure scenarios for outbound calls (nobetci/net.py), adapted from Emre Kadir
Dağdelen's tests in efefdev/nobetci#1. urlopen is replaced by a scripted fake
and nopanic.testing.instant() skips the waits, so nothing touches the network.
"""
import email.message
import io
import json
import time
import unittest
import urllib.error
from unittest import mock

from nopanic import testing

from nobetci import net
from nobetci.ai import AI
from tests.helpers import make_config


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def ok(obj):
    return lambda req, timeout: Resp(json.dumps(obj).encode())


def http_error(code, body=b"", headers=None):
    def make(req, timeout):
        msg = email.message.Message()
        for k, v in (headers or {}).items():
            msg[k] = v
        raise urllib.error.HTTPError(req.full_url, code, "error", msg, io.BytesIO(body))
    return make


def refused(req, timeout):
    raise urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))


def timed_out(req, timeout):
    raise TimeoutError("timed out")


class FakeNetwork:
    """Plays a script of responses; the last one repeats."""

    def __init__(self, *script):
        self.script = list(script)
        self.requests = []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        step = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        return step(req, timeout)


class NetTestCase(unittest.TestCase):
    def setUp(self):
        net.telegram_breaker.reset()

    def fake(self, *script):
        fake = FakeNetwork(*script)
        patcher = mock.patch("urllib.request.urlopen", fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        return fake


class TelegramTest(NetTestCase):
    def test_429_waits_retry_after_then_delivers(self):
        body = json.dumps({"ok": False, "parameters": {"retry_after": 7}}).encode()
        fake = self.fake(http_error(429, body), ok({"ok": True, "result": {"message_id": 1}}))
        with testing.instant() as sleeps:
            reply = net.telegram_api("t", "sendMessage", {"chat_id": 1, "text": "x"})
        self.assertTrue(reply["ok"])
        self.assertEqual(len(fake.requests), 2)
        self.assertGreaterEqual(max(sleeps), 7)

    def test_send_message_is_not_resent_after_a_timeout(self):
        fake = self.fake(timed_out)
        with testing.instant(), self.assertRaises(TimeoutError):
            net.telegram_api("t", "sendMessage", {"chat_id": 1, "text": "x"})
        self.assertEqual(len(fake.requests), 1)  # a duplicate alert is worse than a lost retry

    def test_edit_is_retried_after_a_timeout(self):
        fake = self.fake(timed_out, ok({"ok": True}))
        with testing.instant():
            self.assertTrue(net.telegram_api("t", "editMessageText", {"message_id": 1})["ok"])
        self.assertEqual(len(fake.requests), 2)

    def test_bad_token_is_not_retried(self):
        fake = self.fake(http_error(401))
        with testing.instant(), self.assertRaises(urllib.error.HTTPError):
            net.telegram_api("t", "getMe")
        self.assertEqual(len(fake.requests), 1)

    def test_outage_opens_the_circuit_and_bounds_requests(self):
        fake = self.fake(refused)
        failures = 0
        with testing.instant():
            for _ in range(6):
                try:
                    net.telegram_api("t", "sendMessage", {"chat_id": 1, "text": "x"})
                except Exception:
                    failures += 1
        self.assertEqual(failures, 6)
        self.assertLess(len(fake.requests), 6 * 4)  # without the breaker: 24
        self.assertEqual(net.telegram_breaker.state, "open")

    def test_token_never_appears_in_bot_log(self):
        from nobetci.telegram import Telegram
        self.fake(http_error(401))
        with testing.instant(), mock.patch("builtins.print") as printed:
            Telegram("123:SECRET", 1).send("x")
        self.assertNotIn("SECRET", " ".join(str(c) for c in printed.call_args_list))


class AITest(NetTestCase):
    def ai(self, **cfg):
        return AI(make_config("/tmp", AI_API_KEY="k", AI_MODELS="m1,m2,m3", **cfg))

    def answer(self, text):
        return ok({"choices": [{"message": {"content": text}}]})

    def test_rejected_key_stops_after_one_request(self):
        fake = self.fake(http_error(401))
        with testing.instant():
            self.assertIsNone(self.ai().complete("s", "u"))
        self.assertEqual(len(fake.requests), 1)

    def test_long_429_moves_to_next_model_at_once(self):
        fake = self.fake(http_error(429, headers={"Retry-After": "30"}), self.answer("CLEAN"))
        with testing.instant() as sleeps:
            self.assertEqual(self.ai().complete("s", "u"), "CLEAN")
        models = [json.loads(r.data)["model"] for r in fake.requests]
        self.assertEqual(models, ["m1", "m2"])
        self.assertEqual(sleeps, [])

    def test_short_429_retries_the_same_model(self):
        fake = self.fake(http_error(429, headers={"Retry-After": "2"}), self.answer("CLEAN"))
        with testing.instant():
            self.ai().complete("s", "u")
        self.assertEqual([json.loads(r.data)["model"] for r in fake.requests], ["m1", "m1"])

    def test_503_retries_the_same_model(self):
        fake = self.fake(http_error(503), self.answer("CLEAN"))
        with testing.instant():
            self.assertEqual(self.ai().complete("s", "u"), "CLEAN")
        self.assertEqual([json.loads(r.data)["model"] for r in fake.requests], ["m1", "m1"])

    def test_time_budget_bounds_a_hanging_provider(self):
        def hang(req, timeout):
            time.sleep(min(timeout, 0.4))
            raise TimeoutError("timed out")
        self.fake(hang)
        started = time.monotonic()
        with testing.instant():
            self.assertIsNone(self.ai(AI_TIME_BUDGET="2").complete("s", "u"))
        self.assertLess(time.monotonic() - started, 3)


class GenericTest(NetTestCase):
    def test_get_text_retries_transient_errors(self):
        fake = self.fake(refused, http_error(502), lambda r, t: Resp(b"1.2.3.0/24"))
        with testing.instant():
            self.assertEqual(net.get_text("https://example.invalid"), "1.2.3.0/24")
        self.assertEqual(len(fake.requests), 3)

    def test_create_requests_are_not_resent_after_timeout(self):
        fake = self.fake(timed_out)
        with testing.instant(), self.assertRaises(TimeoutError):
            net.request_json("https://example.invalid", {"a": 1}, resend=False)
        self.assertEqual(len(fake.requests), 1)


if __name__ == "__main__":
    unittest.main()
