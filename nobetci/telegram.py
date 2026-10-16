"""Minimal Telegram Bot API client."""
from nobetci import net


class Telegram:
    def __init__(self, token, chat_id):
        self.token = token
        self.chat_id = str(chat_id)

    def call(self, method, payload=None, timeout=30):
        # Retries, pacing and the circuit breaker live in nobetci.net
        try:
            return net.telegram_api(self.token, method, payload, timeout=timeout)
        except Exception as exc:
            # Never print the URL: it contains the bot token
            print(f"Telegram {method} failed: {type(exc).__name__}: {getattr(exc, 'code', '')}")
            return None

    def send(self, text, buttons=None, chat_id=None):
        payload = {
            "chat_id": chat_id or self.chat_id,
            "text": text[:4000],
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if buttons:
            payload["reply_markup"] = {"inline_keyboard": buttons}
        result = self.call("sendMessage", payload)
        if result and result.get("ok"):
            return result["result"]["message_id"]
        return None

    def edit(self, message_id, text, buttons=None, chat_id=None):
        payload = {
            "chat_id": chat_id or self.chat_id,
            "message_id": message_id,
            "text": text[:4000],
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
            "reply_markup": {"inline_keyboard": buttons or []},
        }
        return self.call("editMessageText", payload)

    def answer(self, callback_id, text=""):
        return self.call("answerCallbackQuery", {"callback_query_id": callback_id, "text": text[:190]})

    def typing(self):
        return self.call("sendChatAction", {"chat_id": self.chat_id, "action": "typing"})


def button(text, data):
    return {"text": text, "callback_data": data[:64]}
