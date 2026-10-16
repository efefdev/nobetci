import os
import tempfile
from unittest import mock

from nobetci.config import Config, DEFAULTS


def make_config(tmp, **overrides):
    config = Config(DEFAULTS)
    config.update({
        "TELEGRAM_BOT_TOKEN": "123:test",
        "TELEGRAM_CHAT_ID": "1000",
        "DB_PATH": os.path.join(tmp, "test.db"),
        "STATE_DIR": os.path.join(tmp, "state"),
        "BLOCKLIST_PATH": os.path.join(tmp, "nginx", "blocked-ips.conf"),
        "NGINX_ACCESS_LOG": os.path.join(tmp, "access.log"),
        "NGINX_ERROR_LOG": os.path.join(tmp, "error.log"),
        "AUTH_LOG": os.path.join(tmp, "auth.log"),
        "AI_API_KEY": "",
        "GROQ_API_KEY": "",
        "SERVER_IP": "8.8.4.4",
    })
    config.update(overrides)
    return config


class TempDirMixin:
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        # nginx and systemctl are never touched by tests
        patcher = mock.patch("nobetci.firewall._reload_nginx")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)


def access_line(ip, request, status=200, agent="Mozilla/5.0"):
    from datetime import datetime
    stamp = datetime.now().astimezone().strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{ip} - - [{stamp}] "{request}" {status} 123 "-" "{agent}"'
