import os
import unittest
from datetime import datetime, timedelta
from unittest import mock

from nobetci import db, firewall
from nobetci.actions import Actions
from nobetci.bot import Bot
from tests.helpers import TempDirMixin, make_config, access_line


class ActionsTest(TempDirMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.config = make_config(self.tmp)
        db.init(self.config["DB_PATH"])
        self.actions = Actions(self.config)

    def test_ban_writes_file_and_db_with_expiry(self):
        result = self.actions.ban("45.33.1.2", timedelta(days=7), "test")
        self.assertEqual(result.status, "done")
        self.assertEqual(firewall.banned_ips(self.config["BLOCKLIST_PATH"]), ["45.33.1.2"])
        bans = self.actions.active_bans()
        self.assertEqual(bans[0]["ip"], "45.33.1.2")
        self.assertIsNotNone(bans[0]["expiry"])
        with open(self.config["BLOCKLIST_PATH"]) as f:
            self.assertTrue(f.read().rstrip().endswith("allow all;"))

    def test_already_and_protected(self):
        self.actions.ban("45.33.1.2", None, "x")
        self.assertEqual(self.actions.ban("45.33.1.2", None, "x").status, "already")
        self.assertEqual(self.actions.ban("8.8.4.4", None, "x").status, "protected")
        self.assertEqual(self.actions.ban("192.168.1.9", None, "x").status, "protected")
        self.assertEqual(self.actions.ban("not-an-ip", None, "x").status, "invalid")

    def test_unban_closes_record(self):
        self.actions.ban("45.33.1.2", None, "x")
        self.assertEqual(self.actions.unban("45.33.1.2").status, "done")
        self.assertEqual(self.actions.active_bans(), [])
        self.assertEqual(self.actions.unban("45.33.1.2").status, "not_banned")

    def test_manual_bans_expire_too(self):
        self.actions.ban("45.33.1.2", timedelta(minutes=1), "x")
        self.actions.ban("45.33.1.3", None, "x")
        with db.connect(self.config["DB_PATH"]) as conn:
            conn.execute("UPDATE ban_log SET expiry='2000-01-01 00:00:00' WHERE ip='45.33.1.2'")
        self.assertEqual(self.actions.expire(), ["45.33.1.2"])
        self.assertEqual([b["ip"] for b in self.actions.active_bans()], ["45.33.1.3"])

    def test_pending_is_single_use(self):
        pid = self.actions.propose("ban", "45.33.1.2", "XSS", "86400")
        self.assertEqual(self.actions.take_pending(pid, "approved")["target"], "45.33.1.2")
        self.assertIsNone(self.actions.take_pending(pid, "approved"))

    def test_pending_expires(self):
        pid = self.actions.propose("ban", "45.33.1.2", "XSS", "86400")
        old = (datetime.now() - timedelta(days=1)).strftime(db.TIME_FMT)
        with db.connect(self.config["DB_PATH"]) as conn:
            conn.execute("UPDATE pending_commands SET timestamp=? WHERE id=?", (old, pid))
        self.assertIsNone(self.actions.take_pending(pid, "approved"))

    def test_legacy_pending_rows_are_ignored(self):
        with db.connect(self.config["DB_PATH"]) as conn:
            cur = conn.execute("INSERT INTO pending_commands (timestamp, command, status) VALUES (?, ?, 'pending')",
                               (db.now(), "chmod 777 /etc/shadow"))
        self.assertIsNone(self.actions.take_pending(cur.lastrowid, "approved"))

    def test_failed_nginx_test_reverts(self):
        with mock.patch("nobetci.firewall._reload_nginx", side_effect=firewall.FirewallError("bad")):
            self.assertEqual(self.actions.ban("45.33.1.2", None, "x").status, "error")
        self.assertEqual(firewall.banned_ips(self.config["BLOCKLIST_PATH"]), [])


class BotTest(TempDirMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.config = make_config(self.tmp, AI_CHAT="off")
        db.init(self.config["DB_PATH"])
        self.bot = Bot(self.config)
        self.sent = []
        self.bot.tg = mock.Mock()
        self.bot.tg.send.side_effect = lambda text, buttons=None: self.sent.append((text, buttons)) or 1
        self.bot.last_cmd = 0

    def message(self, text, chat=1000):
        self.bot.last_cmd = 0
        self.bot.on_message({"chat": {"id": chat}, "from": {"id": chat, "username": "u"}, "text": text})

    def callback(self, data, chat=1000):
        self.bot.on_callback({"id": "cb", "data": data, "from": {"id": chat},
                              "message": {"chat": {"id": chat}, "message_id": 5, "text": "alert"}})

    def test_strangers_get_no_reply(self):
        self.message("/ban 45.33.1.2", chat=666)
        self.assertEqual(self.sent, [])
        self.assertIn("666", self.bot.strangers)
        self.assertEqual(firewall.banned_ips(self.config["BLOCKLIST_PATH"]), [])

    def test_strangers_cannot_press_buttons(self):
        pid = self.bot.actions.propose("ban", "45.33.1.2", "XSS", "86400")
        self.callback(f"ok:{pid}", chat=666)
        self.assertEqual(firewall.banned_ips(self.config["BLOCKLIST_PATH"]), [])
        self.bot.tg.answer.assert_not_called()

    def test_approve_button_bans(self):
        pid = self.bot.actions.propose("ban", "45.33.1.2", "XSS", "86400")
        self.callback(f"ok:{pid}")
        self.assertEqual(firewall.banned_ips(self.config["BLOCKLIST_PATH"]), ["45.33.1.2"])
        self.callback(f"ok:{pid}")  # pressing twice does nothing more
        self.assertEqual(len(firewall.banned_ips(self.config["BLOCKLIST_PATH"])), 1)

    def test_unban_button(self):
        self.bot.actions.ban("45.33.1.2", None, "x")
        self.callback("u:45.33.1.2")
        self.assertEqual(firewall.banned_ips(self.config["BLOCKLIST_PATH"]), [])

    def test_ban_command_turkish_duration(self):
        self.message("/ban 45.33.1.2 1g tarama yaptı")
        self.assertIn("1 gün", self.sent[-1][0])
        ban = self.bot.actions.active_bans()[0]
        self.assertEqual(ban["reason"], "tarama yaptı")
        expiry = datetime.strptime(ban["expiry"], db.TIME_FMT)
        self.assertAlmostEqual((expiry - datetime.now()).total_seconds(), 86400, delta=60)

    def test_ban_bad_duration(self):
        self.message("/ban 45.33.1.2 7x")
        self.assertEqual(firewall.banned_ips(self.config["BLOCKLIST_PATH"]), [])

    def test_html_in_reason_is_escaped(self):
        self.message("/ban 45.33.1.2 7d <b>x</b>")
        self.assertIn("&lt;b&gt;", self.sent[-1][0])

    def test_banlist_has_unban_buttons(self):
        self.bot.actions.ban("45.33.1.2", timedelta(days=2), "x")
        self.message("/banlist")
        text, buttons = self.sent[-1]
        self.assertIn("45.33.1.2", text)
        self.assertEqual(buttons[0][0]["callback_data"], "u:45.33.1.2")

    def test_help_lists_ban(self):
        self.message("/help")
        self.assertIn("/ban", self.sent[-1][0])


class PipelineTest(TempDirMixin, unittest.TestCase):
    def test_trap_hit_is_banned_and_alerted(self):
        from nobetci import pipeline
        config = make_config(self.tmp)
        with open(config["NGINX_ACCESS_LOG"], "w") as f:
            f.write(access_line("45.33.1.9", "GET /.env HTTP/1.1", status=444) + "\n")
            f.write(access_line("8.8.4.4", "GET /.env HTTP/1.1") + "\n")  # our own IP: ignored
        sent = []
        with mock.patch("nobetci.pipeline.Telegram") as tg, mock.patch("nobetci.logs.journal", return_value=[]):
            tg.return_value.send.side_effect = lambda text, buttons=None: sent.append(text)
            detections, ai_text, threats, alerts = pipeline.run(config)
        self.assertEqual(firewall.banned_ips(config["BLOCKLIST_PATH"]), ["45.33.1.9"])
        self.assertEqual(len(sent), 1)
        self.assertTrue(os.path.exists(os.path.join(config["STATE_DIR"], "last_run")))


if __name__ == "__main__":
    unittest.main()


class ChatSnapshotTest(TempDirMixin, unittest.TestCase):
    def test_snapshot_knows_the_ssh_port_and_masks_addresses(self):
        from nobetci import audit
        outputs = {
            "sshd": "port 2222\npasswordauthentication no\npermitrootlogin no\npubkeyauthentication yes\n",
            "ss": 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
                  'LISTEN 0 511 45.33.1.2:443 0.0.0.0:* users:(("nginx",pid=2,fd=6))\n',
            "ufw": "Status: active\n\nTo Action From\n2222/tcp ALLOW 88.12.34.56\n",
            "systemctl": "active\n",
        }

        def fake_run(cmd, timeout=20):
            out = outputs.get(cmd[0])
            return (0, out) if out is not None else (None, "")

        config = make_config(self.tmp)
        db.init(config["DB_PATH"])
        bot = Bot(config)
        with mock.patch.object(audit, "_run", side_effect=fake_run):
            snap = bot.snapshot("ssh hangi portta?")
        self.assertIn("SSH: port 2222", snap)
        self.assertIn("0.0.0.0:2222/sshd", snap)
        self.assertNotIn("45.33.1.2", snap)
        self.assertNotIn("88.12.34.56", snap)
