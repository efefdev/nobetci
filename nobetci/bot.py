"""
Telegram listener. Only the configured chat is served; strangers get no
reply at all and are summarised to the admin once an hour.
"""
import re
import subprocess
import threading
import time
from datetime import datetime, timedelta

from nobetci import ai as ai_mod
from nobetci import audit, db, firewall, logs, pipeline, updater
from nobetci.actions import Actions
from nobetci.durations import humanize, looks_like_duration, parse_duration
from nobetci.i18n import SEVERITY_EMOJI, Raw, esc, translator
from nobetci.ipcheck import IP_PATTERN, parse_ip
from nobetci.telegram import Telegram, button

COOLDOWN = 2
STRANGER_SUMMARY_EVERY = 3600
COMMANDS = [
    ("status", {"tr": "Sunucu durumu", "en": "Server status"}),
    ("log", {"tr": "Son X saatin özeti", "en": "Last X hours summary"}),
    ("banlist", {"tr": "Aktif banlar", "en": "Active bans"}),
    ("ban", {"tr": "IP banla: /ban <ip> [süre] [sebep]", "en": "Ban IP: /ban <ip> [duration] [reason]"}),
    ("unban", {"tr": "Banı kaldır", "en": "Remove a ban"}),
    ("threats", {"tr": "Bugünün tehditleri", "en": "Today's threats"}),
    ("stats", {"tr": "Son 7 gün", "en": "Last 7 days"}),
    ("analyze", {"tr": "Şimdi analiz et", "en": "Analyze now"}),
    ("audit", {"tr": "Sertleştirme denetimi", "en": "Hardening audit"}),
    ("update", {"tr": "Güncelleme kontrolü", "en": "Check for updates"}),
    ("help", {"tr": "Yardım", "en": "Help"}),
]


def _first_line(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return "?"


def left_label(expiry, t):
    if not expiry:
        return t("left_permanent")
    delta = datetime.strptime(expiry, db.TIME_FMT) - datetime.now()
    if delta.total_seconds() <= 0:
        return t("left", d=t("dur_minute", n=0))
    minutes = int(delta.total_seconds() // 60)
    for unit, size in (("day", 1440), ("hour", 60)):
        if minutes >= size:
            return t("left", d=t(f"dur_{unit}", n=minutes // size))
    return t("left", d=t("dur_minute", n=max(minutes, 1)))


class Bot:
    def __init__(self, config):
        self.config = config
        self.lang = config.get("LANG", "tr")
        self.t = translator(self.lang)
        self.chat_id = str(config["TELEGRAM_CHAT_ID"])
        self.tg = Telegram(config["TELEGRAM_BOT_TOKEN"], self.chat_id)
        self.actions = Actions(config)
        self.ai = ai_mod.AI(config)
        self.chat_enabled = config.flag("AI_CHAT") and self.ai.enabled
        self.last_cmd = 0.0
        self.busy = threading.Lock()
        self.strangers = {}
        self.last_stranger_summary = time.time()

    # PLUMBING

    def send(self, text, buttons=None):
        return self.tg.send(text, buttons)

    def background(self, fn, *args):
        """Long jobs (analysis, audit, AI chat) run off the polling loop, one at a time."""
        def job():
            if not self.busy.acquire(blocking=False):
                self.send(self.t("busy"))
                return
            try:
                fn(*args)
            except Exception as exc:
                self.send(self.t("error", e=exc))
            finally:
                self.busy.release()
        threading.Thread(target=job, daemon=True).start()

    def note_stranger(self, chat, user):
        name = user.get("username") or user.get("first_name") or "?"
        self.strangers[str(chat.get("id"))] = f"{name} ({chat.get('id')})"

    def flush_strangers(self):
        if time.time() - self.last_stranger_summary < STRANGER_SUMMARY_EVERY:
            return
        self.last_stranger_summary = time.time()
        if self.strangers:
            who = ", ".join(list(self.strangers.values())[:10])
            self.send(self.t("stranger_summary", n=len(self.strangers), who=who))
            self.strangers.clear()

    # COMMANDS

    def cmd_help(self, args):
        chat = self.t("help_chat") if self.chat_enabled else ""
        self.send(self.t("help", chat=Raw(chat)))

    def cmd_status(self, args):
        disk = _first_line(["df", "-h", "--output=used,size,pcent", "/"]).splitlines()[-1].split()
        mem = _first_line(["free", "-h"]).splitlines()
        mem = mem[1].split() if len(mem) > 1 else ["", "?", "?"]
        try:
            with open("/proc/loadavg") as f:
                load = " ".join(f.read().split()[:3])
            with open("/proc/uptime") as f:
                up = timedelta(seconds=int(float(f.read().split()[0])))
        except OSError:
            load, up = "?", "?"
        lines = [self.t("status_title"),
                 self.t("status_body", disk=" / ".join(disk[:2]) + (f" ({disk[2]})" if len(disk) > 2 else ""),
                        ram=f"{mem[2]} / {mem[1]}", load=load, uptime=str(up).split(".")[0]),
                 "", self.t("status_services")]
        for unit in ("nginx", "ssh", "nobetci-bot", "nobetci-analyze.timer"):
            state = _first_line(["systemctl", "is-active", unit])
            lines.append(f"{'🟢' if state == 'active' else '🔴'} {esc(unit)}: {esc(state)}")
        if firewall.blocklist_included(self.config["BLOCKLIST_PATH"]) is False:
            lines += ["", self.t("status_blocklist_missing", path=self.config["BLOCKLIST_PATH"])]
        self.send("\n".join(lines))

    def cmd_log(self, args):
        hours = int(args) if args.strip().isdigit() else 1
        hours = min(max(hours, 1), 24)
        batch = logs.collect(self.config, datetime.now() - timedelta(hours=hours), self.actions.protection)
        parts = []
        if batch.access:
            parts.append("<b>nginx</b>\n<pre>" + esc("\n".join(l[:160] for l in batch.access[-15:])) + "</pre>")
        ssh = [l for l in batch.auth if re.search(r"failed|invalid|accepted", l, re.I)]
        if ssh:
            parts.append("<b>SSH</b>\n<pre>" + esc("\n".join(l[-160:] for l in ssh[-12:])) + "</pre>")
        if batch.firewall:
            parts.append("<b>UFW</b>\n<pre>" + esc("\n".join(l[-140:] for l in batch.firewall[-8:])) + "</pre>")
        body = "\n\n".join(parts) if parts else self.t("log_none", h=hours)
        self.send(self.t("log_title", h=hours) + "\n\n" + body)

    def cmd_banlist(self, args):
        bans = self.actions.active_bans()
        if not bans:
            self.send(self.t("banlist_empty"))
            return
        lines = [self.t("banlist_title", n=len(bans)), ""]
        for b in bans[:20]:
            lines.append(self.t("banlist_line", ip=b["ip"], reason=b["reason"] or "-", left=left_label(b["expiry"], self.t)))
        if len(bans) > 20:
            lines.append(self.t("banlist_more", n=len(bans) - 20))
        buttons = [[button(self.t("btn_unban", ip=b["ip"]), f"u:{b['ip']}")] for b in bans[:8]]
        self.send("\n".join(lines), buttons)

    def cmd_ban(self, args):
        parts = args.split(None, 2)
        if not parts:
            self.send(self.t("ban_usage"))
            return
        ip = parts[0]
        duration, reason = timedelta(days=7), "manual"
        rest = parts[1:]
        if rest and looks_like_duration(rest[0]):
            duration = parse_duration(rest.pop(0))
        elif rest and len(rest[0]) <= 4 and re.fullmatch(r"\d+\w*", rest[0]):
            self.send(self.t("ban_bad_duration", d=rest[0]))
            return
        if rest:
            reason = " ".join(rest)[:200]
        self.report_ban(self.actions.ban(ip, duration, reason, "MANUAL"), duration, reason)

    def report_ban(self, result, duration, reason, edit=None):
        t = self.t
        if result.status == "done":
            text = t("ban_done", ip=result.ip, d=humanize(duration, t), reason=reason)
            if result.edge:
                text += "\n" + t("ban_edge")
            buttons = [[button(t("btn_undo"), f"u:{result.ip}")]]
        else:
            key = {"already": "ban_already", "invalid": "ban_bad_ip"}.get(result.status)
            if result.status == "protected":
                text = t("ban_protected", ip=result.ip, why=t(f"protected_{result.detail}"))
            elif key:
                text = t(key, ip=result.ip)
            else:
                text = t("ban_failed", e=result.detail)
            buttons = None
        self.actions.log_command(f"ban {result.ip}", reason, result.status + " " + result.detail)
        if edit:
            self.tg.edit(edit, text, buttons)
        else:
            self.send(text, buttons)

    def cmd_unban(self, args, edit=None):
        ip = args.strip().split(" ")[0] if args.strip() else ""
        if not ip:
            self.send(self.t("unban_usage"))
            return
        result = self.actions.unban(ip)
        self.actions.log_command(f"unban {ip}", "telegram", result.status)
        text = {"done": self.t("unban_done", ip=result.ip), "not_banned": self.t("unban_not", ip=result.ip),
                "invalid": self.t("ban_bad_ip", ip=ip)}.get(result.status, self.t("error", e=result.detail))
        if edit:
            self.tg.edit(edit, text)
        else:
            self.send(text)

    def cmd_threats(self, args):
        today = datetime.now().strftime("%Y-%m-%d")
        with db.connect(self.config["DB_PATH"]) as conn:
            rule_rows = conn.execute(
                "SELECT rule_name, severity, COUNT(*) n FROM rule_detections WHERE timestamp LIKE ?"
                " GROUP BY rule_id ORDER BY n DESC LIMIT 8", (f"{today}%",)).fetchall()
            ai_rows = conn.execute(
                "SELECT category, severity, COUNT(*) n FROM threats WHERE timestamp LIKE ?"
                " GROUP BY category ORDER BY n DESC LIMIT 8", (f"{today}%",)).fetchall()
        if not rule_rows and not ai_rows:
            self.send(self.t("threats_none"))
            return
        lines = [self.t("threats_title")]
        for title, rows, name in ((self.t("threats_rules"), rule_rows, "rule_name"), (self.t("threats_ai"), ai_rows, "category")):
            if rows:
                lines += ["", title] + [f"{SEVERITY_EMOJI.get(r['severity'], 'ℹ️')} {esc(r[name])} · {self.t('times', n=r['n'])}"
                                        for r in rows]
        self.send("\n".join(lines))

    def cmd_stats(self, args):
        with db.connect(self.config["DB_PATH"]) as conn:
            rows = conn.execute("SELECT * FROM statistics ORDER BY timestamp DESC LIMIT 7").fetchall()
        if not rows:
            self.send(self.t("stats_none"))
            return
        lines = [self.t("stats_title"), ""] + [
            self.t("stats_line", day=r["timestamp"], total=r["total_analyses"], critical=r["critical"],
                   high=r["high"], medium=r["medium"], low=r["low"]) for r in rows]
        self.send("\n".join(lines))

    def cmd_analyze(self, args):
        self.send(self.t("analyze_start"))
        self.background(self._analyze)

    def _analyze(self):
        detections, ai_text, threats, alerts = pipeline.run(self.config)
        if ai_text is None and self.ai.enabled and not detections:
            text = self.t("analyze_failed", why=pipeline.last_ai_error or "-")
        elif ai_text and threats:
            text = self.t("analyze_ai_note") + "\n\n" + esc(ai_text)
        else:
            text = self.t("analyze_clean") if not detections else esc(
                "\n".join(f"{d.name}: {d.ip} ({d.count})" for d in detections))
        self.send(self.t("analyze_done", text=Raw(text)))

    def cmd_audit(self, args):
        self.background(lambda: self.send(audit.format_report(audit.run(self.config), self.t, self.lang)))

    def cmd_update(self, args):
        def job():
            try:
                tag, notes = updater.check()
            except Exception as exc:
                self.send(self.t("update_failed", e=exc))
                return
            buttons = []
            prev = updater.previous(self.config["STATE_DIR"])
            if prev:
                pid = self.actions.propose("rollback", prev, "telegram")
                buttons.append([button(f"{self.t('btn_rollback')} ({prev})", f"ok:{pid}")])
            if not tag:
                self.send(self.t("update_none", v=updater.current()), buttons or None)
                return
            pid = self.actions.propose("update", tag, "telegram")
            buttons.insert(0, [button(self.t("btn_update"), f"ok:{pid}"), button(self.t("btn_reject"), f"no:{pid}")])
            self.send(self.t("update_available", new=tag, cur=updater.current(), notes=notes or "-"), buttons)
        self.background(job)

    # AI CHAT

    def snapshot(self, question):
        """(facts, untrusted): trusted server state, and attacker-writable evidence."""
        mask = ai_mod.mask
        facts = [f"Server time: {datetime.now():%Y-%m-%d %H:%M}"]
        untrusted = []
        try:
            with open("/proc/loadavg") as f:
                facts.append("Load: " + " ".join(f.read().split()[:3]))
        except OSError:
            pass
        facts.append("Server facts:")
        facts += [f"- {fact}" for fact in audit.server_facts(self.config, mask)]
        bans = self.actions.active_bans()
        facts.append(f"Active bans ({len(bans)}):")
        facts += [f"- {mask(b['ip'])} reason={b['reason']} rule={b['rule_id']} since={b['timestamp']} until={b['expiry'] or 'permanent'}"
                  for b in bans[:25]]
        since = (datetime.now() - timedelta(hours=24)).strftime(db.TIME_FMT)
        with db.connect(self.config["DB_PATH"]) as conn:
            stats = conn.execute("SELECT * FROM statistics ORDER BY timestamp DESC LIMIT 7").fetchall()
            facts.append("Daily stats: " + "; ".join(
                f"{s['timestamp']} total={s['total_analyses']} critical={s['critical']} high={s['high']}" for s in stats))
            rows = conn.execute("SELECT timestamp, rule_name, severity, match_count, description FROM rule_detections"
                                " WHERE timestamp >= ? ORDER BY id DESC LIMIT 40", (since,)).fetchall()
            untrusted.append("Rule detections, last 24h (ip: sample request):")
            untrusted += [f"- {r['timestamp']} {r['severity']} {r['rule_name']} x{r['match_count']}: {mask(r['description'] or '')}"
                          for r in rows]
            last = conn.execute("SELECT timestamp, raw_analysis FROM analyses WHERE raw_analysis != ''"
                                " ORDER BY id DESC LIMIT 1").fetchone()
            if last:
                untrusted.append(f"Previous AI analysis ({last['timestamp']}), itself derived from logs:\n"
                                 f"{last['raw_analysis'][:2500]}")
            # The admin may ask about a specific IP: give its own history, unmasked only for that IP
            for raw in re.findall(IP_PATTERN, question)[:2]:
                ip = parse_ip(raw)
                if ip is None:
                    continue
                ip = str(ip)
                hist = conn.execute("SELECT timestamp, reason, rule_id, expiry, active FROM ban_log WHERE ip=?"
                                    " ORDER BY id DESC LIMIT 10", (ip,)).fetchall()
                found = conn.execute("SELECT timestamp, rule_name, match_count, description FROM rule_detections"
                                     " WHERE description LIKE ? ORDER BY id DESC LIMIT 10", (f"{ip}:%",)).fetchall()
                facts.append(f"About {ip}: protected={self.actions.protection.reason(ip) or 'no'}")
                facts += [f"- ban {h['timestamp']} reason={h['reason']} rule={h['rule_id']} until={h['expiry'] or 'permanent'} active={h['active']}"
                          for h in hist]
                untrusted += [f"- detection for {ip} {d['timestamp']} {d['rule_name']} x{d['match_count']}: {mask(d['description'] or '')}"
                              for d in found]
                batch = logs.collect(self.config, datetime.now() - timedelta(hours=24))
                own = [l for l in batch.access + batch.auth if ip in l][-15:]
                if own:
                    untrusted.append(f"Recent log lines from {ip} (other data masked):")
                    untrusted += [mask(l)[:300] for l in own]
        return "\n".join(facts)[:5000], "\n".join(untrusted)[:8000]

    def chat(self, text):
        if not self.chat_enabled:
            self.send(self.t("chat_off"))
            return

        def job():
            self.tg.typing()
            facts, untrusted = self.snapshot(text)
            answer = self.ai.chat(text, facts, untrusted)
            self.send(esc(answer) if answer else self.t("chat_failed", why=self.ai.error_summary()))
        self.background(job)

    # DISPATCH

    def on_message(self, message):
        chat = message.get("chat", {})
        if str(chat.get("id")) != self.chat_id:
            self.note_stranger(chat, message.get("from", {}))
            return
        text = (message.get("text") or "").strip()
        if not text:
            return
        now = time.time()
        if now - self.last_cmd < COOLDOWN:
            self.send(self.t("too_fast", s=int(COOLDOWN - (now - self.last_cmd)) + 1))
            return
        self.last_cmd = now
        if not text.startswith("/"):
            self.chat(text)
            return
        cmd, _, args = text.partition(" ")
        cmd = cmd[1:].split("@")[0].lower()
        handler = getattr(self, f"cmd_{'help' if cmd == 'start' else cmd}", None)
        if handler is None:
            self.send(self.t("unknown", cmd=cmd))
            return
        try:
            handler(args.strip())
        except Exception as exc:
            self.send(self.t("error", e=exc))

    def on_callback(self, query):
        message = query.get("message") or {}
        chat = message.get("chat", {})
        if str(chat.get("id")) != self.chat_id:
            self.note_stranger(chat, query.get("from", {}))
            return
        data = query.get("data", "")
        kind, _, value = data.partition(":")
        message_id = message.get("message_id")
        self.tg.answer(query["id"])
        if kind == "u":
            self.cmd_unban(value, edit=message_id)
        elif kind in ("ok", "no") and value.isdigit():
            pending = self.actions.take_pending(int(value), "approved" if kind == "ok" else "rejected")
            original = esc(message.get("text", ""))
            if pending is None:
                self.tg.edit(message_id, original + "\n\n" + self.t("pending_gone"))
            elif kind == "no":
                self.tg.edit(message_id, original + "\n\n" + self.t("pending_rejected"))
            else:
                self.run_pending(pending, message_id, original)

    def run_pending(self, pending, message_id, original):
        action, target = pending["action"], pending["target"]
        if action == "ban":
            seconds = int(pending["duration"] or 0)
            duration = timedelta(seconds=seconds) if seconds else None
            self.report_ban(self.actions.ban(target, duration, pending["reason"] or "approved", "APPROVED"),
                            duration, pending["reason"] or "approved", edit=message_id)
        elif action in ("update", "rollback"):
            self.tg.edit(message_id, original + "\n\n" + self.t("update_running"))
            self.actions.log_command(f"{action} {target}", "telegram", "started")
            updater.spawn(target)

    # LOOP

    def register_commands(self):
        self.tg.call("setMyCommands", {"commands": [
            {"command": c, "description": d.get(self.lang, d["en"])} for c, d in COMMANDS]})

    def run(self):
        db.init(self.config["DB_PATH"])
        if not self.config["TELEGRAM_BOT_TOKEN"] or not self.chat_id:
            raise SystemExit("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set in the config file")
        self.register_commands()
        print(f"[{datetime.now()}] Nöbetçi bot listening")
        offset = 0
        while True:
            try:
                reply = self.tg.call("getUpdates", {"offset": offset, "timeout": 25,
                                                    "allowed_updates": ["message", "callback_query"]}, timeout=35)
                self.flush_strangers()
                if not reply or not reply.get("ok"):
                    time.sleep(5)
                    continue
                for update in reply.get("result", []):
                    offset = update["update_id"] + 1
                    if "callback_query" in update:
                        self.on_callback(update["callback_query"])
                    elif "message" in update:
                        self.on_message(update["message"])
            except KeyboardInterrupt:
                return
            except Exception as exc:
                print(f"Bot loop error: {type(exc).__name__}: {exc}")
                time.sleep(5)
