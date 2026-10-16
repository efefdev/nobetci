"""
One analysis run: collect logs, run the rules, apply automatic bans, ask the
AI, notify Telegram, store the results. Started by the nobetci-analyze timer
or by /analyze; everything is passed in memory, nothing goes through /tmp.
"""
import fcntl
import os
from contextlib import contextmanager
from datetime import datetime

from nobetci import ai as ai_mod
from nobetci import db, logs, rules
from nobetci.actions import Actions
from nobetci.durations import humanize
from nobetci.i18n import SEVERITY_EMOJI, esc, translator
from nobetci.telegram import Telegram, button

AI_WARN_EVERY = 1800
last_ai_error = ""  # why the AI failed in the last run(), for /analyze


def save_detections(conn, detections):
    for d in detections:
        conn.execute(
            "INSERT INTO rule_detections (timestamp, rule_id, rule_name, severity, description, match_count, action)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (db.now(), d.rule_id, d.name, d.severity, f"{d.ip}: {d.sample}"[:500], d.count, d.action))


def save_analysis(conn, text, threats, log_size, highest):
    cur = conn.execute(
        "INSERT INTO analyses (timestamp, raw_analysis, max_severity, notification_sent, log_size) VALUES (?, ?, ?, 1, ?)",
        (db.now(), ai_mod.mask(text or ""), highest, log_size))
    for t in threats:
        conn.execute(
            "INSERT INTO threats (analysis_id, timestamp, category, severity, description, action) VALUES (?, ?, ?, ?, ?, ?)",
            (cur.lastrowid, db.now(), t["category"], t["severity"], ai_mod.mask(t["description"]), t["action"]))
    today = datetime.now().strftime("%Y-%m-%d")
    column = {"CLEAN": "clean", "LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}[highest]
    if conn.execute("SELECT 1 FROM statistics WHERE timestamp=?", (today,)).fetchone():
        conn.execute(f"UPDATE statistics SET total_analyses=total_analyses+1, {column}={column}+1 WHERE timestamp=?",
                     (today,))
    else:
        conn.execute(f"INSERT INTO statistics (timestamp, total_analyses, {column}) VALUES (?, 1, 1)", (today,))


def _ai_warning_due(state_dir):
    path = os.path.join(state_dir, "last_ai_warning")
    now = datetime.now().timestamp()
    try:
        with open(path) as f:
            if now - float(f.read().strip()) < AI_WARN_EVERY:
                return False
    except (OSError, ValueError):
        pass
    with open(path, "w") as f:
        f.write(str(now))
    return True


@contextmanager
def run_lock(state_dir):
    """The timer and /analyze must not read the same logs twice at once."""
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    with open(os.path.join(state_dir, "analyze.lock"), "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def run(config, quiet=False):
    """Run once, holding the lock. Returns (detections, ai_text, threats, alerts)."""
    with run_lock(config["STATE_DIR"]):
        return _run(config, quiet)


def _run(config, quiet):
    t = translator(config.get("LANG"))
    actions = Actions(config)
    tg = Telegram(config["TELEGRAM_BOT_TOKEN"], config["TELEGRAM_CHAT_ID"])
    db.init(config["DB_PATH"])
    started = datetime.now()
    since = logs.last_run(config["STATE_DIR"])
    batch = logs.collect(config, since, actions.protection)

    detections = rules.apply(batch, config)
    alerts = []
    banned = set()
    for d in detections:
        emoji = SEVERITY_EMOJI.get(d.severity, "ℹ️")
        head = t("alert_rule", emoji=emoji, name=d.name, description=f"{d.ip} · {t('times', n=d.count)}\n{d.sample}")
        if d.action == "BAN":
            result = actions.ban(d.ip, d.ban, d.name, d.rule_id, automatic=True)
            if result.status in ("done", "already"):
                banned.add(d.ip)
            if result.status == "done":
                text = head + "\n\n" + t("alert_auto", ip=d.ip, d=humanize(d.ban, t))
                alerts.append((text, [[button(t("btn_undo"), f"u:{d.ip}")]]))
        elif d.action == "ASK" and d.ip not in banned and actions.protection.bannable(d.ip):
            banned.add(d.ip)  # one proposal per IP per run
            pending = actions.propose("ban", d.ip, d.name, duration=str(int(d.ban.total_seconds())))
            text = head + "\n\n" + t("alert_proposal", ip=d.ip, d=humanize(d.ban, t))
            alerts.append((text, [[button(t("btn_approve"), f"ok:{pending}"), button(t("btn_reject"), f"no:{pending}")]]))

    global last_ai_error
    ai = ai_mod.AI(config)
    ai_text, threats = None, []
    last_ai_error = ""
    if ai.enabled and (batch.access or batch.auth or batch.error or batch.warnings):
        ai_text = ai.analyze(logs.ai_view(batch, ai_mod.mask))
        if ai_text is None:
            last_ai_error = ai.error_summary()
            if not quiet and _ai_warning_due(config["STATE_DIR"]):
                tg.send(t("warn_ai", why=ai.error_summary()))
        else:
            threats = ai_mod.parse_threats(ai_text)
            for th in threats:
                if th["severity"] in ("HIGH", "CRITICAL") or (th["severity"] == "MEDIUM" and not detections):
                    emoji = SEVERITY_EMOJI.get(th["severity"], "🔶")
                    text = t("alert_title", emoji=emoji, sev=t(f"sev_{th['severity']}")) + "\n" + \
                        t("alert_body", category=th["category"], description=th["description"])
                    if th["action"]:
                        text += "\n\n🎯 " + esc(th["action"])
                    # The AI never proposes bans: an IP it names could be planted in the logs
                    alerts.append((text, None))

    highest_ai = max((th["severity"] for th in threats), key=rules.SEVERITY_ORDER.index, default="CLEAN")
    highest = max(rules.highest(detections), highest_ai, key=rules.SEVERITY_ORDER.index)
    with db.connect(config["DB_PATH"]) as conn:
        save_detections(conn, detections)
        if ai_text is not None or detections:
            save_analysis(conn, ai_text or "", threats, batch.size(), highest)

    if not quiet:
        for text, buttons in alerts:
            tg.send(text, buttons)
    logs.mark_run(config["STATE_DIR"], started)
    return detections, ai_text, threats, alerts


def expire(config):
    db.init(config["DB_PATH"])
    lifted = Actions(config).expire()
    for ip in lifted:
        print(f"Unbanned (expired): {ip}")
    return lifted


def daily_report(config):
    t = translator(config.get("LANG"))
    db.init(config["DB_PATH"])
    today = datetime.now().strftime("%Y-%m-%d")
    with db.connect(config["DB_PATH"]) as conn:
        stats = conn.execute("SELECT * FROM statistics WHERE timestamp=?", (today,)).fetchone()
        bans = conn.execute("SELECT COUNT(*) FROM ban_log WHERE timestamp LIKE ?", (f"{today}%",)).fetchone()[0]
        rule_rows = conn.execute(
            "SELECT rule_name, severity, COUNT(*) n FROM rule_detections WHERE timestamp LIKE ?"
            " GROUP BY rule_id ORDER BY n DESC LIMIT 5", (f"{today}%",)).fetchall()
        ai_rows = conn.execute(
            "SELECT category, severity, COUNT(*) n FROM threats WHERE timestamp LIKE ?"
            " GROUP BY category ORDER BY n DESC LIMIT 5", (f"{today}%",)).fetchall()
    parts = [t("report_title", day=today), ""]
    if stats:
        parts.append(t("report_analyses", total=stats["total_analyses"], clean=stats["clean"], low=stats["low"],
                       medium=stats["medium"], high=stats["high"], critical=stats["critical"]))
    else:
        parts.append(t("report_none"))
    parts.append(t("report_bans", n=bans))
    if rule_rows:
        parts += ["", t("threats_rules")] + [
            f"{SEVERITY_EMOJI.get(r['severity'], 'ℹ️')} " + esc(r["rule_name"])
            + " · " + t("times", n=r["n"]) for r in rule_rows]
    if ai_rows:
        parts += ["", t("threats_ai")] + [
            f"{SEVERITY_EMOJI.get(r['severity'], 'ℹ️')} " + esc(r["category"])
            + " · " + t("times", n=r["n"]) for r in ai_rows]
    text = "\n".join(parts)
    Telegram(config["TELEGRAM_BOT_TOKEN"], config["TELEGRAM_CHAT_ID"]).send(text)
    return text
