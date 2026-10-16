"""
The only things Nöbetçi can do to the server. Telegram buttons carry an
action name and an id, never a shell command, so nothing outside this file
can be executed from a chat.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta

from nobetci import db, firewall
from nobetci.ipcheck import Protection, parse_ip

PENDING_TTL = timedelta(hours=12)
ACTIONS = {"ban", "update", "rollback"}


@dataclass
class Result:
    status: str          # done | already | protected | invalid | error | not_banned
    ip: str = ""
    detail: str = ""
    edge: bool = False


class Actions:
    def __init__(self, config):
        self.config = config
        self.db_path = config["DB_PATH"]
        self.blocklist = config["BLOCKLIST_PATH"]
        self.protection = Protection(config)
        self.cloudflare = firewall.Cloudflare(config)

    # BAN / UNBAN

    def ban(self, ip_text, duration, reason, rule_id="MANUAL", automatic=False):
        ip = parse_ip(ip_text)
        if ip is None:
            return Result("invalid", ip_text)
        ip = str(ip)
        why = self.protection.reason(ip)
        if why:
            return Result("protected", ip, why)
        try:
            added = firewall.nginx_ban(self.blocklist, ip)
        except Exception as exc:
            return Result("error", ip, str(exc))
        if not added:
            return Result("already", ip)

        edge_id = None
        if self.cloudflare.enabled:
            try:
                edge_id = self.cloudflare.block(ip, f"{rule_id} {reason}")
            except Exception as exc:
                print(f"Cloudflare block failed for {ip}: {exc}")

        expiry = (datetime.now() + duration).strftime(db.TIME_FMT) if duration else None
        with db.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO ban_log (timestamp, ip, reason, rule_id, automatic, expiry, active, edge_rule_id)"
                " VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                (db.now(), ip, reason[:200], rule_id, int(automatic), expiry, edge_id))
        return Result("done", ip, edge=bool(edge_id))

    def unban(self, ip_text):
        ip = parse_ip(ip_text)
        if ip is None:
            return Result("invalid", ip_text)
        ip = str(ip)
        try:
            removed = firewall.nginx_unban(self.blocklist, ip)
        except Exception as exc:
            return Result("error", ip, str(exc))
        with db.connect(self.db_path) as conn:
            rows = conn.execute("SELECT id, edge_rule_id FROM ban_log WHERE ip=? AND active=1", (ip,)).fetchall()
            for row in rows:
                if row["edge_rule_id"] and self.cloudflare.enabled:
                    try:
                        self.cloudflare.unblock(row["edge_rule_id"])
                    except Exception as exc:
                        print(f"Cloudflare unblock failed for {ip}: {exc}")
            conn.execute("UPDATE ban_log SET active=0, unbanned_at=? WHERE ip=? AND active=1", (db.now(), ip))
        return Result("done" if removed or rows else "not_banned", ip)

    def expire(self):
        """Lift every ban whose expiry has passed; returns the IPs."""
        with db.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT DISTINCT ip FROM ban_log WHERE active=1 AND expiry IS NOT NULL AND expiry <= ?",
                (db.now(),)).fetchall()
        lifted = []
        for row in rows:
            # A longer, newer ban on the same IP wins
            with db.connect(self.db_path) as conn:
                longer = conn.execute(
                    "SELECT 1 FROM ban_log WHERE ip=? AND active=1 AND (expiry IS NULL OR expiry > ?)",
                    (row["ip"], db.now())).fetchone()
                if longer:
                    conn.execute("UPDATE ban_log SET active=0 WHERE ip=? AND active=1 AND expiry <= ?",
                                 (row["ip"], db.now()))
                    continue
            if self.unban(row["ip"]).status == "done":
                lifted.append(row["ip"])
        return lifted

    def active_bans(self):
        """Bans that are really in the nginx file, newest first, with expiry."""
        in_file = set(firewall.banned_ips(self.blocklist))
        with db.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT ip, reason, rule_id, expiry, timestamp FROM ban_log WHERE active=1 ORDER BY id DESC"
            ).fetchall()
            stale = {r["ip"] for r in rows} - in_file
            for ip in stale:
                conn.execute("UPDATE ban_log SET active=0 WHERE ip=? AND active=1", (ip,))
        seen, bans = set(), []
        for r in rows:
            if r["ip"] in in_file and r["ip"] not in seen:
                seen.add(r["ip"])
                bans.append(dict(r))
        for ip in sorted(in_file - seen):
            bans.append({"ip": ip, "reason": "", "rule_id": "", "expiry": None, "timestamp": ""})
        return bans

    # PROPOSALS (Approve / Reject buttons)

    def propose(self, action, target, reason, duration=""):
        assert action in ACTIONS
        with db.connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO pending_commands (timestamp, command, reason, chat_id, status, action, target, duration)"
                " VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)",
                (db.now(), f"{action} {target}", reason[:200], self.config["TELEGRAM_CHAT_ID"],
                 action, target, duration))
            return cur.lastrowid

    def take_pending(self, pending_id, status):
        """Atomically move a pending proposal to status; returns it or None."""
        with db.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id, timestamp, action, target, duration, reason FROM pending_commands"
                " WHERE id=? AND status='pending' AND action IS NOT NULL", (pending_id,)).fetchone()
            if not row:
                return None
            if datetime.now() - datetime.strptime(row["timestamp"], db.TIME_FMT) > PENDING_TTL:
                conn.execute("UPDATE pending_commands SET status='expired' WHERE id=?", (pending_id,))
                return None
            cur = conn.execute("UPDATE pending_commands SET status=? WHERE id=? AND status='pending'",
                               (status, pending_id))
            return dict(row) if cur.rowcount == 1 else None

    def log_command(self, command, reason, result):
        with db.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO command_history (timestamp, command, reason, result, approved_by) VALUES (?,?,?,?,?)",
                (db.now(), command, reason, result[:2000], "telegram"))
