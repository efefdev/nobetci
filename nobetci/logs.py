"""
Log collection in plain Python. Timestamps are parsed into datetimes, so a
month change or a space-padded day can no longer confuse the "since" filter.
"""
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from nobetci.ipcheck import parse_ip

MAX_READ = 20 * 1024 * 1024
MAX_LOOKBACK = timedelta(hours=24)
FIRST_RUN_LOOKBACK = timedelta(minutes=5)

_ACCESS_TIME = re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}) ([+-]\d{4})\]")
_ERROR_TIME = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
_SYSLOG_TIME = re.compile(r"^(\w{3})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2})")
_ISO_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
_QUIET_STATUS = re.compile(r'" (444|403|301|302|304) ')


def access_time(line):
    m = _ACCESS_TIME.search(line)
    if not m:
        return None
    try:
        day, mon, rest = m.group(1).split("/", 2)
        year, clock = rest.split(":", 1)
        stamp = datetime(int(year), _MONTHS[mon], int(day), *map(int, clock.split(":")))
    except (KeyError, ValueError):
        return None
    # nginx writes local time with its offset; convert to naive local time
    sign = 1 if m.group(2)[0] == "+" else -1
    offset = timedelta(hours=int(m.group(2)[1:3]), minutes=int(m.group(2)[3:5])) * sign
    local_offset = datetime.now().astimezone().utcoffset() or timedelta()
    return stamp - offset + local_offset


def error_time(line):
    m = _ERROR_TIME.match(line)
    return datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S") if m else None


def syslog_time(line, now=None):
    m = _ISO_TIME.match(line)
    if m:
        return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    m = _SYSLOG_TIME.match(line)
    if not m or m.group(1) not in _MONTHS:
        return None
    now = now or datetime.now()
    h, mi, s = map(int, m.group(3).split(":"))
    stamp = datetime(now.year, _MONTHS[m.group(1)], int(m.group(2)), h, mi, s)
    # A December line read in January belongs to last year
    if stamp - now > timedelta(days=1):
        stamp = stamp.replace(year=now.year - 1)
    return stamp


def _tail_lines(path):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size > MAX_READ:
                f.seek(size - MAX_READ)
                f.readline()
            data = f.read()
    except OSError:
        return []
    return data.decode("utf-8", errors="replace").splitlines()


def read_since(path, since, timestamp):
    """Lines of path (and path.1 when it was rotated after `since`) newer than since."""
    paths = []
    rotated = path + ".1"
    try:
        if os.path.exists(rotated) and datetime.fromtimestamp(os.path.getmtime(rotated)) >= since:
            paths.append(rotated)
    except OSError:
        pass
    paths.append(path)
    out = []
    for p in paths:
        for line in _tail_lines(p):
            stamp = timestamp(line)
            if stamp is not None and stamp >= since:
                out.append(line)
    return out


def journal(args, since):
    cmd = ["journalctl", "--no-pager", "-o", "short-iso", "--since", since.strftime("%Y-%m-%d %H:%M:%S")] + args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [l for l in r.stdout.splitlines() if l and not l.startswith("-- ")]


def leading_ip(line):
    first = line.split(" ", 1)[0]
    return parse_ip(first)


@dataclass
class Logs:
    since: datetime
    access: list = field(default_factory=list)
    error: list = field(default_factory=list)
    auth: list = field(default_factory=list)
    firewall: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    def rule_text(self):
        """Everything the rule engine looks at."""
        return "\n".join(self.access + self.auth + self.firewall)

    def size(self):
        return sum(len(l) + 1 for l in self.access + self.error + self.auth + self.firewall + self.warnings)


def collect(config, since, protection=None):
    logs = Logs(since=since)
    access = read_since(config["NGINX_ACCESS_LOG"], since, access_time)
    if protection is not None:
        # Our own and Cloudflare health traffic is noise for both rules and AI
        access = [l for l in access if (ip := leading_ip(l)) is None or protection.bannable(ip)]
    logs.access = access
    logs.error = [l for l in read_since(config["NGINX_ERROR_LOG"], since, error_time)
                  if not re.search(r"signal process|graceful|reopening", l)]
    auth = journal(["-u", "ssh", "-u", "sshd"], since)
    if not auth:
        auth = read_since(config["AUTH_LOG"], since, syslog_time)
    logs.auth = [l for l in auth if re.search(r"sshd|sudo", l)]
    logs.firewall = [l for l in journal(["-k"], since) if "UFW BLOCK" in l][-300:]
    logs.warnings = [l for l in journal(["-p", "warning"], since)
                     if not re.search(r"sudo|cron|CRON|certbot|systemd|rsyslog|logrotate|UFW", l)][-8:]
    return logs


def ai_view(logs, mask, limit=15000):
    """The masked, trimmed slice sent to the AI model."""
    access = [l for l in logs.access if not _QUIET_STATUS.search(l)]
    auth = [l for l in logs.auth if not re.search(r"session opened|session closed|pam_unix", l)]
    parts = [
        ("NGINX ERROR", logs.error[-80:]),
        ("AUTH/SSH", auth[-120:]),
        ("SYSLOG", logs.warnings),
        ("NGINX ACCESS", access[-200:]),
    ]
    text = "\n".join(f"=== {name} ===\n" + "\n".join(lines) for name, lines in parts)
    return mask(text)[:limit]


def last_run(state_dir):
    path = os.path.join(state_dir, "last_run")
    now = datetime.now()
    try:
        with open(path) as f:
            stamp = datetime.fromisoformat(f.read().strip())
    except (OSError, ValueError):
        return now - FIRST_RUN_LOOKBACK
    return max(stamp, now - MAX_LOOKBACK)


def mark_run(state_dir, when):
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    with open(os.path.join(state_dir, "last_run"), "w") as f:
        f.write(when.isoformat(timespec="seconds"))
