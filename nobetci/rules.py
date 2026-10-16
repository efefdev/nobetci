"""
Rule engine. Every rule is evaluated per source IP, so every detection knows
whom it is about, and the ban decision never relies on the AI.
"""
import re
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from nobetci.durations import parse_duration
from nobetci.ipcheck import IP_PATTERN, parse_ip

_ACCESS = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "([^"]*)" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?')
_SSH_FROM = re.compile(rf"from ({IP_PATTERN})")
_UFW_SRC = re.compile(rf"SRC=({IP_PATTERN})")


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    source: str            # access | auth | firewall
    pattern: str
    threshold: int
    action: str            # BAN (automatic) | ASK (Telegram approval) | LOG
    ban: str = "1d"
    field: str = "request"  # access only: request | agent | line

    def __post_init__(self):
        self.regex = re.compile(self.pattern, re.IGNORECASE)


RULES = [
    Rule("BRUTE_FORCE_SSH", "SSH brute force", "CRITICAL", "auth",
         r"Failed password for", 5, "BAN", "7d"),
    Rule("INVALID_USER_SSH", "SSH invalid user", "HIGH", "auth",
         r"Invalid user", 3, "BAN", "1d"),
    Rule("SQL_INJECTION", "SQL injection", "CRITICAL", "access",
         r"(union(\s|/\*.*?\*/)+select|'\s*or\s*'?1'?\s*=\s*'?1|drop\s+table|information_schema|sleep\(\d|benchmark\()", 1, "BAN", "7d"),
    Rule("WEBSHELL", "Webshell probe", "CRITICAL", "access",
         r"(/shell\.php|[?&](cmd|exec)=|system\(|passthru\(|/c99\.php|/r57\.php|/webshell)", 1, "BAN", "90d"),
    Rule("PATH_TRAVERSAL", "Path traversal", "HIGH", "access",
         r"((\.\./){2,}|(\.\.\\){2,}|/etc/passwd|/proc/self/environ)", 1, "BAN", "7d"),
    Rule("SCANNER", "Attack tool", "CRITICAL", "access",
         r"(sqlmap|nikto|masscan|zgrab|nuclei|dirbuster|gobuster|wpscan)", 1, "BAN", "30d", field="agent"),
    Rule("XSS", "XSS attempt", "HIGH", "access",
         r"(<script|javascript:|onerror\s*=|onload\s*=|document\.cookie)", 1, "ASK", "1d"),
    Rule("SENSITIVE_FILE", "Sensitive file probe", "MEDIUM", "access",
         r"(/\.env|/\.git/|wp-config|id_rsa|/\.htaccess|/\.htpasswd)", 3, "ASK", "7d"),
    Rule("PORT_SCAN", "Port scan", "LOW", "firewall",
         r"SYN", 50, "LOG"),
    Rule("HTTP_FLOOD", "Request flood", "HIGH", "access",
         r".", 300, "ASK", "1d", field="line"),
]

SEVERITY_ORDER = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class Detection:
    rule_id: str
    name: str
    severity: str
    ip: str
    count: int
    action: str
    ban: timedelta | None
    sample: str


def decode(text):
    # Twice, because scanners double-encode (%252e%252e)
    return urllib.parse.unquote_plus(urllib.parse.unquote(text))


def parse_access(line):
    m = _ACCESS.match(line)
    if not m:
        return None
    return {"ip": m.group(1), "request": decode(m.group(2)), "status": m.group(3),
            "agent": m.group(4) or "", "line": line}


def _path(request):
    parts = request.split(" ")
    target = parts[1] if len(parts) > 1 else request
    return target.split("?", 1)[0].lower()


def trap_rule(config):
    paths = [p.lower() for p in config.list("TRAP_PATHS")]
    if not paths:
        return None, []
    return Rule("TRAP", "Trap URL", "CRITICAL", "access", r"$^", 1, "BAN", config.get("TRAP_BAN", "30d")), paths


def apply(logs, config):
    """Return detections for this batch of logs."""
    counts = defaultdict(lambda: [0, ""])
    trap, trap_paths = trap_rule(config)
    access = [a for a in (parse_access(l) for l in logs.access) if a]

    for rule in RULES:
        if rule.source == "access":
            for entry in access:
                if rule.regex.search(entry[rule.field]):
                    hit = counts[(rule.id, entry["ip"])]
                    hit[0] += 1
                    hit[1] = hit[1] or entry["request"][:200]
        else:
            lines = logs.auth if rule.source == "auth" else logs.firewall
            extractor = _SSH_FROM if rule.source == "auth" else _UFW_SRC
            for line in lines:
                if rule.regex.search(line):
                    m = extractor.search(line)
                    if m:
                        hit = counts[(rule.id, m.group(1))]
                        hit[0] += 1
                        hit[1] = hit[1] or line[-200:]

    if trap:
        for entry in access:
            path = _path(entry["request"])
            if any(path == p or path.startswith(p.rstrip("/") + "/") for p in trap_paths):
                hit = counts[("TRAP", entry["ip"])]
                hit[0] += 1
                hit[1] = hit[1] or entry["request"][:200]

    by_id = {r.id: r for r in RULES}
    if trap:
        by_id["TRAP"] = trap
    detections = []
    for (rule_id, ip), (count, sample) in counts.items():
        rule = by_id[rule_id]
        if count < rule.threshold or parse_ip(ip) is None:
            continue
        detections.append(Detection(rule.id, rule.name, rule.severity, ip, count, rule.action,
                                    parse_duration(rule.ban) if rule.action != "LOG" else None, sample))
    detections.sort(key=lambda d: (-SEVERITY_ORDER.index(d.severity), -d.count))
    return detections


def highest(detections):
    best = "CLEAN"
    for d in detections:
        if SEVERITY_ORDER.index(d.severity) > SEVERITY_ORDER.index(best):
            best = d.severity
    return best
