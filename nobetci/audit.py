"""
/audit: read-only hardening checks. Nothing here changes the server; each
finding says how to fix it by hand.
"""
import glob
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime

from nobetci import firewall
from nobetci.config import find_config_path

COMMON_PORTS = {22, 80, 443}


@dataclass
class Finding:
    key: str
    title: dict
    ok: bool | None      # None: could not check
    detail: str = ""
    fix: str = ""


def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None, ""


def _sshd():
    code, out = _run(["sshd", "-T"])
    if code != 0:
        return None
    return dict(line.split(" ", 1) for line in out.splitlines() if " " in line)


def check_ssh_password(sshd):
    title = {"tr": "SSH parola girişi kapalı", "en": "SSH password login disabled"}
    if sshd is None:
        return Finding("ssh_password", title, None)
    ok = sshd.get("passwordauthentication") == "no"
    return Finding("ssh_password", title, ok, "PasswordAuthentication yes",
                   "PasswordAuthentication no  (/etc/ssh/sshd_config.d/) && systemctl reload ssh")


def check_ssh_root(sshd):
    title = {"tr": "SSH root girişi kapalı", "en": "SSH root login disabled"}
    if sshd is None:
        return Finding("ssh_root", title, None)
    value = sshd.get("permitrootlogin", "")
    return Finding("ssh_root", title, value in ("no", "prohibit-password", "without-password"),
                   f"PermitRootLogin {value}", "PermitRootLogin no && systemctl reload ssh")


def check_ufw():
    title = {"tr": "Güvenlik duvarı (UFW) açık", "en": "Firewall (UFW) active"}
    code, out = _run(["ufw", "status"])
    if code is None:
        return Finding("ufw", title, None)
    return Finding("ufw", title, "Status: active" in out, "ufw inactive",
                   "ufw allow OpenSSH && ufw allow 'Nginx Full' && ufw enable")


def check_ports():
    title = {"tr": "Gereksiz açık port yok", "en": "No unexpected open ports"}
    code, out = _run(["ss", "-H", "-tlnp"])
    if code != 0:
        return Finding("ports", title, None)
    exposed = set()
    for line in out.splitlines():
        cols = line.split()
        if len(cols) < 4:
            continue
        addr = cols[3]
        host, _, port = addr.rpartition(":")
        if host.strip("[]") in ("127.0.0.1", "::1") or host.startswith("127.") or "%lo" in host:
            continue
        if port.isdigit() and int(port) not in COMMON_PORTS:
            proc = re.search(r'"([^"]+)"', line)
            exposed.add(f"{port}{'/' + proc.group(1) if proc else ''}")
    return Finding("ports", title, not exposed, ", ".join(sorted(exposed)),
                   "ufw deny <port>  ya da servisi 127.0.0.1'e bağla / or bind it to 127.0.0.1")


def check_certificates():
    title = {"tr": "SSL sertifikaları 14 günden uzun geçerli", "en": "SSL certificates valid for 14+ days"}
    certs = glob.glob("/etc/letsencrypt/live/*/cert.pem")
    if not certs:
        return Finding("ssl", title, None)
    soon = []
    for cert in certs:
        code, out = _run(["openssl", "x509", "-enddate", "-noout", "-in", cert])
        if code != 0:
            continue
        try:
            end = datetime.strptime(out.strip().split("=", 1)[1], "%b %d %H:%M:%S %Y %Z")
        except (IndexError, ValueError):
            continue
        days = (end - datetime.utcnow()).days
        if days < 14:
            soon.append(f"{os.path.basename(os.path.dirname(cert))} ({days}d)")
    return Finding("ssl", title, not soon, ", ".join(soon), "certbot renew")


def check_updates():
    title = {"tr": "Bekleyen güvenlik güncellemesi yok", "en": "No pending security updates"}
    code, out = _run(["apt-get", "-s", "upgrade"], timeout=90)
    if code != 0:
        return Finding("updates", title, None)
    pending = [l.split()[1] for l in out.splitlines() if l.startswith("Inst ") and "security" in l.lower()]
    return Finding("updates", title, not pending, f"{len(pending)}: " + ", ".join(pending[:6]),
                   "apt-get update && apt-get upgrade  (otomatik: apt install unattended-upgrades)")


def check_server_tokens():
    title = {"tr": "nginx sürümü gizli (server_tokens off)", "en": "nginx version hidden (server_tokens off)"}
    code, out = _run(["nginx", "-T"])
    if code != 0:
        return Finding("server_tokens", title, None)
    return Finding("server_tokens", title, bool(re.search(r"^\s*server_tokens\s+off;", out, re.M)),
                   "server_tokens on", "server_tokens off;  (http bloğu) && nginx -t && systemctl reload nginx")


def check_blocklist(config):
    title = {"tr": "Ban dosyası nginx'e dahil", "en": "Ban file included in nginx"}
    included = firewall.blocklist_included(config["BLOCKLIST_PATH"])
    return Finding("blocklist", title, included, config["BLOCKLIST_PATH"],
                   f"include {config['BLOCKLIST_PATH']};  (server bloğu)")


def check_config_mode():
    title = {"tr": "config.env yalnızca root okuyabiliyor", "en": "config.env readable by root only"}
    path = find_config_path()
    if not path:
        return Finding("config_mode", title, None)
    mode = os.stat(path).st_mode & 0o777
    return Finding("config_mode", title, mode & 0o077 == 0, oct(mode), f"chmod 600 {path}")


def run(config):
    sshd = _sshd()
    return [
        check_ssh_password(sshd),
        check_ssh_root(sshd),
        check_ufw(),
        check_ports(),
        check_certificates(),
        check_updates(),
        check_server_tokens(),
        check_blocklist(config),
        check_config_mode(),
    ]


def format_report(findings, t, lang):
    checked = [f for f in findings if f.ok is not None]
    score = sum(1 for f in checked if f.ok)
    lines = [t("audit_title", score=score, total=len(checked)), ""]
    for f in sorted(findings, key=lambda f: {False: 0, True: 1, None: 2}[f.ok]):
        title = f.title.get(lang, f.title["en"])
        if f.ok is None:
            lines.append(t("audit_skip", title=title))
        elif f.ok:
            lines.append(t("audit_ok", title=title))
        else:
            lines.append(t("audit_bad", title=title, detail=f.detail, fix=f.fix))
    return "\n".join(lines)


def _first(cmd, timeout=10):
    code, out = _run(cmd, timeout)
    return out.strip() if code == 0 else ""


def server_facts(config, mask):
    """
    Read-only facts about this server for the AI chat ("which port is SSH on?").
    Nothing secret: no keys, no config values, and addresses go through mask().
    """
    from nobetci import __version__
    facts = [f"Nöbetçi version: {__version__}"]
    try:
        with open("/etc/os-release") as f:
            pretty = next((l.split("=", 1)[1].strip().strip('"') for l in f if l.startswith("PRETTY_NAME=")), "")
        facts.append(f"OS: {pretty} (kernel {_first(['uname', '-r'])})")
    except OSError:
        pass

    sshd = _sshd()
    if sshd:
        ports = [line.split(" ", 1)[1] for line in _first(["sshd", "-T"]).splitlines() if line.startswith("port ")]
        facts.append(f"SSH: port {', '.join(ports) or sshd.get('port', '?')}, "
                     f"PasswordAuthentication {sshd.get('passwordauthentication', '?')}, "
                     f"PermitRootLogin {sshd.get('permitrootlogin', '?')}, "
                     f"PubkeyAuthentication {sshd.get('pubkeyauthentication', '?')}")
    else:
        facts.append("SSH: configuration could not be read (sshd -T failed)")

    listening = []
    for line in _first(["ss", "-H", "-tlnp"]).splitlines():
        cols = line.split()
        if len(cols) >= 4:
            proc = re.search(r'"([^"]+)"', line)
            addr = cols[3]
            if not re.match(r"^(0\.0\.0\.0|\*|\[::\]|127\.|\[::1\])", addr):
                addr = mask(addr)
            listening.append(f"{addr}{'/' + proc.group(1) if proc else ''}")
    if listening:
        facts.append("Listening TCP: " + ", ".join(sorted(set(listening))))

    ufw = _first(["ufw", "status"])
    if ufw:
        facts.append("UFW:\n" + mask("\n".join(ufw.splitlines()[:30])))

    states = []
    for unit in ("nginx", "ssh", "fail2ban", "nobetci-bot", "nobetci-analyze.timer", "unattended-upgrades"):
        state = _first(["systemctl", "is-active", unit]) or "unknown"
        states.append(f"{unit}={state}")
    facts.append("Services: " + ", ".join(states))

    code, out = _run(["nginx", "-T"], 20)
    if code == 0:
        names = sorted({n for m in re.findall(r"^\s*server_name\s+([^;]+);", out, re.M) for n in m.split() if n != "_"})
        facts.append(f"nginx server names: {', '.join(names[:20]) or '-'}")
        facts.append(f"nginx ban list included: {firewall.blocklist_included(config['BLOCKLIST_PATH'])}")

    certs = check_certificates()
    if certs.ok is not None:
        facts.append(f"SSL certificates expiring within 14 days: {certs.detail or 'none'}")

    disk = _first(["df", "-h", "--output=used,size,pcent", "/"]).splitlines()
    if len(disk) > 1:
        facts.append("Disk /: " + " ".join(disk[-1].split()))
    mem = _first(["free", "-h"]).splitlines()
    if len(mem) > 1:
        cols = mem[1].split()
        facts.append(f"Memory: {cols[2]} used of {cols[1]}")
    facts.append(f"AI: {config.get('AI_PROVIDER')} models {config.get('AI_MODELS')}")
    return facts
