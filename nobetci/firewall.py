"""
Where bans are applied: the nginx deny list (always) and Cloudflare's edge
(when CF_API_TOKEN is set). All writes are atomic and nginx is tested before
it is reloaded, so a bad file never takes the site down.
"""
import os
import subprocess
import tempfile

from nobetci import net

HEADER = "# Nöbetçi blocked IPs. Managed automatically, do not edit by hand.\n"


class FirewallError(Exception):
    pass


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return HEADER


def banned_ips(path):
    ips = []
    for line in _read(path).splitlines():
        line = line.strip()
        if line.startswith("deny ") and line.endswith(";"):
            ips.append(line[5:-1].strip())
    return ips


def _write(path, ips):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    body = HEADER + "".join(f"deny {ip};\n" for ip in ips) + "allow all;\n"
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".nobetci-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(body)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def _reload_nginx():
    test = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if test.returncode != 0:
        raise FirewallError(test.stderr.strip().splitlines()[-1] if test.stderr.strip() else "nginx -t failed")
    subprocess.run(["systemctl", "reload", "nginx"], capture_output=True)


def nginx_ban(path, ip):
    """Add ip; returns False when it was already there."""
    ips = banned_ips(path)
    if ip in ips:
        return False
    before = _read(path)
    _write(path, ips + [ip])
    try:
        _reload_nginx()
    except FirewallError:
        with open(path, "w") as f:
            f.write(before)
        raise
    return True


def nginx_unban(path, ip):
    ips = banned_ips(path)
    if ip not in ips:
        return False
    _write(path, [i for i in ips if i != ip])
    _reload_nginx()
    return True


def blocklist_included(path):
    """True/False when nginx -T could be read, None when nginx is not available."""
    try:
        r = subprocess.run(["nginx", "-T"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    return f"# configuration file {path}:" in r.stdout


class Cloudflare:
    """IP Access Rules at zone (CF_ZONE_ID) or account (CF_ACCOUNT_ID) level."""

    API = "https://api.cloudflare.com/client/v4"

    def __init__(self, config):
        self.token = config.get("CF_API_TOKEN", "")
        if config.get("CF_ZONE_ID"):
            self.base = f"{self.API}/zones/{config['CF_ZONE_ID']}/firewall/access_rules/rules"
        elif config.get("CF_ACCOUNT_ID"):
            self.base = f"{self.API}/accounts/{config['CF_ACCOUNT_ID']}/firewall/access_rules/rules"
        else:
            self.base = ""

    @property
    def enabled(self):
        return bool(self.token and self.base)

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def block(self, ip, note):
        target = "ip6" if ":" in ip else "ip"
        reply = net.request_json(self.base, {
            "mode": "block",
            "configuration": {"target": target, "value": ip},
            "notes": f"nobetci: {note}"[:500],
        }, headers=self._headers(), timeout=15, resend=False)
        if not reply.get("success"):
            raise FirewallError(str(reply.get("errors")))
        return reply["result"]["id"]

    def unblock(self, rule_id):
        reply = net.request_json(f"{self.base}/{rule_id}", headers=self._headers(), method="DELETE", timeout=15)
        return bool(reply.get("success"))
