"""Keep nginx's set_real_ip_from list in sync with Cloudflare's published ranges."""
import ipaddress
import os
import subprocess
import tempfile

from nobetci import net

CONF_FILE = "/etc/nginx/conf.d/cloudflare-real-ip.conf"


def render(ranges):
    lines = ["# Cloudflare IP ranges - restore real visitor IP (managed by nobetci)"]
    lines += [f"set_real_ip_from {r};" for r in ranges]
    lines += ["real_ip_header CF-Connecting-IP;", "real_ip_recursive on;"]
    return "\n".join(lines) + "\n"


def fetch():
    ranges = []
    for url in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"):
        for line in net.get_text(url).split():
            # Only well-formed networks reach the nginx config
            ranges.append(str(ipaddress.ip_network(line.strip(), strict=False)))
    if len(ranges) < 10:
        raise RuntimeError("Cloudflare returned too few ranges, refusing to write")
    return ranges


def refresh(path=CONF_FILE):
    content = render(fetch())
    try:
        with open(path) as f:
            if f.read() == content:
                print("No changes in Cloudflare IPs.")
                return False
    except FileNotFoundError:
        pass
    before = None
    if os.path.exists(path):
        with open(path) as f:
            before = f.read()
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".nobetci-")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    if subprocess.run(["nginx", "-t"], capture_output=True).returncode != 0:
        if before is None:
            os.remove(path)
        else:
            with open(path, "w") as f:
                f.write(before)
        raise RuntimeError("nginx -t failed, change reverted")
    subprocess.run(["systemctl", "reload", "nginx"])
    print("Cloudflare IPs updated and nginx reloaded.")
    return True
