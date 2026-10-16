"""
Which addresses may never be banned, and IP extraction from log lines.
Everything goes through ipaddress, so 1.2.3.45 is not mistaken for 1.2.3.4.
"""
import ipaddress

CLOUDFLARE_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
CLOUDFLARE_NETWORKS = [ipaddress.ip_network(r) for r in CLOUDFLARE_RANGES]

IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
IPV6 = r"[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}"
IP_PATTERN = f"(?:{IPV4}|{IPV6})"


def parse_ip(text):
    try:
        ip = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    # ::ffff:1.2.3.4 behaves like 1.2.3.4
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def _networks(entries):
    nets = []
    for entry in entries:
        try:
            nets.append(ipaddress.ip_network(entry.strip(), strict=False))
        except ValueError:
            pass
    return nets


class Protection:
    """Decides whether an IP is protected and why."""

    def __init__(self, config):
        self.whitelist = _networks(config.list("WHITELIST") + config.list("SERVER_IP"))

    def reason(self, ip):
        """Return None when the IP may be banned, otherwise a short reason key."""
        if isinstance(ip, str):
            ip = parse_ip(ip)
        if ip is None:
            return "invalid"
        if any(ip in net for net in self.whitelist):
            return "whitelist"
        if any(ip.version == net.version and ip in net for net in CLOUDFLARE_NETWORKS):
            return "cloudflare"
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast \
                or ip.is_reserved or ip.is_unspecified:
            return "private"
        return None

    def bannable(self, ip):
        return self.reason(ip) is None
