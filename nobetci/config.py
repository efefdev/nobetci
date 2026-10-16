"""
Configuration: a flat KEY="value" file, root-only (0600).

/etc/nobetci/config.env is the current location; /etc/soc/config.env from
1.x installs is still read so an upgrade never loses the tokens.
"""
import os

CONFIG_PATHS = [
    os.environ.get("NOBETCI_CONFIG", ""),
    "/etc/nobetci/config.env",
    "/etc/soc/config.env",
]

DEFAULTS = {
    "TELEGRAM_BOT_TOKEN": "",
    "TELEGRAM_CHAT_ID": "",
    "SERVER_IP": "",
    "WHITELIST": "",
    "LANG": "tr",
    "DB_PATH": "/var/lib/nobetci/nobetci.db",
    "STATE_DIR": "/var/lib/nobetci",
    # AI
    "AI_PROVIDER": "groq",
    "AI_BASE_URL": "",
    "AI_API_KEY": "",
    "GROQ_API_KEY": "",
    "AI_MODELS": "moonshotai/kimi-k2-instruct,llama-3.3-70b-versatile,llama-3.1-8b-instant",
    "AI_TIME_BUDGET": "75",
    "AI_CHAT": "on",
    # Logs
    "NGINX_ACCESS_LOG": "/var/log/nginx/access.log",
    "NGINX_ERROR_LOG": "/var/log/nginx/error.log",
    "AUTH_LOG": "/var/log/auth.log",
    "BLOCKLIST_PATH": "/etc/nginx/snippets/blocked-ips.conf",
    # Traps
    "TRAP_PATHS": "/.env,/.git/config,/.aws/credentials,/phpinfo.php,/wp-config.php.bak",
    "TRAP_BAN": "30d",
    # Cloudflare edge bans (optional)
    "CF_API_TOKEN": "",
    "CF_ZONE_ID": "",
    "CF_ACCOUNT_ID": "",
    # Updates
    "UPDATE_REPO": "efefdev/nobetci",
}

PROVIDER_URLS = {
    "groq": "https://api.groq.com/openai/v1",
    "ollama": "http://127.0.0.1:11434/v1",
    "openai": "https://api.openai.com/v1",
}


def find_config_path():
    for path in CONFIG_PATHS:
        if path and os.path.exists(path):
            return path
    return None


def parse_env(text):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


class Config(dict):
    def list(self, key):
        return [p.strip() for p in self.get(key, "").split(",") if p.strip()]

    def int(self, key, default=0):
        try:
            return int(self.get(key, default))
        except (TypeError, ValueError):
            return default

    def flag(self, key):
        return self.get(key, "").lower() in ("1", "on", "yes", "true", "evet")

    @property
    def ai_base_url(self):
        return self.get("AI_BASE_URL") or PROVIDER_URLS.get(self.get("AI_PROVIDER"), "")

    @property
    def ai_api_key(self):
        # GROQ_API_KEY is the 1.x name, kept so old config files work unchanged
        return self.get("AI_API_KEY") or self.get("GROQ_API_KEY")


def load_config(path=None):
    config = Config(DEFAULTS)
    path = path or find_config_path()
    if path:
        with open(path, encoding="utf-8") as f:
            config.update(parse_env(f.read()))
    # 1.x installs kept the database under /var/lib/soc
    if config["DB_PATH"] == DEFAULTS["DB_PATH"] and os.path.exists("/var/lib/soc/soc_logs.db") \
            and not os.path.exists(DEFAULTS["DB_PATH"]):
        config["DB_PATH"] = "/var/lib/soc/soc_logs.db"
    return config
