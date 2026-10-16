#!/usr/bin/env python3
"""
Nöbetçi installer. Safe to run again: an existing config is never
overwritten (only missing keys are appended), and a 1.x install
(soc-ai-telegram-bot) is migrated in place.

    sudo python3 install.py            first install / reinstall
    sudo python3 install.py --upgrade  used by `nobetci update`
"""
import os
import shutil
import subprocess
import sys

SRC = os.path.dirname(os.path.abspath(__file__))
APP_DIR = "/opt/nobetci/app"
CONFIG_DIR = "/etc/nobetci"
CONFIG = f"{CONFIG_DIR}/config.env"
LEGACY_CONFIG = "/etc/soc/config.env"
STATE_DIR = "/var/lib/nobetci"
WRAPPER = "/usr/local/bin/nobetci"
REPO_URL = "https://github.com/efefdev/nobetci.git"
UNITS = ["nobetci-bot.service", "nobetci-analyze.service", "nobetci-analyze.timer",
         "nobetci-expire.service", "nobetci-expire.timer", "nobetci-report.service",
         "nobetci-report.timer", "nobetci-cloudflare-ips.service", "nobetci-cloudflare-ips.timer"]
ENABLE = ["nobetci-bot.service", "nobetci-analyze.timer", "nobetci-expire.timer", "nobetci-report.timer"]
LEGACY_SCRIPTS = ["soc_config.py", "soc-db-init.py", "soc-db-save.py", "soc-bot-listener.py", "soc-notifier.py",
                  "soc-log-analyzer.py", "soc-rule-engine.py", "soc-daily-report.py", "soc-auto-ban.py",
                  "soc-auto-unban.py", "nginx-ban-ip.py", "nginx-unban-ip.py", "soc-update.py",
                  "update-cloudflare-ips.py", "soc_resilience.py"]

GREEN, CYAN, YELLOW, RESET = "\033[0;32m", "\033[0;36m", "\033[0;33m", "\033[0m"


def run(cmd, check=False):
    return subprocess.run(cmd, check=check)


def step(n, total, text):
    print(f"[{n}/{total}] {text}")


def parse_keys(path):
    keys = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                keys.add(line.split("=", 1)[0].strip())
    return keys


def install_app():
    """Put the code in /opt/nobetci/app as a git checkout (updates move between tags there)."""
    if os.path.realpath(SRC) == os.path.realpath(APP_DIR):
        return
    if os.path.exists(APP_DIR):
        shutil.rmtree(APP_DIR)
    os.makedirs(os.path.dirname(APP_DIR), mode=0o755, exist_ok=True)
    shutil.copytree(SRC, APP_DIR, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "config.env", "site"))
    if os.path.isdir(os.path.join(APP_DIR, ".git")):
        run(["git", "-C", APP_DIR, "remote", "set-url", "origin", REPO_URL])
    run(["chown", "-R", "root:root", "/opt/nobetci"])
    run(["chmod", "-R", "go-w", "/opt/nobetci"])


def install_wrapper():
    # -I: ignore PYTHONPATH and the current directory, so nothing outside /opt/nobetci/app is imported
    body = ("#!/bin/sh\n"
            f"exec /usr/bin/python3 -I -c 'import sys; sys.path.insert(0, \"{APP_DIR}\"); "
            "from nobetci.cli import main; sys.exit(main(sys.argv[1:]))' \"$@\"\n")
    with open(WRAPPER, "w") as f:
        f.write(body)
    os.chmod(WRAPPER, 0o755)


def install_config():
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)
    example = os.path.join(SRC, "config_templates", "config.env.example")
    if not os.path.exists(CONFIG):
        if os.path.exists(LEGACY_CONFIG):
            shutil.copy(LEGACY_CONFIG, CONFIG)
            print(f"{CYAN}  1.x config migrated from {LEGACY_CONFIG}{RESET}")
        elif os.path.exists(os.path.join(SRC, "config.env")):
            shutil.copy(os.path.join(SRC, "config.env"), CONFIG)
        else:
            shutil.copy(example, CONFIG)
            print(f"{YELLOW}  New config created. Fill in {CONFIG} and run: sudo nobetci check{RESET}")
    else:
        # Never overwrite: only append keys this version knows and the file lacks
        have = parse_keys(CONFIG)
        missing = []
        with open(example, encoding="utf-8") as f:
            for line in f:
                key = line.split("=", 1)[0].strip()
                if "=" in line and not line.startswith("#") and key not in have:
                    if key == "AI_API_KEY" and "GROQ_API_KEY" in have:
                        continue
                    missing.append(line.rstrip("\n"))
        if missing:
            with open(CONFIG, "a", encoding="utf-8") as f:
                f.write("\n# Added by the Nöbetçi installer\n" + "\n".join(missing) + "\n")
            print(f"{CYAN}  Added new settings: {', '.join(m.split('=')[0] for m in missing)}{RESET}")
    os.chown(CONFIG, 0, 0)
    os.chmod(CONFIG, 0o600)


def migrate_legacy():
    if os.path.exists("/etc/systemd/system/soc-bot-listener.service"):
        run(["systemctl", "disable", "--now", "soc-bot-listener"])
        os.remove("/etc/systemd/system/soc-bot-listener.service")
        print(f"{CYAN}  Old soc-bot-listener service removed{RESET}")
    for name in LEGACY_SCRIPTS:
        path = os.path.join("/usr/local/bin", name)
        if os.path.exists(path):
            os.remove(path)
    if os.path.exists(LEGACY_CONFIG):
        os.chmod(LEGACY_CONFIG, 0o600)


def install_units():
    for unit in UNITS:
        shutil.copy(os.path.join(SRC, "systemd", unit), f"/etc/systemd/system/{unit}")
    run(["systemctl", "daemon-reload"])
    for unit in ENABLE:
        run(["systemctl", "enable", "--now", unit])
    run(["systemctl", "restart", "nobetci-bot.service"])


def main():
    if os.geteuid() != 0:
        sys.exit("Please run as root: sudo python3 install.py")
    if sys.version_info < (3, 10):
        sys.exit("Python 3.10 or newer is required")
    upgrade = "--upgrade" in sys.argv
    total = 6
    print(f"{GREEN}Nöbetçi installer{RESET}\n")

    step(1, total, "Checking system packages...")
    for tool in ("nginx", "git", "journalctl"):
        if not shutil.which(tool):
            print(f"{YELLOW}  {tool} not found{RESET}")
    if not upgrade and not shutil.which("git") and shutil.which("apt-get"):
        run(["apt-get", "install", "-y", "-qq", "git"])

    step(2, total, f"Installing the code to {APP_DIR}...")
    install_app()
    install_wrapper()

    step(3, total, "Configuration...")
    install_config()

    step(4, total, "Migrating 1.x files...")
    migrate_legacy()

    step(5, total, "Database...")
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    run([WRAPPER, "check"])

    step(6, total, "systemd services and timers...")
    install_units()

    print(f"\n{GREEN}✔ Done.{RESET}")
    print(f"Logs:   {CYAN}journalctl -fu nobetci-bot{RESET}")
    print(f"Timers: {CYAN}systemctl list-timers 'nobetci-*'{RESET}")
    print(f"Check:  {CYAN}sudo nobetci check{RESET}")


if __name__ == "__main__":
    main()
