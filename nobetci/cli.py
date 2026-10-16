"""nobetci <command>: one entry point for the timers, the bot and the admin."""
import argparse
import sys

from nobetci import __version__
from nobetci.config import load_config


def main(argv=None):
    parser = argparse.ArgumentParser(prog="nobetci", description="Nöbetçi server watchman")
    parser.add_argument("--version", action="version", version=f"nobetci {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("listen", help="run the Telegram bot")
    sub.add_parser("analyze", help="one analysis run (rules, bans, AI, alerts)")
    sub.add_parser("expire", help="lift bans whose time is up")
    sub.add_parser("report", help="send the daily report")
    sub.add_parser("audit", help="print the hardening audit")
    sub.add_parser("check", help="check the configuration")
    sub.add_parser("cloudflare-ips", help="refresh the nginx real-IP list from Cloudflare")
    p = sub.add_parser("ban", help="ban an IP")
    p.add_argument("ip")
    p.add_argument("duration", nargs="?", default="7d")
    p.add_argument("reason", nargs="*", default=["manual"])
    p = sub.add_parser("unban", help="unban an IP")
    p.add_argument("ip")
    p = sub.add_parser("update", help="check for or apply a release")
    p.add_argument("--apply", metavar="TAG")
    args = parser.parse_args(argv)

    config = load_config()

    if args.command == "listen":
        from nobetci.bot import Bot
        Bot(config).run()
    elif args.command == "analyze":
        from nobetci import pipeline
        detections, ai_text, threats, alerts = pipeline.run(config)
        print(f"detections={len(detections)} ai_threats={len(threats)} alerts={len(alerts)}"
              f" ai={'ok' if ai_text is not None else 'off/failed'}")
    elif args.command == "expire":
        from nobetci import pipeline
        pipeline.expire(config)
    elif args.command == "report":
        from nobetci import pipeline
        pipeline.daily_report(config)
    elif args.command == "audit":
        import html
        import re
        from nobetci import audit
        from nobetci.i18n import translator
        text = audit.format_report(audit.run(config), translator(config.get("LANG")), config.get("LANG"))
        print(html.unescape(re.sub(r"</?\w+>", "", text)))
    elif args.command == "check":
        return check(config)
    elif args.command == "cloudflare-ips":
        from nobetci import cloudflare_ips
        cloudflare_ips.refresh()
    elif args.command in ("ban", "unban"):
        from nobetci import db
        from nobetci.actions import Actions
        from nobetci.durations import parse_duration
        db.init(config["DB_PATH"])
        actions = Actions(config)
        if args.command == "ban":
            result = actions.ban(args.ip, parse_duration(args.duration), " ".join(args.reason), "CLI")
        else:
            result = actions.unban(args.ip)
        print(result.status, result.ip, result.detail)
        return 0 if result.status in ("done", "already", "not_banned") else 1
    elif args.command == "update":
        from nobetci import updater
        if args.apply:
            updater.apply(args.apply, config["STATE_DIR"])
        else:
            tag, notes = updater.check()
            print(f"{tag}\n{notes}" if tag else f"up to date: {updater.current()}")
    return 0


def check(config):
    from nobetci import db, firewall
    from nobetci.ai import AI
    from nobetci.config import find_config_path
    problems = []
    path = find_config_path()
    if not path:
        problems.append("config file not found (/etc/nobetci/config.env)")
    for key in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
        if not config.get(key) or "your_" in config.get(key, ""):
            problems.append(f"{key} is not set")
    try:
        db.init(config["DB_PATH"])
    except OSError as exc:
        problems.append(f"database: {exc}")
    if not AI(config).enabled:
        print("note: AI is off (no API key or models); the rule engine still runs")
    if firewall.blocklist_included(config["BLOCKLIST_PATH"]) is False:
        problems.append(f"nginx does not include {config['BLOCKLIST_PATH']}: bans would have no effect."
                        f" Add 'include {config['BLOCKLIST_PATH']};' to your server block(s).")
    for p in problems:
        print(f"problem: {p}")
    if not problems:
        print("ok")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
