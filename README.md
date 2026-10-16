# Nöbetçi

**A self-hosted watchman for Linux servers running nginx, controlled from Telegram.**
[nobetci.efef.dev](https://nobetci.efef.dev) · [Türkçe](#türkçe)

Nöbetçi reads your nginx, SSH and firewall logs every three minutes. A rule engine catches SSH brute force,
SQL injection, webshell probes, path traversal, attack tools and hits on trap URLs, and bans the IP in nginx
(and, optionally, at Cloudflare's edge). An AI layer reviews the same logs for anything the rules miss. You get
the alerts in Telegram, approve or undo bans with a button, and can simply ask the bot what happened.

It complements fail2ban; it does not replace it.

> Formerly `soc-ai-telegram-bot`. Upgrading from 1.x keeps your config, database and bans; see [Upgrading](#upgrading-from-1x).

## Features

- **Rule engine, per IP.** Every detection knows its source IP. Bans never depend on the AI.
- **Trap URLs.** Paths no real visitor asks for (`/.env`, `/.git/config` …) ban instantly.
- **Approval flow.** Lower-confidence detections (XSS, sensitive-file probes, request floods) arrive with
  *Approve / Reject* buttons. Buttons carry a fixed action (ban an IP for a duration), never a shell command.
- **Telegram control.** `/status`, `/log`, `/banlist` with per-IP *Unban* buttons, `/ban` with flexible durations
  (`30m`, `6h`, `7d`, `2w`, `permanent`, or Turkish `1s`, `1g`, `kalici`), *Undo* on every ban, TR/EN messages.
- **Plain-language chat.** Any message that is not a command goes to the AI, which answers from a read-only
  snapshot of the server: *"what happened in the last hour?"*, *"why did you ban 45.33.1.2?"*
- **Your choice of AI.** Groq, a local [Ollama](https://ollama.com) model (nothing leaves the server), or any
  OpenAI-compatible endpoint. IPs, e-mails, passwords and tokens are masked before logs are sent anywhere.
- **Prompt-injection aware.** Logs are fenced and marked as untrusted data; nothing the model writes can ban anyone.
- **`/audit`.** Read-only hardening check: SSH password/root login, UFW, open ports, certificate expiry, pending
  security updates, `server_tokens`, the nginx ban include, config permissions. Each finding comes with a fix.
- **Daily report** at 23:55, **automatic unban** when a ban's time is up.
- **Safe updates.** `/update` moves only between release tags, shows the changes first, asks for approval and
  can roll back.
- **No dependencies.** Python 3.10+ standard library only; nothing is installed from PyPI.

## Requirements

- Ubuntu 22.04+ / Debian 12+ (systemd, journald), Python 3.10+
- nginx, ideally UFW
- A Telegram bot from [@BotFather](https://t.me/BotFather) and your chat ID
- Optional: a [Groq](https://console.groq.com) API key, a local Ollama, or another OpenAI-compatible endpoint

## Install

```bash
git clone https://github.com/efefdev/nobetci.git
cd nobetci
sudo python3 install.py
```

The installer puts the code in `/opt/nobetci/app`, the `nobetci` command in `/usr/local/bin`, creates
`/etc/nobetci/config.env` (root only, `0600`) and enables the bot plus three timers. Then:

1. Fill in `/etc/nobetci/config.env` (at least `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `SERVER_IP`).
2. **Include the ban list in nginx**, inside every `server { }` block you want protected:
   ```nginx
   include /etc/nginx/snippets/blocked-ips.conf;
   ```
   Without this line bans are written but have no effect. `nobetci check` and `/status` warn you.
3. Optional snippets in `config_templates/`: `block-sensitives.conf` (drops common probes) and
   `cloudflare-real-ip.conf` (real visitor IPs behind Cloudflare; kept fresh by the weekly
   `nobetci-cloudflare-ips.timer` if you enable it).
4. `sudo nobetci check`, then `sudo systemctl restart nobetci-bot` and send `/help` to your bot.

Running the installer again is safe: an existing config is never overwritten, only new settings are appended.

## Commands

| Telegram | CLI | |
|---|---|---|
| `/status` | | disk, memory, load, services, nginx include check |
| `/log [hours]` | | nginx, SSH and UFW summary (max 24 h) |
| `/banlist` | | active bans with time left and *Unban* buttons |
| `/ban <ip> [duration] [reason]` | `nobetci ban <ip> [duration] [reason]` | default duration 7 days |
| `/unban <ip>` | `nobetci unban <ip>` | |
| `/threats`, `/stats` | | today / last 7 days |
| `/analyze` | `nobetci analyze` | run an analysis now |
| `/audit` | `nobetci audit` | hardening audit |
| `/update` | `nobetci update` | check for a new release |
| | `nobetci check` | validate the configuration |

The timers run `nobetci analyze` (every 3 min), `nobetci expire` (every 30 min) and `nobetci report` (23:55).
Change their schedule with `systemctl edit nobetci-analyze.timer`.

## Configuration

Everything lives in `/etc/nobetci/config.env`; see [`config_templates/config.env.example`](config_templates/config.env.example).
The most useful settings:

- `WHITELIST`: comma-separated IPs or CIDRs that are never banned (your home or office). `SERVER_IP`,
  Cloudflare ranges and private networks are always protected.
- `AI_PROVIDER`: `groq`, `ollama` or `openai`; `AI_BASE_URL` for any other OpenAI-compatible endpoint,
  `AI_MODELS` is the fallback chain. Leave the key empty to run rules only.
- `TRAP_PATHS` / `TRAP_BAN`: never list a path your site really serves. Not WordPress? Add `/wp-login.php,/xmlrpc.php`.
- `CF_API_TOKEN` + `CF_ZONE_ID` (or `CF_ACCOUNT_ID`): also block at Cloudflare's edge.
  The token needs *Zone › Firewall Services › Edit*.
- `LANG`: `tr` or `en`.

Rules and their ban durations are in [`nobetci/rules.py`](nobetci/rules.py).

## Security model

- The bot answers only `TELEGRAM_CHAT_ID`. Strangers get no reply; you get an hourly summary of who tried.
  Button presses from any other chat are ignored. In a group chat, every member can press buttons.
- Telegram can trigger a fixed set of actions only (ban, unban, update, roll back), never a shell command.
- Logs are attacker-controlled. They are masked, fenced as data, and the AI cannot cause a ban.
- The config file and database are root-only. Everything runs as root because it edits nginx config.
- Updates follow release tags, never `main`, and need your approval.

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Upgrading from 1.x

Run `git pull && sudo python3 install.py` in your old clone once. The installer copies `/etc/soc/config.env` to
`/etc/nobetci/config.env` (your `GROQ_API_KEY` keeps working), keeps using `/var/lib/soc/soc_logs.db`, keeps the
same nginx ban file, removes the old `soc-*` scripts and the `soc-bot-listener` service, and enables the new timers.
From then on use `/update`.

## Development

```bash
python3 -m unittest discover -s tests -t .
```

The tests need no network, tokens, nginx or root.

## Disclaimer

Nöbetçi helps; it does not guarantee security. Try it on a staging server first, keep backups, and keep SSH
access that does not depend on the web server. You use it at your own risk.

Contact: [efealtintas.com](https://efealtintas.com) · [hi@efealtintas.com](mailto:hi@efealtintas.com) · License: MIT

---

## Türkçe

**Nöbetçi**, nginx çalıştıran Linux sunucular için kendi sunucunda çalışan, Telegram'dan yönetilen bir nöbetçi.

Üç dakikada bir nginx, SSH ve güvenlik duvarı loglarını okur. Kural motoru SSH kaba kuvvet denemelerini,
SQL injection'ı, webshell aramalarını, dizin geçişini, saldırı araçlarını ve tuzak URL'lere gelen istekleri
yakalar, IP'yi nginx'te (istersen Cloudflare'in kenarında da) banlar. Yapay zeka katmanı kuralların
kaçırdıklarına bakar. Uyarılar Telegram'a gelir; banı butonla onaylar ya da geri alırsın, bota ne olduğunu da
düz Türkçe sorabilirsin. fail2ban'in yerine değil, yanında çalışır.

**Öne çıkanlar:** IP bazlı kural motoru · tuzak URL'ler · Onayla/Reddet butonları (butonlar komut değil sabit
eylem taşır) · `/banlist`'te IP başına *Kaldır*, her banda *Geri al* · esnek süreler (`30dk`, `6s`, `7g`, `2hf`,
`kalici`) · komut dışındaki mesajlara yapay zekanın salt okunur cevabı · Groq, yerel Ollama ya da OpenAI uyumlu
uç nokta · loglar dışarı çıkmadan maskelenir · `/audit` sertleştirme denetimi · günlük rapor ve otomatik ban
kaldırma · yalnızca etiketli sürümlere, onayla ve geri alınabilir güncelleme · sıfır dış bağımlılık.

### Kurulum

```bash
git clone https://github.com/efefdev/nobetci.git
cd nobetci
sudo python3 install.py
```

1. `/etc/nobetci/config.env` dosyasını doldur (en az `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `SERVER_IP`).
2. **Ban listesini nginx'e dahil et.** Korumak istediğin her `server { }` bloğuna ekle:
   `include /etc/nginx/snippets/blocked-ips.conf;` Bu satır yoksa banlar dosyaya yazılır ama işe yaramaz;
   `nobetci check` ve `/status` seni uyarır.
3. `sudo nobetci check`, ardından bota `/help` yaz.

Kurulumu tekrar çalıştırmak güvenli: mevcut config'in üzerine yazılmaz, yalnızca yeni ayarlar eklenir.

**1.x'ten geçiş:** eski klonunda bir kez `git pull && sudo python3 install.py` çalıştır. Config, veritabanı ve
banlar korunur, eski `soc-*` betikleri ve servis kaldırılır. Sonrasında güncellemeler için `/update` kullan.

### Sorumluluk reddi

Nöbetçi güvenliğe yardım eder, garanti vermez. Önce test sunucusunda dene, yedek al, web sunucusuna bağlı
olmayan bir SSH erişimin olsun. Kullanım sorumluluğu sana aittir.
