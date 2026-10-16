"""Bot texts in Turkish and English. Messages use Telegram HTML; values are escaped by t()."""
import html

TEXTS = {
    "tr": {
        "dur_permanent": "kalıcı",
        "dur_week": "{n} hafta", "dur_day": "{n} gün", "dur_hour": "{n} saat", "dur_minute": "{n} dakika",
        "sev_CRITICAL": "Kritik", "sev_HIGH": "Yüksek", "sev_MEDIUM": "Orta", "sev_LOW": "Düşük", "sev_CLEAN": "Temiz",
        "protected_whitelist": "beyaz listede", "protected_cloudflare": "Cloudflare adresi",
        "protected_private": "özel/yerel ağ", "protected_invalid": "geçersiz IP",
        "btn_approve": "✅ Onayla", "btn_reject": "✖️ Reddet", "btn_unban": "Ban kaldır · {ip}", "btn_undo": "↩️ Geri al",
        "btn_update": "⬆️ Güncelle", "btn_rollback": "↩️ Önceki sürüme dön",
        "help": (
            "<b>Nöbetçi</b>\n\n"
            "/status · sunucu durumu\n"
            "/log [saat] · son X saatin özeti\n"
            "/banlist · aktif banlar\n"
            "/ban &lt;ip&gt; [süre] [sebep] · ör. <code>/ban 45.33.1.2 7g tarama</code>\n"
            "/unban &lt;ip&gt; · banı kaldır\n"
            "/threats · bugünün tehditleri\n"
            "/stats · son 7 gün\n"
            "/analyze · şimdi analiz et\n"
            "/audit · sunucu sertleştirme denetimi\n"
            "/update · güncelleme kontrolü\n\n"
            "Süreler: 30dk, 6s, 7g, 2hf, kalici (ya da 30m, 6h, 7d, 2w, permanent)\n"
            "{chat}"
        ),
        "help_chat": "Komut dışında yazdıklarına yapay zeka cevap verir: <i>son bir saatte ne oldu?</i>",
        "unknown": "Bilinmeyen komut: {cmd}. /help yaz.",
        "too_fast": "Biraz yavaş, {s} saniye bekle.",
        "error": "Hata: {e}",
        "status_title": "<b>Sunucu durumu</b>",
        "status_body": "Disk: {disk}\nBellek: {ram}\nYük: {load}\nAçık kalma: {uptime}",
        "status_services": "<b>Servisler</b>",
        "status_blocklist_missing": "⚠️ Ban dosyası nginx'e dahil edilmemiş, banlar etkisiz. Kurulum: <code>include {path};</code> satırını server bloğuna ekle.",
        "banlist_title": "<b>Aktif banlar</b> ({n})",
        "banlist_empty": "Aktif ban yok.",
        "banlist_line": "<code>{ip}</code> · {reason} · {left}",
        "banlist_more": "… ve {n} tane daha",
        "left_permanent": "kalıcı",
        "left": "{d} kaldı",
        "ban_usage": "Kullanım: /ban &lt;ip&gt; [süre] [sebep]\nÖrnek: <code>/ban 45.33.1.2 7g tarama</code>",
        "ban_bad_ip": "Geçersiz IP: {ip}",
        "ban_bad_duration": "Süreyi anlayamadım: {d}. Örnek: 30dk, 6s, 7g, kalici",
        "ban_protected": "{ip} banlanamaz ({why}).",
        "ban_done": "🔒 <b>{ip}</b> banlandı\nSüre: {d}\nSebep: {reason}",
        "ban_already": "{ip} zaten banlı.",
        "ban_failed": "Ban başarısız: {e}",
        "ban_edge": "Cloudflare kenarında da engellendi.",
        "unban_usage": "Kullanım: /unban &lt;ip&gt;",
        "unban_done": "🔓 <b>{ip}</b> banı kaldırıldı.",
        "unban_not": "{ip} banlı değil.",
        "threats_title": "<b>Bugünün tehditleri</b>",
        "threats_rules": "<b>Kural motoru</b>",
        "threats_ai": "<b>Yapay zeka</b>",
        "threats_none": "Bugün tehdit görülmedi.",
        "times": "{n} kez",
        "stats_title": "<b>Son 7 gün</b>",
        "stats_line": "{day} · {total} analiz · 🚨{critical} ⚠️{high} 🔶{medium} 🔷{low}",
        "stats_none": "Henüz istatistik yok.",
        "log_title": "<b>Son {h} saat</b>",
        "log_none": "Son {h} saatte kayda değer bir şey yok.",
        "analyze_start": "Analiz başladı…",
        "analyze_done": "<b>Analiz tamamlandı</b>\n\n{text}",
        "analyze_clean": "Temiz, olağandışı bir şey yok.",
        "analyze_failed": "Yapay zeka analizi yapılamadı. Kural motoru çalışmaya devam ediyor.",
        "alert_title": "{emoji} <b>{sev} seviye tehdit</b>",
        "alert_body": "{category}\n\n{description}",
        "alert_rule": "{emoji} <b>{name}</b>\n{description}",
        "alert_proposal": "Öneri: <code>{ip}</code> adresini {d} banla.",
        "alert_auto": "Otomatik banlandı: <code>{ip}</code> ({d}).",
        "pending_gone": "Bu öneri artık geçerli değil.",
        "pending_rejected": "Reddedildi.",
        "pending_running": "Uygulanıyor…",
        "stranger_summary": "👀 Son bir saatte {n} yabancı sohbet bota yazmaya çalıştı: {who}",
        "warn_ai": "⚠️ Yapay zeka analizi başarısız (tüm modeller). Kural motoru çalışıyor.",
        "report_title": "📊 <b>Günlük güvenlik raporu</b> · {day}",
        "report_analyses": "Analiz: {total} · Temiz {clean} · 🔷{low} 🔶{medium} ⚠️{high} 🚨{critical}",
        "report_bans": "Bugün banlanan: {n} IP",
        "report_none": "Bugün veri yok.",
        "audit_title": "🛡 <b>Sertleştirme denetimi</b> · {score}/{total}",
        "audit_ok": "✅ {title}",
        "audit_bad": "❌ <b>{title}</b>\n   {detail}\n   Düzeltme: <code>{fix}</code>",
        "audit_skip": "· {title}: kontrol edilemedi",
        "update_none": "Güncel: {v}",
        "update_available": "⬆️ Yeni sürüm: <b>{new}</b> (şu an {cur})\n\n{notes}",
        "update_running": "Güncelleniyor… Bot birazdan yeniden başlayacak.",
        "update_failed": "Güncelleme başarısız: {e}",
        "chat_off": "Sohbet kapalı. Komutlar için /help.",
        "chat_thinking": "Bakıyorum…",
        "busy": "Başka bir iş sürüyor, bitince tekrar dene.",
    },
    "en": {
        "dur_permanent": "permanent",
        "dur_week": "{n} week(s)", "dur_day": "{n} day(s)", "dur_hour": "{n} hour(s)", "dur_minute": "{n} minute(s)",
        "sev_CRITICAL": "Critical", "sev_HIGH": "High", "sev_MEDIUM": "Medium", "sev_LOW": "Low", "sev_CLEAN": "Clean",
        "protected_whitelist": "whitelisted", "protected_cloudflare": "Cloudflare address",
        "protected_private": "private/local network", "protected_invalid": "invalid IP",
        "btn_approve": "✅ Approve", "btn_reject": "✖️ Reject", "btn_unban": "Unban · {ip}", "btn_undo": "↩️ Undo",
        "btn_update": "⬆️ Update", "btn_rollback": "↩️ Roll back",
        "help": (
            "<b>Nöbetçi</b>\n\n"
            "/status · server status\n"
            "/log [hours] · summary of the last X hours\n"
            "/banlist · active bans\n"
            "/ban &lt;ip&gt; [duration] [reason] · e.g. <code>/ban 45.33.1.2 7d scanner</code>\n"
            "/unban &lt;ip&gt; · remove a ban\n"
            "/threats · today's threats\n"
            "/stats · last 7 days\n"
            "/analyze · analyze now\n"
            "/audit · server hardening check\n"
            "/update · check for updates\n\n"
            "Durations: 30m, 6h, 7d, 2w, permanent\n"
            "{chat}"
        ),
        "help_chat": "Anything that is not a command goes to the AI: <i>what happened in the last hour?</i>",
        "unknown": "Unknown command: {cmd}. Try /help.",
        "too_fast": "Slow down, wait {s} seconds.",
        "error": "Error: {e}",
        "status_title": "<b>Server status</b>",
        "status_body": "Disk: {disk}\nMemory: {ram}\nLoad: {load}\nUptime: {uptime}",
        "status_services": "<b>Services</b>",
        "status_blocklist_missing": "⚠️ The ban file is not included in nginx, bans have no effect. Add <code>include {path};</code> to your server block.",
        "banlist_title": "<b>Active bans</b> ({n})",
        "banlist_empty": "No active bans.",
        "banlist_line": "<code>{ip}</code> · {reason} · {left}",
        "banlist_more": "… and {n} more",
        "left_permanent": "permanent",
        "left": "{d} left",
        "ban_usage": "Usage: /ban &lt;ip&gt; [duration] [reason]\nExample: <code>/ban 45.33.1.2 7d scanner</code>",
        "ban_bad_ip": "Invalid IP: {ip}",
        "ban_bad_duration": "Could not read the duration: {d}. Examples: 30m, 6h, 7d, permanent",
        "ban_protected": "{ip} cannot be banned ({why}).",
        "ban_done": "🔒 <b>{ip}</b> banned\nDuration: {d}\nReason: {reason}",
        "ban_already": "{ip} is already banned.",
        "ban_failed": "Ban failed: {e}",
        "ban_edge": "Also blocked at Cloudflare's edge.",
        "unban_usage": "Usage: /unban &lt;ip&gt;",
        "unban_done": "🔓 <b>{ip}</b> unbanned.",
        "unban_not": "{ip} is not banned.",
        "threats_title": "<b>Today's threats</b>",
        "threats_rules": "<b>Rule engine</b>",
        "threats_ai": "<b>AI</b>",
        "threats_none": "No threats today.",
        "times": "{n} times",
        "stats_title": "<b>Last 7 days</b>",
        "stats_line": "{day} · {total} analyses · 🚨{critical} ⚠️{high} 🔶{medium} 🔷{low}",
        "stats_none": "No statistics yet.",
        "log_title": "<b>Last {h} hours</b>",
        "log_none": "Nothing noteworthy in the last {h} hours.",
        "analyze_start": "Analysis started…",
        "analyze_done": "<b>Analysis complete</b>\n\n{text}",
        "analyze_clean": "Clean, nothing unusual.",
        "analyze_failed": "AI analysis failed. The rule engine keeps running.",
        "alert_title": "{emoji} <b>{sev} severity threat</b>",
        "alert_body": "{category}\n\n{description}",
        "alert_rule": "{emoji} <b>{name}</b>\n{description}",
        "alert_proposal": "Suggestion: ban <code>{ip}</code> for {d}.",
        "alert_auto": "Banned automatically: <code>{ip}</code> ({d}).",
        "pending_gone": "This suggestion is no longer valid.",
        "pending_rejected": "Rejected.",
        "pending_running": "Applying…",
        "stranger_summary": "👀 {n} unknown chat(s) tried to talk to the bot in the last hour: {who}",
        "warn_ai": "⚠️ AI analysis failed (all models). The rule engine keeps running.",
        "report_title": "📊 <b>Daily security report</b> · {day}",
        "report_analyses": "Analyses: {total} · Clean {clean} · 🔷{low} 🔶{medium} ⚠️{high} 🚨{critical}",
        "report_bans": "Banned today: {n} IP(s)",
        "report_none": "No data today.",
        "audit_title": "🛡 <b>Hardening audit</b> · {score}/{total}",
        "audit_ok": "✅ {title}",
        "audit_bad": "❌ <b>{title}</b>\n   {detail}\n   Fix: <code>{fix}</code>",
        "audit_skip": "· {title}: could not check",
        "update_none": "Up to date: {v}",
        "update_available": "⬆️ New version: <b>{new}</b> (current {cur})\n\n{notes}",
        "update_running": "Updating… the bot will restart shortly.",
        "update_failed": "Update failed: {e}",
        "chat_off": "Chat is off. See /help for commands.",
        "chat_thinking": "Looking…",
        "busy": "Another job is running, try again when it finishes.",
    },
}

SEVERITY_EMOJI = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "🔶", "LOW": "🔷", "CLEAN": "✅"}


class Raw(str):
    """A value that is already HTML and must not be escaped."""


def translator(lang):
    table = TEXTS.get(lang, TEXTS["tr"])

    def t(key, **values):
        text = table.get(key) or TEXTS["en"].get(key, key)
        safe = {k: v if isinstance(v, Raw) else html.escape(str(v), quote=False) for k, v in values.items()}
        return text.format(**safe) if safe else text

    return t


def esc(text):
    return html.escape(str(text), quote=False)
