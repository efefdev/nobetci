"""Ban durations: 30m, 6h, 7d, 2w, permanent, plus the Turkish 1s/1g/1h(afta)/kalici."""
import re
from datetime import timedelta

PERMANENT = None

_UNITS = {
    "m": "minutes", "min": "minutes", "dk": "minutes",
    "h": "hours", "s": "hours", "sa": "hours", "saat": "hours",
    "d": "days", "g": "days", "gun": "days", "gün": "days",
    "w": "weeks", "hf": "weeks", "hafta": "weeks",
}
_PERMANENT_WORDS = {"permanent", "perm", "forever", "kalici", "kalıcı", "süresiz", "suresiz"}


def parse_duration(text):
    """
    Return a timedelta, PERMANENT (None) for a permanent ban, or raise ValueError.
    """
    text = text.strip().lower()
    if text in _PERMANENT_WORDS:
        return PERMANENT
    m = re.fullmatch(r"(\d+)\s*([a-zçğıöşü]+)", text)
    if not m or m.group(2) not in _UNITS:
        raise ValueError(text)
    amount = int(m.group(1))
    if amount <= 0 or amount > 3650:
        raise ValueError(text)
    return timedelta(**{_UNITS[m.group(2)]: amount})


def looks_like_duration(text):
    try:
        parse_duration(text)
        return True
    except ValueError:
        return False


def humanize(delta, t):
    """Short human label, e.g. '7 gün' / '7 days'."""
    if delta is PERMANENT:
        return t("dur_permanent")
    minutes = int(delta.total_seconds() // 60)
    for unit, size in (("week", 10080), ("day", 1440), ("hour", 60), ("minute", 1)):
        if minutes >= size and minutes % size == 0:
            return t(f"dur_{unit}", n=minutes // size)
    return t("dur_minute", n=max(minutes, 1))
