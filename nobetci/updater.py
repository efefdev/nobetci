"""
Updates move only between release tags (v2.1.0, ...), never to whatever is on
main. The admin sees the changes first, approves in Telegram, and can roll
back to the previous tag.
"""
import os
import re
import subprocess

from nobetci import __version__

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def _git(*args, timeout=60):
    r = subprocess.run(["git", "-C", APP_DIR, *args], capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or f"git {args[0]} failed")
    return r.stdout.strip()


def _key(tag):
    m = TAG.match(tag)
    return tuple(int(x) for x in m.groups()) if m else None


def current():
    return f"v{__version__}"


def check():
    """Return (newest_tag, notes) or (None, '') when up to date."""
    _git("fetch", "--quiet", "--tags", "--force", "origin")
    tags = [t for t in _git("tag", "--list", "v*").splitlines() if _key(t)]
    if not tags:
        return None, ""
    newest = max(tags, key=_key)
    if _key(newest) <= _key(current()):
        return None, ""
    try:
        notes = _git("log", "--no-merges", "--format=• %s", f"{current()}..{newest}")
    except RuntimeError:
        notes = ""
    lines = notes.splitlines()
    if len(lines) > 15:
        lines = lines[:15] + [f"… +{len(lines) - 15}"]
    return newest, "\n".join(lines)


def apply(tag, state_dir):
    """Check out tag, reinstall and restart. Run detached (systemd-run), as it restarts the bot."""
    if not _key(tag):
        raise ValueError(f"not a release tag: {tag}")
    _git("fetch", "--quiet", "--tags", "--force", "origin")
    previous = current()
    _git("checkout", "--quiet", "--detach", f"refs/tags/{tag}")
    with open(os.path.join(state_dir, "previous_version"), "w") as f:
        f.write(previous)
    subprocess.run(["/usr/bin/python3", "-I", os.path.join(APP_DIR, "install.py"), "--upgrade"], check=True)


def previous(state_dir):
    try:
        with open(os.path.join(state_dir, "previous_version")) as f:
            tag = f.read().strip()
        return tag if _key(tag) else None
    except OSError:
        return None


def spawn(tag):
    """Start apply() outside the bot's own service so the restart cannot kill it."""
    subprocess.Popen(["systemd-run", "--unit", "nobetci-update", "--collect", "--quiet",
                      "/usr/local/bin/nobetci", "update", "--apply", tag])
