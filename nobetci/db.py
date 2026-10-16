"""SQLite storage. Schema is created and migrated in place; the file is 0600."""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime

TIME_FMT = "%Y-%m-%d %H:%M:%S"

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    summary TEXT,
    raw_analysis TEXT,
    max_severity TEXT DEFAULT 'CLEAN',
    notification_sent INTEGER DEFAULT 0,
    log_size INTEGER
);
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER,
    timestamp TEXT NOT NULL,
    category TEXT,
    severity TEXT,
    description TEXT,
    action TEXT,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
);
CREATE TABLE IF NOT EXISTS statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    total_analyses INTEGER DEFAULT 0,
    clean INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0,
    medium INTEGER DEFAULT 0,
    high INTEGER DEFAULT 0,
    critical INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ban_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    ip TEXT,
    reason TEXT,
    rule_id TEXT,
    automatic INTEGER DEFAULT 1,
    expiry TEXT
);
CREATE TABLE IF NOT EXISTS command_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    command TEXT,
    reason TEXT,
    result TEXT,
    approved_by TEXT
);
CREATE TABLE IF NOT EXISTS pending_commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    command TEXT,
    reason TEXT,
    message_id INTEGER,
    chat_id TEXT,
    status TEXT DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS rule_detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    rule_id TEXT,
    rule_name TEXT,
    severity TEXT,
    description TEXT,
    match_count INTEGER,
    action TEXT
);
CREATE INDEX IF NOT EXISTS idx_analyses_timestamp ON analyses (timestamp);
CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats (timestamp);
CREATE INDEX IF NOT EXISTS idx_statistics_timestamp ON statistics (timestamp);
CREATE INDEX IF NOT EXISTS idx_ban_log_ip ON ban_log (ip);
CREATE INDEX IF NOT EXISTS idx_rule_detections_timestamp ON rule_detections (timestamp);
"""

# Columns added after 1.x: (table, column, definition)
MIGRATIONS = [
    ("ban_log", "active", "INTEGER DEFAULT 1"),
    ("ban_log", "unbanned_at", "TEXT"),
    ("ban_log", "edge_rule_id", "TEXT"),
    ("pending_commands", "action", "TEXT"),
    ("pending_commands", "target", "TEXT"),
    ("pending_commands", "duration", "TEXT"),
]


def now():
    return datetime.now().strftime(TIME_FMT)


def init(path):
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA)
        for table, column, definition in MIGRATIONS:
            existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        conn.commit()
    finally:
        conn.close()
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


@contextmanager
def connect(path):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
