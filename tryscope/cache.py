"""
TryScope - SQLite cache
Stores lookup results with TTL to reduce API calls.
"""
import json
import sqlite3
import time
from pathlib import Path
from typing import Optional, Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    ip          TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    score       INTEGER,
    verdict     TEXT,
    lookup_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_history_ip ON history(ip);
CREATE INDEX IF NOT EXISTS idx_history_time ON history(lookup_at);
"""


class Cache:
    def __init__(self, db_path: str = "cache/tryscope.db",
                 ttl_hours: int = 24):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_hours * 3600
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def get(self, ip: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT data, created_at FROM cache WHERE ip = ?", (ip,)
        ).fetchone()
        if not row:
            return None
        age = int(time.time()) - row["created_at"]
        if age > self.ttl_seconds:
            self.conn.execute("DELETE FROM cache WHERE ip = ?", (ip,))
            self.conn.commit()
            return None
        try:
            return json.loads(row["data"])
        except Exception:
            return None

    def set(self, ip: str, data: dict):
        self.conn.execute(
            "INSERT OR REPLACE INTO cache (ip, data, created_at) "
            "VALUES (?, ?, ?)",
            (ip, json.dumps(data, default=str), int(time.time())),
        )
        self.conn.commit()

    def add_history(self, ip: str, score: int = 0, verdict: str = ""):
        self.conn.execute(
            "INSERT INTO history (ip, score, verdict, lookup_at) "
            "VALUES (?, ?, ?, ?)",
            (ip, score, verdict, int(time.time())),
        )
        self.conn.commit()

    def get_history(self, ip: str, limit: int = 20) -> list:
        rows = self.conn.execute(
            "SELECT * FROM history WHERE ip = ? "
            "ORDER BY lookup_at DESC LIMIT ?",
            (ip, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def recent(self, limit: int = 20) -> list:
        rows = self.conn.execute(
            "SELECT ip, data, created_at FROM cache "
            "ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def count(self) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) FROM cache"
        ).fetchone()[0]

    def clear(self):
        self.conn.execute("DELETE FROM cache")
        self.conn.commit()

    def close(self):
        self.conn.close()
