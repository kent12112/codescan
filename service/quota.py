"""Atomic request reservations that survive gateway process and Pod restarts."""
import sqlite3
import time
from pathlib import Path
from contextlib import contextmanager


class Quota:
    def __init__(self, path, daily=200, minute=30):
        self.path, self.daily, self.minute = str(path), daily, minute
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE IF NOT EXISTS usage (role TEXT, day INTEGER, minute INTEGER, calls INTEGER, PRIMARY KEY(role,day,minute))')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute('PRAGMA synchronous=FULL')
            with db:
                yield db
        finally:
            db.close()

    def reserve(self, role, now=None):
        stamp = int(time.time() if now is None else now)
        day, minute = stamp // 86400, stamp // 60
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            daily = db.execute('SELECT COALESCE(SUM(calls),0) FROM usage WHERE role=? AND day=?', (role, day)).fetchone()[0]
            current = db.execute('SELECT calls FROM usage WHERE role=? AND day=? AND minute=?', (role, day, minute)).fetchone()
            if daily >= self.daily or (current and current[0] >= self.minute):
                return False
            db.execute('INSERT INTO usage VALUES(?,?,?,1) ON CONFLICT(role,day,minute) DO UPDATE SET calls=calls+1', (role, day, minute))
            db.execute('DELETE FROM usage WHERE day < ?', (day - 7,))
        return True
