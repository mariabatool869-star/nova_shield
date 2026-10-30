import sqlite3
import hashlib
import json
import os
from datetime import datetime, timezone


class Vault:
    """NX-04 VAULT — The memory module. SQLite-backed immutable ledger."""

    UNIT_ID = "NX-04"
    CALLSIGN = "VAULT"

    def __init__(self, db_path="records/novashield.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        # THE FIX: check_same_thread=False allows Flask to share the connection
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT,
                score REAL,
                human_decision TEXT,
                hash TEXT,
                prev_hash TEXT,
                recorded_at TEXT
            )
        ''')
        self.conn.commit()

        self.cursor.execute("SELECT hash FROM decisions ORDER BY id DESC LIMIT 1")
        row = self.cursor.fetchone()
        self.prev_hash = row[0] if row else "GENESIS"

    def record(self, decision: dict) -> dict:
        entry = dict(decision)
        entry["recorded_at"] = datetime.now(timezone.utc).isoformat()
        entry["prev_hash"] = self.prev_hash

        payload = json.dumps(entry, sort_keys=True).encode("utf-8")
        entry["hash"] = hashlib.sha256(payload).hexdigest()
        self.prev_hash = entry["hash"]

        self.cursor.execute('''
            INSERT INTO decisions (alert_type, score, human_decision, hash, prev_hash, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            entry.get("alert_type", "unknown"),
            entry.get("score", 0.0),
            entry.get("human_decision", "unknown"),
            entry["hash"],
            entry["prev_hash"],
            entry["recorded_at"]
        ))
        self.conn.commit()
        return entry

    def get_all(self):
        self.cursor.execute("SELECT * FROM decisions ORDER BY id DESC")
        return self.cursor.fetchall()

    def verify_chain(self):
        self.cursor.execute("SELECT hash, prev_hash FROM decisions ORDER BY id ASC")
        rows = self.cursor.fetchall()
        expected_prev = "GENESIS"
        for row in rows:
            if row[1] != expected_prev:
                return False, len(rows)
            expected_prev = row[0]
        return True, len(rows)