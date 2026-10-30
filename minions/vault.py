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
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Create table with original_score for forensics
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT,
                score REAL,
                original_score REAL,
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

        score = entry.get("score", 0.0)
        
        self.cursor.execute('''
            INSERT INTO decisions (alert_type, score, original_score, human_decision, hash, prev_hash, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            entry.get("alert_type", "unknown"),
            score,
            score, # Store the original score here
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
        self.cursor.execute("SELECT id, alert_type, score, original_score, hash, prev_hash FROM decisions ORDER BY id ASC")
        rows = self.cursor.fetchall()
        expected_prev = "GENESIS"
        forensic_report = []
        
        for row in rows:
            rec_id, alert_type, current_score, original_score, stored_hash, prev_hash = row
            
            # 1. Check if the chain link is broken
            if prev_hash != expected_prev:
                forensic_report.append({"id": rec_id, "reason": "Chain broken", "expected": expected_prev, "actual": prev_hash})
            
            # 2. Check if the current data was changed (Forensics)
            if current_score != original_score:
                forensic_report.append({
                    "id": rec_id, 
                    "reason": "Score Tampered", 
                    "expected": original_score, 
                    "actual": current_score
                })
            
            expected_prev = stored_hash

        if forensic_report:
            return False, len(rows), forensic_report
        return True, len(rows), []