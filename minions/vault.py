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

        payload = {
            "alert_type": entry.get("alert_type"),
            "score": entry.get("score"),
            "human_decision": entry.get("human_decision"),
            "recorded_at": entry["recorded_at"],
            "prev_hash": entry["prev_hash"]
        }
        entry["hash"] = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        self.prev_hash = entry["hash"]

        score = entry.get("score", 0.0)
        
        self.cursor.execute('''
            INSERT INTO decisions (alert_type, score, original_score, human_decision, hash, prev_hash, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            entry.get("alert_type", "unknown"),
            score,
            score,
            entry.get("human_decision", "unknown"),
            entry["hash"],
            entry["prev_hash"],
            entry["recorded_at"]
        ))
        self.conn.commit()
        return entry

    def get_all(self):
        # Create a fresh cursor to avoid threading collisions
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM decisions ORDER BY id DESC")
        return cursor.fetchall()

    def verify_chain(self):
        # Create a fresh cursor to avoid threading collisions
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, alert_type, score, original_score, human_decision, hash, prev_hash, recorded_at FROM decisions ORDER BY id ASC")
        rows = cursor.fetchall()
        
        expected_prev = "GENESIS"
        forensic_report = []
        
        for row in rows:
            rec_id, alert_type, current_score, original_score, human_decision, stored_hash, prev_hash, recorded_at = row
            
            payload = {
                "alert_type": alert_type,
                "score": current_score,
                "human_decision": human_decision,
                "recorded_at": recorded_at,
                "prev_hash": prev_hash
            }
            recomputed_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
            
            if prev_hash != expected_prev:
                forensic_report.append({"id": rec_id, "reason": "Chain broken", "expected": expected_prev, "actual": prev_hash})
            
            if recomputed_hash != stored_hash:
                if current_score != original_score:
                    forensic_report.append({"id": rec_id, "reason": "Score Tampered", "expected": original_score, "actual": current_score})
                else:
                    forensic_report.append({"id": rec_id, "reason": "Record Tampered", "expected": "Original Hash", "actual": "Modified Data"})
            
            expected_prev = stored_hash

        if forensic_report:
            return False, len(rows), forensic_report
        return True, len(rows), []