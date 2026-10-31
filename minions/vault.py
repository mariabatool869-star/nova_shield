
import sqlite3
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone

class Vault:
    """NX-04 VAULT — HMAC-Secured, SQLite-backed immutable ledger."""

    UNIT_ID = "NX-04"
    CALLSIGN = "VAULT"

    def __init__(self, db_path="records/novashield.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        # In production, this would be an environment variable
        self.secret_key = b"novashield_super_secret_key_2026" 
        
        conn = self._get_conn()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT,
                score REAL,
                human_decision TEXT,
                analyst TEXT,
                hash TEXT,
                prev_hash TEXT,
                recorded_at TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def _get_conn(self):
        # check_same_thread=False is safe because we use short-lived connections
        return sqlite3.connect(self.db_path, check_same_thread=False, timeout=10)

    def _get_prev_hash(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT hash FROM decisions ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else "GENESIS"

    def record(self, decision: dict) -> dict:
        entry = dict(decision)
        entry["recorded_at"] = datetime.now(timezone.utc).isoformat()
        entry["prev_hash"] = self._get_prev_hash()

        # Canonical JSON serialization for exact hashing
        payload = {
            "alert_type": entry.get("alert_type"),
            "score": str(entry.get("score")), # Round to string to avoid float issues
            "human_decision": entry.get("human_decision"),
            "analyst": entry.get("analyst", "unknown"),
            "recorded_at": entry["recorded_at"],
            "prev_hash": entry["prev_hash"]
        }
        payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        
        # HMAC-SHA256 (Secure against DB admins)
        entry["hash"] = hmac.new(self.secret_key, (entry["prev_hash"] + payload_str).encode(), hashlib.sha256).hexdigest()

        conn = self._get_conn()
        conn.execute('''
            INSERT INTO decisions (alert_type, score, human_decision, analyst, hash, prev_hash, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            entry.get("alert_type"), entry.get("score"), entry.get("human_decision"),
            entry.get("analyst", "unknown"), entry["hash"], entry["prev_hash"], entry["recorded_at"]
        ))
        conn.commit()
        conn.close()
        return entry

    def get_all(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM decisions ORDER BY id DESC")
        rows = cursor.fetchall()
        conn.close()
        return rows

    def verify_chain(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT id, alert_type, score, human_decision, analyst, hash, prev_hash, recorded_at FROM decisions ORDER BY id ASC")
        rows = cursor.fetchall()
        conn.close()
        
        expected_prev = "GENESIS"
        forensic_report = []
        
        for row in rows:
            rec_id, alert_type, current_score, human_decision, analyst, stored_hash, prev_hash, recorded_at = row
            
            payload = {
                "alert_type": alert_type,
                "score": str(current_score),
                "human_decision": human_decision,
                "analyst": analyst,
                "recorded_at": recorded_at,
                "prev_hash": prev_hash
            }
            payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            recomputed_hash = hmac.new(self.secret_key, (prev_hash + payload_str).encode(), hashlib.sha256).hexdigest()
            
            if prev_hash != expected_prev:
                forensic_report.append({"id": rec_id, "reason": "Chain broken"})
            if not hmac.compare_digest(recomputed_hash, stored_hash):
                forensic_report.append({"id": rec_id, "reason": "HMAC Signature Invalid - Data Tampered"})
            
            expected_prev = stored_hash

        if forensic_report:
            return False, len(rows), forensic_report
        return True, len(rows), []