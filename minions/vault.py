import sqlite3
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Load environment variables from .env
load_dotenv()

class Vault:
    """NX-04 VAULT — Ed25519-signed, externally anchored, tamper-evident ledger."""

    UNIT_ID = "NX-04"
    CALLSIGN = "VAULT"

    def __init__(self, db_path="records/novashield.db", anchor_path="anchor.log"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.anchor_path = anchor_path
        
        # Load the Ed25519 private key from .env
        priv_hex = os.getenv("NOVASHIELD_PRIVATE_KEY")
        if not priv_hex:
            raise ValueError("NOVASHIELD_PRIVATE_KEY not found in .env")
        self.private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
        
        # HMAC key (secondary check)
        self.hmac_key = b"novashield_secondary_hmac_key"
        
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
                signature TEXT,
                recorded_at TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def _get_conn(self):
        return sqlite3.connect(self.db_path, check_same_thread=False, timeout=10)

    def _get_prev_hash(self):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT hash FROM decisions ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else "GENESIS"

    def _anchor(self, record_hash: str, record_id: int):
        """Appends the hash to anchor.log for external proof."""
        timestamp = datetime.now(timezone.utc).isoformat()
        with open(self.anchor_path, "a") as f:
            f.write(f"{record_id}|{timestamp}|{record_hash}\n")

    def record(self, decision: dict) -> dict:
        entry = dict(decision)
        entry["recorded_at"] = datetime.now(timezone.utc).isoformat()
        entry["prev_hash"] = self._get_prev_hash()

        payload = {
            "alert_type": entry.get("alert_type"),
            "score": str(entry.get("score")),
            "human_decision": entry.get("human_decision"),
            "analyst": entry.get("analyst", "unknown"),
            "recorded_at": entry["recorded_at"],
            "prev_hash": entry["prev_hash"]
        }
        payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        # 1. HMAC hash chain
        entry["hash"] = hmac.new(
            self.hmac_key,
            (entry["prev_hash"] + payload_str).encode(),
            hashlib.sha256
        ).hexdigest()

        # 2. Ed25519 signature
        entry["signature"] = self.private_key.sign(payload_str.encode()).hex()

        # 3. Write to DB
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO decisions (alert_type, score, human_decision, analyst, hash, prev_hash, signature, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            entry.get("alert_type"),
            entry.get("score"),
            entry.get("human_decision"),
            entry.get("analyst", "unknown"),
            entry["hash"],
            entry["prev_hash"],
            entry["signature"],
            entry["recorded_at"]
        ))
        record_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # 4. External anchor
        self._anchor(entry["hash"], record_id)

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
        cursor.execute("SELECT id, alert_type, score, human_decision, analyst, hash, prev_hash, signature, recorded_at FROM decisions ORDER BY id ASC")
        rows = cursor.fetchall()
        conn.close()

        expected_prev = "GENESIS"
        forensic_report = []

        for row in rows:
            rec_id, alert_type, current_score, human_decision, analyst, stored_hash, prev_hash, signature, recorded_at = row

            payload = {
                "alert_type": alert_type,
                "score": str(current_score),
                "human_decision": human_decision,
                "analyst": analyst,
                "recorded_at": recorded_at,
                "prev_hash": prev_hash
            }
            payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))

            recomputed_hash = hmac.new(
                self.hmac_key,
                (prev_hash + payload_str).encode(),
                hashlib.sha256
            ).hexdigest()

            if prev_hash != expected_prev:
                forensic_report.append({"id": rec_id, "reason": "Chain broken"})

            if not hmac.compare_digest(recomputed_hash, stored_hash):
                forensic_report.append({"id": rec_id, "reason": "HMAC Invalid - Data Tampered"})

            try:
                public_key = self.private_key.public_key()
                public_key.verify(bytes.fromhex(signature), payload_str.encode())
            except Exception:
                forensic_report.append({"id": rec_id, "reason": "Ed25519 Signature Invalid"})

            expected_prev = stored_hash

        if forensic_report:
            return False, len(rows), forensic_report
        return True, len(rows), []

    def verify_anchor(self):
        """Reads anchor.log and confirms each hash still exists in the DB."""
        if not os.path.exists(self.anchor_path):
            return []
        missing = []
        with open(self.anchor_path, "r") as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) != 3:
                    continue
                rec_id, timestamp, record_hash = parts
                conn = self._get_conn()
                cursor = conn.cursor()
                cursor.execute("SELECT hash FROM decisions WHERE id = ?", (rec_id,))
                row = cursor.fetchone()
                conn.close()
                if not row or row[0] != record_hash:
                    missing.append({"id": rec_id, "reason": "Record deleted from DB but exists in anchor.log"})
        return missing