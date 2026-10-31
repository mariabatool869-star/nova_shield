import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import psycopg2
from psycopg2.extras import RealDictCursor

load_dotenv()

class Vault:
    """NX-04 VAULT — PostgreSQL-backed immutable multi-tenant ledger."""

    UNIT_ID = "NX-04"
    CALLSIGN = "VAULT"

    def __init__(self, db_url=None):
        self.db_url = db_url or os.getenv("DATABASE_URL")
        if not self.db_url:
            raise ValueError("DATABASE_URL not found in .env")
        self.anchor_path = "anchor.log"
        
        priv_hex = os.getenv("NOVASHIELD_PRIVATE_KEY")
        if not priv_hex:
            raise ValueError("NOVASHIELD_PRIVATE_KEY not found in .env")
        self.private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
        self.hmac_key = b"novashield_secondary_hmac_key"

    def _get_conn(self):
        return psycopg2.connect(self.db_url)

    def _get_prev_hash(self, tenant_id: str):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT hash FROM decisions WHERE tenant_id = %s ORDER BY id DESC LIMIT 1", (tenant_id,))
        row = cur.fetchone()
        conn.close()
        return row[0] if row else "GENESIS"

    def _anchor(self, record_hash: str, record_id: int, tenant_id: str):
        timestamp = datetime.now(timezone.utc).isoformat()
        with open(self.anchor_path, "a") as f:
            f.write(f"{tenant_id}|{record_id}|{timestamp}|{record_hash}\n")

    def record(self, decision: dict, tenant_id: str = "default") -> dict:
        entry = dict(decision)
        entry["recorded_at"] = datetime.now(timezone.utc).isoformat()
        entry["prev_hash"] = self._get_prev_hash(tenant_id)

        payload = {
            "tenant_id": tenant_id,
            "alert_type": entry.get("alert_type"),
            "score": str(entry.get("score")),
            "human_decision": entry.get("human_decision"),
            "analyst": entry.get("analyst", "unknown"),
            "recorded_at": entry["recorded_at"],
            "prev_hash": entry["prev_hash"]
        }
        payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        entry["hash"] = hmac.new(self.hmac_key, (entry["prev_hash"] + payload_str).encode(), hashlib.sha256).hexdigest()
        entry["signature"] = self.private_key.sign(payload_str.encode()).hex()

        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO decisions (tenant_id, alert_type, score, human_decision, analyst, hash, prev_hash, signature, recorded_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
        ''', (
            tenant_id, entry.get("alert_type"), entry.get("score"),
            entry.get("human_decision"), entry.get("analyst"),
            entry["hash"], entry["prev_hash"], entry["signature"], entry["recorded_at"]
        ))
        record_id = cur.fetchone()[0]
        conn.commit()
        conn.close()

        self._anchor(entry["hash"], record_id, tenant_id)
        return entry

    def get_all(self, tenant_id: str = "default"):
        conn = self._get_conn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM decisions WHERE tenant_id = %s ORDER BY id DESC", (tenant_id,))
        rows = cur.fetchall()
        conn.close()
        return rows

    def verify_chain(self, tenant_id: str = "default"):
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, alert_type, score, human_decision, analyst, hash, prev_hash, signature, recorded_at FROM decisions WHERE tenant_id = %s ORDER BY id ASC", (tenant_id,))
        rows = cur.fetchall()
        conn.close()

        expected_prev = "GENESIS"
        report = []

        for row in rows:
            rec_id, alert_type, score, human_decision, analyst, stored_hash, prev_hash, signature, recorded_at = row
            payload = {
                "tenant_id": tenant_id, "alert_type": alert_type, "score": str(score),
                "human_decision": human_decision, "analyst": analyst,
                "recorded_at": recorded_at.isoformat(), "prev_hash": prev_hash
            }
            payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            recomputed_hash = hmac.new(self.hmac_key, (prev_hash + payload_str).encode(), hashlib.sha256).hexdigest()

            if prev_hash != expected_prev:
                report.append({"id": rec_id, "reason": "Chain broken"})
            if not hmac.compare_digest(recomputed_hash, stored_hash):
                report.append({"id": rec_id, "reason": "HMAC Invalid"})
            try:
                self.private_key.public_key().verify(bytes.fromhex(signature), payload_str.encode())
            except Exception:
                report.append({"id": rec_id, "reason": "Ed25519 Signature Invalid"})

            expected_prev = stored_hash

        return (not report), len(rows), report