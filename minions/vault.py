import json
import hashlib
import os
from datetime import datetime, timezone


class Vault:
    """NX-04 VAULT — The memory module. Append-only, tamper-evident ledger."""

    UNIT_ID = "NX-04"
    CALLSIGN = "VAULT"

    def __init__(self, records_dir="records"):
        self.records_dir = records_dir
        os.makedirs(self.records_dir, exist_ok=True)
        self.prev_hash = "GENESIS"

    def record(self, decision: dict) -> dict:
        """Append a decision to the ledger. Returns the sealed entry."""
        entry = dict(decision)
        entry["unit"] = f"{self.UNIT_ID} {self.CALLSIGN}"
        entry["recorded_at"] = datetime.now(timezone.utc).isoformat()
        entry["prev_hash"] = self.prev_hash

        payload = json.dumps(entry, sort_keys=True).encode("utf-8")
        entry["hash"] = hashlib.sha256(payload).hexdigest()
        self.prev_hash = entry["hash"]

        path = os.path.join(
            self.records_dir, f"decision_{entry['decision_id']}.json"
        )
        with open(path, "w") as f:
            json.dump(entry, f, indent=2)
        return entry