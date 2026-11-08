"""Append-only, hash-chained offline SOC audit log.

Research-only. No database, network, Vault, or enforcement operations.
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock

_LOCK = RLock()
_GENESIS = "0" * 64


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _hash(record):
    return hashlib.sha256(_canonical(record)).hexdigest()


def verify_audit(path):
    """Verify the complete chain; return the number of valid records."""
    path = Path(path)
    if not path.exists():
        return 0

    previous = _GENESIS
    count = 0

    with path.open("rb") as stream:
        for raw in stream:
            if not raw.endswith(b"\n"):
                raise ValueError("Incomplete audit record")
            try:
                entry = json.loads(raw)
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError("Invalid audit JSON") from exc

            if not isinstance(entry, dict):
                raise ValueError("Invalid audit entry")

            stored_hash = entry.get("record_hash")
            record = {
                key: value for key, value in entry.items()
                if key != "record_hash"
            }

            if record.get("previous_hash") != previous:
                raise ValueError("Broken audit hash chain")

            if stored_hash != _hash(record):
                raise ValueError("Audit record hash mismatch")

            previous = stored_hash
            count += 1

    return count


def append_decision(path, decision):
    """Validate the chain and durably append one reviewed SOC decision."""
    if not isinstance(decision, dict):
        raise ValueError("Decision must be a dictionary")

    required = (
        "case_id", "analyst", "human_decision", "justification"
    )
    if any(
        not isinstance(decision.get(key), str)
        or not decision[key].strip()
        for key in required
    ):
        raise ValueError("Incomplete audit decision")

    if (
        decision.get("enforcement_enabled") is not False
        or decision.get("action_executed") is not False
    ):
        raise ValueError("Enforcement must remain disabled")

    path = Path(path)

    with _LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)

        # Never append to a corrupt or incomplete chain.
        verify_audit(path)

        previous = _GENESIS
        if path.exists() and path.stat().st_size:
            with path.open("rb") as stream:
                last = None
                for raw in stream:
                    last = raw
            previous = json.loads(last)["record_hash"]

        record = {
            "schema_version": 1,
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "case_id": decision["case_id"],
            "analyst": decision["analyst"],
            "human_decision": decision["human_decision"],
            "justification": decision["justification"],
            "case_classification": decision.get("case_classification"),
            "enforcement_enabled": False,
            "action_executed": False,
            "previous_hash": previous,
        }
        record["record_hash"] = _hash(record)

        payload = _canonical(record) + b"\n"

        fd = os.open(
            str(path),
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600
        )
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            raise

        return {
            "audit_status": "PERSISTED_OFFLINE",
            "record_hash": record["record_hash"],
        }
