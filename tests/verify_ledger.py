import json
import glob
import hashlib


def verify():
    files = sorted(
        glob.glob("records/decision_*.json"),
        key=lambda p: int(p.split("_")[-1].split(".")[0]),
    )
    if not files:
        print("Empty ledger.")
        return

    expected_prev = "GENESIS"
    intact = True

    for path in files:
        with open(path) as f:
            entry = json.load(f)

        if entry["prev_hash"] != expected_prev:
            print(f"[LINK BROKEN] {path}")
            intact = False

        stored = entry["hash"]
        payload = {k: v for k, v in entry.items() if k != "hash"}
        recomputed = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()

        if recomputed != stored:
            print(f"[TAMPERED]    {path}")
            intact = False

        expected_prev = stored

    print(
        f"\n✓ LEDGER INTACT ({len(files)} entries)\n"
        if intact
        else "\n✗ LEDGER COMPROMISED\n"
    )


if __name__ == "__main__":
    verify()