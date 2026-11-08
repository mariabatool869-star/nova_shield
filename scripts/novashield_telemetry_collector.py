#!/usr/bin/env python3
"""Unprivileged, bounded NovaShield observer-output collector.

Stores aggregate observations only; does not capture traffic or classify threats.
"""
import argparse
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIRECTORY = ROOT / "records" / "telemetry"
DESTINATION = DIRECTORY / "latest.json"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--provenance",
        choices=("synthetic_test", "operator_observed"),
        default="synthetic_test",
    )
    args = parser.parse_args()

    if os.geteuid() == 0:
        raise SystemExit("ABORT: Collector must not run as root.")

    if DIRECTORY.is_symlink() or not DIRECTORY.is_dir():
        raise SystemExit("ABORT: Telemetry directory unavailable.")

    if DIRECTORY.stat().st_uid != os.getuid():
        raise SystemExit("ABORT: Telemetry directory owner mismatch.")

    if DIRECTORY.stat().st_mode & 0o077:
        raise SystemExit("ABORT: Telemetry directory is not private.")

    if DESTINATION.is_symlink():
        raise SystemExit("ABORT: Snapshot path is a symbolic link.")

    counts = {"tcp": 0, "udp": 0, "other": 0, "ipv4": 0, "ipv6": 0}
    interface = None
    header_seen = False
    stopped = False
    capture_status = None
    reported_count = None
    observed = 0

    for index, raw in enumerate(sys.stdin):
        if index >= 300:
            raise SystemExit("ABORT: Input exceeds 300 lines.")
        if len(raw) > 4096:
            raise SystemExit("ABORT: Oversized input line.")

        line = raw.strip()

        if line == "NOVASHIELD | LIVE NETWORK OBSERVATION":
            header_seen = True
        elif line.startswith("Interface:"):
            candidate = line.partition(":")[2].strip()
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", candidate):
                raise SystemExit("ABORT: Invalid interface label.")
            interface = candidate
        elif re.match(r"^\[\d{3}\] ", line):
            packet = re.sub(r"^\[\d{3}\] ", "", line)
            match = re.search(r"\b(IP6|IP)\s", packet)
            if not match:
                continue

            observed += 1
            if observed > 100:
                raise SystemExit("ABORT: Packet limit exceeded.")

            counts["ipv6" if match.group(1) == "IP6" else "ipv4"] += 1

            if (
                re.search(r"\bFlags \[", packet)
                or re.search(r"\btcp\b", packet, re.IGNORECASE)
            ):
                counts["tcp"] += 1
            elif re.search(r"\budp\b", packet, re.IGNORECASE):
                counts["udp"] += 1
            else:
                counts["other"] += 1

        elif line.startswith("Capture status:"):
            if capture_status is not None:
                raise SystemExit("ABORT: Duplicate capture status.")
            capture_status = line.partition(":")[2].strip()
        elif line.startswith("Observed packet lines:"):
            try:
                reported_count = int(line.partition(":")[2].strip())
            except ValueError:
                raise SystemExit("ABORT: Invalid reported packet count.")
        elif line == "Capture stopped.":
            stopped = True

    if not header_seen or interface is None or not stopped:
        raise SystemExit("ABORT: Incomplete observer output.")

    if reported_count != observed:
        raise SystemExit("ABORT: Observer packet count mismatch.")

    accepted_statuses = {"process_complete", "packet_limit", "time_limit"}
    if capture_status not in accepted_statuses:
        raise SystemExit(
            "ABORT: Missing, unsuccessful or unknown capture status."
        )

    snapshot = {
        "schema_version": 1,
        "source": "isolated_tcpdump_observer",
        "provenance": args.provenance,
        "mode": "observation_only",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "interface": interface,
        "observed_packet_lines": observed,
        "protocol_counts": counts,
        "observer_reported_stopped": True,
        "capture_status": capture_status,
        "capture_active": False,
        "ai_status": "not_run",
        "enforcement_enabled": False,
        "status": "observer_output_collected",
    }

    fd, temporary = tempfile.mkstemp(prefix=".snapshot_", dir=DIRECTORY)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(snapshot, output, indent=2)
            output.write("\n")
        os.replace(temporary, DESTINATION)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

    print("Telemetry snapshot saved:", DESTINATION)
    print("Observed packet lines:", observed)
    print("Protocol counts:", counts)
    print("No AI inference or enforcement performed.")

if __name__ == "__main__":
    main()
