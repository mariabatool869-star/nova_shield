#!/usr/bin/env python3
"""NovaShield isolated live network observer.

Captures packet headers only. No AI predictions, blocking, or database access.
"""

import argparse
import os
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description="NovaShield live observation demo")
    parser.add_argument("--interface", default="en0")
    parser.add_argument("--seconds", type=int, default=15)
    parser.add_argument("--max-packets", type=int, default=30)
    args = parser.parse_args()

    if not 1 <= args.seconds <= 60:
        parser.error("--seconds must be between 1 and 60")
    if not 1 <= args.max_packets <= 100:
        parser.error("--max-packets must be between 1 and 100")

    if os.geteuid() != 0:
        print("Packet capture requires elevated permissions on this Mac.")
        print("Run only this isolated observer with sudo, not the dashboard.")
        return 1

    print("NOVASHIELD | LIVE NETWORK OBSERVATION", flush=True)
    print("Interface:", args.interface, flush=True)
    print("Maximum duration:", args.seconds, "seconds", flush=True)
    print("Maximum packets:", args.max_packets, flush=True)
    print("Mode: OBSERVATION ONLY — NO AI CLASSIFICATION", flush=True)
    print("-" * 55, flush=True)

    command = [
        "/usr/sbin/tcpdump", "-i", args.interface,
        "-n", "-q", "-l", "-s", "96",
        "-c", str(args.max_packets),
        "tcp or udp",
    ]

    start = time.monotonic()
    count = 0
    stop_reason = "time_limit"
    forced_kill = False

    with subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    ) as process:
        try:
            import selectors
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)

            while time.monotonic() - start < args.seconds:
                if process.poll() is not None:
                    stop_reason = "process_exit"
                    break
                remaining = args.seconds - (time.monotonic() - start)
                events = selector.select(timeout=min(0.25, max(0, remaining)))
                for key, _ in events:
                    line = key.fileobj.readline().strip()
                    if line.startswith("IP ") or " IP " in line or " IP6 " in line:
                        count += 1
                        print(f"[{count:03}] {line}", flush=True)
                if count >= args.max_packets:
                    stop_reason = "packet_limit"
                    break
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    forced_kill = True
                    process.kill()
                    process.wait()

    return_code = process.returncode

    if forced_kill:
        status = "forced_termination"
    elif stop_reason == "process_exit":
        status = "process_complete" if return_code == 0 else "capture_error"
    elif return_code in (0, -15):
        status = stop_reason
    else:
        status = "capture_error"

    print("-" * 55)
    print("Observed packet lines:", count)
    print("Capture status:", status)
    print("Capture stopped.")
    print("No AI predictions, firewall actions, or database writes.")
    return 1 if status in ("capture_error", "forced_termination") else 0


if __name__ == "__main__":
    sys.exit(main())
