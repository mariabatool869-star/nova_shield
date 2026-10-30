import re


class Optic:
    """NX-01 OPTIC — The vision sensor. Watches logs, produces candidate alerts."""

    UNIT_ID = "NX-01"
    CALLSIGN = "OPTIC"

    def __init__(self):
        self.pattern = re.compile(r"Failed password for (\S+) from (\S+)")

    def scan(self, log_line: str, decision_id: int, packet_size: int = 1000, duration: float = 1.0) -> dict | None:
        match = self.pattern.search(log_line)

        if match:
            target_user = match.group(1)
            src_ip = match.group(2)

            features = {
                "failed_logins_60s": 50, # In live mode we would count this
                "is_root_target": 1 if target_user == "root" else 0,
                "src_ip_unseen": 1,
                "avg_packet_size": packet_size,
                "duration_seconds": duration
            }

            return {
                "decision_id": decision_id,
                "alert_type": "ssh_failed_login",
                "features": features,
                "score": 0.0,
                "explanation": [],
                "action": "monitor",
                "raw_log": log_line.strip()
            }

        return None