import re


class Optic:
    """NX-01 OPTIC — The vision sensor. Watches logs, produces candidate alerts."""

    UNIT_ID = "NX-01"
    CALLSIGN = "OPTIC"

    def __init__(self):
        self.pattern = re.compile(r"(\d+) connections from (\S+) on port (\d+)")
        self.privileged_users = ["root", "admin", "administrator", "jenkins", "ubuntu", "ec2-user", "sa"]

    def scan(self, log_line: str, decision_id: int) -> dict | None:
        match = self.pattern.search(log_line)

        if match:
            connection_count = int(match.group(1))
            src_ip = match.group(2)
            port = int(match.group(3))

            target_user = "root"  # Simulating SSH target for the demo
            
            features = {
                "failed_logins_60s": connection_count * 10,
                "is_privileged_target": 1 if target_user.lower() in self.privileged_users else 0,
                "src_ip_unseen": 1,
                "avg_packet_size": 64,  # Small packets (SYN flood)
                "duration_seconds": 0.5
            }

            return {
                "decision_id": decision_id,
                "alert_type": f"port_scan_on_{port}",
                "features": features,
                "score": 0.0,
                "explanation": [],
                "action": "monitor",
                "raw_log": log_line.strip()
            }

        return None