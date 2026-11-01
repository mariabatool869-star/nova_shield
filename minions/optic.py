
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

            # Map port to attack type
            if port == 80:
                alert_type = "ddos_on_80"
            elif port == 22 and connection_count > 40:
                alert_type = "port_scan_on_22"
            elif port == 22:
                alert_type = "brute_force_on_22"
            elif port == 443:
                alert_type = "botnet_c2_on_443"
            else:
                alert_type = f"anomaly_on_{port}"

            target_user = "root"
            
            features = {
                "failed_logins_60s": connection_count * 10,
                "is_privileged_target": 1 if target_user.lower() in self.privileged_users else 0,
                "src_ip_unseen": 1,
                "avg_packet_size": 64,
                "duration_seconds": 0.5
            }

            return {
                "decision_id": decision_id,
                "alert_type": alert_type,
                "features": features,
                "score": 0.0,
                "explanation": [],
                "action": "monitor",
                "raw_log": log_line.strip()
            }

        return None