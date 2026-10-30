import re


class Optic:
    """NX-01 OPTIC — The vision sensor. Watches logs, produces candidate alerts."""

    UNIT_ID = "NX-01"
    CALLSIGN = "OPTIC"

    def __init__(self):
        # A simple pattern to catch "Failed password" attempts
        self.pattern = re.compile(r"Failed password for (\S+) from (\S+)")

    def scan(self, log_line: str, decision_id: int) -> dict | None:
        """Scans a single log line. Returns an alert dict if it's suspicious."""
        match = self.pattern.search(log_line)

        if match:
            target_user = match.group(1)
            src_ip = match.group(2)

            return {
                "decision_id": decision_id,
                "alert_type": "ssh_failed_login",
                "score": 0.85,  # We will make this a real AI model later
                "explanation": [
                    f"Failed login attempt for user: {target_user}",
                    f"Source IP: {src_ip}"
                ],
                "action": "monitor", # We'll let SERVO decide actions later
                "raw_log": log_line.strip()
            }

        return None  # If it doesn't match the pattern, it's normal traffic