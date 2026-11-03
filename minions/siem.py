import json
from datetime import datetime


class SIEMExporter:
    """
    NX-05 SENTINEL - SIEM integration and webhooks.
    """

    UNIT_ID  = "NX-05"
    CALLSIGN = "SENTINEL"

    def __init__(self):
        print("[NX-05 SENTINEL] Ready. OK")

    def save_to_file(self, alert):
        """Save alert to NDJSON file"""
        try:
            with open("records/siem/alerts.ndjson", "a") as f:
                alert_record = {
                    "timestamp": datetime.now().isoformat(),
                    "attack_type": alert.get("attack_type", "UNKNOWN"),
                    "confidence": alert.get("confidence", 0),
                    "explanation": alert.get("explanation", ""),
                    "raw_log": alert.get("raw_log", "")
                }
                f.write(json.dumps(alert_record) + "\n")
            print("[NX-05 SENTINEL] Alert saved")
        except Exception as e:
            print("[NX-05 SENTINEL] Save failed: " + str(e))

    def send_webhook(self, alert):
        """Send alert via webhook (simulated)"""
        try:
            attack = alert.get("attack_type", "UNKNOWN")
            conf = alert.get("confidence", 0)
            expl = alert.get("explanation", "N/A")
            print("[NX-05 SENTINEL] Alert - " + attack + " (" + str(conf) + ")")
        except Exception as e:
            print("[NX-05 SENTINEL] Webhook error: " + str(e))
