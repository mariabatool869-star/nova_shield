import json
import os
import requests
from datetime import datetime, timezone

class SIEMExporter:
    """NX-05 SENTINEL — Exports alerts to Slack/Discord and SIEM formats."""

    def __init__(self, webhook_url=None):
        # You can put a Slack/Discord webhook URL here for testing
        self.webhook_url = webhook_url or os.getenv("WEBHOOK_URL")

    def to_ecs(self, alert: dict) -> dict:
        """Converts a NovaShield alert into Elastic Common Schema (ECS) format."""
        return {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "ecs": {"version": "8.11.0"},
            "event": {
                "kind": "alert",
                "category": ["network", "intrusion_detection"],
                "type": ["info"],
                "action": "threat-flagged",
                "module": "novashield",
                "dataset": "novashield.alerts",
                "risk_score": round(alert.get("score", 0) * 100, 1),
            },
            "rule": {
                "name": "novashield-cortex-lightgbm",
                "description": alert.get("alert_type", "Unknown Threat"),
            },
            "source": {"ip": "10.0.0.99"}, # In production, parse from raw_log
            "novashield": {
                "raw_log": alert.get("raw_log"),
                "shap_explanation": alert.get("explanation"),
                "counterfactual": alert.get("counterfactual"),
                "human_decision": alert.get("human_decision"),
            }
        }

    def send_webhook(self, alert: dict) -> bool:
        """Sends a formatted alert to Slack or Discord."""
        if not self.webhook_url:
            print("[NX-05 SENTINEL] ⚠️ No Webhook URL configured. Skipping.")
            return False

        # Format the message
        score_pct = int(alert.get("score", 0) * 100)
        message = {
            "content": f"🚨 **NOVASHIELD THREAT DETECTED** 🚨\n"
                       f"**Type:** {alert.get('alert_type')}\n"
                       f"**Risk Score:** {score_pct}%\n"
                       f"**Top Reason:** {alert['explanation'][0]['feature']} (Weight: {alert['explanation'][0]['impact']})\n"
                       f"**Counterfactual:** {alert.get('counterfactual')}\n"
                       f"**Raw Log:** `{alert.get('raw_log')}`"
        }

        try:
            response = requests.post(self.webhook_url, json=message, timeout=5)
            if response.status_code in [200, 204]:
                print(f"[NX-05 SENTINEL] ✅ Webhook sent successfully.")
                return True
            else:
                print(f"[NX-05 SENTINEL] ❌ Webhook failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"[NX-05 SENTINEL] ❌ Webhook error: {e}")
            return False

    def save_to_file(self, alert: dict):
        """Saves the ECS formatted alert to a local NDJSON file (for SIEM ingestion)."""
        ecs_alert = self.to_ecs(alert)
        os.makedirs("records/siem", exist_ok=True)
        with open("records/siem/alerts.ndjson", "a") as f:
            f.write(json.dumps(ecs_alert) + "\n")
        print(f"[NX-05 SENTINEL] 💾 Alert saved to records/siem/alerts.ndjson")