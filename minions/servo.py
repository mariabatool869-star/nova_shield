class Servo:
    """NX-03 SERVO — The actuator arm. Holds the gate for human approval."""

    UNIT_ID = "NX-03"
    CALLSIGN = "SERVO"

    def handle(self, alert: dict) -> dict:
        """Pauses the pipeline and asks the human for a decision."""
        print(f"\n[{self.UNIT_ID} {self.CALLSIGN}] ⚠️  HOLDING GATE")
        print(f"Alert Type: {alert['alert_type']} (Score: {alert['score']})")
        
        for reason in alert["explanation"]:
            print(f"  - {reason}")
        
        # This is the human-in-the-loop moment
        decision = input(">>> Approve block? [y/N]: ").strip().lower()
        
        if decision == 'y':
            alert["action"] = "block"
            alert["human_decision"] = "approved"
            print(f"[{self.UNIT_ID} {self.CALLSIGN}] Action approved. Passing to VAULT.")
        else:
            alert["action"] = "monitor_only"
            alert["human_decision"] = "rejected"
            print(f"[{self.UNIT_ID} {self.CALLSIGN}] Action rejected. Passing to VAULT.")
            
        return alert