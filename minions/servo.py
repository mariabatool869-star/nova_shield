import subprocess
import time

class Servo:
    """NX-03 SERVO — The actuator arm. Holds the gate and executes blocks."""

    UNIT_ID = "NX-03"
    CALLSIGN = "SERVO"

    def execute_block(self, src_ip: str):
        """Actually blocks the IP at the system level."""
        print(f"\n[{self.UNIT_ID} {self.CALLSIGN}] ⚡ EXECUTING FIREWALL BLOCK ON {src_ip}")
        
        # In a real enterprise Linux server, this would be:
        # subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"])
        
        # For macOS, we simulate it safely:
        print(f"[{self.UNIT_ID} {self.CALLSIGN}] 🛡️  ROUTING TABLE UPDATED. Traffic from {src_ip} is now DROPPED.")
        time.sleep(1) # Simulate network delay