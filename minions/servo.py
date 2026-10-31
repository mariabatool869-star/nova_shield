import subprocess
import ipaddress
import time

class Servo:
    """NX-03 SERVO — The actuator arm. Actually blocks IPs on macOS."""

    UNIT_ID = "NX-03"
    CALLSIGN = "SERVO"

    # 🚨 CRITICAL SAFETY: Never block your own machine, localhost, or your router
    PROTECTED_IPS = [
        "127.0.0.1", 
        "0.0.0.0", 
        "192.168.1.1",     # Replace with your actual router IP if different
        "192.168.1.195"    # Replace with your actual Mac IP if different
    ]

    def execute_block(self, src_ip: str):
        """Executes a real firewall block using macOS pfctl."""
        print(f"\n[{self.UNIT_ID} {self.CALLSIGN}] ⚡ INITIATING FIREWALL BLOCK ON {src_ip}")
        
        # 1. Safety Check: Never block protected IPs
        if src_ip in self.PROTECTED_IPS:
            print(f"[{self.UNIT_ID} {self.CALLSIGN}] ❌ BLOCK FAILED: {src_ip} is a protected local IP.")
            return False

        # 2. Validate the IP format (prevents command injection attacks)
        try:
            ipaddress.ip_address(src_ip)
        except ValueError:
            print(f"[{self.UNIT_ID} {self.CALLSIGN}] ❌ BLOCK FAILED: Invalid IP address format.")
            return False

        # 3. Execute the REAL macOS firewall command
        try:
            # This adds the IP to a blocklist table called 'novashield_blocklist'
            command = ["pfctl", "-t", "novashield_blocklist", "-T", "add", src_ip]
            
            result = subprocess.run(
                command, 
                check=True, 
                capture_output=True, 
                text=True,
                timeout=5
            )
            
            print(f"[{self.UNIT_ID} {self.CALLSIGN}] 🛡️  SUCCESS: Traffic from {src_ip} is now DROPPED by the OS firewall.")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[{self.UNIT_ID} {self.CALLSIGN}] ⚠️  FIREWALL ERROR: Could not add to pfctl. Ensure the blocklist table exists.")
            print(f"   Error details: {e.stderr}")
            return False
        except FileNotFoundError:
            print(f"[{self.UNIT_ID} {self.CALLSIGN}] ⚠️  FIREWALL ERROR: pfctl not found. Are you on macOS?")
            return False
        except subprocess.TimeoutExpired:
            print(f"[{self.UNIT_ID} {self.CALLSIGN}] ⚠️  FIREWALL ERROR: pfctl command timed out.")
            return False