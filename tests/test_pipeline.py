from minions.optic import Optic
from minions.servo import Servo
from minions.vault import Vault

# 1. Bring the units online
optic = Optic()
servo = Servo()
vault = Vault()

# 2. Read the fake log file
with open("data/sample.log", "r") as f:
    lines = f.readlines()

alert_counter = 200
print("NX-01 OPTIC is scanning logs...\n")

# 3. OPTIC scans every line
for line in lines:
    alert = optic.scan(line, alert_counter)
    
    if alert:
        print(f"[{optic.UNIT_ID} {optic.CALLSIGN}] Threat found!")
        
        # 4. SERVO asks the human
        approved_alert = servo.handle(alert)
        
        # 5. VAULT seals the human's decision
        vault.record(approved_alert)
        alert_counter += 1
    else:
        print(f"[{optic.UNIT_ID} {optic.CALLSIGN}] Normal traffic. Ignoring.")

print("\nPipeline complete. Check the ledger.")