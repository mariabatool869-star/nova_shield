from minions.optic import Optic
from minions.cortex import Cortex
from minions.servo import Servo
from minions.vault import Vault

optic = Optic()
cortex = Cortex()
servo = Servo()
vault = Vault()

with open("data/sample.log", "r") as f:
    lines = f.readlines()

alert_counter = 300
print("NX-01 OPTIC is scanning logs...\n")

for line in lines:
    alert = optic.scan(line, alert_counter)
    
    if alert:
        print(f"[{optic.UNIT_ID} {optic.CALLSIGN}] Threat found!")
        
        # 1. CORTEX analyzes and explains
        enriched_alert = cortex.explain(alert)
        
        # 2. SERVO asks the human
        approved_alert = servo.handle(enriched_alert)
        
        # 3. VAULT seals it
        vault.record(approved_alert)
        alert_counter += 1
    else:
        print(f"[{optic.UNIT_ID} {optic.CALLSIGN}] Normal traffic. Ignoring.")

print("\nPipeline complete. Check the ledger.")