from minions.optic import Optic
from minions.vault import Vault

# 1. Bring the units online
optic = Optic()
vault = Vault()

# 2. Read the fake log file
with open("data/sample.log", "r") as f:
    lines = f.readlines()

alert_counter = 100
print("NX-01 OPTIC is scanning logs...")

# 3. OPTIC scans every line
for line in lines:
    alert = optic.scan(line, alert_counter)
    
    # 4. If OPTIC finds a threat, hand it to VAULT
    if alert:
        print(f"[{optic.UNIT_ID} {optic.CALLSIGN}] Threat found! Passing to VAULT.")
        vault.record(alert)
        alert_counter += 1
    else:
        print(f"[{optic.UNIT_ID} {optic.CALLSIGN}] Normal traffic. Ignoring.")

print("\nPipeline complete. Check the ledger.")