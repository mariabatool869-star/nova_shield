from minions.vault import Vault

vault = Vault()
vault.record({
    "decision_id": 1,
    "alert_type": "ssh_brute_force",
    "score": 0.91,
    "explanation": ["47 failed logins in 60s", "target=root"],
    "action": "block",
})
vault.record({
    "decision_id": 2,
    "alert_type": "port_scan",
    "score": 0.78,
    "explanation": ["22 distinct ports probed in 4s", "source not in baseline"],
    "action": "monitor",
})

print("NX-04 VAULT sealed 2 decisions into the ledger.")