import time
import requests
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

BASE_URL = "http://127.0.0.1:5000"

# 🔥 THE FIX: Use a persistent session to keep the admin cookie
session = requests.Session()

def simulate_attack(attack_name, log_line):
    print(f"\n{'='*60}")
    print(f"🚀 SIMULATING: {attack_name}")
    print(f"{'='*60}")
    print(f"Payload: {log_line}")
    
    response = session.post(
        f"{BASE_URL}/api/scan",
        json={"log_line": log_line},
        headers={"Content-Type": "application/json"}
    )
    
    if response.status_code != 200:
        print(f"❌ Failed to trigger scan: {response.status_code}")
        return
    
    data = response.json()
    if data.get("status") == "threat":
        print(f"✅ THREAT DETECTED")
        print(f"   Risk Score: {data['score']}")
        print(f"   Top Reason: {data['explanation'][0]['feature']} (Weight: {data['explanation'][0]['impact']})")
        print(f"   Counterfactual: {data.get('counterfactual')}")
        print(f"   Raw Log: {data['raw_log']}")
        
        print(f"\n🔐 SENDING APPROVAL TO SERVO...")
        decide_res = session.post(
            f"{BASE_URL}/api/decide",
            json={"decision": "approve"},
            headers={"Content-Type": "application/json"}
        )
        if decide_res.status_code == 200:
            print(f"✅ BLOCK APPROVED AND EXECUTED")
        else:
            print(f"⚠️  Approval failed: {decide_res.status_code}")
    else:
        print(f"⚠️  No threat detected (clean).")
    
    time.sleep(2)

def main():
    print("=" * 60)
    print("🛡️  NOVASHIELD LIVE ATTACK SIMULATION")
    print("=" * 60)
    
    # 🔥 Log in using the session object
    print("🔑 Logging in as Admin...")
    session.post(f"{BASE_URL}/api/login", json={"role": "admin"})
    
    try:
        session.get(f"{BASE_URL}/api/verify", timeout=5)
    except requests.exceptions.ConnectionError:
        print("❌ ERROR: Server is not running.")
        return
    
    simulate_attack("DDoS Attack (150 connections to port 80)", "Live TCP: 150 connections from 10.0.0.99 on port 80")
    simulate_attack("Port Scan (50 connections to port 22)", "Live TCP: 50 connections from 10.0.0.100 on port 22")
    simulate_attack("SSH Brute Force (30 connections to port 22)", "Live TCP: 30 connections from 10.0.0.101 on port 22")
    simulate_attack("Botnet C2 (10 connections to port 443)", "Live TCP: 10 connections from 10.0.0.102 on port 443")
    
    print(f"\n{'='*60}")
    print("📊 FINAL LEDGER VERIFICATION")
    print(f"{'='*60}")
    verify_res = session.get(f"{BASE_URL}/api/verify")
    if verify_res.status_code == 200:
        data = verify_res.json()
        print(f"Status: {data['status'].upper()}")
        print(f"Total Records: {data['count']}")
        if data['status'] == 'intact':
            print("✅ All cryptographic signatures are valid.")
        else:
            print(f"❌ Tampering detected: {data.get('report')}")

if __name__ == "__main__":
    main()