import sys
import requests
import time

BASE_URL = "http://127.0.0.1:5000"

ATTACKS = {
    "ddos": ("DDoS", "Live TCP: 150 connections from 10.0.0.99 on port 80"),
    "hulk": ("DoS Hulk", "Live TCP: 120 connections from 10.0.0.100 on port 80"),
    "goldeneye": ("DoS GoldenEye", "Live TCP: 90 connections from 10.0.0.101 on port 80"),
    "slowloris": ("DoS slowloris", "Live TCP: 60 connections from 10.0.0.102 on port 80"),
    "slowhttptest": ("DoS Slowhttptest", "Live TCP: 50 connections from 10.0.0.103 on port 80"),
    "portscan": ("PortScan", "Live TCP: 50 connections from 10.0.0.104 on port 22"),
    "ftp": ("FTP-Patator", "Live TCP: 30 connections from 10.0.0.105 on port 21"),
    "ssh": ("SSH-Patator", "Live TCP: 30 connections from 10.0.0.106 on port 22"),
    "bot": ("Bot", "Live TCP: 10 connections from 10.0.0.107 on port 443"),
    "webrute": ("Web Attack - Brute Force", "Live TCP: 20 connections from 10.0.0.108 on port 80"),
    "webxss": ("Web Attack - XSS", "Live TCP: 15 connections from 10.0.0.109 on port 80"),
    "websql": ("Web Attack - SQL Injection", "Live TCP: 15 connections from 10.0.0.110 on port 80"),
    "infil": ("Infiltration", "Live TCP: 5 connections from 10.0.0.111 on port 443"),
    "heartbleed": ("Heartbleed", "Live TCP: 5 connections from 10.0.0.112 on port 443"),
    "all": ("All Attacks", None),
}

def run_attack(name, log_line):
    print(f"\n{'='*60}")
    print(f"🚀 TESTING: {name}")
    print(f"{'='*60}")
    
    session = requests.Session()
    session.post(f"{BASE_URL}/api/login", json={"role": "admin"})
    
    response = session.post(
        f"{BASE_URL}/api/scan",
        json={"log_line": log_line},
        headers={"Content-Type": "application/json"}
    )
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ DETECTED: {data.get('alert_type')}")
        print(f"   Confidence: {data.get('score')}")
        print(f"   Raw Log: {data.get('raw_log')}")
        print(f"\n⏳ WAITING FOR HUMAN APPROVAL IN BROWSER...")
        print(f"   Open http://127.0.0.1:5000 and click 'Approve Block'")
    else:
        print(f"❌ Failed: {response.status_code}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 -m tests.manual_attack [attack_name]")
        print("Attacks:", ", ".join(ATTACKS.keys()))
        sys.exit(1)
    
    attack = sys.argv[1].lower()
    
    if attack == "all":
        for name, (label, log_line) in ATTACKS.items():
            if name != "all":
                run_attack(label, log_line)
                input("Press Enter to continue...")
    elif attack in ATTACKS:
        label, log_line = ATTACKS[attack]
        run_attack(label, log_line)
    else:
        print(f"Unknown attack: {attack}")