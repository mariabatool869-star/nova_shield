import sys
import requests

BASE_URL = "http://127.0.0.1:5000"

def run_attack(attack_name, attack_type):
    print(f"\n{'='*60}")
    print(f"🚀 RUNNING: {attack_name}")
    print(f"{'='*60}")
    
    session = requests.Session()
    session.post(f"{BASE_URL}/api/login", json={"role": "admin"})
    
    url = f"{BASE_URL}/api/scan?type={attack_type}"
    print(f"🌐 Sending: {url}")
    response = session.get(url)
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ THREAT DETECTED")
        print(f"   Raw Log Received: {data.get('raw_log')}")
    else:
        print(f"❌ Failed: {response.status_code}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 -m tests.manual_attack [ddos|portscan|bruteforce|botnet]")
        sys.exit(1)
    
    attack = sys.argv[1].lower()
    
    if attack == "ddos":
        run_attack("DDoS Attack", "ddos")
    elif attack == "portscan":
        run_attack("Port Scan", "portscan")
    elif attack == "bruteforce":
        run_attack("SSH Brute Force", "bruteforce")
    elif attack == "botnet":
        run_attack("Botnet C2", "botnet")
    else:
        print(f"Unknown attack: {attack}")