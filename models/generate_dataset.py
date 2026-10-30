import pandas as pd
import random
import numpy as np

def generate_data(num_samples=10000):
    data = []
    for _ in range(num_samples):
        # 80% normal traffic, 20% attack traffic
        is_attack = random.random() < 0.2
        
        if is_attack:
            # Attack patterns: high failed logins, targeting root, unseen IPs
            failed_logins = random.randint(10, 100)
            is_root = random.choice([1, 1, 1, 0]) # 75% chance targeting root
            src_unseen = 1
            packet_size = random.randint(60, 100) # Small packets (SYN flood)
            duration = random.uniform(0.1, 2.0) # Fast connections
            label = 1
        else:
            # Normal patterns: low failed logins, mostly regular users
            failed_logins = random.randint(0, 3)
            is_root = random.choice([0, 0, 0, 1]) # 25% chance root login (legit admin)
            src_unseen = random.choice([0, 0, 0, 1]) # Mostly known IPs
            packet_size = random.randint(500, 1500) # Large packets (Data transfer)
            duration = random.uniform(1.0, 30.0) # Longer connections
            label = 0
            
        data.append([failed_logins, is_root, src_unseen, packet_size, duration, label])
        
    df = pd.DataFrame(data, columns=[
        "failed_logins_60s", "is_root_target", "src_ip_unseen", 
        "avg_packet_size", "duration_seconds", "label"
    ])
    
    # Save to CSV
    df.to_csv("models/nova_dataset.csv", index=False)
    print(f"✅ Generated {num_samples} records and saved to models/nova_dataset.csv")

if __name__ == "__main__":
    generate_data()