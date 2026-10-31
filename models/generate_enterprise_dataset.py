import pandas as pd
import numpy as np
import os

np.random.seed(42)

def generate_flow(is_attack, attack_type=None):
    """Generate a realistic network flow with 78 features."""
    if not is_attack:
        # Normal traffic
        flow_duration = np.random.uniform(1.0, 30.0)
        fwd_packets = np.random.randint(2, 50)
        bwd_packets = np.random.randint(2, 50)
        fwd_bytes = np.random.randint(500, 5000)
        bwd_bytes = np.random.randint(500, 5000)
        flow_bytes_s = (fwd_bytes + bwd_bytes) / flow_duration
        flow_packets_s = (fwd_packets + bwd_packets) / flow_duration
        packet_len_mean = (fwd_bytes + bwd_bytes) / (fwd_packets + bwd_packets)
        syn_flag = np.random.randint(0, 2)
        fin_flag = np.random.randint(0, 2)
        rst_flag = 0
        psh_flag = np.random.randint(0, 2)
        ack_flag = 1
        urg_flag = 0
        label = 0
        attack_type = "BENIGN"
    else:
        # Attack traffic
        if attack_type == "DDoS":
            flow_duration = np.random.uniform(0.001, 0.1)
            fwd_packets = np.random.randint(1, 5)
            bwd_packets = 0
            fwd_bytes = np.random.randint(40, 100)
            bwd_bytes = 0
            syn_flag = 1
            fin_flag = 0
            rst_flag = 0
            psh_flag = 0
            ack_flag = 0
            urg_flag = 0
        elif attack_type == "PortScan":
            flow_duration = np.random.uniform(0.001, 0.05)
            fwd_packets = np.random.randint(1, 3)
            bwd_packets = 0
            fwd_bytes = np.random.randint(40, 60)
            bwd_bytes = 0
            syn_flag = 1
            fin_flag = 0
            rst_flag = 1
            psh_flag = 0
            ack_flag = 0
            urg_flag = 0
        elif attack_type == "Botnet":
            flow_duration = np.random.uniform(5.0, 300.0)
            fwd_packets = np.random.randint(10, 100)
            bwd_packets = np.random.randint(10, 100)
            fwd_bytes = np.random.randint(200, 2000)
            bwd_bytes = np.random.randint(200, 2000)
            syn_flag = np.random.randint(0, 2)
            fin_flag = np.random.randint(0, 2)
            rst_flag = 0
            psh_flag = 1
            ack_flag = 1
            urg_flag = 0
        elif attack_type == "BruteForce":
            flow_duration = np.random.uniform(0.1, 2.0)
            fwd_packets = np.random.randint(5, 20)
            bwd_packets = np.random.randint(5, 20)
            fwd_bytes = np.random.randint(200, 1000)
            bwd_bytes = np.random.randint(200, 1000)
            syn_flag = 1
            fin_flag = 0
            rst_flag = 1
            psh_flag = 1
            ack_flag = 1
            urg_flag = 0
        
        flow_bytes_s = (fwd_bytes + bwd_bytes) / max(flow_duration, 0.001)
        flow_packets_s = (fwd_packets + bwd_packets) / max(flow_duration, 0.001)
        packet_len_mean = (fwd_bytes + bwd_bytes) / max((fwd_packets + bwd_packets), 1)
        label = 1

    # Build the 78-feature row (CIC-IDS2017 style)
    row = {
        "Destination Port": np.random.choice([22, 80, 443, 8080, 3389, 445, 53, 3306]),
        "Flow Duration": flow_duration,
        "Total Fwd Packets": fwd_packets,
        "Total Backward Packets": bwd_packets,
        "Total Length of Fwd Packets": fwd_bytes,
        "Total Length of Bwd Packets": bwd_bytes,
        "Fwd Packet Length Mean": fwd_bytes / max(fwd_packets, 1),
        "Bwd Packet Length Mean": bwd_bytes / max(bwd_packets, 1),
        "Flow Bytes/s": flow_bytes_s,
        "Flow Packets/s": flow_packets_s,
        "Flow IAT Mean": flow_duration / max(fwd_packets + bwd_packets, 1),
        "Fwd IAT Mean": flow_duration / max(fwd_packets, 1),
        "Bwd IAT Mean": flow_duration / max(bwd_packets, 1),
        "Min Packet Length": min(fwd_bytes, bwd_bytes) if bwd_bytes > 0 else fwd_bytes,
        "Max Packet Length": max(fwd_bytes, bwd_bytes),
        "Packet Length Mean": packet_len_mean,
        "Packet Length Std": np.random.uniform(0, 50),
        "Packet Length Variance": np.random.uniform(0, 2500),
        "FIN Flag Count": fin_flag,
        "SYN Flag Count": syn_flag,
        "RST Flag Count": rst_flag,
        "PSH Flag Count": psh_flag,
        "ACK Flag Count": ack_flag,
        "URG Flag Count": urg_flag,
        "Down/Up Ratio": bwd_packets / max(fwd_packets, 1),
        "Average Packet Size": packet_len_mean,
        "Label": label,
        "Attack_Type": attack_type,
    }
    
    # Fill the remaining features with realistic defaults
    for i in range(78 - len(row)):
        row[f"Feature_{i}"] = np.random.uniform(0, 100)
    
    return row

def generate_dataset(num_rows=100000):
    print(f"Generating {num_rows} realistic network flows...")
    rows = []
    for _ in range(num_rows):
        r = np.random.random()
        if r < 0.7:
            rows.append(generate_flow(is_attack=False))
        elif r < 0.85:
            rows.append(generate_flow(is_attack=True, attack_type="DDoS"))
        elif r < 0.92:
            rows.append(generate_flow(is_attack=True, attack_type="PortScan"))
        elif r < 0.97:
            rows.append(generate_flow(is_attack=True, attack_type="BruteForce"))
        else:
            rows.append(generate_flow(is_attack=True, attack_type="Botnet"))
    
    df = pd.DataFrame(rows)
    
    os.makedirs("models/datasets", exist_ok=True)
    output_path = "models/datasets/cic_enterprise.csv"
    df.to_csv(output_path, index=False)
    print(f"✅ Dataset saved to {output_path}")
    print(f"   Total rows: {len(df)}")
    print(f"   Total columns: {len(df.columns)}")
    print(f"   Attack distribution:\n{df['Attack_Type'].value_counts()}")

if __name__ == "__main__":
    generate_dataset()