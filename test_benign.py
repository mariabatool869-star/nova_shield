import pickle
import pandas as pd
import numpy as np
from minions.cortex import Cortex

# Load test data
df_test = pd.read_csv('models/datasets/cic_2018/wednesday_dos2.csv', encoding='latin-1', low_memory=False)
df_test.columns = df_test.columns.str.strip()

# Get a BENIGN sample
benign_sample = df_test[df_test['Label'] == 'Benign'].iloc[0]

print("=" * 70)
print("TESTING BENIGN DETECTION")
print("=" * 70)
print(f"\nSample label: {benign_sample['Label']}")
print(f"Dst Port: {benign_sample['Dst Port']}")

# Build alert
alert = {
    "dst_port": int(benign_sample['Dst Port']),
    "raw_log": f"Normal traffic on port {int(benign_sample['Dst Port'])}",
    "alert_type": "Benign",
    "features": {
        "protocol": int(benign_sample['Protocol']),
        "Flow_Duration": float(benign_sample['Flow Duration']),
        "Total_Fwd_Packets": float(benign_sample['Tot Fwd Pkts']),
        "Total_Backward_Packets": float(benign_sample['Tot Bwd Pkts']),
        "Total_Length_Fwd_Packets": float(benign_sample['TotLen Fwd Pkts']),
        "Total_Length_Bwd_Packets": float(benign_sample['TotLen Bwd Pkts']),
        "Fwd_Packet_Length_Max": float(benign_sample['Fwd Pkt Len Max']),
        "Fwd_Packet_Length_Min": float(benign_sample['Fwd Pkt Len Min']),
        "Fwd_Packet_Length_Mean": float(benign_sample['Fwd Pkt Len Mean']),
        "Fwd_Packet_Length_Std": float(benign_sample['Fwd Pkt Len Std']),
        "Bwd_Packet_Length_Max": float(benign_sample['Bwd Pkt Len Max']),
        "Bwd_Packet_Length_Min": float(benign_sample['Bwd Pkt Len Min']),
        "Bwd_Packet_Length_Mean": float(benign_sample['Bwd Pkt Len Mean']),
        "Bwd_Packet_Length_Std": float(benign_sample['Bwd Pkt Len Std']),
        "Flow_Bytes_per_s": float(benign_sample['Flow Byts/s']),
        "Flow_Packets_per_s": float(benign_sample['Flow Pkts/s']),
        "Flow_IAT_Mean": float(benign_sample['Flow IAT Mean']),
        "Flow_IAT_Std": float(benign_sample['Flow IAT Std']),
        "Flow_IAT_Max": float(benign_sample['Flow IAT Max']),
        "Flow_IAT_Min": float(benign_sample['Flow IAT Min']),
        "Fwd_IAT_Total": float(benign_sample['Fwd IAT Tot']),
        "Fwd_IAT_Mean": float(benign_sample['Fwd IAT Mean']),
        "Fwd_IAT_Std": float(benign_sample['Fwd IAT Std']),
        "Fwd_IAT_Max": float(benign_sample['Fwd IAT Max']),
        "Fwd_IAT_Min": float(benign_sample['Fwd IAT Min']),
        "Bwd_IAT_Total": float(benign_sample['Bwd IAT Tot']),
        "Bwd_IAT_Mean": float(benign_sample['Bwd IAT Mean']),
        "Bwd_IAT_Std": float(benign_sample['Bwd IAT Std']),
        "Bwd_IAT_Max": float(benign_sample['Bwd IAT Max']),
        "Bwd_IAT_Min": float(benign_sample['Bwd IAT Min']),
        "Fwd_PSH_Flags": float(benign_sample['Fwd PSH Flags']),
        "Bwd_PSH_Flags": float(benign_sample['Bwd PSH Flags']),
        "Fwd_URG_Flags": float(benign_sample['Fwd URG Flags']),
        "Bwd_URG_Flags": float(benign_sample['Bwd URG Flags']),
        "Fwd_Header_Length": float(benign_sample['Fwd Header Len']),
        "Bwd_Header_Length": float(benign_sample['Bwd Header Len']),
        "Bwd_Packets_per_s": float(benign_sample['Bwd Pkts/s']),
        "Min_Packet_Length": float(benign_sample['Pkt Len Min']),
        "Max_Packet_Length": float(benign_sample['Pkt Len Max']),
        "Packet_Length_Mean": float(benign_sample['Pkt Len Mean']),
        "Packet_Length_Std": float(benign_sample['Pkt Len Std']),
        "Packet_Length_Variance": float(benign_sample['Pkt Len Var']),
        "FIN_Flag_Count": float(benign_sample['FIN Flag Cnt']),
        "SYN_Flag_Count": float(benign_sample['SYN Flag Cnt']),
        "RST_Flag_Count": float(benign_sample['RST Flag Cnt']),
        "PSH_Flag_Count": float(benign_sample['PSH Flag Cnt']),
        "ACK_Flag_Count": float(benign_sample['ACK Flag Cnt']),
        "CWE_Flag_Count": float(benign_sample['CWE Flag Count']),
        "ECE_Flag_Count": float(benign_sample['ECE Flag Cnt']),
        "Down_Up_Ratio": float(benign_sample['Down/Up Ratio']),
        "Average_Packet_Size": float(benign_sample['Pkt Size Avg']),
        "Avg_Fwd_Segment_Size": float(benign_sample['Fwd Seg Size Avg']),
        "Avg_Bwd_Segment_Size": float(benign_sample['Bwd Seg Size Avg']),
        "Fwd_Avg_Bytes_Bulk": float(benign_sample['Fwd Byts/b Avg']),
        "Fwd_Avg_Packets_Bulk": float(benign_sample['Fwd Pkts/b Avg']),
        "Fwd_Avg_Bulk_Rate": float(benign_sample['Fwd Blk Rate Avg']),
        "Bwd_Avg_Bytes_Bulk": float(benign_sample['Bwd Byts/b Avg']),
        "Bwd_Avg_Packets_Bulk": float(benign_sample['Bwd Pkts/b Avg']),
        "Bwd_Avg_Bulk_Rate": float(benign_sample['Bwd Blk Rate Avg']),
        "Subflow_Fwd_Packets": float(benign_sample['Subflow Fwd Pkts']),
        "Subflow_Fwd_Bytes": float(benign_sample['Subflow Fwd Byts']),
        "Subflow_Bwd_Packets": float(benign_sample['Subflow Bwd Pkts']),
        "Subflow_Bwd_Bytes": float(benign_sample['Subflow Bwd Byts']),
        "Init_Win_bytes_forward": float(benign_sample['Init Fwd Win Byts']),
        "Init_Win_bytes_backward": float(benign_sample['Init Bwd Win Byts']),
        "act_data_pkt_fwd": float(benign_sample['Fwd Act Data Pkts']),
        "min_seg_size_forward": float(benign_sample['Fwd Seg Size Min']),
        "Active_Mean": float(benign_sample['Active Mean']),
        "Active_Std": float(benign_sample['Active Std']),
        "Active_Max": float(benign_sample['Active Max']),
        "Active_Min": float(benign_sample['Active Min']),
        "Idle_Mean": float(benign_sample['Idle Mean']),
        "Idle_Std": float(benign_sample['Idle Std']),
        "Idle_Max": float(benign_sample['Idle Max']),
        "Idle_Min": float(benign_sample['Idle Min']),
    }
}

cortex = Cortex()
result = cortex.explain(alert)

print("\n" + "=" * 70)
print("DETECTION RESULT")
print("=" * 70)
print(f"✅ Predicted: {result.get('predicted')}")
print(f"✅ Score: {result.get('score')}")
print(f"✅ Is Threat: {result.get('is_threat')}")
print(f"✅ Model Used: {result.get('model_used', 'Main Cortex')}")
print("\n" + "=" * 70)
