import os
import pickle
import warnings
import numpy as np
import pandas as pd
import lightgbm as lgb
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, f1_score, accuracy_score
from sklearn.utils.class_weight import compute_class_weight

warnings.filterwarnings("ignore")

COLUMN_MAP = {
    "Dst Port": "Destination Port", "Protocol": "Protocol", "Flow Duration": "Flow Duration",
    "Tot Fwd Pkts": "Total Fwd Packets", "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets", "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max", "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean", "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max", "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean", "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s", "Flow Pkts/s": "Flow Packets/s",
    "Flow IAT Mean": "Flow IAT Mean", "Flow IAT Std": "Flow IAT Std",
    "Flow IAT Max": "Flow IAT Max", "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Tot": "Fwd IAT Total", "Fwd IAT Mean": "Fwd IAT Mean", "Fwd IAT Std": "Fwd IAT Std",
    "Fwd IAT Max": "Fwd IAT Max", "Fwd IAT Min": "Fwd IAT Min",
    "Bwd IAT Tot": "Bwd IAT Total", "Bwd IAT Mean": "Bwd IAT Mean", "Bwd IAT Std": "Bwd IAT Std",
    "Bwd IAT Max": "Bwd IAT Max", "Bwd IAT Min": "Bwd IAT Min",
    "Fwd PSH Flags": "Fwd PSH Flags", "Bwd PSH Flags": "Bwd PSH Flags",
    "Fwd URG Flags": "Fwd URG Flags", "Bwd URG Flags": "Bwd URG Flags",
    "Fwd Header Len": "Fwd Header Length", "Bwd Header Len": "Bwd Header Length",
    "FwdPkts/s": "Fwd Packets/s", "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Min Packet Length", "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean", "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count", "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count", "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count", "URGFlag Cnt": "URG Flag Count",
    "CWE Flag Count": "CWE Flag Count", "ECE Flag Cnt": "ECE Flag Count",
    "Down/Up Ratio": "Down/Up Ratio", "Pkt Size Avg": "Average Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size", "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk", "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate", "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk", "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets", "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets", "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init Win Bytes Forward", "Init Bwd Win Byts": "Init Win Bytes Backward",
    "Fwd Act Data Pkts": "Act Data Pkt Fwd", "Fwd Seg Size Min": "Min Seg Size Forward",
    "Active Mean": "Active Mean", "Active Std": "Active Std", "Active Max": "Active Max",
    "Active Min": "Active Min", "Idle Mean": "Idle Mean", "Idle Std": "Idle Std",
    "Idle Max": "Idle Max", "Idle Min": "Idle Min",
}

LABEL_MAP = {
    "DDOS attack-HOIC": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",
    "DDoS": "DDoS",
    "Benign": "BENIGN",
    "benign": "BENIGN",
    "BENIGN": "BENIGN"
}

OUTPUT_DIR = Path("models")

def clip_outliers(df, feature_cols):
    print("  Clipping outliers...")
    for col in feature_cols:
        if col in df.columns:
            p99 = df[col].quantile(0.99)
            p01 = df[col].quantile(0.01)
            if p99 > p01:
                df[col] = df[col].clip(lower=p01, upper=p99)
    return df

def preprocess(df):
    print(f"Preprocessing {len(df)} rows...")
    df = df.rename(columns=COLUMN_MAP)
    df["Label"] = df["Label"].map(lambda x: LABEL_MAP.get(str(x).strip(), "BENIGN"))
    feature_cols = [c for c in COLUMN_MAP.values() if c in df.columns]
    print(f"  Features: {len(feature_cols)}")
    print("  Labels:")
    for lbl, cnt in df["Label"].value_counts().items():
        print(f"    {lbl}: {cnt}")
    
    X = df[feature_cols].copy()
    y = df["Label"].copy()
    
    for col in X.columns:
        if X[col].dtype == object:
            X[col] = pd.to_numeric(X[col], errors="coerce")
    
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)
    X = clip_outliers(X, feature_cols)
    
    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    print(f"  Classes: {list(le.classes_)}")
    return X, y_enc, feature_cols, le

def main():
    print("=" * 70)
    print("NOVASHIELD - DDoS MODEL RETRAINING")
    print("=" * 70)
    
    print("\n1. Loading Data...")
    df_train = pd.read_csv('models/datasets/cic_2018/wednesday_dos_train.csv', encoding='latin-1', low_memory=False)
    df_train.columns = df_train.columns.str.strip()
    df_test = pd.read_csv('models/datasets/cic_2018/wednesday_dos_test.csv', encoding='latin-1', low_memory=False)
    df_test.columns = df_test.columns.str.strip()
    
    print("\n2. Preprocessing Train Data...")
    X_train, y_train, feat_names, le = preprocess(df_train)
    
    print("\n3. Preprocessing Test Data...")
    X_test, y_test, _, _ = preprocess(df_test)
    
    print("\n4. Training LightGBM...")
    X_tr, X_val, y_tr, y_val = train_test_split(X_train, y_train, test_size=0.2, stratify=y_train, random_state=42)
    
    classes = np.unique(y_train)
    weights = compute_class_weight("balanced", classes=classes, y=y_train)
    cw = dict(zip([int(c) for c in classes], weights))
    
    model = lgb.LGBMClassifier(
        n_estimators=500,
        learning_rate=0.05,
        max_depth=10,
        num_leaves=127,
        min_child_samples=5,
        subsample=0.8,
        colsample_bytree=0.8,
        class_weight=cw,
        n_jobs=-1,
        random_state=42,
        verbose=-1
    )
    
    model.fit(
        X_tr, y_tr,
        eval_set=[(X_val, y_val)],
        callbacks=[
            lgb.early_stopping(50, verbose=False),
            lgb.log_evaluation(100)
        ]
    )
    
    y_pred_val = model.predict(X_val)
    print(f"\nValidation Accuracy: {accuracy_score(y_val, y_pred_val):.4f}")
    
    print("\n5. Final Test Evaluation...")
    y_pred_test = model.predict(X_test)
    test_acc = accuracy_score(y_test, y_pred_test)
    test_f1 = f1_score(y_test, y_pred_test, average='weighted')
    
    print(f"✅ Test Accuracy: {test_acc:.4f}")
    print(f"✅ Test F1-Score: {test_f1:.4f}")
    print("\nTest Report:")
    print(classification_report(y_test, y_pred_test, target_names=le.classes_, zero_division=0))
    
    print("\n6. Saving Model...")
    with open(OUTPUT_DIR / "ddos_model.pkl", "wb") as f:
        pickle.dump(model, f)
    
    with open(OUTPUT_DIR / "ddos_feature_names.pkl", "wb") as f:
        pickle.dump(feat_names, f)
    
    with open(OUTPUT_DIR / "ddos_l_encoder.pkl", "wb") as f:
        pickle.dump(le, f)
    
    print("  ✅ Model saved to models/ddos_model.pkl")
    print("  ✅ Features saved")
    print("  ✅ Encoder saved")
    
    print("\n" + "=" * 70)
    print("✅ RETRAINING COMPLETE!")
    print("=" * 70)

if __name__ == "__main__":
    main()
