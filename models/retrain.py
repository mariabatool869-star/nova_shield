"""
NovaShield Model Retraining v3
Uses raw feature values without log transform.
Key distinguishing features identified from data analysis.
"""

import os
import pickle
import warnings
import json
import shutil
import numpy as np
import pandas as pd
import lightgbm as lgb

from pathlib import Path
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, f1_score
from sklearn.utils.class_weight import compute_class_weight

warnings.filterwarnings("ignore")

COLUMN_MAP = {
    "Dst Port"        : "Destination Port",
    "Protocol"        : "Protocol",
    "Flow Duration"   : "Flow Duration",
    "Tot Fwd Pkts"    : "Total Fwd Packets",
    "Tot Bwd Pkts"    : "Total Backward Packets",
    "TotLen Fwd Pkts" : "Total Length of Fwd Packets",
    "TotLen Bwd Pkts" : "Total Length of Bwd Packets",
    "Fwd Pkt Len Max" : "Fwd Packet Length Max",
    "Fwd Pkt Len Min" : "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std" : "Fwd Packet Length Std",
    "Bwd Pkt Len Max" : "Bwd Packet Length Max",
    "Bwd Pkt Len Min" : "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std" : "Bwd Packet Length Std",
    "Flow Byts/s"     : "Flow Bytes/s",
    "Flow Pkts/s"     : "Flow Packets/s",
    "Flow IAT Mean"   : "Flow IAT Mean",
    "Flow IAT Std"    : "Flow IAT Std",
    "Flow IAT Max"    : "Flow IAT Max",
    "Flow IAT Min"    : "Flow IAT Min",
    "Fwd IAT Tot"     : "Fwd IAT Total",
    "Fwd IAT Mean"    : "Fwd IAT Mean",
    "Fwd IAT Std"     : "Fwd IAT Std",
    "Fwd IAT Max"     : "Fwd IAT Max",
    "Fwd IAT Min"     : "Fwd IAT Min",
    "Bwd IAT Tot"     : "Bwd IAT Total",
    "Bwd IAT Mean"    : "Bwd IAT Mean",
    "Bwd IAT Std"     : "Bwd IAT Std",
    "Bwd IAT Max"     : "Bwd IAT Max",
    "Bwd IAT Min"     : "Bwd IAT Min",
    "Fwd PSH Flags"   : "Fwd PSH Flags",
    "Bwd PSH Flags"   : "Bwd PSH Flags",
    "Fwd URG Flags"   : "Fwd URG Flags",
    "Bwd URG Flags"   : "Bwd URG Flags",
    "Fwd Header Len"  : "Fwd Header Length",
    "Bwd Header Len"  : "Bwd Header Length",
    "FwdPkts/s"       : "Fwd Packets/s",
    "Bwd Pkts/s"      : "Bwd Packets/s",
    "Pkt Len Min"     : "Min Packet Length",
    "Pkt Len Max"     : "Max Packet Length",
    "Pkt Len Mean"    : "Packet Length Mean",
    "Pkt Len Std"     : "Packet Length Std",
    "Pkt Len Var"     : "Packet Length Variance",
    "FIN Flag Cnt"    : "FIN Flag Count",
    "SYN Flag Cnt"    : "SYN Flag Count",
    "RST Flag Cnt"    : "RST Flag Count",
    "PSH Flag Cnt"    : "PSH Flag Count",
    "ACK Flag Cnt"    : "ACK Flag Count",
    "URGFlag Cnt"     : "URG Flag Count",
    "CWE Flag Count"  : "CWE Flag Count",
    "ECE Flag Cnt"    : "ECE Flag Count",
    "Down/Up Ratio"   : "Down/Up Ratio",
    "Pkt Size Avg"    : "Average Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Byts/b Avg"  : "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg"  : "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg"  : "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg"  : "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init Win Bytes Forward",
    "Init Bwd Win Byts": "Init Win Bytes Backward",
    "Fwd Act Data Pkts": "Act Data Pkt Fwd",
    "Fwd Seg Size Min" : "Min Seg Size Forward",
    "Active Mean"      : "Active Mean",
    "Active Std"       : "Active Std",
    "Active Max"       : "Active Max",
    "Active Min"       : "Active Min",
    "Idle Mean"        : "Idle Mean",
    "Idle Std"         : "Idle Std",
    "Idle Max"         : "Idle Max",
    "Idle Min"         : "Idle Min",
}

LABEL_MAP = {
    "Benign"                   : "BENIGN",
    "benign"                   : "BENIGN",
    "BENIGN"                   : "BENIGN",
    "FTP-BruteForce"           : "FTP-Patator",
    "SSH-Bruteforce"           : "SSH-Patator",
    "DDOS attack-HOIC"         : "DDoS",
    "DDOS attack-LOIC-UDP"     : "DDoS",
    "DDoS"                     : "DDoS",
    "DoS attacks-GoldenEye"    : "DoS GoldenEye",
    "DoS GoldenEye"            : "DoS GoldenEye",
    "DoS attacks-Slowloris"    : "DoS Slowloris",
    "DoS slowloris"            : "DoS Slowloris",
    "DoS attacks-SlowHTTPTest" : "DoS Slowhttptest",
    "DoS attacks-Hulk"         : "DoS Hulk",
    "Bot"                      : "Bot",
    "Infiltration"             : "Infiltration",
    "Brute Force -Web"         : "Web Attack Brute Force",
    "Brute Force -XSS"         : "Web Attack XSS",
    "SQL Injection"            : "Web Attack SQL Injection",
    "SQLInjection"             : "Web Attack SQL Injection",
    "PortScan"                 : "PortScan",
    "FTP-Patator"              : "FTP-Patator",
    "SSH-Patator"              : "SSH-Patator",
    "Heartbleed"               : "Heartbleed",
}

OUTPUT_DIR    = Path("models")
ROWS_PER_FILE = 200000


def load_files(data_dir):
    files = [
        "thursday_bruteforce.csv",
        "thursday_infiltration.csv",
        "friday_ddos_portscan.csv",
        "wednesday_dos.csv",
        "wednesday_dos2.csv",
    ]
    dfs = []
    for fname in files:
        path = os.path.join(data_dir, fname)
        if not os.path.exists(path):
            print("  SKIP: " + fname)
            continue
        print("  Loading: " + fname)
        try:
            df = pd.read_csv(
                path, encoding="latin-1",
                low_memory=False, nrows=ROWS_PER_FILE
            )
            df.columns = df.columns.str.strip()
            cols = [
                c for c in
                list(COLUMN_MAP.keys()) + ["Label"]
                if c in df.columns
            ]
            df = df[cols]
            print("    Rows: " + str(len(df)))
            counts = df["Label"].value_counts().to_dict()
            print("    " + str(counts))
            dfs.append(df)
        except Exception as e:
            print("  ERROR: " + str(e))
    if not dfs:
        raise ValueError("No files loaded")
    result = pd.concat(dfs, ignore_index=True)
    print("Total: " + str(len(result)) + " rows")
    return result


def clip_outliers(df, feature_cols):
    """
    Clip extreme outliers at 99th percentile.
    This helps the model generalise better
    without needing log transform.
    """
    print("Clipping outliers at 99th percentile...")
    for col in feature_cols:
        p99 = df[col].quantile(0.99)
        p01 = df[col].quantile(0.01)
        if p99 > p01:
            df[col] = df[col].clip(lower=p01, upper=p99)
    return df


def preprocess(df):
    print("\nPreprocessing " + str(len(df)) + " rows...")

    df = df.rename(columns=COLUMN_MAP)
    df["Label"] = df["Label"].map(
        lambda x: LABEL_MAP.get(str(x).strip(), "BENIGN")
    )

    feature_cols = [
        c for c in COLUMN_MAP.values()
        if c in df.columns
    ]
    print("Features: " + str(len(feature_cols)))

    print("Labels:")
    for lbl, cnt in df["Label"].value_counts().items():
        print("  " + str(lbl) + ": " + str(cnt))

    X = df[feature_cols].copy()
    y = df["Label"].copy()

    for col in X.columns:
        if X[col].dtype == object:
            X[col] = pd.to_numeric(X[col], errors="coerce")

    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    # Clip outliers instead of log transform
    X = clip_outliers(X, feature_cols)

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    print("Classes: " + str(list(le.classes_)))
    return X, y_enc, feature_cols, le


def train(X, y, le):
    print("\nTraining LightGBM v3...")
    print("Samples: " + str(len(X)))

    classes = np.unique(y)
    weights = compute_class_weight(
        "balanced", classes=classes, y=y
    )
    cw = dict(zip([int(c) for c in classes], weights))

    X_tr, X_val, y_tr, y_val = train_test_split(
        X, y, test_size=0.2,
        stratify=y, random_state=42
    )

    model = lgb.LGBMClassifier(
        n_estimators     = 500,
        learning_rate    = 0.05,
        max_depth        = 10,
        num_leaves       = 127,
        min_child_samples= 5,
        subsample        = 0.8,
        colsample_bytree = 0.8,
        class_weight     = cw,
        n_jobs           = -1,
        random_state     = 42,
        verbose          = -1,
    )

    print("Training... 10-20 minutes...")
    model.fit(
        X_tr, y_tr,
        eval_set=[(X_val, y_val)],
        callbacks=[
            lgb.early_stopping(50, verbose=False),
            lgb.log_evaluation(100)
        ]
    )

    y_pred = model.predict(X_val)
    f1 = f1_score(y_val, y_pred, average="weighted")
    print("F1: " + str(round(f1, 4)))
    print(classification_report(
        y_val, y_pred,
        target_names=le.classes_,
        zero_division=0
    ))
    return model


def save(model, feature_cols, le):
    old = OUTPUT_DIR / "cortex_model.pkl"
    if old.exists():
        shutil.copy(
            old,
            OUTPUT_DIR / "cortex_model_backup3.pkl"
        )
        print("Old model backed up")

    with open(OUTPUT_DIR / "cortex_model.pkl", "wb") as f:
        pickle.dump(model, f)
    with open(OUTPUT_DIR / "feature_names.pkl", "wb") as f:
        pickle.dump(feature_cols, f)
    with open(OUTPUT_DIR / "label_encoder.pkl", "wb") as f:
        pickle.dump(le, f)

    meta = {
        "trained_at"    : datetime.utcnow().isoformat(),
        "feature_count" : len(feature_cols),
        "feature_names" : feature_cols,
        "classes"       : list(le.classes_),
        "transform"     : "clip_outliers_p99_no_log",
        "version"       : "3"
    }
    with open(OUTPUT_DIR / "model_metadata.json", "w") as f:
        json.dump(meta, f, indent=2)

    print("All files saved.")
    print("Attack types: " + str(list(le.classes_)))


def main():
    print("=" * 55)
    print("NOVASHIELD MODEL TRAINING v3")
    print("Strategy: clip outliers, no log transform")
    print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 55)

    df = load_files("models/datasets/cic_2018")
    X, y, feat_names, le = preprocess(df)
    model = train(X, y, le)
    save(model, feat_names, le)

    print("\n" + "=" * 55)
    print("TRAINING COMPLETE!")
    print("Run: python3 app.py")
    print("=" * 55)


if __name__ == "__main__":
    main()

