from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd

ROOT = Path("phase6_xai")
ARTIFACTS = ROOT / "artifacts"

print("NOVASHIELD PHASE 6 - OFFLINE PREDICTION")

required = [
    ARTIFACTS / "random_forest.joblib",
    ARTIFACTS / "lightgbm.joblib",
    ARTIFACTS / "feature_medians.joblib",
    ARTIFACTS / "model_metadata.json",
]

if any(not p.is_file() or p.is_symlink() for p in required):
    raise SystemExit("STOP: Missing or linked Phase 6 artifact.")

# Load only locally generated Phase 6 artifacts.
# Never load untrusted joblib/pickle files.
metadata = json.loads(required[3].read_text())
features = metadata["features"]

rf = joblib.load(required[0])
lgb = joblib.load(required[1])
medians = joblib.load(required[2])

source = Path(
    "models/datasets/cic_2017/"
    "Wednesday-workingHours.pcap_ISCX.csv"
)

if not source.is_file() or source.is_symlink():
    raise SystemExit("STOP: Expected CIC-IDS2017 CSV missing.")

# Search the CSV in manageable chunks for a labeled attack.
example = None
rows_scanned = 0

for df in pd.read_csv(source, chunksize=25000, low_memory=False):
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise SystemExit("STOP: Dataset label column missing.")

    rows_scanned += len(df)
    labels = df["Label"].astype(str).str.strip()
    attacks = df[labels.notna() & labels.ne("BENIGN") & labels.ne("")]

    if not attacks.empty:
        example = attacks.iloc[[0]]
        break

if example is None:
    raise SystemExit("STOP: No labeled attack found in dataset.")

print("Rows scanned:", rows_scanned)
true_label = str(example["Label"].iloc[0]).strip()

missing = [name for name in features if name not in example.columns]
if missing:
    raise SystemExit("STOP: Dataset missing trained feature columns.")

X = example[features].apply(pd.to_numeric, errors="coerce")
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(medians)

rf_prediction = str(rf.predict(X)[0])
lgb_prediction = str(lgb.predict(X)[0])

result = {
    "dataset_label": true_label,
    "random_forest_prediction": rf_prediction,
    "random_forest_probability": float(rf.predict_proba(X).max()),
    "lightgbm_prediction": lgb_prediction,
    "lightgbm_probability": float(lgb.predict_proba(X).max()),
    "models_agree": rf_prediction == lgb_prediction,
    "random_forest_correct": rf_prediction == true_label,
    "lightgbm_correct": lgb_prediction == true_label,
}

print(json.dumps(result, indent=2))
print("OFFLINE PREDICTION COMPLETE")
print("No retraining or live network access.")
