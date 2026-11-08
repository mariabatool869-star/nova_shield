from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd

root = Path("phase6_xai")
artifacts = root / "artifacts"
source = Path(
    "models/datasets/cic_2017/"
    "Wednesday-workingHours.pcap_ISCX.csv"
)

paths = [
    artifacts / "random_forest.joblib",
    artifacts / "lightgbm.joblib",
    artifacts / "feature_medians.joblib",
    artifacts / "model_metadata.json",
]

if any(not p.is_file() or p.is_symlink() for p in paths):
    raise SystemExit("STOP: Missing or linked Phase 6 artifact.")

if not source.is_file() or source.is_symlink():
    raise SystemExit("STOP: CIC-IDS2017 source missing.")

print("NOVASHIELD PHASE 6 - SLOWLORIS INVESTIGATION")

# Only locally generated Phase 6 artifacts are trusted.
metadata = json.loads(paths[3].read_text())
features = metadata["features"]
rf = joblib.load(paths[0])
lgb = joblib.load(paths[1])
medians = joblib.load(paths[2])

samples = []
scanned = 0

for chunk in pd.read_csv(source, chunksize=25000, low_memory=False):
    chunk.columns = chunk.columns.str.strip()
    if "Label" not in chunk:
        raise SystemExit("STOP: Label column missing.")

    scanned += len(chunk)
    matches = chunk[
        chunk["Label"].astype(str).str.strip() == "DoS slowloris"
    ]
    if not matches.empty:
        samples.append(matches.head(20 - sum(len(x) for x in samples)))
    if sum(len(x) for x in samples) >= 20:
        break

if not samples:
    raise SystemExit("STOP: No DoS slowloris flows found.")

data = pd.concat(samples, ignore_index=True)
missing = [f for f in features if f not in data.columns]
if missing:
    raise SystemExit("STOP: Trained features missing from dataset.")

X = data[features].apply(pd.to_numeric, errors="coerce")
X = X.replace([np.inf, -np.inf], np.nan).fillna(medians)

rf_pred = rf.predict(X)
lgb_pred = lgb.predict(X)

print("Rows scanned:", scanned)
print("Slowloris flows tested:", len(X))
print("Random Forest correct:", int((rf_pred == "DoS slowloris").sum()))
print("LightGBM correct:", int((lgb_pred == "DoS slowloris").sum()))
print("Both missed:", int(
    ((rf_pred != "DoS slowloris") &
     (lgb_pred != "DoS slowloris")).sum()
))

print("\nFIRST 20 PREDICTIONS")
for i, (a, b) in enumerate(zip(rf_pred, lgb_pred), 1):
    print(f"{i:02d}: RF={a} | LightGBM={b}")

print("\nSLOWLORIS INVESTIGATION COMPLETE")
print("No retraining, live traffic, or external integrations.")
