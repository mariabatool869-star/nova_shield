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
    raise SystemExit("STOP: Expected dataset missing.")

metadata = json.loads(paths[3].read_text())
features = metadata["features"]

# Load only trusted artifacts created locally by Phase 6.
rf = joblib.load(paths[0])
lgb = joblib.load(paths[1])
medians = joblib.load(paths[2])

samples = []
count = 0

for chunk in pd.read_csv(source, chunksize=25000, low_memory=False):
    chunk.columns = chunk.columns.str.strip()
    if "Label" not in chunk:
        raise SystemExit("STOP: Label column missing.")

    matches = chunk[
        chunk["Label"].astype(str).str.strip() == "DoS slowloris"
    ]
    if not matches.empty:
        take = matches.head(20 - count)
        samples.append(take)
        count += len(take)
    if count >= 20:
        break

if count != 20:
    raise SystemExit("STOP: Fewer than 20 attack flows found.")

data = pd.concat(samples, ignore_index=True)

missing = [f for f in features if f not in data.columns]
if missing:
    raise SystemExit("STOP: Trained features missing.")

X = data[features].apply(pd.to_numeric, errors="coerce")
X = X.replace([np.inf, -np.inf], np.nan).fillna(medians)

rf_pred = rf.predict(X)
lgb_pred = lgb.predict(X)

missed = (
    (rf_pred != "DoS slowloris") &
    (lgb_pred != "DoS slowloris")
)
correct = (
    (rf_pred == "DoS slowloris") &
    (lgb_pred == "DoS slowloris")
)

if missed.sum() != 10 or correct.sum() != 10:
    raise SystemExit("STOP: Expected 10 missed and 10 correct flows.")

comparison = pd.DataFrame({
    "feature": features,
    "missed_median": X.loc[missed].median().values,
    "correct_median": X.loc[correct].median().values,
})

scale = (
    comparison[["missed_median", "correct_median"]]
    .abs().max(axis=1).clip(lower=1e-9)
)
comparison["relative_difference"] = (
    (comparison["missed_median"] - comparison["correct_median"])
    .abs() / scale
)

comparison = comparison.sort_values(
    "relative_difference", ascending=False
)

print("NOVASHIELD PHASE 6 - SLOWLORIS FEATURE COMPARISON")
print("Missed flows:", int(missed.sum()))
print("Correct flows:", int(correct.sum()))
print("\nTOP 15 FEATURE DIFFERENCES")
print(comparison.head(15).to_string(index=False))

print("\nFEATURE COMPARISON COMPLETE")
print("No retraining or external integrations.")
