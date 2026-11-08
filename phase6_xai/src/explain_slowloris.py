from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd
import shap

root = Path("phase6_xai")
artifacts = root / "artifacts"
source = Path(
    "models/datasets/cic_2017/"
    "Wednesday-workingHours.pcap_ISCX.csv"
)

paths = [
    artifacts / "random_forest.joblib",
    artifacts / "feature_medians.joblib",
    artifacts / "model_metadata.json",
]

if any(not p.is_file() or p.is_symlink() for p in paths):
    raise SystemExit("STOP: Missing or linked Phase 6 artifact.")
if not source.is_file() or source.is_symlink():
    raise SystemExit("STOP: Dataset missing.")

metadata = json.loads(paths[2].read_text())
features = metadata["features"]

# Load only locally generated, trusted Phase 6 artifacts.
rf = joblib.load(paths[0])
medians = joblib.load(paths[1])

samples = []
count = 0

for chunk in pd.read_csv(source, chunksize=25000, low_memory=False):
    chunk.columns = chunk.columns.str.strip()
    if "Label" not in chunk.columns:
        raise SystemExit("STOP: Label column missing.")

    matches = chunk[
        chunk["Label"].astype(str).str.strip() == "DoS slowloris"
    ]
    if not matches.empty:
        selected = matches.head(20 - count)
        samples.append(selected)
        count += len(selected)
    if count >= 20:
        break

if count != 20:
    raise SystemExit("STOP: Expected 20 Slowloris flows.")

data = pd.concat(samples, ignore_index=True)

missing = [f for f in features if f not in data.columns]
if missing:
    raise SystemExit("STOP: Missing trained features.")

X = data[features].apply(pd.to_numeric, errors="coerce")
X = X.replace([np.inf, -np.inf], np.nan).fillna(medians)

predictions = rf.predict(X)

missed_indices = np.flatnonzero(predictions != "DoS slowloris")
correct_indices = np.flatnonzero(predictions == "DoS slowloris")

if len(missed_indices) == 0 or len(correct_indices) == 0:
    raise SystemExit("STOP: Both example types required.")

explainer = shap.TreeExplainer(rf)

print("NOVASHIELD PHASE 6 - SLOWLORIS SHAP ANALYSIS")

for name, idx in [
    ("MISSED ATTACK", int(missed_indices[0])),
    ("DETECTED ATTACK", int(correct_indices[0]))
]:
    sample = X.iloc[[idx]]
    prediction = str(predictions[idx])
    class_index = list(rf.classes_).index(prediction)

    values = explainer.shap_values(
        sample, check_additivity=False
    )

    if isinstance(values, list):
        contributions = values[class_index][0]
    else:
        contributions = values[0, :, class_index]

    ranked = np.argsort(np.abs(contributions))[::-1][:8]

    print("\n" + name)
    print("Flow number:", idx + 1)
    print("Actual label: DoS slowloris")
    print("RF prediction:", prediction)
    print("RF probability:", round(
        float(rf.predict_proba(sample)[0, class_index]), 4
    ))

    for i in ranked:
        print(
            f"{features[i]}: "
            f"value={float(sample.iloc[0, i]):.4f}, "
            f"SHAP={float(contributions[i]):+.5f}"
        )

print("\nSLOWLORIS SHAP ANALYSIS COMPLETE")
print("No retraining or external integrations.")
