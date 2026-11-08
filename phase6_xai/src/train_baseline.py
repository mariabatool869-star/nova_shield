from pathlib import Path
from collections import Counter
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from lightgbm import LGBMClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

ROOT = Path("models/datasets/cic_2017")
SEED = 42
SAMPLE_PER_FILE = 30000

frames = []
for path in sorted(ROOT.glob("*.csv")):
    print("Reading:", path.name, flush=True)
    parts = []
    for chunk in pd.read_csv(path, chunksize=25000, low_memory=False):
        chunk.columns = chunk.columns.str.strip()
        chunk["Label"] = chunk["Label"].astype(str).str.strip()
        parts.append(chunk.sample(
            n=min(2500, len(chunk)),
            random_state=SEED
        ))
    frame = pd.concat(parts, ignore_index=True)
    frames.append(frame.sample(
        n=min(SAMPLE_PER_FILE, len(frame)),
        random_state=SEED
    ))

data = pd.concat(frames, ignore_index=True)
y = data.pop("Label")
X = data.select_dtypes(include="number")
X = X.replace([np.inf, -np.inf], np.nan)
# Missing values are filled after splitting, using training data only.

print("Rows:", len(X))
print("Features:", len(X.columns))
print("Classes:", dict(Counter(y)))

counts = y.value_counts()
keep = y.isin(counts[counts >= 5].index)
X, y = X.loc[keep], y.loc[keep]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=SEED, stratify=y
)

medians = X_train.median()
X_train = X_train.fillna(medians).fillna(0)
X_test = X_test.fillna(medians).fillna(0)

models = {
    "Random Forest": RandomForestClassifier(
        n_estimators=60, n_jobs=-1, random_state=SEED
    ),
    "LightGBM": LGBMClassifier(
        n_estimators=150, learning_rate=0.05,
        num_leaves=15, min_child_samples=40,
        class_weight="balanced", verbosity=-1,
        random_state=SEED, n_jobs=4
    )
}

trained = {}

for name, model in models.items():
    print("\nTRAINING:", name, flush=True)
    model.fit(X_train, y_train)
    trained[name] = model
    prediction = model.predict(X_test)
    print(classification_report(
        y_test, prediction, zero_division=0
    ))

from sklearn.metrics import f1_score

rf = trained["Random Forest"]
lgb = trained["LightGBM"]
classes = rf.classes_

rf_prob = rf.predict_proba(X_test)
lgb_prob = lgb.predict_proba(X_test)

if not np.array_equal(classes, lgb.classes_):
    raise SystemExit("STOP: Model class orders differ.")

ensemble_prob = (rf_prob + lgb_prob) / 2
ensemble_pred = classes[np.argmax(ensemble_prob, axis=1)]

print("\nENSEMBLE RESULTS")
print(classification_report(
    y_test, ensemble_pred, zero_division=0
))
print("Ensemble macro F1:", round(
    f1_score(y_test, ensemble_pred, average="macro"), 4
))


importance = pd.DataFrame({
    "feature": X_train.columns,
    "importance": rf.feature_importances_
}).sort_values("importance", ascending=False)

output = Path("phase6_xai/reports/rf_feature_importance.csv")
if output.is_symlink():
    raise SystemExit("STOP: Feature report is a symbolic link.")

if not output.exists():
    importance.head(20).to_csv(output, index=False)
else:
    print("Existing feature report preserved.")

print("\nTOP 10 RANDOM FOREST FEATURES")
print(importance.head(10).to_string(index=False))
print("Feature importance report:", output)


import json
import shap

print("\nGENERATING SHAP EXPLANATION", flush=True)

sample = X_test.iloc[[0]]
predicted = rf.predict(sample)[0]
class_index = list(rf.classes_).index(predicted)

explainer = shap.TreeExplainer(rf)
values = explainer.shap_values(sample, check_additivity=False)

if isinstance(values, list):
    contributions = values[class_index][0]
else:
    contributions = values[0, :, class_index]

ranked = np.argsort(np.abs(contributions))[::-1][:5]

lgb_prediction = lgb.predict(sample)[0]
lgb_confidence = float(lgb.predict_proba(sample).max())

explanation = {
    "lightgbm_predicted_class": str(lgb_prediction),
    "lightgbm_probability": lgb_confidence,
    "models_agree": bool(predicted == lgb_prediction),
    "predicted_class": str(predicted),
    "predicted_probability": float(
        rf.predict_proba(sample)[0, class_index]
    ),
    "top_features": [
        {
            "feature": str(X_test.columns[i]),
            "value": float(sample.iloc[0, i]),
            "shap_value": float(contributions[i])
        }
        for i in ranked
    ]
}

output = Path("phase6_xai/reports/model_agreement_example.json")
if output.is_symlink():
    raise SystemExit("STOP: SHAP report is a symbolic link.")

if not output.exists():
    output.write_text(json.dumps(explanation, indent=2) + "\n")
else:
    print("Existing SHAP report preserved.")

print(json.dumps(explanation, indent=2))
print("SHAP EXPLANATION COMPLETE")
print("Report:", output)


print("\nMODEL DISAGREEMENT ANALYSIS")

rf_predictions = rf.predict(X_test)
lgb_predictions = lgb.predict(X_test)
disagree = rf_predictions != lgb_predictions

print("Test flows:", len(X_test))
print("Disagreements:", int(disagree.sum()))
print("Disagreement rate:", round(100 * disagree.mean(), 3), "%")

comparison = pd.DataFrame({
    "actual": y_test.to_numpy(),
    "rf_prediction": rf_predictions,
    "lgb_prediction": lgb_predictions,
    "disagree": disagree
})

summary = comparison.groupby("actual").agg(
    test_flows=("disagree", "size"),
    disagreements=("disagree", "sum")
)
summary["disagreement_pct"] = (
    100 * summary["disagreements"] / summary["test_flows"]
)

print(summary.sort_values(
    "disagreement_pct", ascending=False
).to_string())

output = Path("phase6_xai/reports/model_disagreement.csv")

if output.is_symlink():
    raise SystemExit("STOP: Disagreement report is a symbolic link.")

if not output.exists():
    summary.to_csv(output)
else:
    print("Existing disagreement report preserved.")
print("Disagreement report:", output)

print("\nDISAGREEMENT CORRECTNESS ANALYSIS")

actual = y_test.to_numpy()
rf_correct = rf_predictions == actual
lgb_correct = lgb_predictions == actual

counts = {
    "both_correct": int((disagree & rf_correct & lgb_correct).sum()),
    "rf_only_correct": int((disagree & rf_correct & ~lgb_correct).sum()),
    "lgb_only_correct": int((disagree & ~rf_correct & lgb_correct).sum()),
    "neither_correct": int((disagree & ~rf_correct & ~lgb_correct).sum())
}

for name, count in counts.items():
    print(name + ":", count)

if sum(counts.values()) != int(disagree.sum()):
    raise SystemExit("STOP: Correctness counts do not match disagreements.")

details = comparison.loc[disagree].copy()
details["rf_correct"] = rf_correct[disagree]
details["lgb_correct"] = lgb_correct[disagree]

detail_path = Path("phase6_xai/reports/disagreement_details.csv")
if detail_path.exists() or detail_path.is_symlink():
    print("Existing disagreement details preserved.")
else:
    details.to_csv(detail_path, index=False)
    print("Detailed report:", detail_path)

print("DISAGREEMENT CORRECTNESS ANALYSIS COMPLETE")



# PHASE 6 MODEL ARTIFACT EXPORT
print("\nSAVING PHASE 6 MODEL ARTIFACTS")

import joblib
import json

artifact_dir = Path("phase6_xai/artifacts")

artifacts = {
    "random_forest.joblib": rf,
    "lightgbm.joblib": lgb,
    "feature_medians.joblib": medians,
}

metadata_path = artifact_dir / "model_metadata.json"

metadata = {
    "experiment": "NovaShield Phase 6 CIC-IDS2017",
    "features": list(X_train.columns),
    "classes": [str(c) for c in rf.classes_],
    "model_types": ["RandomForestClassifier", "LGBMClassifier"],
    "training_rows": int(len(X_train)),
    "test_rows": int(len(X_test)),
    "warning": "Experimental offline models; not production validated.",
    "firewall_enabled": False,
    "database_enabled": False,
    "cloud_enabled": False
}

if not artifact_dir.is_dir() or artifact_dir.is_symlink():
    raise SystemExit("STOP: Expected Phase 6 artifacts folder missing.")

targets = [artifact_dir / name for name in artifacts]
targets.append(metadata_path)

if any(t.exists() or t.is_symlink() for t in targets):
    raise SystemExit("STOP: One or more model artifacts already exist.")

for name, obj in artifacts.items():
    joblib.dump(obj, artifact_dir / name)
    print("Saved:", artifact_dir / name)

metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
print("Saved:", metadata_path)
print("PHASE 6 MODEL ARTIFACT EXPORT COMPLETE")

print("\nNOVASHIELD BASELINE COMPLETE")
print("Existing model files modified: NO")
