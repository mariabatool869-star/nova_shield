from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from lightgbm import LGBMClassifier

root = Path("models/datasets/cic_2017")
train_parts = []
test_parts = []

for file in sorted(root.glob("*.csv")):
    print("Reading:", file.name, flush=True)
    target = test_parts if file.name.startswith("Monday") else train_parts
    for chunk in pd.read_csv(file, chunksize=25000, low_memory=False):
        chunk.columns = chunk.columns.str.strip()
        chunk["Label"] = chunk["Label"].astype(str).str.strip()
        target.append(chunk.sample(
            n=min(2500, len(chunk)), random_state=42
        ))

train = pd.concat(train_parts, ignore_index=True)
test = pd.concat(test_parts, ignore_index=True)

y_train = train.pop("Label")
y_test = test.pop("Label")

X_train = train.select_dtypes(include="number")
X_test = test.reindex(columns=X_train.columns)

X_train = X_train.replace([np.inf, -np.inf], np.nan)
X_test = X_test.replace([np.inf, -np.inf], np.nan)

medians = X_train.median()
X_train = X_train.fillna(medians).fillna(0)
X_test = X_test.fillna(medians).fillna(0)

models = {
    "Random Forest": RandomForestClassifier(
        n_estimators=60, n_jobs=-1, random_state=42
    ),
    "LightGBM": LGBMClassifier(
        n_estimators=150, learning_rate=0.05,
        num_leaves=15, min_child_samples=40,
        class_weight="balanced", verbosity=-1,
        random_state=42, n_jobs=4
    )
}

print("\nMONDAY INDEPENDENT-CAPTURE TEST")
print("Training rows:", len(X_train))
print("Monday test rows:", len(X_test))

for name, model in models.items():
    print("\nTraining:", name, flush=True)
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    false_alarms = int((predictions != "BENIGN").sum())
    rate = 100 * false_alarms / len(predictions)
    print(name, "false alarms:", false_alarms)
    print(name, "false-positive rate:", round(rate, 3), "%")

print("\nHOLDOUT CHECK COMPLETE")
