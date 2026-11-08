
from pathlib import Path
from datetime import datetime, timezone
import json
import sys

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
PHASE = ROOT / "phase6_xai"
ART = PHASE / "artifacts"
REPORTS = PHASE / "reports"

def main():
    print("\n[1/5] Loading trusted Phase 6 metadata")
    meta = json.loads((ART / "model_metadata.json").read_text())
    features = meta["features"]

    for key in ("firewall_enabled", "database_enabled", "cloud_enabled"):
        if meta.get(key) is not False:
            raise RuntimeError("Safety flag not disabled: " + key)

    if len(features) != 78 or len(set(features)) != 78:
        raise RuntimeError("Invalid 78-feature metadata")

    print("[2/5] Loading existing Random Forest and LightGBM")
    rf = joblib.load(ART / "random_forest.joblib")
    lgb = joblib.load(ART / "lightgbm.joblib")
    medians = joblib.load(ART / "feature_medians.joblib")

    if not hasattr(rf, "predict") or not hasattr(lgb, "predict"):
        raise RuntimeError("One model does not support predict()")

    for name, model in (("Random Forest", rf), ("LightGBM", lgb)):
        count = getattr(model, "n_features_in_", None)
        if count is not None and count != len(features):
            raise RuntimeError(name + " feature count mismatch")
        learned = getattr(model, "feature_names_in_", None)
        if learned is not None:
            if name == "LightGBM":
                expected_names = [
                    __import__("re").sub(r"\s+", "_", f)
                    for f in features
                ]
            else:
                expected_names = features

            if list(learned) != expected_names:
                raise RuntimeError(name + " feature order mismatch")

    if not hasattr(rf, "classes_") or not hasattr(lgb, "classes_"):
        raise RuntimeError("Model class metadata unavailable")
    rf_classes = [str(x) for x in rf.classes_]
    lgb_classes = [str(x) for x in lgb.classes_]
    if set(rf_classes) != set(lgb_classes):
        raise RuntimeError("Model label sets differ")

    print("[3/5] Selecting a small existing CIC-IDS2017 sample")
    dataset_dir = ROOT / "models" / "datasets"
    if not dataset_dir.is_dir():
        raise RuntimeError("Dataset directory not found")

    candidates = sorted(dataset_dir.rglob("*.csv"))
    selected = None
    header_map = None

    for path in candidates:
        if "2017" not in str(path).lower():
            continue
        try:
            header = pd.read_csv(path, nrows=0).columns.tolist()
            mapping = {str(h).strip(): h for h in header}
            if all(f in mapping for f in features):
                selected = path
                header_map = mapping
                break
        except (OSError, ValueError, UnicodeError, pd.errors.ParserError):
            continue

    if selected is None:
        raise RuntimeError(
            "No CIC-IDS2017 CSV containing all 78 features found. "
            "No model or dataset was changed."
        )

    usecols = [header_map[f] for f in features]
    label_column = header_map.get("Label")
    if label_column is not None:
        usecols.append(label_column)

    sample = pd.read_csv(selected, usecols=usecols, nrows=64, low_memory=False)
    sample.columns = [str(c).strip() for c in sample.columns]
    if sample.empty:
        raise RuntimeError("Selected dataset has no rows")

    X = sample.reindex(columns=features).apply(
        pd.to_numeric, errors="coerce"
    ).replace([np.inf, -np.inf], np.nan)

    if isinstance(medians, pd.Series):
        fill = medians.reindex(features)
    elif isinstance(medians, dict):
        fill = pd.Series(medians).reindex(features)
    else:
        values = np.asarray(medians).reshape(-1)
        if len(values) != len(features):
            raise RuntimeError("Median artifact length mismatch")
        fill = pd.Series(values, index=features)

    fill = pd.to_numeric(fill, errors="coerce")
    if fill.isna().any():
        raise RuntimeError("Missing or invalid saved feature medians")

    X = X.fillna(fill).astype("float64")
    if not np.isfinite(X.to_numpy()).all():
        raise RuntimeError("Nonfinite input remains after imputation")

    print("[4/5] Predicting with BOTH models on identical samples")
    rf_pred = rf.predict(X)
    X_lgb = X.copy()
    X_lgb.columns = list(lgb.feature_names_in_)
    lgb_pred = lgb.predict(X_lgb)

    if len(rf_pred) != len(X) or len(lgb_pred) != len(X):
        raise RuntimeError("Prediction length mismatch")

    agreement = float(np.mean(
        np.asarray(rf_pred).astype(str) ==
        np.asarray(lgb_pred).astype(str)
    ))

    output_rows = []
    for i in range(len(X)):
        row = {
            "sample_index": i,
            "random_forest_prediction": str(rf_pred[i]),
            "lightgbm_prediction": str(lgb_pred[i]),
            "models_agree": bool(str(rf_pred[i]) == str(lgb_pred[i])),
        }
        if "Label" in sample.columns:
            row["dataset_label"] = str(sample["Label"].iloc[i])
        output_rows.append(row)

    print("[5/5] Saving new integration report")
    report = {
        "stage": 5,
        "purpose": "Two-model offline integration smoke test",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_csv": str(selected.relative_to(ROOT)),
        "sample_count": len(X),
        "feature_count": len(features),
        "random_forest_classes": rf_classes,
        "lightgbm_classes": lgb_classes,
        "model_agreement_rate": agreement,
        "results": output_rows,
        "limitations": [
            "Previously used data: not independent validation",
            "This is an integration smoke test, not an accuracy estimate",
            "SHAP and dashboard integration remain separate stages",
        ],
        "firewall_enabled": False,
        "database_enabled": False,
        "cloud_enabled": False,
        "original_files_modified": False,
    }

    REPORTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = REPORTS / ("stage5_integration_" + stamp + ".json")
    with destination.open("x") as f:
        json.dump(report, f, indent=2, allow_nan=False)

    print("\n=== STAGE 5 RESULT ===")
    print("PASS: Both existing models loaded")
    print("PASS: 78-feature input prepared")
    print("PASS: Both models predicted the same", len(X), "flows")
    print("Model agreement: {:.2%}".format(agreement))
    print("Report:", destination.relative_to(ROOT))
    print("Original files modified: NO")
    print("Firewall/database/cloud: DISABLED")
    print("Next stage: SHAP explainability")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("\nSTAGE 5 STOPPED:", type(exc).__name__, str(exc))
        sys.exit(1)
