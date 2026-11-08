
from pathlib import Path
from datetime import datetime, timezone
import json
import re
import sys

import joblib
import numpy as np
import pandas as pd
import shap

ROOT = Path(__file__).resolve().parents[2]
PHASE = ROOT / "phase6_xai"
ART = PHASE / "artifacts"
REPORTS = PHASE / "reports"

def stop(message):
    raise RuntimeError(message)

def normalize_shap(values, n_features, n_classes):
    """Return SHAP values in [samples, features, classes] order."""
    if isinstance(values, list):
        if len(values) != n_classes:
            stop("Unexpected SHAP class-list length")
        arrays = [np.asarray(v, dtype=float) for v in values]
        result = np.stack(arrays, axis=2)
    else:
        result = np.asarray(values, dtype=float)
        if result.ndim == 2 and n_classes == 1:
            result = result[:, :, None]
        elif result.ndim == 3 and result.shape[1] == n_classes \
                and result.shape[2] == n_features:
            result = np.transpose(result, (0, 2, 1))

    if result.ndim != 3 or result.shape[1:] != (n_features, n_classes):
        stop("Unexpected SHAP shape: " + str(result.shape))
    if not np.isfinite(result).all():
        stop("Nonfinite SHAP contributions")
    return result

def normalize_base(expected, n_classes):
    arr = np.asarray(expected, dtype=float).reshape(-1)
    if len(arr) != n_classes or not np.isfinite(arr).all():
        stop("Unexpected SHAP base values")
    return arr

def explain(name, model, X, features):
    print("Computing genuine Tree SHAP:", name, flush=True)
    classes = np.asarray(model.classes_)
    predictions = model.predict(X)
    n_classes = len(classes)

    explainer = shap.TreeExplainer(model, model_output="raw")
    raw_values = explainer.shap_values(X, check_additivity=False)
    values = normalize_shap(raw_values, len(features), n_classes)
    bases = normalize_base(explainer.expected_value, n_classes)

    results = []
    for i, prediction in enumerate(predictions):
        matches = np.flatnonzero(classes == prediction)
        if len(matches) != 1:
            stop("Cannot map prediction to SHAP class")
        index = int(matches[0])
        contributions = values[i, :, index]
        reconstructed = float(bases[index] + contributions.sum())

        # RF raw Tree SHAP represents class probability.
        # LightGBM multiclass raw Tree SHAP represents class margin.
        if name == "Random Forest":
            target = float(model.predict_proba(X.iloc[[i]])[0, index])
            output_type = "class_probability"
        else:
            booster = getattr(model, "booster_", None)
            if booster is None:
                stop("LightGBM raw-score interface unavailable")
            margins = np.asarray(
                booster.predict(X.iloc[[i]], raw_score=True)
            ).reshape(-1)
            if len(margins) != n_classes:
                stop("Unexpected LightGBM raw-score shape")
            target = float(margins[index])
            output_type = "raw_class_margin"

        residual = abs(reconstructed - target)
        if not np.isfinite(residual) or residual > 0.01:
            stop(
                name + " SHAP reconstruction failed: "
                + str(residual)
            )

        top_indices = np.argsort(np.abs(contributions))[-8:][::-1]
        top_features = [
            {
                "feature": features[int(j)],
                "value": float(X.iloc[i, int(j)]),
                "shap_contribution": float(contributions[int(j)]),
                "direction": (
                    "increases_class_output"
                    if contributions[int(j)] > 0
                    else "decreases_class_output"
                    if contributions[int(j)] < 0
                    else "neutral"
                ),
            }
            for j in top_indices
        ]

        results.append({
            "sample_index": i,
            "predicted_class": str(prediction),
            "output_type": output_type,
            "base_value": float(bases[index]),
            "shap_sum": float(contributions.sum()),
            "reconstructed_output": reconstructed,
            "actual_model_output": target,
            "reconstruction_error": residual,
            "top_features": top_features,
        })
    return results

def main():
    print("[1/5] Reading existing Stage 5 report")
    reports = sorted(REPORTS.glob("stage5_integration_*.json"))
    if not reports:
        stop("Stage 5 report missing")
    previous = json.loads(reports[-1].read_text())
    if previous.get("sample_count", 0) < 2:
        stop("Stage 5 report does not contain enough samples")

    print("[2/5] Loading trusted models and preprocessing")
    meta = json.loads((ART / "model_metadata.json").read_text())
    for flag in ("firewall_enabled", "database_enabled", "cloud_enabled"):
        if meta.get(flag) is not False:
            stop("Safety flag not disabled: " + flag)

    features = meta["features"]
    if len(features) != 78 or len(set(features)) != 78:
        stop("Invalid feature metadata")

    rf = joblib.load(ART / "random_forest.joblib")
    lgb = joblib.load(ART / "lightgbm.joblib")
    medians = joblib.load(ART / "feature_medians.joblib")

    if list(rf.feature_names_in_) != features:
        stop("Random Forest feature order mismatch")
    normalized = [re.sub(r"\s+", "_", f) for f in features]
    if list(lgb.feature_names_in_) != normalized:
        stop("LightGBM feature normalization mismatch")
    if list(map(str, rf.classes_)) != list(map(str, lgb.classes_)):
        stop("Model class order mismatch")

    source = (ROOT / previous["source_csv"]).resolve()
    dataset_root = (ROOT / "models" / "datasets").resolve()
    if not source.is_relative_to(dataset_root) or not source.is_file():
        stop("Unsafe or missing Stage 5 dataset path")

    print("[3/5] Preparing two existing network flows")
    headers = pd.read_csv(source, nrows=0).columns.tolist()
    mapping = {str(h).strip(): h for h in headers}
    if not all(f in mapping for f in features):
        stop("Stage 5 source is missing required features")

    data = pd.read_csv(
        source,
        usecols=[mapping[f] for f in features],
        nrows=2,
        low_memory=False
    )
    data.columns = [str(c).strip() for c in data.columns]
    X = data.reindex(columns=features).apply(
        pd.to_numeric, errors="coerce"
    ).replace([np.inf, -np.inf], np.nan)

    if isinstance(medians, pd.Series):
        fill = medians.reindex(features)
    elif isinstance(medians, dict):
        fill = pd.Series(medians).reindex(features)
    else:
        fill = pd.Series(
            np.asarray(medians).reshape(-1), index=features
        )
    fill = pd.to_numeric(fill, errors="coerce")
    if fill.isna().any():
        stop("Invalid saved feature medians")

    X = X.fillna(fill).astype("float64")
    if len(X) != 2 or not np.isfinite(X.to_numpy()).all():
        stop("Invalid sample input")

    X_lgb = X.copy()
    X_lgb.columns = normalized

    print("[4/5] Explaining predictions from both models")
    rf_results = explain("Random Forest", rf, X, features)
    lgb_results = explain("LightGBM", lgb, X_lgb, features)

    print("[5/5] Saving verified SHAP report")
    report = {
        "stage": 6,
        "status": "passed",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "method": "genuine Tree SHAP, predicted class",
        "source_stage5_report": reports[-1].name,
        "samples_explained": 2,
        "features": 78,
        "random_forest": rf_results,
        "lightgbm": lgb_results,
        "important_interpretation": [
            "Random Forest contributions are in probability units",
            "LightGBM contributions are in raw-margin units",
            "These units must not be compared directly",
            "SHAP describes model behavior, not attack causality",
            "Two examples do not establish explanation stability",
            "This is not independent model validation"
        ],
        "firewall_enabled": False,
        "database_enabled": False,
        "cloud_enabled": False,
        "original_files_modified": False
    }

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = REPORTS / ("stage6_shap_" + stamp + ".json")
    with destination.open("x") as f:
        json.dump(report, f, indent=2, allow_nan=False)

    print("\n=== STAGE 6 RESULT ===")
    print("PASS: Genuine Random Forest Tree SHAP")
    print("PASS: Genuine LightGBM Tree SHAP")
    print("PASS: Predicted-class explanations")
    print("PASS: SHAP output reconstruction checked")
    print("Samples explained: 2")
    print("Report:", destination.relative_to(ROOT))
    print("Original models and datasets modified: NO")
    print("Firewall/database/cloud: DISABLED")
    print("Next stage: Local XAI dashboard")

    for name, rows in (
        ("Random Forest", rf_results),
        ("LightGBM", lgb_results)
    ):
        first = rows[0]
        print(
            name, "sample 0:", first["predicted_class"],
            "| top feature:",
            first["top_features"][0]["feature"]
        )

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("\nSTAGE 6 STOPPED:", type(exc).__name__, str(exc))
        sys.exit(1)
