
"""Offline Phase 6 Cortex adapter. No legacy application imports."""

from pathlib import Path
import json
import numpy as np
import pandas as pd
import joblib
import shap


class CortexPhase6:
    """NX-02: Dual-model prediction and genuine predicted-class SHAP."""

    UNIT_ID = "NX-02"
    CALLSIGN = "CORTEX"

    def __init__(self, artifact_dir=None):
        if artifact_dir is None:
            artifact_dir = (
                Path(__file__).resolve().parents[1] / "artifacts"
            )
        artifact_dir = Path(artifact_dir)

        metadata = json.loads(
            (artifact_dir / "model_metadata.json").read_text(
                encoding="utf-8"
            )
        )
        self.features = list(metadata["features"])

        if len(self.features) != 78 or len(set(self.features)) != 78:
            raise ValueError("Expected 78 unique model features.")

        self.rf = joblib.load(
            artifact_dir / "random_forest.joblib"
        )
        self.lgb = joblib.load(
            artifact_dir / "lightgbm.joblib"
        )

        rf_names = list(self.rf.feature_names_in_)
        lgb_names = list(self.lgb.feature_names_in_)

        if rf_names != self.features:
            raise ValueError("Random Forest feature order mismatch.")

        normalize = lambda name: str(name).replace(" ", "_")
        if [normalize(x) for x in lgb_names] != [
            normalize(x) for x in self.features
        ]:
            raise ValueError("LightGBM feature order mismatch.")

        self.lgb_names = lgb_names
        self.rf_explainer = shap.TreeExplainer(
            self.rf, model_output="raw"
        )
        self.lgb_explainer = shap.TreeExplainer(
            self.lgb, model_output="raw"
        )

    def _prepare(self, features):
        if not isinstance(features, dict):
            raise ValueError("Features must be a dictionary.")

        missing = [f for f in self.features if f not in features]
        if missing:
            raise ValueError(
                "Incomplete flow: missing "
                + str(len(missing))
                + " required features; examples: "
                + ", ".join(missing[:5])
            )

        values = []
        for name in self.features:
            value = features[name]
            try:
                number = float(value)
            except (TypeError, ValueError):
                raise ValueError(
                    "Non-numeric feature: " + name
                ) from None

            if not np.isfinite(number):
                raise ValueError(
                    "Non-finite feature: " + name
                )
            values.append(number)

        return pd.DataFrame(
            [values], columns=self.features
        )

    @staticmethod
    def _class_contributions(explainer, frame, class_index):
        values = explainer.shap_values(frame)

        if isinstance(values, list):
            selected = np.asarray(values[class_index])[0]
        else:
            values = np.asarray(values)
            if values.ndim == 3:
                selected = values[0, :, class_index]
            elif values.ndim == 2:
                selected = values[0]
            else:
                raise ValueError(
                    "Unexpected SHAP output shape."
                )

        return np.asarray(selected, dtype=float)

    def _predict_one(self, model, explainer, frame, names):
        predicted = model.predict(frame)[0]
        classes = list(model.classes_)
        index = classes.index(predicted)

        probabilities = model.predict_proba(frame)[0]
        contributions = self._class_contributions(
            explainer, frame, index
        )

        if len(contributions) != len(self.features):
            raise ValueError("SHAP feature count mismatch.")

        ranked = np.argsort(
            np.abs(contributions)
        )[::-1][:8]

        explanation = []
        for position in ranked:
            contribution = float(contributions[position])
            explanation.append({
                "feature": self.features[position],
                "value": float(
                    frame.iloc[0, position]
                ),
                "shap_value": contribution,
                "direction": (
                    "positive" if contribution > 0
                    else "negative" if contribution < 0
                    else "neutral"
                ),
            })

        return {
            "prediction": str(predicted),
            "confidence": float(probabilities[index]),
            "explanation": explanation,
            "shap_output": (
                "class_probability"
                if model is self.rf
                else "raw_model_margin"
            ),
        }

    def explain(self, alert):
        """Return enriched alert without changing its original fields."""
        if not isinstance(alert, dict):
            raise ValueError("Alert must be a dictionary.")

        rf_frame = self._prepare(alert.get("features"))
        lgb_frame = rf_frame.copy()
        lgb_frame.columns = self.lgb_names

        rf_result = self._predict_one(
            self.rf, self.rf_explainer,
            rf_frame, self.features
        )
        lgb_result = self._predict_one(
            self.lgb, self.lgb_explainer,
            lgb_frame, self.lgb_names
        )

        enriched = dict(alert)
        enriched["phase6_ai"] = {
            "source": "real_78_feature_flow",
            "random_forest": rf_result,
            "lightgbm": lgb_result,
            "models_agree": (
                rf_result["prediction"]
                == lgb_result["prediction"]
            ),
            "explanations": "genuine_tree_shap",
            "enforcement_enabled": False,
        }
        return enriched
