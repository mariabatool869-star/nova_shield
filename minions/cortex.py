import pickle
import pandas as pd
import shap
import numpy as np


class Cortex:
    """NX-02 CORTEX — The enterprise brain. LightGBM + SHAP explainability."""

    UNIT_ID = "NX-02"
    CALLSIGN = "CORTEX"

    def __init__(self):
        # Load the enterprise LightGBM model
        with open("models/cortex_model.pkl", "rb") as f:
            self.model = pickle.load(f)
        
        # Load the feature names (76 features)
        with open("models/feature_names.pkl", "rb") as f:
            raw_feature_names = pickle.load(f)
        
        # Fix whitespace in feature names (LightGBM warning)
        self.feature_names = [f.replace(" ", "_") for f in raw_feature_names]
        
        # Build SHAP explainer
        self.explainer = shap.TreeExplainer(self.model)

        print(f"[{self.UNIT_ID} {self.CALLSIGN}] Loaded {len(self.feature_names)} features.")

    def explain(self, alert: dict) -> dict:
        """Explains the prediction using SHAP values."""
        features = alert["features"]
        
        # Build a dataframe from the incoming features
        # If incoming features don't match 76, pad with defaults
        incoming = {}
        for name in self.feature_names:
            # Map our simple feature names to the enterprise ones
            if "failed_logins_60s" in name.lower() and "failed_logins_60s" in features:
                incoming[name] = features["failed_logins_60s"]
            elif "flag_syn" in name.lower() and "is_root_target" in features:
                incoming[name] = features["is_root_target"]
            else:
                incoming[name] = features.get(name, 0)
        
        X = pd.DataFrame([incoming])
        
        # Get the probability
        prob = self.model.predict_proba(X)[0][1]
        alert["score"] = round(float(prob), 2)

        # Get SHAP values
        shap_values = self.explainer.shap_values(X)
        
        # LightGBM returns a list for binary classification; take the attack class
        if isinstance(shap_values, list):
            shap_values = shap_values[1][0]
        else:
            shap_values = shap_values[0]

        # Get top 3 features by absolute impact
        impacts = list(zip(self.feature_names, shap_values))
        impacts.sort(key=lambda x: abs(x[1]), reverse=True)
        
        explanation_items = []
        for feat, impact in impacts[:3]:
            explanation_items.append({
                "feature": feat,
                "impact": round(float(impact), 3),
                "direction": "increases_risk" if impact > 0 else "decreases_risk",
                "magnitude": abs(float(impact)),
            })

        alert["explanation"] = explanation_items

        # Counterfactual
        top_feature = impacts[0][0]
        cf = f"If {top_feature} were normal, this traffic would likely be classified as BENIGN."
        alert["counterfactual"] = cf

        return alert