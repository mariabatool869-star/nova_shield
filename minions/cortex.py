import pickle
import pandas as pd
import shap


class Cortex:
    """NX-02 CORTEX — The processing core. Uses AI to score and explain."""

    UNIT_ID = "NX-02"
    CALLSIGN = "CORTEX"

    def __init__(self):
        # Load the trained brain
        with open("models/cortex_model.pkl", "rb") as f:
            self.model = pickle.load(f)
        
        # Set up SHAP explainer (using the modern Explainer API)
        self.explainer = shap.Explainer(self.model)
        self.feature_names = ["failed_logins_60s", "is_root_target", "src_ip_unseen"]

    def explain(self, alert: dict) -> dict:
        """Takes an alert, runs the AI, and explains the 'why'."""
        features = alert["features"]
        
        # 1. Get the AI score
        X = pd.DataFrame([features], columns=self.feature_names)
        prob = self.model.predict_proba(X)[0][1]
        alert["score"] = round(prob, 2)

        # 2. Get SHAP explanations (Robust version handling)
        explanation = self.explainer(X)
        shap_values = explanation.values[0] # This gets the values for the first instance
        
        # If it returns values for both classes, we only want the "attack" class (index 1)
        if len(shap_values.shape) > 1 and shap_values.shape[1] > 1:
            shap_values = shap_values[:, 1]

        feature_impacts = list(zip(self.feature_names, shap_values))
        
        # Sort by absolute impact
        feature_impacts.sort(key=lambda x: abs(x[1]), reverse=True)

        # 3. Create human-readable explanations
        new_explanations = []
        for feat, impact in feature_impacts[:2]: # Top 2 features
            if impact > 0.01:
                new_explanations.append(f"{feat} (increased risk by +{impact:.2f})")
            elif impact < -0.01:
                new_explanations.append(f"{feat} (decreased risk by {impact:.2f})")

        alert["explanation"] = new_explanations
        return alert