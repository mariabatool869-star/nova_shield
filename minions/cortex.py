import pickle
import pandas as pd
import shap


class Cortex:
    """NX-02 CORTEX — The processing core. Uses AI to score and explain."""

    UNIT_ID = "NX-02"
    CALLSIGN = "CORTEX"

    def __init__(self):
        with open("models/cortex_model.pkl", "rb") as f:
            self.model = pickle.load(f)
        
        self.explainer = shap.Explainer(self.model)
        self.feature_names = [
            "failed_logins_60s", "is_root_target", "src_ip_unseen", 
            "avg_packet_size", "duration_seconds"
        ]

    def explain(self, alert: dict) -> dict:
        features = alert["features"]
        
        # 1. Get the AI score
        X = pd.DataFrame([features], columns=self.feature_names)
        prob = self.model.predict_proba(X)[0][1]
        alert["score"] = round(prob, 2)

        # 2. Get SHAP explanations
        explanation = self.explainer(X)
        shap_values = explanation.values[0]
        
        if len(shap_values.shape) > 1 and shap_values.shape[1] > 1:
            shap_values = shap_values[:, 1]

        feature_impacts = list(zip(self.feature_names, shap_values))
        feature_impacts.sort(key=lambda x: abs(x[1]), reverse=True)

        # 3. Build structured explanation for UI
        explanation_items = []
        top_risk_feature = None
        top_risk_value = 0

        for feat, impact in feature_impacts[:3]:
            explanation_items.append({
                "feature": feat,
                "impact": round(float(impact), 3),
                "direction": "increases_risk" if impact > 0 else "decreases_risk",
                "magnitude": abs(float(impact)),
            })
            if impact > top_risk_value:
                top_risk_value = impact
                top_risk_feature = feat

        alert["explanation"] = explanation_items
        
        # 4. Generate counterfactual based on new features
        cf = None
        if top_risk_feature == "src_ip_unseen" and features.get("src_ip_unseen") == 1:
            cf = "If this source IP were in the known baseline, risk would drop significantly."
        elif top_risk_feature == "is_root_target" and features.get("is_root_target") == 1:
            cf = "If the target account were a non-privileged user, risk would drop significantly."
        elif top_risk_feature == "failed_logins_60s" and features.get("failed_logins_60s", 0) > 5:
            cf = "If failed login attempts were below 5, risk would drop to ~0.45."
        elif top_risk_feature == "avg_packet_size" and features.get("avg_packet_size", 1000) < 200:
            cf = "If packet sizes were larger (indicating real data), risk would drop."
        
        alert["counterfactual"] = cf
        return alert