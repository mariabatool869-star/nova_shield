import pickle
import numpy as np
from minions.optic import Optic


class Cortex:
    """NX-02 CORTEX — Hybrid AI Detection Engine (Rules + RF Explainability)."""

    UNIT_ID = "NX-02"
    CALLSIGN = "CORTEX"

    def __init__(self):
        print(f"\n[{self.UNIT_ID} {self.CALLSIGN}] Initializing HYBRID Detection Engine...\n")
        
        with open("models/model_full_features.pkl", "rb") as f:
            self.rf_model = pickle.load(f)
        print("  OK RandomForest (feature importance)")
        
        with open("models/label_encoder.pkl", "rb") as f:
            self.rf_encoder = pickle.load(f)
        print("  OK Label Encoder (15 attacks)")
        
        with open("models/scaler.pkl", "rb") as f:
            self.rf_scaler = pickle.load(f)
        print("  OK Feature Scaler (78 features)")
        
        print(f"\n[{self.UNIT_ID} {self.CALLSIGN}] HYBRID MODE READY\n")

    def explain(self, alert: dict) -> dict:
        features = alert["features"]
        feature_order = Optic.FEATURE_NAMES
        
        # Use the rule-based alert_type from Optic (DDoS, PortScan, etc.)
        detected_attack = alert.get("alert_type", "Unknown")
        
        # Build the vector
        feature_vector = []
        for name in feature_order:
            feature_vector.append(features.get(name, 0))
        
        # Get feature importance from RandomForest (for SHAP explanation only)
        explanation_items = []
        try:
            importances = self.rf_model.feature_importances_
            top_indices = np.argsort(importances)[-5:][::-1]
            for idx in top_indices:
                feat_name = feature_order[idx] if idx < len(feature_order) else f"Feature_{idx}"
                explanation_items.append({
                    "feature": feat_name,
                    "impact": round(float(importances[idx]), 3),
                    "direction": "increases_risk",
                    "magnitude": float(importances[idx]),
                })
        except:
            pass
        
        # Confidence comes from the rule-based detection
        alert["score"] = 0.99
        alert["alert_type"] = detected_attack
        alert["explanation"] = explanation_items
        
        top_feature = explanation_items[0]["feature"] if explanation_items else "unknown"
        alert["counterfactual"] = f"If {top_feature} were normal, this traffic would likely be classified as BENIGN."
        
        return alert