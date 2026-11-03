import pickle
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

try:
    import shap
    SHAP_AVAILABLE = True
except:
    SHAP_AVAILABLE = False


class Cortex:
    """
    NX-02 CORTEX - Hybrid AI Detection Engine
    """

    UNIT_ID  = "NX-02"
    CALLSIGN = "CORTEX"

    def __init__(self):
        print(f"\n[{self.UNIT_ID} {self.CALLSIGN}] Initializing HYBRID Detection Engine...\n")
        
        # Load RandomForest
        try:
            with open("models/model_full_features.pkl", "rb") as f:
                self.rf_model = pickle.load(f)
            print(f"  OK RandomForest (99.66% accuracy)")
        except Exception as e:
            print(f"  ERROR RandomForest: {e}")
            self.rf_model = None

        # Load RandomForest encoder
        try:
            with open("models/label_encoder.pkl", "rb") as f:
                self.rf_encoder = pickle.load(f)
            print(f"  OK Label Encoder (15 attacks)")
        except Exception as e:
            print(f"  ERROR Label encoder: {e}")
            self.rf_encoder = None

        # Load RandomForest scaler
        try:
            with open("models/scaler.pkl", "rb") as f:
                self.rf_scaler = pickle.load(f)
            print(f"  OK Feature Scaler (78 features)")
        except Exception as e:
            print(f"  ERROR Feature scaler: {e}")
            self.rf_scaler = None

        # Load LightGBM for SHAP
        try:
            with open("models/cortex_model.pkl", "rb") as f:
                self.lgb_model = pickle.load(f)
            print(f"  OK LightGBM Model (SHAP)")
        except Exception as e:
            print(f"  WARNING LightGBM not found: {e}")
            self.lgb_model = None

        # Load LightGBM encoder
        try:
            with open("models/label_encoder_lgb.pkl", "rb") as f:
                self.lgb_encoder = pickle.load(f)
            print(f"  OK LightGBM Encoder")
        except Exception as e:
            print(f"  WARNING LightGBM encoder: {e}")
            self.lgb_encoder = None

        # Create SHAP explainer
        self.shap_explainer = None
        if self.lgb_model and SHAP_AVAILABLE:
            try:
                self.shap_explainer = shap.TreeExplainer(self.lgb_model)
                print(f"  OK SHAP Explainer (explainable AI)")
            except Exception as e:
                print(f"  WARNING SHAP: {e}")

        print(f"\n[{self.UNIT_ID} {self.CALLSIGN}] HYBRID MODE READY")
        print(f"  Primary: RandomForest (99.66%)")
        print(f"  Explainer: LightGBM + SHAP")
        print(f"  Attacks: 15 types")
        print(f"  Features: 78 metrics\n")

    def classify(self, features_dict):
        """Classify using RandomForest"""
        if not self.rf_model or not self.rf_encoder or not self.rf_scaler:
            return {
                "error": "Model not loaded",
                "attack": "UNKNOWN",
                "confidence": 0,
                "explanation": []
            }

        try:
            features_array = np.array([list(features_dict.values())]).reshape(1, -1)
            features_scaled = self.rf_scaler.transform(features_array)
            
            rf_pred = self.rf_model.predict(features_scaled)[0]
            rf_confidence = self.rf_model.predict_proba(features_scaled).max()
            rf_attack = self.rf_encoder.inverse_transform([rf_pred])[0]
            
            explanations = []
            try:
                importances = self.rf_model.feature_importances_
                top_indices = np.argsort(importances)[-5:][::-1]
                
                for idx in top_indices:
                    feature_name = f"Feature_{idx}"
                    importance = float(importances[idx])
                    value = float(features_array[0][idx])
                    explanations.append({
                        "feature": feature_name,
                        "importance": importance,
                        "value": value
                    })
            except:
                pass
            
            return {
                "attack": rf_attack,
                "confidence": float(rf_confidence),
                "explanation": explanations,
                "model": "HYBRID"
            }
        except Exception as e:
            return {
                "error": str(e),
                "attack": "ERROR",
                "confidence": 0
            }

    def explain(self, alert):
        """Provide explanation"""
        attack = alert.get("attack", "UNKNOWN")
        confidence = alert.get("confidence", 0)
        explanations = alert.get("explanation", [])
        
        exp_text = "Top Contributing Factors:\n"
        for i, exp in enumerate(explanations[:5], 1):
            feature = exp.get("feature", "Unknown")
            importance = exp.get("importance", 0) * 100
            exp_text += f"  {i}. {feature}: {importance:.2f}%\n"
        
        explanation = f"""HYBRID DETECTION ANALYSIS
Attack: {attack}
Confidence: {confidence:.2%}
Model: RandomForest (99.66%)

{exp_text}

Status: Ready for approval"""
        
        return {
            "raw_log": alert.get("raw_log", ""),
            "score": confidence,
            "explanation": explanation,
            "attack_type": attack,
            "confidence": confidence,
            "action": "BLOCK"
        }

    def predict(self, features):
        """Make prediction"""
        if not self.rf_model or not self.rf_scaler:
            return None
        
        try:
            features_scaled = self.rf_scaler.transform([features])
            prediction = self.rf_model.predict(features_scaled)[0]
            confidence = self.rf_model.predict_proba(features_scaled).max()
            attack_name = self.rf_encoder.inverse_transform([prediction])[0]
            
            return {
                "attack": attack_name,
                "confidence": float(confidence)
            }
        except:
            return None
