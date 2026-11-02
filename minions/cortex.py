import pickle
import pandas as pd
import shap
import numpy as np


class Cortex:
    """
    NX-02 CORTEX - AI detection engine.
    Trained on CIC-IDS2018 v3 with 76 real features.
    Uses LightGBM + SHAP for explainable predictions.
    """

    UNIT_ID  = "NX-02"
    CALLSIGN = "CORTEX"

    # Maps model feature names (spaces) to
    # optic.py feature names (underscores)
    # IMPORTANT: Only include features the model has
    FEATURE_MAP = {
        "Destination Port"              : "dst_port",
        "Protocol"                      : "protocol",
        "Flow Duration"                 : "Flow_Duration",
        "Total Fwd Packets"             : "Total_Fwd_Packets",
        "Total Backward Packets"        : "Total_Backward_Packets",
        "Total Length of Fwd Packets"   : "Total_Length_Fwd_Packets",
        "Total Length of Bwd Packets"   : "Total_Length_Bwd_Packets",
        "Fwd Packet Length Max"         : "Fwd_Packet_Length_Max",
        "Fwd Packet Length Min"         : "Fwd_Packet_Length_Min",
        "Fwd Packet Length Mean"        : "Fwd_Packet_Length_Mean",
        "Fwd Packet Length Std"         : "Fwd_Packet_Length_Std",
        "Bwd Packet Length Max"         : "Bwd_Packet_Length_Max",
        "Bwd Packet Length Min"         : "Bwd_Packet_Length_Min",
        "Bwd Packet Length Mean"        : "Bwd_Packet_Length_Mean",
        "Bwd Packet Length Std"         : "Bwd_Packet_Length_Std",
        "Flow Bytes/s"                  : "Flow_Bytes_per_s",
        "Flow Packets/s"                : "Flow_Packets_per_s",
        "Flow IAT Mean"                 : "Flow_IAT_Mean",
        "Flow IAT Std"                  : "Flow_IAT_Std",
        "Flow IAT Max"                  : "Flow_IAT_Max",
        "Flow IAT Min"                  : "Flow_IAT_Min",
        "Fwd IAT Total"                 : "Fwd_IAT_Total",
        "Fwd IAT Mean"                  : "Fwd_IAT_Mean",
        "Fwd IAT Std"                   : "Fwd_IAT_Std",
        "Fwd IAT Max"                   : "Fwd_IAT_Max",
        "Fwd IAT Min"                   : "Fwd_IAT_Min",
        "Bwd IAT Total"                 : "Bwd_IAT_Total",
        "Bwd IAT Mean"                  : "Bwd_IAT_Mean",
        "Bwd IAT Std"                   : "Bwd_IAT_Std",
        "Bwd IAT Max"                   : "Bwd_IAT_Max",
        "Bwd IAT Min"                   : "Bwd_IAT_Min",
        "Fwd PSH Flags"                 : "Fwd_PSH_Flags",
        "Bwd PSH Flags"                 : "Bwd_PSH_Flags",
        "Fwd URG Flags"                 : "Fwd_URG_Flags",
        "Bwd URG Flags"                 : "Bwd_URG_Flags",
        "Fwd Header Length"             : "Fwd_Header_Length",
        "Bwd Header Length"             : "Bwd_Header_Length",
        "Bwd Packets/s"                 : "Bwd_Packets_per_s",
        "Min Packet Length"             : "Min_Packet_Length",
        "Max Packet Length"             : "Max_Packet_Length",
        "Packet Length Mean"            : "Packet_Length_Mean",
        "Packet Length Std"             : "Packet_Length_Std",
        "Packet Length Variance"        : "Packet_Length_Variance",
        "FIN Flag Count"                : "FIN_Flag_Count",
        "SYN Flag Count"                : "SYN_Flag_Count",
        "RST Flag Count"                : "RST_Flag_Count",
        "PSH Flag Count"                : "PSH_Flag_Count",
        "ACK Flag Count"                : "ACK_Flag_Count",
        "CWE Flag Count"                : "CWE_Flag_Count",
        "ECE Flag Count"                : "ECE_Flag_Count",
        "Down/Up Ratio"                 : "Down_Up_Ratio",
        "Average Packet Size"           : "Average_Packet_Size",
        "Avg Fwd Segment Size"          : "Avg_Fwd_Segment_Size",
        "Avg Bwd Segment Size"          : "Avg_Bwd_Segment_Size",
        "Fwd Avg Bytes/Bulk"            : "Fwd_Avg_Bytes_Bulk",
        "Fwd Avg Packets/Bulk"          : "Fwd_Avg_Packets_Bulk",
        "Fwd Avg Bulk Rate"             : "Fwd_Avg_Bulk_Rate",
        "Bwd Avg Bytes/Bulk"            : "Bwd_Avg_Bytes_Bulk",
        "Bwd Avg Packets/Bulk"          : "Bwd_Avg_Packets_Bulk",
        "Bwd Avg Bulk Rate"             : "Bwd_Avg_Bulk_Rate",
        "Subflow Fwd Packets"           : "Subflow_Fwd_Packets",
        "Subflow Fwd Bytes"             : "Subflow_Fwd_Bytes",
        "Subflow Bwd Packets"           : "Subflow_Bwd_Packets",
        "Subflow Bwd Bytes"             : "Subflow_Bwd_Bytes",
        "Init Win Bytes Forward"        : "Init_Win_bytes_forward",
        "Init Win Bytes Backward"       : "Init_Win_bytes_backward",
        "Act Data Pkt Fwd"              : "act_data_pkt_fwd",
        "Min Seg Size Forward"          : "min_seg_size_forward",
        "Active Mean"                   : "Active_Mean",
        "Active Std"                    : "Active_Std",
        "Active Max"                    : "Active_Max",
        "Active Min"                    : "Active_Min",
        "Idle Mean"                     : "Idle_Mean",
        "Idle Std"                      : "Idle_Std",
        "Idle Max"                      : "Idle_Max",
        "Idle Min"                      : "Idle_Min",
    }

    DISPLAY_NAMES = {
        "Destination Port"       : "Target Port",
        "Flow Duration"          : "Flow Duration",
        "Flow Bytes/s"           : "Bytes Per Second",
        "Flow Packets/s"         : "Packets Per Second",
        "SYN Flag Count"         : "SYN Packets",
        "ACK Flag Count"         : "ACK Packets",
        "RST Flag Count"         : "RST Packets",
        "PSH Flag Count"         : "PSH Packets",
        "FIN Flag Count"         : "FIN Packets",
        "Total Fwd Packets"      : "Forward Packets",
        "Total Backward Packets" : "Backward Packets",
        "Packet Length Mean"     : "Avg Packet Size",
        "Flow IAT Mean"          : "Avg Time Between Packets",
        "Down/Up Ratio"          : "Download/Upload Ratio",
        "Bwd Packets/s"          : "Backward Packet Rate",
        "Init Win Bytes Forward" : "TCP Window Size",
        "Average Packet Size"    : "Average Packet Size",
    }

    def __init__(self):
        try:
            with open("models/cortex_model.pkl", "rb") as f:
                self.model = pickle.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(
                "Model not found. "
                "Run: python3 models/retrain.py"
            )

        try:
            with open("models/feature_names.pkl", "rb") as f:
                self.feature_names = pickle.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(
                "Feature names not found. "
                "Run: python3 models/retrain.py"
            )

        try:
            with open("models/label_encoder.pkl", "rb") as f:
                self.label_encoder = pickle.load(f)
        except FileNotFoundError:
            self.label_encoder = None

        try:
            self.explainer = shap.TreeExplainer(self.model)
            shap_status = "SHAP enabled"
        except Exception as e:
            self.explainer = None
            shap_status = "SHAP disabled"

        print(
            f"[{self.UNIT_ID} {self.CALLSIGN}] Ready. "
            f"{len(self.feature_names)} features. "
            f"{shap_status}."
        )

    # ----------------------------------------------------------
    # PUBLIC
    # ----------------------------------------------------------

    def explain(self, alert: dict) -> dict:
        """Run AI classification and explanation."""
        try:
            X      = self._build_features(alert)
            alert  = self._predict(X, alert)
            if self.explainer:
                alert = self._explain_shap(X, alert)
            else:
                alert = self._explain_fallback(alert)
            alert["counterfactual"] = (
                self._counterfactual(alert)
            )
            return alert
        except Exception as e:
            print(f"[{self.UNIT_ID}] ERROR: {e}")
            import traceback
            traceback.print_exc()
            alert["score"]          = 0.5
            alert["explanation"]    = []
            alert["counterfactual"] = "Analysis error."
            return alert

    # ----------------------------------------------------------
    # PRIVATE: Feature Building
    # ----------------------------------------------------------

    def _build_features(
        self, alert: dict
    ) -> pd.DataFrame:
        """
        Build dataframe with exactly the features
        the model expects in correct order.
        """
        optic_feats = alert.get("features", {})
        dst_port    = alert.get("dst_port", 0)
        row         = {}

        for model_name in self.feature_names:
            if model_name == "Destination Port":
                row[model_name] = float(dst_port)
                continue

            if model_name == "Protocol":
                row[model_name] = float(
                    optic_feats.get("protocol", 6)
                )
                continue

            optic_key = self.FEATURE_MAP.get(model_name)
            if optic_key:
                val = optic_feats.get(optic_key, 0.0)
                row[model_name] = float(val)
            else:
                row[model_name] = 0.0

        df = pd.DataFrame([row])

        if df.shape[1] != len(self.feature_names):
            print(
                f"[{self.UNIT_ID}] WARNING: "
                f"Shape mismatch: "
                f"got {df.shape[1]}, "
                f"expected {len(self.feature_names)}"
            )

        return df

    # ----------------------------------------------------------
    # PRIVATE: Prediction
    # ----------------------------------------------------------

    def _predict(
        self, X: pd.DataFrame, alert: dict
    ) -> dict:
        """Run model prediction."""
        proba      = self.model.predict_proba(X)[0]
        pred_idx   = int(np.argmax(proba))
        confidence = float(np.max(proba))

        if self.label_encoder is not None:
            class_name = str(
                self.label_encoder.classes_[pred_idx]
            )
        else:
            class_name = alert.get("alert_type", "Unknown")

        print(f"[{self.UNIT_ID}] Top predictions:")
        if self.label_encoder is not None:
            for idx in np.argsort(proba)[::-1][:3]:
                cls = self.label_encoder.classes_[idx]
                pct = proba[idx] * 100
                print(f"  {cls}: {pct:.1f}%")

        is_threat = (
            class_name != "BENIGN" and confidence > 0.6
        )

        alert["score"]     = round(confidence, 3)
        alert["predicted"] = class_name
        alert["is_threat"] = is_threat

        if is_threat:
            alert["alert_type"] = class_name

        return alert

    # ----------------------------------------------------------
    # PRIVATE: SHAP
    # ----------------------------------------------------------

    def _explain_shap(
        self, X: pd.DataFrame, alert: dict
    ) -> dict:
        """Generate SHAP explanation."""
        try:
            shap_vals = self.explainer.shap_values(X)
            pred_idx  = int(np.argmax(
                self.model.predict_proba(X)[0]
            ))

            if isinstance(shap_vals, list):
                idx  = min(pred_idx, len(shap_vals) - 1)
                vals = np.array(
                    shap_vals[idx][0], dtype=float
                )
            elif isinstance(shap_vals, np.ndarray):
                if shap_vals.ndim == 3:
                    vals = shap_vals[0, :, pred_idx]
                else:
                    vals = shap_vals[0]
            else:
                vals = np.array(shap_vals[0], dtype=float)

            impacts = sorted(
                zip(self.feature_names, vals),
                key=lambda x: abs(float(x[1])),
                reverse=True
            )

            explanation = []
            for feat, impact in impacts[:3]:
                display = self.DISPLAY_NAMES.get(feat, feat)
                explanation.append({
                    "feature"  : feat,
                    "display"  : display,
                    "impact"   : round(float(impact), 4),
                    "direction": (
                        "increases_risk"
                        if float(impact) > 0
                        else "decreases_risk"
                    ),
                    "magnitude": round(abs(float(impact)), 4),
                    "value"    : float(X[feat].values[0]),
                })

            alert["explanation"] = explanation
            alert["top_feature"] = (
                impacts[0][0] if impacts else "Unknown"
            )

        except Exception as e:
            print(f"[{self.UNIT_ID}] SHAP error: {e}")
            alert = self._explain_fallback(alert)

        return alert

    def _explain_fallback(self, alert: dict) -> dict:
        """Rule-based explanation fallback."""
        features = alert.get("features", {})
        score    = alert.get("score", 0.5)

        checks = [
            ("Flow_Packets_per_s", "Packets Per Second",
             "Extreme packet rate indicates attack"),
            ("Flow_Duration",      "Flow Duration",
             "Unusual flow duration pattern"),
            ("Init_Win_bytes_forward", "TCP Window Size",
             "Unusual TCP window size"),
            ("PSH_Flag_Count",     "PSH Packets",
             "PSH flag pattern matches attack"),
        ]

        explanation = []
        for key, display, reason in checks:
            val = features.get(key, 0)
            if val != 0:
                explanation.append({
                    "feature"  : display,
                    "display"  : display,
                    "impact"   : round(score, 4),
                    "direction": "increases_risk",
                    "magnitude": round(score, 4),
                    "value"    : float(val),
                    "reason"   : reason,
                })
            if len(explanation) == 3:
                break

        alert["explanation"] = explanation
        alert["top_feature"] = (
            explanation[0]["feature"]
            if explanation else "Unknown"
        )
        return alert

    def _counterfactual(self, alert: dict) -> str:
        """What would make this traffic appear benign."""
        score      = alert.get("score", 0)
        alert_type = alert.get("alert_type", "Unknown")

        if score < 0.5:
            return "Traffic is within normal parameters."

        hints = {
            "DoS GoldenEye": (
                "If packet rate exceeded 100/s and "
                "flow duration dropped below 1,000,000, "
                "this would appear as normal HTTP traffic."
            ),
            "DoS Slowloris": (
                "If PSH flags were present with higher "
                "packet rates, this would not match "
                "the Slowloris attack signature."
            ),
            "SSH-Patator": (
                "If connection attempts dropped below "
                "5 per minute with natural timing, "
                "this would appear as legitimate SSH."
            ),
            "FTP-Patator": (
                "If connection attempts dropped below "
                "3 per minute with natural timing, "
                "this would appear as legitimate FTP."
            ),
            "DDoS": (
                "If traffic came from a single source "
                "with lower packet rates, this would "
                "not trigger DDoS detection."
            ),
            "Bot": (
                "If timing intervals had natural "
                "variation and different port patterns, "
                "this would not match bot signatures."
            ),
            "Web Attack Brute Force": (
                "If request rate dropped below 10/min "
                "with varied parameters, this would "
                "appear as normal web browsing."
            ),
            "Web Attack SQL Injection": (
                "If request payloads contained no "
                "SQL keywords, this would pass as "
                "normal web traffic."
            ),
            "Web Attack XSS": (
                "If payloads contained no script tags, "
                "this would appear as normal traffic."
            ),
        }

        return hints.get(
            alert_type,
            f"If key network metrics were within normal "
            f"ranges, confidence would drop below "
            f"the 60% detection threshold."
        )

