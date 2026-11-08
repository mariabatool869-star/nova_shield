"""NovaShield Phase 7A — Offline SOC investigation reports.

Uses existing Phase 6 predictions. Does not train models or enforce actions.
"""
from datetime import datetime, timezone
from uuid import uuid4


def _model_summary(result):
    result = result if isinstance(result, dict) else {}
    return {
        "prediction": str(result.get("prediction", "UNKNOWN")),
        "confidence": result.get("confidence"),
        "shap_output": result.get("shap_output"),
        "top_features": result.get("explanation", result.get("top_features", [])),
    }


def generate_soc_report(enriched_alert):
    """Generate a review-only SOC report for a suspicious/malicious flow."""
    if not isinstance(enriched_alert, dict):
        raise ValueError("Expected enriched alert dictionary.")

    ai = enriched_alert.get("phase6_ai")
    if not isinstance(ai, dict):
        raise ValueError("Missing Phase 6 AI result.")

    if ai.get("source") != "real_78_feature_flow":
        raise ValueError("Report requires verified real-flow inference.")

    rf = _model_summary(ai.get("random_forest"))
    lgb = _model_summary(ai.get("lightgbm"))

    rf_label = rf["prediction"].strip().upper()
    lgb_label = lgb["prediction"].strip().upper()

    if rf_label == "BENIGN" and lgb_label == "BENIGN":
        return None

    disagreement = rf_label != lgb_label
    classification = "SUSPICIOUS" if disagreement else "MALICIOUS"

    assessment = (
        "The models disagree. Human investigation is required before "
        "determining whether this flow represents a threat."
        if disagreement else
        "Both existing AI models classified this flow as non-benign. "
        "This is a model-based assessment, not independent proof of an attack."
    )

    evidence = {
        "random_forest": {
            "prediction": rf["prediction"],
            "confidence": rf["confidence"],
            "shap_output": rf["shap_output"],
            "top_features": rf["top_features"],
        },
        "lightgbm": {
            "prediction": lgb["prediction"],
            "confidence": lgb["confidence"],
            "shap_output": lgb["shap_output"],
            "top_features": lgb["top_features"],
        },
    }

    investigation_steps = [
        "Review the original network flow and its surrounding traffic.",
        "Verify source and destination context, ports, and timestamps.",
        "Compare traffic volume and packet behavior with normal activity.",
        "Correlate findings with available firewall, IDS, and system logs.",
        "Determine whether the observed behavior supports the AI classification.",
        "Record the analyst decision before considering any response action.",
    ]

    limitations = [
        "AI predictions are not independent proof of an attack.",
        "Model confidence does not establish real-world certainty.",
        "SHAP explains model behavior, not the actual cause of network activity.",
        "Random Forest and LightGBM SHAP values use different output scales.",
        "This offline dataset demonstration does not monitor live traffic.",
        "No firewall or containment action is authorized or executed.",
    ]

    return {
        "case_id": "NS-SOC-" + uuid4().hex[:12].upper(),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "AWAITING_ANALYST_REVIEW",
        "classification": classification,
        "detection_mode": enriched_alert.get("detection_mode"),
        "model_agreement": not disagreement,
        "models": {
            "random_forest": rf,
            "lightgbm": lgb,
        },
        "assessment": assessment,
        "evidence": evidence,
        "investigation_steps": investigation_steps,
        "limitations": limitations,
        "recommended_action": "INVESTIGATE",
        "human_approval_required": True,
        "analyst_decision": None,
        "enforcement_enabled": False,
        "action_executed": False,
    }
