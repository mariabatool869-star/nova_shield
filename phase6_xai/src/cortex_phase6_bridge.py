
"""Safe offline bridge for NovaShield's original Cortex interface."""

from copy import deepcopy
from cortex_phase6_adapter import CortexPhase6


class CortexPhase6Bridge:
    """Preserve explain(alert) while separating demo and real-flow paths."""

    UNIT_ID = "NX-02"
    CALLSIGN = "CORTEX"

    def __init__(self):
        # Lazy initialization: demo alerts never load ML models.
        self._engine = None

    def explain(self, alert):
        """Original dashboard-compatible demonstration path."""
        if not isinstance(alert, dict):
            raise ValueError("Alert must be a dictionary.")

        result = deepcopy(alert)
        result["phase6_ai"] = {
            "status": "not_run",
            "reason": (
                "Original Optic produces rule-based demonstration "
                "features, not measured 78-feature network flows."
            ),
            "source": "original_optic_demo",
            "enforcement_enabled": False,
        }
        result["detection_mode"] = "rule_based_demo"
        return result

    def explain_verified_flow(self, alert):
        """Offline entry point for records verified by the caller.

        This method must only be called by a trusted offline CIC data
        loader. It is not exposed as a dashboard HTTP endpoint.
        """
        if not isinstance(alert, dict):
            raise ValueError("Alert must be a dictionary.")

        if self._engine is None:
            self._engine = CortexPhase6()

        result = self._engine.explain(alert)
        result["detection_mode"] = "offline_cic_ai"
        result["phase6_ai"]["status"] = "completed"
        return result
