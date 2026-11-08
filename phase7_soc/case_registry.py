"""In-memory registry for offline SOC cases.

No database connections, live alert handling, or enforcement.
"""

from threading import RLock


class SocCaseRegistry:
    def __init__(self):
        self._lock = RLock()
        self._cases = {}

    def register(self, report):
        if not isinstance(report, dict):
            raise ValueError("SOC report must be a dictionary")

        case_id = report.get("case_id")

        if (
            not isinstance(case_id, str)
            or not case_id.startswith("NS-SOC-")
            or report.get("status") != "AWAITING_ANALYST_REVIEW"
            or report.get("enforcement_enabled") is not False
            or report.get("action_executed") is not False
        ):
            raise ValueError("Invalid offline SOC report")

        with self._lock:
            if case_id in self._cases:
                raise ValueError("SOC case already registered")

            self._cases[case_id] = {
                "report": dict(report),
                "state": "PENDING",
            }

        return case_id

    def claim(self, case_id):
        with self._lock:
            entry = self._cases.get(case_id)

            if entry is None or entry["state"] != "PENDING":
                return None

            entry["state"] = "CLAIMED"
            return dict(entry["report"])

    def complete(self, case_id):
        with self._lock:
            entry = self._cases.get(case_id)

            if entry is None or entry["state"] != "CLAIMED":
                return False

            entry["state"] = "COMPLETED"
            return True

    def release(self, case_id):
        with self._lock:
            entry = self._cases.get(case_id)

            if entry is None or entry["state"] != "CLAIMED":
                return False

            entry["state"] = "PENDING"
            return True
