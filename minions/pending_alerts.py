"""Thread-safe, in-memory pending-alert registry for development."""

from copy import deepcopy
from threading import Lock
from uuid import uuid4


class PendingAlertRegistry:
    def __init__(self):
        self._lock = Lock()
        self._alerts = {}

    def add(self, alert):
        alert_copy = deepcopy(alert)
        alert_id = str(uuid4())
        alert_copy["alert_id"] = alert_id

        with self._lock:
            self._alerts[alert_id] = {
                "status": "pending",
                "alert": alert_copy,
            }

        return deepcopy(alert_copy)

    def list_pending(self):
        """Return independent copies of alerts awaiting a decision."""
        with self._lock:
            return [
                deepcopy(entry["alert"])
                for entry in self._alerts.values()
                if entry["status"] == "pending"
            ]

    def claim(self, alert_id):
        if not isinstance(alert_id, str):
            return None

        with self._lock:
            entry = self._alerts.get(alert_id)

            if entry is None or entry["status"] != "pending":
                return None

            entry["status"] = "processing"
            return deepcopy(entry["alert"])

    def complete(self, alert_id):
        with self._lock:
            entry = self._alerts.get(alert_id)

            if entry is None or entry["status"] != "processing":
                return False

            entry["status"] = "completed"
            return True

    def release(self, alert_id):
        with self._lock:
            entry = self._alerts.get(alert_id)

            if entry is None or entry["status"] != "processing":
                return False

            entry["status"] = "pending"
            return True
