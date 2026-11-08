
"""Read-only compatibility tests for the original NovaShield interface."""

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORTEX = ROOT / "minions" / "cortex.py"
OPTIC = ROOT / "minions" / "optic.py"
DASHBOARD = ROOT / "dashboard" / "app.py"
METADATA = ROOT / "phase6_xai" / "artifacts" / "model_metadata.json"

for path in (CORTEX, OPTIC, DASHBOARD, METADATA):
    assert path.is_file(), f"Missing required file: {path}"

dashboard_source = DASHBOARD.read_text(encoding="utf-8")
optic_source = OPTIC.read_text(encoding="utf-8")
metadata = json.loads(METADATA.read_text(encoding="utf-8"))

assert "cortex.explain(alert)" in dashboard_source
print("PASS: Original dashboard calls cortex.explain(alert)")

required = metadata["features"]
assert len(required) == 78 and len(set(required)) == 78
print("PASS: Phase 6 requires 78 unique features")

optic_tree = ast.parse(optic_source)
optic_class = next(
    node for node in optic_tree.body
    if isinstance(node, ast.ClassDef) and node.name == "Optic"
)

scan = next(
    node for node in optic_class.body
    if isinstance(node, ast.FunctionDef) and node.name == "scan"
)

scan_source = ast.get_source_segment(optic_source, scan) or ""
assert 'values.get(name, 0)' in scan_source
print("PASS: Original Optic zero-fills unspecified measurements")

assert '"features": features' in scan_source
print("PASS: Original Optic returns an alert feature dictionary")

# Do not import or execute the original Cortex, Optic, or dashboard.
from cortex_phase6_adapter import CortexPhase6

# Test validation without loading models or running SHAP.
adapter = object.__new__(CortexPhase6)
adapter.features = required

try:
    adapter._prepare({"Flow Duration": 100})
except ValueError as exc:
    assert "Incomplete flow" in str(exc)
    print("PASS: Incomplete real-flow input rejected")
else:
    raise AssertionError("Incomplete input was accepted")

print("\n=== INTEGRATION DECISION ===")
print("Original Optic output: DEMONSTRATION / RULE-BASED")
print("Phase 6 AI input: REAL, VERIFIED 78-FEATURE FLOW ONLY")
print("Direct Optic-to-AI connection: NOT SAFE YET")
print("Original dashboard: PRESERVED")
print("Original Cortex: PRESERVED")
print("Models retrained: NO")
print("Firewall/database/cloud: NOT ACTIVATED")
print("\nPASS: Cortex compatibility review completed")
