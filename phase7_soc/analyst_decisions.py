"""Phase 7C: Validate offline SOC analyst decisions.

No database writes, firewall operations, or automatic enforcement.
"""

ALLOWED_DECISIONS = frozenset({
    "CONFIRMED_THREAT",
    "FALSE_POSITIVE",
    "NEEDS_INVESTIGATION",
})


def validate_analyst_decision(case_id, analyst, decision, justification):
    if not isinstance(case_id, str) or not case_id.startswith("NS-SOC-"):
        raise ValueError("Invalid SOC case ID")

    if not isinstance(analyst, str) or not analyst.strip():
        raise ValueError("Analyst identifier required")

    if decision not in ALLOWED_DECISIONS:
        raise ValueError("Unsupported analyst decision")

    if not isinstance(justification, str) or not justification.strip():
        raise ValueError("Written justification required")

    return {
        "case_id": case_id,
        "analyst": analyst.strip(),
        "human_decision": decision,
        "justification": justification.strip(),
        "enforcement_enabled": False,
        "action_executed": False,
    }
