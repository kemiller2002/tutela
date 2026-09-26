"""Domain helpers for Tutela adversarial campaign evidence."""

VALID_OUTCOMES = {"RESISTED", "DEGRADED_SAFE", "VIOLATED", "INDETERMINATE", "NOT_RUN"}

def scenario_blocks_verified_security(scenario: dict) -> bool:
    """Return True when this scenario cannot support a Verified invariant result."""
    return scenario.get("outcome") in {"VIOLATED", "INDETERMINATE", "NOT_RUN"}

def campaign_negative_knowledge(campaign: dict) -> list[str]:
    """Preserve explicit unknown coverage plus scenario limitations."""
    unknowns = list(campaign.get("unknownCoverage", []))
    for scenario in campaign.get("scenarios", []):
        if scenario.get("outcome") in {"INDETERMINATE", "NOT_RUN"}:
            unknowns.append(f"{scenario.get('id','unknown')}: {scenario.get('outcome')}")
        unknowns.extend(scenario.get("limitations", []))
    return unknowns

def outcome_counts(campaign: dict) -> dict[str, int]:
    """Descriptive counts only. This intentionally does not compute a security score."""
    counts = {name: 0 for name in sorted(VALID_OUTCOMES)}
    for scenario in campaign.get("scenarios", []):
        outcome = scenario.get("outcome")
        if outcome in counts:
            counts[outcome] += 1
    return counts
