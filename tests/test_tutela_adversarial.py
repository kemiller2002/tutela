from src.tutela_adversarial import campaign_negative_knowledge, outcome_counts, scenario_blocks_verified_security

def test_violated_indeterminate_and_not_run_block_verified_support():
    for outcome in ("VIOLATED", "INDETERMINATE", "NOT_RUN"):
        assert scenario_blocks_verified_security({"outcome": outcome})
    assert not scenario_blocks_verified_security({"outcome": "RESISTED"})
    assert not scenario_blocks_verified_security({"outcome": "DEGRADED_SAFE"})

def test_negative_knowledge_preserves_unknowns_and_limitations():
    campaign = {
        "unknownCoverage": ["concurrent replay not exercised"],
        "scenarios": [
            {"id":"A1","outcome":"INDETERMINATE","limitations":["dependency behavior unknown"]},
            {"id":"A2","outcome":"RESISTED","limitations":["single payload family only"]}
        ]
    }
    result = campaign_negative_knowledge(campaign)
    assert "concurrent replay not exercised" in result
    assert "A1: INDETERMINATE" in result
    assert "dependency behavior unknown" in result
    assert "single payload family only" in result

def test_counts_are_descriptive_not_a_score():
    counts = outcome_counts({"scenarios":[{"outcome":"RESISTED"},{"outcome":"DEGRADED_SAFE"},{"outcome":"VIOLATED"}]})
    assert counts["RESISTED"] == 1
    assert counts["DEGRADED_SAFE"] == 1
    assert counts["VIOLATED"] == 1
    assert "score" not in counts
