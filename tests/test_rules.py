"""Every rule has valid metadata, fires on all its attack logs and stays quiet on benign logs."""

import pytest
from sigma.collection import SigmaCollection

from detection_as_code.rules import RULES_DIR, evaluate, load_rules, metadata_problems

RULES = load_rules()


def test_rules_exist():
    assert len(RULES) >= 6


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.path.stem)
def test_rule_has_labelled_logs(rule):
    assert rule.attack, f"{rule.path.stem}: add tests/fixtures/{rule.path.stem}/attack.jsonl"
    assert rule.benign, f"{rule.path.stem}: add tests/fixtures/{rule.path.stem}/benign.jsonl"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.path.stem)
def test_rule_fires_on_every_attack_event(rule):
    missed = [e["CommandLine"] for e in rule.attack if not rule.match(e)]
    assert not missed, f"missed attack events: {missed}"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.path.stem)
def test_rule_is_quiet_on_benign_events(rule):
    noisy = [e["CommandLine"] for e in rule.benign if rule.match(e)]
    assert not noisy, f"false positives: {noisy}"
    assert evaluate(rule).passed


def test_rules_parse_with_official_pysigma():
    """The reference Sigma library must accept every rule without errors."""
    texts = [p.read_text(encoding="utf-8") for p in sorted(RULES_DIR.rglob("*.yml"))]
    collection = SigmaCollection.from_yaml("\n---\n".join(texts), collect_errors=True)
    errors = [str(e) for rule in collection.rules for e in rule.errors]
    assert not errors
    assert len(collection.rules) == len(RULES)


def test_metadata_validation_catches_problems():
    doc = dict.fromkeys(
        (
            "title",
            "id",
            "status",
            "description",
            "author",
            "owner",
            "date",
            "level",
            "falsepositives",
        ),
        "x",
    )
    doc.update(tags=["attack.t1059"], logsource={}, detection={"sel": {}})
    problems = metadata_problems(doc)
    assert any("UUID" in p for p in problems)
    assert any("level" in p for p in problems)
    assert any("tactic" in p for p in problems)
    assert any("condition" in p for p in problems)
    assert metadata_problems({})  # every required field missing
