"""Every rule has valid metadata, fires on all its attack logs and stays quiet on benign logs."""

import subprocess
import sys

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


def test_attack_data_cache_is_never_loaded():
    """pySigma's optional ATT&CK cache unpickles files from disk; this project must never load it.

    diskcache 5.6.3 (CVE-2025-69872) backed that cache up to pySigma 2.0.1; 2.0.2 moved to
    diskcache-community. Either way, replaying the rules must not import the cache.
    """
    code = (
        "import sys\n"
        "from sigma.collection import SigmaCollection\n"
        "from detection_as_code.rules import RULES_DIR, evaluate, load_rules\n"
        "texts = [p.read_text(encoding='utf-8') for p in sorted(RULES_DIR.rglob('*.yml'))]\n"
        "SigmaCollection.from_yaml('\\n---\\n'.join(texts), collect_errors=True)\n"
        "[evaluate(r) for r in load_rules()]\n"
        "mods = ('diskcache', 'diskcache_community', 'sigma.data.mitre_attack')\n"
        "print(*(m in sys.modules for m in mods))\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)  # noqa: S603
    assert out.stdout.split() == ["False", "False", "False"]
