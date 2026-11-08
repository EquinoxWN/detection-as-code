"""Every rule has valid metadata, fires on all its attack logs and stays quiet on benign logs."""

import shutil
import subprocess
import sys

import pytest
from sigma.collection import SigmaCollection

from detection_as_code.rules import (
    RULES_DIR,
    Rule,
    RuleResult,
    _read_jsonl,
    evaluate,
    load_rule,
    load_rules,
    metadata_problems,
)

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
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=120
    )
    assert out.stdout.split() == ["False", "False", "False"]


def _valid_doc(**changes):
    """A rule document that passes the metadata policy, with optional changes."""
    doc = {
        "title": "t",
        "id": "0b4f4b4e-1111-4111-8111-111111111111",
        "status": "test",
        "description": "d",
        "author": "a",
        "owner": "detection-engineering",
        "date": "2026-11-01",
        "level": "high",
        "tags": ["attack.execution", "attack.t1059.001"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"sel": {"Image|endswith": "x.exe"}, "condition": "sel"},
        "falsepositives": ["none"],
    }
    doc.update(changes)
    return doc


def test_valid_doc_has_no_problems():
    assert metadata_problems(_valid_doc()) == []


@pytest.mark.parametrize(
    ("changes", "problem"),
    [
        ({"owner": None}, "owner is empty"),  # `owner:` left blank in YAML
        ({"owner": "  "}, "owner is empty"),
        ({"tags": ["attack.execution"]}, "technique tag"),
        ({"tags": ["attack.execution", "attack.t10599"]}, "technique tag"),
        ({"tags": ["attack.execution", "attack.t1059.0011"]}, "technique tag"),
        ({"tags": "attack.execution attack.t1059"}, "list of strings"),
        ({"tags": ["attack.execution", 1059]}, "list of strings"),
        ({"detection": ["sel"]}, "detection must be a mapping"),
    ],
)
def test_metadata_policy_rejects(changes, problem):
    assert any(problem in p for p in metadata_problems(_valid_doc(**changes)))


def test_techniques_are_upper_case_ids():
    rule = Rule(path=RULES_DIR / "x.yml", doc=_valid_doc(), match=lambda e: True)
    assert rule.techniques == ["T1059.001"]


def test_duplicate_rule_ids_are_rejected(tmp_path):
    src = next(iter(sorted(RULES_DIR.rglob("*.yml"))))
    shutil.copy(src, tmp_path / "a.yml")
    shutil.copy(src, tmp_path / "b.yml")
    with pytest.raises(ValueError, match="duplicate id"):
        load_rules(tmp_path, tmp_path)


def test_rule_file_must_be_a_mapping(tmp_path):
    path = tmp_path / "empty.yml"
    path.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="expected one YAML mapping"):
        load_rule(path, tmp_path)


def test_jsonl_skips_blank_lines(tmp_path):
    path = tmp_path / "attack.jsonl"
    path.write_text('{"a": 1}\n\n  \n{"a": 2}\n', encoding="utf-8")
    assert _read_jsonl(path) == [{"a": 1}, {"a": 2}]
    assert _read_jsonl(tmp_path / "missing.jsonl") == []


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ('{"a": 1}\n{"a": \n', r"attack\.jsonl:2: invalid JSON"),
        ("[1, 2]\n", "expected a JSON object"),
    ],
)
def test_jsonl_reports_bad_lines(tmp_path, text, error):
    path = tmp_path / "attack.jsonl"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=error):
        _read_jsonl(path)


@pytest.mark.parametrize(
    ("attack", "benign", "attack_hits", "benign_hits", "passed"),
    [
        ([{}], [{}], 1, 0, True),
        ([], [{}], 0, 0, False),  # no attack logs: nothing proven
        ([{}], [], 1, 0, False),  # no benign logs: nothing proven
        ([{}, {}], [{}], 1, 0, False),  # one attack event missed
        ([{}], [{}, {}], 1, 1, False),  # one benign event flagged
    ],
)
def test_rule_result_passed(attack, benign, attack_hits, benign_hits, passed):
    rule = Rule(
        path=RULES_DIR / "x.yml", doc={}, match=lambda e: True, attack=attack, benign=benign
    )
    assert RuleResult(rule, attack_hits, benign_hits).passed is passed
