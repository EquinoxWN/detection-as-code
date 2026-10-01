"""Load detection rules, check their metadata, and replay their labelled logs."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from detection_as_code.sigma import Predicate, compile_detection

ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = ROOT / "rules"
FIXTURES_DIR = ROOT / "tests" / "fixtures"

LEVELS = ("informational", "low", "medium", "high", "critical")
TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
TACTIC_TAGS = {
    "attack.reconnaissance",
    "attack.resource-development",
    "attack.initial-access",
    "attack.execution",
    "attack.persistence",
    "attack.privilege-escalation",
    "attack.defense-evasion",
    "attack.credential-access",
    "attack.discovery",
    "attack.lateral-movement",
    "attack.collection",
    "attack.command-and-control",
    "attack.exfiltration",
    "attack.impact",
}
REQUIRED = (
    "title",
    "id",
    "status",
    "description",
    "author",
    "owner",
    "date",
    "level",
    "tags",
    "logsource",
    "detection",
    "falsepositives",
)


@dataclass
class Rule:
    """A parsed rule plus its compiled matcher and labelled logs."""

    path: Path
    doc: dict[str, Any]
    match: Predicate
    attack: list[dict[str, Any]] = field(default_factory=list)
    benign: list[dict[str, Any]] = field(default_factory=list)

    @property
    def title(self) -> str:
        return self.doc["title"]

    @property
    def techniques(self) -> list[str]:
        return [
            t.removeprefix("attack.").upper() for t in self.doc["tags"] if TECHNIQUE_TAG.match(t)
        ]


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read one JSON object per non-empty line."""
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def metadata_problems(doc: dict[str, Any]) -> list[str]:
    """Return every metadata problem in one rule document."""
    problems = [f"missing field '{k}'" for k in REQUIRED if k not in doc]
    if problems:
        return problems
    try:
        uuid.UUID(str(doc["id"]))
    except ValueError:
        problems.append("id is not a UUID")
    if doc["level"] not in LEVELS:
        problems.append(f"level must be one of {LEVELS}")
    tags = doc["tags"]
    if not any(TECHNIQUE_TAG.match(t) for t in tags):
        problems.append("needs at least one ATT&CK technique tag, e.g. attack.t1059.001")
    if not any(t in TACTIC_TAGS for t in tags):
        problems.append("needs at least one ATT&CK tactic tag, e.g. attack.execution")
    if not str(doc["owner"]).strip():
        problems.append("owner is empty")
    if "condition" not in doc["detection"]:
        problems.append("detection has no condition")
    return problems


def load_rule(path: Path, fixtures: Path = FIXTURES_DIR) -> Rule:
    """Parse and compile one rule and load its fixtures."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    problems = metadata_problems(doc)
    if problems:
        raise ValueError(f"{path.name}: " + "; ".join(problems))
    rule = Rule(path=path, doc=doc, match=compile_detection(doc["detection"]))
    rule.attack = _read_jsonl(fixtures / path.stem / "attack.jsonl")
    rule.benign = _read_jsonl(fixtures / path.stem / "benign.jsonl")
    return rule


def load_rules(rules_dir: Path = RULES_DIR, fixtures: Path = FIXTURES_DIR) -> list[Rule]:
    """Load every rule under rules_dir, rejecting duplicate ids."""
    rules = [load_rule(p, fixtures) for p in sorted(rules_dir.rglob("*.yml"))]
    seen: dict[str, Path] = {}
    for r in rules:
        rid = str(r.doc["id"])
        if rid in seen:
            raise ValueError(f"duplicate id {rid} in {seen[rid].name} and {r.path.name}")
        seen[rid] = r.path
    return rules


@dataclass
class RuleResult:
    """Replay outcome for one rule."""

    rule: Rule
    attack_hits: int
    benign_hits: int

    @property
    def passed(self) -> bool:
        r = self.rule
        return (
            bool(r.attack)
            and bool(r.benign)
            and self.attack_hits == len(r.attack)
            and self.benign_hits == 0
        )


def evaluate(rule: Rule) -> RuleResult:
    """Count how many attack and benign events the rule fires on."""
    return RuleResult(rule, sum(map(rule.match, rule.attack)), sum(map(rule.match, rule.benign)))
