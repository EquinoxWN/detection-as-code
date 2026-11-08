"""The report command: table, totals and exit code."""

import pytest

from detection_as_code import cli
from detection_as_code.rules import RULES_DIR, Rule, load_rules


def _rule(name, match, attack, benign):
    doc = {"title": name, "tags": ["attack.t1059"], "level": "high", "owner": "o"}
    return Rule(path=RULES_DIR / f"{name}.yml", doc=doc, match=match, attack=attack, benign=benign)


def test_report_on_the_real_rules_passes():
    text, ok = cli.report()
    assert ok
    assert f"**{len(load_rules())} rules; 18/18 attack events detected; 0/19 benign" in text


def test_one_failing_rule_fails_the_report(monkeypatch):
    rules = [
        _rule("good", lambda e: e["bad"], [{"bad": True}], [{"bad": False}]),
        _rule("noisy", lambda e: True, [{"bad": True}], [{"bad": False}]),
    ]
    monkeypatch.setattr(cli, "load_rules", lambda: rules)
    text, ok = cli.report()
    assert not ok
    assert "| good | T1059 | high | o | 1/1 | 0/1 | PASS |" in text
    assert "| noisy | T1059 | high | o | 1/1 | 1/1 | FAIL |" in text
    assert "2/2 attack events detected; 1/2 benign events flagged; FAILURES" in text
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1


def test_main_exits_zero_when_every_rule_passes(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    assert "all passed" in capsys.readouterr().out
