"""Command line: replay every rule against its logs and print a Markdown report.

Usage:
    python -m detection_as_code.cli            # report; exit 1 if any rule fails
"""

from __future__ import annotations

import sys

from detection_as_code.rules import evaluate, load_rules


def report() -> tuple[str, bool]:
    """Build the per-rule results table and an overall pass flag."""
    results = [evaluate(r) for r in load_rules()]
    lines = [
        "| Rule | ATT&CK | Level | Owner | Attack events detected | Benign events flagged | Result |",
        "|---|---|---|---|---|---|---|",
    ]
    for res in results:
        r = res.rule
        lines.append(
            f"| {r.title} | {', '.join(r.techniques)} | {r.doc['level']} | {r.doc['owner']} "
            f"| {res.attack_hits}/{len(r.attack)} | {res.benign_hits}/{len(r.benign)} "
            f"| {'PASS' if res.passed else 'FAIL'} |"
        )
    attacks = sum(len(x.rule.attack) for x in results)
    benign = sum(len(x.rule.benign) for x in results)
    detected = sum(x.attack_hits for x in results)
    flagged = sum(x.benign_hits for x in results)
    ok = all(x.passed for x in results)
    lines.append("")
    lines.append(
        f"**{len(results)} rules; {detected}/{attacks} attack events detected; "
        f"{flagged}/{benign} benign events flagged; {'all passed' if ok else 'FAILURES'}.**"
    )
    return "\n".join(lines), ok


def main() -> None:
    """Print the report and exit non-zero on failure."""
    text, ok = report()
    print(text)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
