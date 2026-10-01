"""A small, strict Sigma evaluator: enough of the spec to replay rules against JSON events.

Supported: selections as maps (AND) or lists of maps (OR); value lists (OR, or AND with `all`);
modifiers contains, startswith, endswith, all, re; `*` and `?` wildcards; null values; and
conditions with and / or / not / parentheses / `1 of x*` / `all of x*` / `them`.
Anything else raises UnsupportedSigmaError instead of silently matching wrong.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Mapping
from typing import Any

Event = Mapping[str, Any]
Predicate = Callable[[Event], bool]

MODIFIERS = {"contains", "startswith", "endswith", "all", "re"}


class UnsupportedSigmaError(ValueError):
    """Raised for Sigma features this evaluator does not implement."""


def _wildcard_regex(value: str, prefix: str = "", suffix: str = "") -> re.Pattern[str]:
    """Compile a Sigma string to a case-insensitive regex; * and ? are wildcards, backslash escapes."""
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    return re.compile(prefix + "".join(out) + suffix, re.IGNORECASE | re.DOTALL)


def _value_matcher(value: Any, modifiers: list[str]) -> Callable[[Any], bool]:
    """Build a test for one expected value under the given modifiers."""
    if value is None:
        return lambda actual: actual is None
    if "re" in modifiers:
        pattern = re.compile(str(value))
        return lambda actual: actual is not None and pattern.search(str(actual)) is not None
    if isinstance(value, bool | int | float) and not modifiers:
        return lambda actual: str(actual).lower() == str(value).lower()
    text = str(value)
    # Modifier wildcards are added after translation, so a trailing backslash stays literal.
    if "contains" in modifiers:
        rx = _wildcard_regex(text, ".*", ".*")
    elif "startswith" in modifiers:
        rx = _wildcard_regex(text, suffix=".*")
    elif "endswith" in modifiers:
        rx = _wildcard_regex(text, prefix=".*")
    else:
        rx = _wildcard_regex(text)
    return lambda actual: actual is not None and rx.fullmatch(str(actual)) is not None


def _field_predicate(key: str, expected: Any) -> Predicate:
    """Compile `Field|mod1|mod2: value(s)` into an event predicate."""
    field, *modifiers = key.split("|")
    unknown = set(modifiers) - MODIFIERS
    if unknown:
        raise UnsupportedSigmaError(f"modifier(s) {sorted(unknown)} on field {field!r}")
    values = expected if isinstance(expected, list) else [expected]
    matchers = [_value_matcher(v, modifiers) for v in values]
    combine = all if "all" in modifiers else any
    return lambda event: combine(m(event.get(field)) for m in matchers)


def _selection_predicate(name: str, body: Any) -> Predicate:
    """Compile one named selection."""
    if isinstance(body, Mapping):
        parts = [_field_predicate(k, v) for k, v in body.items()]
        return lambda event: all(p(event) for p in parts)
    if isinstance(body, list) and body and all(isinstance(b, Mapping) for b in body):
        alts = [_selection_predicate(name, b) for b in body]
        return lambda event: any(a(event) for a in alts)
    raise UnsupportedSigmaError(
        f"selection {name!r}: keyword lists and other forms are not supported"
    )


_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _tokenize(condition: str) -> list[str]:
    """Split a condition into words and parentheses."""
    tokens, pos = [], 0
    while pos < len(condition):
        m = _TOKEN.match(condition, pos)
        if not m:
            if condition[pos:].strip():
                raise UnsupportedSigmaError(f"cannot parse condition near {condition[pos:]!r}")
            break
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


class _ConditionParser:
    """Recursive-descent parser: or < and < not < atom."""

    def __init__(self, tokens: list[str], selections: dict[str, Predicate]) -> None:
        self.tokens, self.pos, self.selections = tokens, 0, selections

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self) -> str:
        tok = self._peek()
        if tok is None:
            raise UnsupportedSigmaError("condition ended unexpectedly")
        self.pos += 1
        return tok

    def parse(self) -> Predicate:
        """Parse the whole condition."""
        pred = self._or()
        if self._peek() is not None:
            raise UnsupportedSigmaError(f"unexpected token {self._peek()!r} in condition")
        return pred

    def _or(self) -> Predicate:
        """Parse `a or b or ...`."""
        parts = [self._and()]
        while self._peek() == "or":
            self._take()
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else (lambda e: any(p(e) for p in parts))

    def _and(self) -> Predicate:
        """Parse `a and b and ...`."""
        parts = [self._not()]
        while self._peek() == "and":
            self._take()
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else (lambda e: all(p(e) for p in parts))

    def _not(self) -> Predicate:
        """Parse an optional `not` prefix."""
        if self._peek() == "not":
            self._take()
            inner = self._not()
            return lambda e: not inner(e)
        return self._atom()

    def _atom(self) -> Predicate:
        """Parse a parenthesised expression, a quantifier or a selection name."""
        tok = self._take()
        if tok == "(":
            pred = self._or()
            if self._take() != ")":
                raise UnsupportedSigmaError("missing closing parenthesis")
            return pred
        if tok in {"1", "all"} and self._peek() == "of":
            self._take()
            pattern = self._take()
            names = [
                n for n in self.selections if pattern == "them" or fnmatch.fnmatchcase(n, pattern)
            ]
            if not names:
                raise UnsupportedSigmaError(f"'{tok} of {pattern}' matches no selection")
            preds = [self.selections[n] for n in names]
            combine = any if tok == "1" else all
            return lambda e: combine(p(e) for p in preds)
        if tok not in self.selections:
            raise UnsupportedSigmaError(f"condition references unknown selection {tok!r}")
        return self.selections[tok]


def compile_detection(detection: Mapping[str, Any]) -> Predicate:
    """Compile a rule's `detection` block into one event predicate."""
    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise UnsupportedSigmaError("condition must be a single string")
    selections = {
        name: _selection_predicate(name, body)
        for name, body in detection.items()
        if name not in {"condition", "timeframe"}
    }
    return _ConditionParser(_tokenize(condition), selections).parse()
