"""Unit tests for the Sigma evaluator on small hand-made events."""

import pytest

from detection_as_code.sigma import UnsupportedSigmaError, compile_detection

EVENT = {
    "Image": r"C:\Windows\System32\cmd.exe",
    "CommandLine": "cmd.exe /c echo Hello",
    "Id": 4688,
}


def matches(detection, event=EVENT):
    return compile_detection(detection)(event)


@pytest.mark.parametrize(
    ("detection", "expected"),
    [
        ({"sel": {"Image|endswith": r"\cmd.exe"}, "condition": "sel"}, True),
        ({"sel": {"Image|endswith": r"\CMD.EXE"}, "condition": "sel"}, True),  # case-insensitive
        ({"sel": {"Image|startswith": r"C:\Windows"}, "condition": "sel"}, True),
        ({"sel": {"CommandLine|contains": "echo"}, "condition": "sel"}, True),
        (
            {"sel": {"CommandLine|contains": ["nope", "echo"]}, "condition": "sel"},
            True,
        ),  # list = OR
        ({"sel": {"CommandLine|contains|all": ["echo", "nope"]}, "condition": "sel"}, False),
        ({"sel": {"CommandLine|contains|all": ["echo", "hello"]}, "condition": "sel"}, True),
        ({"sel": {"CommandLine": "cmd.exe*hello"}, "condition": "sel"}, True),  # wildcard
        ({"sel": {"CommandLine": "cmd.exe"}, "condition": "sel"}, False),  # exact by default
        ({"sel": {"CommandLine|re": r"/c\s+echo"}, "condition": "sel"}, True),
        ({"sel": {"Id": 4688}, "condition": "sel"}, True),
        ({"sel": {"Missing": None}, "condition": "sel"}, True),
        ({"sel": {"Missing|contains": "x"}, "condition": "sel"}, False),
        (
            {
                "sel": [{"Image|endswith": "x.exe"}, {"Image|endswith": "cmd.exe"}],
                "condition": "sel",
            },
            True,
        ),
    ],
)
def test_field_matching(detection, expected):
    assert matches(detection) is expected


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ("a and b", False),
        ("a or b", True),
        ("a and not b", True),
        ("not (a or b)", False),
        ("1 of sel_*", True),
        ("all of sel_*", False),
        ("1 of them", True),
        ("all of them", False),
        ("(a or b) and not b", True),
    ],
)
def test_conditions(condition, expected):
    detection = {
        "a": {"Image|endswith": "cmd.exe"},
        "b": {"Image|endswith": "powershell.exe"},
        "sel_x": {"CommandLine|contains": "echo"},
        "sel_y": {"CommandLine|contains": "nope"},
        "condition": condition,
    }
    assert matches(detection) is expected


def test_literal_brackets_are_not_character_classes():
    detection = {"sel": {"CommandLine": "run [x]"}, "condition": "sel"}
    assert matches(detection, {"CommandLine": "run [x]"})
    assert not matches(detection, {"CommandLine": "run x"})


def test_escaped_wildcard_is_literal():
    detection = {"sel": {"CommandLine": r"a\*b"}, "condition": "sel"}
    assert matches(detection, {"CommandLine": "a*b"})
    assert not matches(detection, {"CommandLine": "aXXb"})


@pytest.mark.parametrize(
    "detection",
    [
        {"sel": {"Image|windash": "x"}, "condition": "sel"},  # unknown modifier
        {"sel": ["keyword"], "condition": "sel"},  # keyword lists
        {"sel": {"Image": "x"}, "condition": "sel | count() > 5"},  # aggregation
        {"sel": {"Image": "x"}, "condition": "other"},  # unknown selection
        {"sel": {"Image": "x"}, "condition": "(sel"},  # unbalanced
        {"sel": {"Image": "x"}, "condition": "1 of nothing*"},
    ],
)
def test_unsupported_features_fail_loudly(detection):
    with pytest.raises(UnsupportedSigmaError):
        compile_detection(detection)


def test_trailing_backslash_with_contains_stays_literal():
    """Regression: a value ending in a backslash plus the contains wildcard stays literal."""
    detection = {"sel": {"CommandLine|contains": "\\Temp\\"}, "condition": "sel"}
    assert matches(detection, {"CommandLine": r"run C:\Windows\Temp\x.cmd"})
    assert not matches(detection, {"CommandLine": r"run C:\Windows\Temp*"})
