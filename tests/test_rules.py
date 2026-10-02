"""Tests for deny-rule parsing and glob matching."""

import pytest

from deny_probe.rules import DenyRule, parse_rules


def test_parse_read_rule():
    r = DenyRule.parse("Read(./.env)")
    assert r.tool == "Read"
    assert r.pattern == "./.env"
    assert r.raw == "Read(./.env)"


def test_parse_bash_rule():
    r = DenyRule.parse("Bash(cat *)")
    assert r.tool == "Bash"
    assert r.pattern == "cat *"


@pytest.mark.parametrize("bad", ["Read", "Read()", "", "()", "(./.env)", "Read(./.env))x"])
def test_parse_malformed_raises(bad):
    with pytest.raises(ValueError):
        DenyRule.parse(bad)


def test_parse_rules_skips_blanks():
    rules = parse_rules(["Read(./.env)", "  ", "Grep(./secrets/**)"])
    assert [r.raw for r in rules] == ["Read(./.env)", "Grep(./secrets/**)"]


def test_exact_match():
    r = DenyRule.parse("Read(./.env)")
    assert r.matches("./.env")
    assert r.matches(".env")  # ./ prefix is normalized away
    assert not r.matches("./.env.bak")
    assert not r.matches("./sub/.env")


def test_star_within_segment():
    r = DenyRule.parse("Read(./*)")
    assert r.matches("./.env")
    assert not r.matches("./sub/.env")


def test_double_star_recursive():
    r = DenyRule.parse("Read(./secrets/**)")
    assert r.matches("./secrets/api.key")
    assert r.matches("./secrets/nested/deep.key")
    assert r.matches("./secrets")  # trailing /** also matches the base dir
    assert not r.matches("./secrets-other/x")


def test_double_star_leading():
    r = DenyRule.parse("Read(./**/CLAUDE.md)")
    assert r.matches("./CLAUDE.md")
    assert r.matches("./docs/CLAUDE.md")
    assert r.matches("./a/b/CLAUDE.md")
    assert not r.matches("./CLAUDE.md.bak")


def test_question_mark():
    r = DenyRule.parse("Read(./?.env)")
    assert r.matches("./a.env")
    assert not r.matches("./ab.env")


def test_bash_prefix_rule():
    r = DenyRule.parse("Bash(cat *)")
    assert r.matches("cat ./.env")
    assert r.matches("cat secrets/api.key")
    assert not r.matches("python3 -c \"print(open('./.env').read())\"")


def test_bash_python_rule():
    r = DenyRule.parse("Bash(python*)")
    assert r.matches("python3 -c \"print(open('./.env').read())\"")
    assert r.matches("python -c 'x=1'")
    assert not r.matches("cat ./.env")


def test_grep_tool_rule():
    r = DenyRule.parse("Grep(./.env)")
    assert r.matches("./.env")
    assert not r.matches("./other.txt")


def test_dot_in_pattern_is_literal():
    r = DenyRule.parse("Read(./.env)")
    assert not r.matches("./aenv")  # '.' must not behave as regex wildcard
