"""Regression tests for real Claude Code permission-matching bugs fixed in
2.1.287 / 2.1.289 (Oct 2026).

Each test pins one upstream fix to a deny-probe route and asserts both
halves of the story:

  1. the naive / exact-string deny config LEAKs -- deny-probe's static model
     reproduces the bypass the vendor just fixed;
  2. the wildcard-hardened config HOLDs -- the fix's lesson (match the full
     command string, not the idealized one) actually closes it.

Upstream sources:
  - https://www.claudeupdates.dev/version/2.1.289  (4 fixes)
  - https://zemna.net/blog/print-the-redirect-before-you-file-always-ask-off/
    (2.1.287 redirect-swallows-always-ask teardown)
"""

from deny_probe.analyzer import HOLD, LEAK, audit
from deny_probe.rules import parse_rules

TARGET = "./.env"


def verdicts(rules, target=TARGET):
    findings = audit(parse_rules(rules), [target])
    return {f.route.id: f.verdict for f in findings}


def test_2_1_289_read_deny_bypassed_via_symlink():
    # "Fixed Read deny rules not applying to files @-mentioned, changed, or
    # selected in the IDE through a symlink."
    v = verdicts(["Read(./.env)"])
    assert v["read-symlink"] == LEAK
    assert v["read-direct"] == HOLD
    # Lesson: the rule must cover the link path too, not just the real path.
    v = verdicts(["Read(./.env*)"])
    assert v["read-symlink"] == HOLD
    assert v["read-direct"] == HOLD


def test_2_1_289_env_var_prefix_dodges_bash_deny():
    # 'Fixed Bash deny and ask rules missing a command behind an environment
    # variable prefix with an expanded value when the sandbox auto-allows
    # commands' (e.g. TZ="$HOME" rm -rf build).
    v = verdicts(["Bash(cat -- ./.env)"])
    assert v["bash-env-prefix"] == LEAK
    assert v["bash-cat"] == HOLD  # the unprefixed command is still caught
    v = verdicts(["Bash(*cat ./.env*)"])
    assert v["bash-env-prefix"] == HOLD


def test_2_1_289_bare_assignment_dodges_bash_deny():
    # 'Fixed a Bash deny or ask rule being skipped under sandbox auto-allow
    # when a bare variable assignment came before the command'
    # (e.g. FOO=1 rm -rf /).
    v = verdicts(["Bash(cat -- ./.env)"])
    assert v["bash-bare-assign"] == LEAK
    assert v["bash-cat"] == HOLD
    v = verdicts(["Bash(*cat ./.env*)"])
    assert v["bash-bare-assign"] == HOLD


def test_2_1_287_redirect_suffix_dodges_bash_deny():
    # 'Fixed ... always-ask [being swallowed] when output was redirected to
    # ~ or a glob path' -- the match is against the full command line, so a
    # redirect suffix changes the compared string.
    v = verdicts(["Bash(cat -- ./.env)"])
    assert v["bash-redirect-suffix"] == LEAK
    assert v["bash-cat"] == HOLD
    v = verdicts(["Bash(*cat ./.env*)"])
    assert v["bash-redirect-suffix"] == HOLD


def test_2_1_289_compound_nested_command_dodges_exact_bash_deny():
    # 'Fixed a deny or ask rule on a nested part of a compound shell command
    # not holding over a user-installed mod's approval on managed machines.'
    # Even without a mod in play, the exact rule never matches the full
    # compound string.
    v = verdicts(["Bash(cat -- ./.env)"])
    assert v["bash-compound-nested"] == LEAK
    assert v["bash-cat"] == HOLD
    v = verdicts(["Bash(*cat ./.env*)"])
    assert v["bash-compound-nested"] == HOLD
