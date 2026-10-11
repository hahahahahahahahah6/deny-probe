"""Tests for the bypass route library."""

import pytest

from deny_probe.routes import ROUTES, get_route


def test_route_ids_unique():
    ids = [r.id for r in ROUTES]
    assert len(ids) == len(set(ids))


def test_library_has_expected_routes():
    ids = {r.id for r in ROUTES}
    expected = {
        "read-direct",
        "grep-tool",
        "glob-tool",
        "bash-cat",
        "bash-grep",
        "bash-sed",
        "bash-awk",
        "bash-head",
        "bash-tail",
        "bash-python",
        "bash-perl",
        "claude-md-import",
        "claude-md-nested",
        # Regression routes for Claude Code 2.1.287 / 2.1.289 fixes.
        "read-symlink",
        "bash-env-prefix",
        "bash-bare-assign",
        "bash-redirect-suffix",
        "bash-compound-nested",
    }
    assert expected <= ids


def test_every_route_has_prompt_and_description():
    for r in ROUTES:
        assert r.live_prompt.strip(), r.id
        assert r.description.strip(), r.id
        assert r.precondition.strip(), r.id
        assert r.leak_kind in {"content", "metadata"}, r.id


def test_argument_substitution():
    r = get_route("bash-cat")
    assert r.argument_for("./.env") == "cat -- ./.env"
    r = get_route("bash-python")
    assert "./.env" in r.argument_for("./.env")


def test_import_routes_ignore_target_path():
    # The @import route always reads CLAUDE.md, not the target itself.
    r = get_route("claude-md-import")
    assert r.argument_for("./secrets/api.key") == "./CLAUDE.md"


def test_shell_targets_are_quoted_and_interpreters_use_argv():
    target = "./secret; echo PWNED"
    assert "'./secret; echo PWNED'" in get_route("bash-grep").argument_for(target)
    python = get_route("bash-python").argument_for(target)
    assert "open('./secret" not in python
    assert "sys.argv[1]" in python and "'./secret; echo PWNED'" in python


def test_nested_claude_md_follows_target_directory():
    assert get_route("claude-md-nested").argument_for("./docs/key") == "./docs/CLAUDE.md"


def test_get_route_unknown_raises():
    with pytest.raises(KeyError):
        get_route("no-such-route")


def test_glob_is_metadata_only():
    assert get_route("glob-tool").leak_kind == "metadata"
    assert all(
        r.leak_kind == "content" for r in ROUTES if r.id != "glob-tool"
    )


def test_regression_route_arguments():
    # The regression routes mutate the command line (or path) so that an
    # exact-string deny rule no longer matches.
    assert get_route("read-symlink").argument_for("./.env") == "./.env.via-link"
    assert get_route("bash-env-prefix").argument_for("./.env") == 'TZ="$HOME" cat ./.env'
    assert get_route("bash-bare-assign").argument_for("./.env") == "FOO=1 cat ./.env"
    assert get_route("bash-redirect-suffix").argument_for("./.env") == "cat ./.env > /tmp/exfil"
    assert get_route("bash-compound-nested").argument_for("./.env") == "echo ok && cat ./.env"
    # None of them is the plain command the naive rule was written for.
    for rid in ("bash-env-prefix", "bash-bare-assign", "bash-redirect-suffix",
                "bash-compound-nested"):
        arg = get_route(rid).argument_for("./.env")
        assert arg != get_route("bash-cat").argument_for("./.env"), rid
