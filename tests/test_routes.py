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
        "bash-python",
        "bash-perl",
        "claude-md-import",
        "claude-md-nested",
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
    assert r.argument_for("./.env") == "cat ./.env"
    r = get_route("bash-python")
    assert "./.env" in r.argument_for("./.env")


def test_import_routes_ignore_target_path():
    # The @import route always reads CLAUDE.md, not the target itself.
    r = get_route("claude-md-import")
    assert r.argument_for("./secrets/api.key") == "./CLAUDE.md"


def test_get_route_unknown_raises():
    with pytest.raises(KeyError):
        get_route("no-such-route")


def test_glob_is_metadata_only():
    assert get_route("glob-tool").leak_kind == "metadata"
    assert all(
        r.leak_kind == "content" for r in ROUTES if r.id != "glob-tool"
    )
