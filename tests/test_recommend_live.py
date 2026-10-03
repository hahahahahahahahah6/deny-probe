"""Tests for hardening suggestions and the live-mode verdict helper."""

from deny_probe.analyzer import LEAK, audit
import subprocess

import pytest

from deny_probe.live import LiveError, check_output, run_live
from deny_probe.recommend import GENERAL_NOTE, suggest, suggestions_for_leaks
from deny_probe.routes import get_route
from deny_probe.rules import parse_rules


def test_suggest_grep_tool():
    assert suggest(get_route("grep-tool"), "./.env") == ["Grep(./.env)"]


def test_suggest_bash_python_covers_interpreters():
    got = suggest(get_route("bash-python"), "./.env")
    assert "Bash(python *)" in got
    assert "Bash(python3 *)" in got


def test_suggest_import_route():
    got = suggest(get_route("claude-md-import"), "./.env")
    assert "Read(./CLAUDE.md)" in got


def test_suggest_nested_claude_md():
    got = suggest(get_route("claude-md-nested"), "./.env")
    assert "Read(./**/CLAUDE.md)" in got


def test_suggest_uses_target_pattern():
    got = suggest(get_route("grep-tool"), "./secrets/**")
    assert got == ["Grep(./secrets/**)"]


def test_suggestions_for_leaks_only_lists_leaks():
    findings = audit(parse_rules(["Read(./.env)"]), ["./.env"])
    recs = suggestions_for_leaks(findings, "./.env")
    route_ids = {r["route"] for r in recs}
    assert "read-direct" not in route_ids  # it holds
    assert "bash-cat" in route_ids
    for r in recs:
        assert r["add_rules"], r["route"]


def test_general_note_mentions_per_tool_enforcement():
    assert "per tool" in GENERAL_NOTE


# --- live.check_output: pure function, safe to unit test ---


def test_check_output_finds_canary_in_answer():
    assert check_output("here is SECRET=abc123 done", "abc123") is True


def test_check_output_finds_canary_in_transcript_only():
    assert check_output("refused to help", "abc123", transcript_text='{"x":"abc123"}') is True


def test_check_output_absent():
    assert check_output("refused to help", "abc123") is False
    assert check_output("refused", "abc123", transcript_text="nothing here") is False


def test_run_live_uses_real_target_and_restores_it(tmp_path, monkeypatch):
    target = tmp_path / "nested" / "secret file"
    target.parent.mkdir()
    target.write_text("original")
    seen = {}
    monkeypatch.setattr("deny_probe.live.shutil.which", lambda _: "/bin/claude")

    def fake_run(argv, **kwargs):
        seen["prompt"] = argv[-1]
        seen["cwd"] = kwargs.get("cwd")
        assert target.read_text() == "SECRET=abc\n"
        return subprocess.CompletedProcess(argv, 0, stdout="abc", stderr="")

    monkeypatch.setattr("deny_probe.live.subprocess.run", fake_run)
    report = run_live(str(target), get_route("bash-cat"), "abc", runs=1)
    assert str(target) in seen["prompt"]
    assert seen["cwd"] is None
    assert target.read_text() == "original"
    assert report["verdict"] == "LEAK"


def test_run_live_nonzero_is_execution_failure(tmp_path, monkeypatch):
    monkeypatch.setattr("deny_probe.live.shutil.which", lambda _: "/bin/claude")
    monkeypatch.setattr(
        "deny_probe.live.subprocess.run",
        lambda *a, **k: subprocess.CompletedProcess(a, 7, stdout="", stderr="bad auth"),
    )
    with pytest.raises(LiveError, match="status 7: bad auth"):
        run_live(str(tmp_path / "secret"), get_route("bash-cat"), "abc", runs=1)


@pytest.mark.parametrize("error", [FileNotFoundError("gone"), OSError("broken")])
def test_run_live_wraps_spawn_os_errors(tmp_path, monkeypatch, error):
    monkeypatch.setattr("deny_probe.live.shutil.which", lambda _: "/bin/claude")
    monkeypatch.setattr("deny_probe.live.subprocess.run", lambda *a, **k: (_ for _ in ()).throw(error))
    with pytest.raises(LiveError, match="could not execute"):
        run_live(str(tmp_path / "secret"), get_route("bash-cat"), "abc", runs=1)


def test_transcript_only_checks_new_text(tmp_path, monkeypatch):
    transcript = tmp_path / "transcript"
    transcript.write_text("old abc")
    monkeypatch.setattr("deny_probe.live.shutil.which", lambda _: "/bin/claude")
    monkeypatch.setattr(
        "deny_probe.live.subprocess.run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="refused", stderr=""),
    )
    report = run_live(str(tmp_path / "secret"), get_route("bash-cat"), "abc", 1, str(transcript))
    assert report["verdict"] == "HOLD"


def test_live_claude_routes_create_preconditions(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = "./docs/secret"
    monkeypatch.setattr("deny_probe.live.shutil.which", lambda _: "/bin/claude")
    seen = []

    def fake_run(*args, **kwargs):
        seen.append((tmp_path / "CLAUDE.md").exists() or (tmp_path / "docs/CLAUDE.md").exists())
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr("deny_probe.live.subprocess.run", fake_run)
    run_live(target, get_route("claude-md-import"), "abc", 1)
    run_live(target, get_route("claude-md-nested"), "abc", 1)
    assert seen == [True, True]
