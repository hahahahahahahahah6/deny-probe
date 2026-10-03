# deny-probe

A penetration tester for Claude Code permission `deny` rules. You write
`Read(./.env)` thinking your secrets are safe — deny-probe shows you the
11 other roads into the same file.

## The problem

Claude Code enforces `permissions.deny` rules **per tool**. A rule like
`Read(./.env)` blocks the Read tool, but says nothing about:

- the **Grep** tool (`Grep` with pattern `.` dumps the whole file),
- **Bash** (`cat`, `grep -r`, `sed`, `awk`, `python3 -c "print(open(...).read())"` …),
- **CLAUDE.md `@import` chains** (`@./.env` in CLAUDE.md pulls the denied
  file into context through a `Read(./CLAUDE.md)` call the rule doesn't cover),
- nested `CLAUDE.md` files that are auto-loaded.

deny-probe ships a built-in library of 13 such bypass routes, predicts
statically which of your deny rules stop which route, and tells you exactly
which rules to add.

## Install

```bash
pip install deny-probe
```

Zero dependencies — stdlib only. Requires Python 3.9+.

## Usage

### Static audit (the main event)

```bash
# Audit the deny rules from your Claude Code settings.json
deny-probe audit --settings ~/.claude/settings.json

# ...or pass rules directly
deny-probe audit --deny 'Read(./.env)' --deny 'Read(./secrets/**)'

# Protect a different file, machine-readable output
deny-probe audit --settings settings.json --target ./config/keys.json --format json
```

Example output for a `Read(./.env)`-only config:

```
Target: ./.env
Deny rules (1):
  Read(./.env)

ROUTE             TOOL    VERDICT  BLOCKED BY
----------------------------------------------------------------------
read-direct       Read    HOLD     Read(./.env)
grep-tool         Grep    LEAK     -
glob-tool         Glob    META     -
bash-cat          Bash    LEAK     -
bash-grep         Bash    LEAK     -
...
bash-python       Bash    LEAK     -
claude-md-import  Read    LEAK     -
claude-md-nested  Read    LEAK     -

Summary for ./.env: 11/13 routes leak content, 1 hold, 1 metadata-only.

Hardening suggestions:
  [grep-tool] Grep tool search
    + Grep(./.env)
  [bash-cat] Bash: cat
    + Bash(cat *)
  [bash-python] Bash: python one-liner
    + Bash(python *)
    + Bash(python3 *)
  ...
```

Verdicts: **HOLD** (a deny rule blocks the route), **LEAK** (file content
reaches the model), **META** (only metadata leaks, e.g. Glob reveals the
file exists but not its content).

Exit code is `1` when any route leaks content, `0` otherwise — so you can
gate on it in CI:

```yaml
- run: deny-probe audit --settings .claude/settings.json --target ./.env
```

### Live verification (manual only)

`--live` replays a route against real `claude -p` sessions using a canary
marker, and checks whether the marker appears in the answer (and optionally
in a transcript file):

```bash
deny-probe live --target ./.env --route bash-cat --runs 3
deny-probe live --target ./.env --all --runs 5 --format json
```

Live mode needs the `claude` CLI on PATH, is nondeterministic, and never
runs in CI.

### Route library

```bash
deny-probe routes
```

Lists the 13 built-in bypass routes with descriptions and preconditions. Head
and tail are separate routes so both command variants are evaluated.

## How the static prediction works

For each (target file, route): the route is **HOLD** iff at least one deny
rule names the route's tool **and** its glob pattern matches the route's
argument. `*` stays within one path segment for file tools, `**` crosses
segments, and Bash command patterns match against the full command line.
That's the whole model — deliberately simple, so the predictions are
auditable.

## Honest limitations

- **The route library covers known techniques.** It is not exhaustive, and
  new Claude Code versions can introduce new tools, new flags, or new
  auto-loading behaviors that open routes this library doesn't know about.
  Re-run after upgrades; treat a clean report as "no *known* bypass", not
  "provably safe".
- **Pattern matching is an approximation.** Claude Code's exact permission
  matching (especially edge cases around absolute paths, symlinks, and
  `~`) is not fully documented; deny-probe implements the documented
  `Tool(pattern)` glob behavior as faithfully as possible, but a predicted
  HOLD is only as accurate as that model.
- **`--live` results are nondeterministic.** The model may refuse, take a
  different route than the one prompted, or leak on run 3 after holding on
  runs 1–2. Live mode is a spot check, not a proof. Run it several times
  before drawing conclusions.
- **Command-prefix blocklists are fragile.** Suggestions like
  `Bash(python *)` block the exact prefix; renamed binaries, new
  interpreters, and creative flags can slip past. For real secrets, prefer
  keeping them out of the agent's working directory (environment-backed
  secret stores, `ask`-gated hooks) over longer deny lists.
- **Preconditions matter.** The CLAUDE.md routes assume the `@import` (or
  the nested file) actually exists. deny-probe reports what *would* happen
  given your rules, not what your repo contains.

## Development

```bash
python -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest tests/ -q
```

55 tests, all static-fixture assertions. `--live` is excluded from CI by
design.

## License

MIT — see [LICENSE](LICENSE).
