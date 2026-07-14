# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-08

### Added

- `agentcage init`: writes a commented, deny-by-default `.agentcage.toml`
  policy to the current directory.
- `agentcage check`: evaluates a command against the policy without
  executing it; `--json` for machine-readable output, exit code 2 on deny.
- `agentcage check --hook`: native Claude Code PreToolUse integration —
  parses the hook payload from stdin and answers with `hookSpecificOutput`
  JSON (`deny` with the matched rule, `ask` on missing/broken policy,
  optional `--approve` mode for policy-driven auto-approval).
- `agentcage run`: executes an allowed command under a Landlock sandbox
  (filesystem read/write allowlists plus TCP bind/connect rules on ABI 4+),
  with runtime kernel probing, audit-mode fallback, `--dry-run` and
  `--strict`.
- `agentcage log`: JSONL audit log of every decision with rules, reasons
  and exit codes; `--replay` re-evaluates recorded commands against the
  current policy and reports decisions that would change.
- Decision engine: splits chained commands on unquoted shell operators,
  respects quoting and escapes, strips leading environment assignments,
  and denies command/process substitution outright.
- Policy loader: `.gitignore`-style upward discovery, strict schema
  validation (unknown keys rejected), versioned format.
- Documentation: policy reference (`docs/policy.md`), Claude Code setup
  guide (`docs/claude-code.md`), hook wrapper example (`examples/hook.sh`).

[0.1.0]: https://github.com/JaydenCJ/agentcage
