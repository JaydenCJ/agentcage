# Contributing to agentcage

Thanks for your interest in making agent sandboxing better. Contributions
of all kinds are welcome: bug reports, policy recipes, docs, code.

## Development setup

Requirements: stable Rust (tested with 1.94), Linux for kernel enforcement
(all pure logic and most tests run on any OS).

```bash
git clone https://github.com/JaydenCJ/agentcage.git
cd agentcage
cd agentcage
cargo build
cargo test
bash scripts/smoke.sh
```

`scripts/smoke.sh` exercises the CLI end to end in a throwaway directory
and must print `SMOKE OK`. It does not require Landlock support: on
kernels (or containers) without it, `run` falls back to audit mode and
the script reports which mode was active.

## Before you open a PR

- `cargo fmt` — formatting is enforced in CI.
- `cargo clippy --all-targets -- -D warnings` — no new warnings.
- `cargo test` — all tests green; add tests for behavior you add or fix.
  Policy parsing, pattern matching and the decision engine are pure logic
  modules: changes there need unit tests, not manual verification notes.
- Keep dependencies minimal. New runtime dependencies need a strong
  reason; this project ships as a single small binary.

## What makes a good change

- **Security behavior must fail closed.** When in doubt, deny and explain.
  Anything that widens what a policy permits needs an explicit test
  showing the boundary.
- **Error messages are UX.** Users see them mid-flow from an agent; one
  clear sentence beats a stack trace.
- **English everywhere in code** — comments, test names, log messages.
  READMEs are maintained in English, Chinese and Japanese; if you change
  user-facing docs, update all three or note in the PR that you need help
  with translations.

## Reporting security issues

If you find a way to bypass enforcement (not just command-string matching
— see the threat model in [docs/policy.md](docs/policy.md)), please do not
open a public issue. Use GitHub's private vulnerability reporting on this
repository instead.

## Questions

Open a [discussion](https://github.com/JaydenCJ/agentcage/discussions) —
policy design questions and "how do I sandbox X" threads are welcome.
