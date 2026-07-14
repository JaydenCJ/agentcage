# Policy reference (`.agentcage.toml`)

The policy file lives at the root of your project and is discovered by
walking up parent directories from the working directory, like
`.gitignore`. `agentcage init` writes a commented default you can edit.
All rules are evaluated locally; agentcage performs no network calls.

```toml
version = 1

[commands]
default = "deny"                # decision when no rule matches
allow = ["cargo test*", "ls*"]  # glob patterns, '*' matches anything
deny  = ["curl *", "sudo *"]    # deny rules always win

[filesystem]
read  = [".", "/usr", "/lib", "/bin", "/etc"]  # readable + executable
write = [".", "/tmp"]                          # writable

[network]
allow = false          # block all TCP bind/connect (Landlock ABI >= 4)
tcp_connect = [443]    # port exceptions while blocked
tcp_bind = []
```

## `version`

Schema version. This build understands `version = 1` and rejects anything
else, so future format changes fail loudly instead of being misread.

## `[commands]`

Command rules are matched against **segments**, not the raw string. Before
matching, agentcage:

1. splits the command on unquoted `&&`, `||`, `;`, `|`, `&`, `(`, `)` and
   newlines — quoting with `'...'`/`"..."` and backslash escapes is
   respected;
2. denies outright any command containing command or process substitution
   (`$(...)`, backticks, `<(...)`, `>(...)`), because the effective command
   cannot be known without executing it;
3. collapses whitespace runs and strips leading environment assignments
   (`CI=1 cargo test` matches rules for `cargo test`);
4. requires **every** segment to pass: `ls && curl evil.sh` is denied even
   though `ls` is allowed.

Patterns are globs where `*` matches any characters including spaces;
matching is case-sensitive and anchored at both ends. Precedence is:

1. any `deny` rule matching any segment → **deny**;
2. otherwise, with `default = "deny"`: every segment must match an `allow`
   rule → **allow**, else **deny**;
3. with `default = "allow"`: everything not denied is allowed.

## `[filesystem]`

Path allowlists enforced with Landlock when `agentcage run` executes a
command. `read` paths are readable and executable (so binaries under
`/usr` can run); `write` paths additionally allow creating, modifying and
deleting files. Relative paths resolve against the directory containing
the policy file. Paths that do not exist on the current machine are
skipped and reported, so one policy can serve heterogeneous dev machines.
The runtime directory `.agentcage/` is always writable so the audit log
keeps working under enforcement.

Landlock rules apply to the executed process **and every process it
spawns**; a child cannot escape by re-execing.

## `[network]`

With `allow = false`, all TCP `bind`/`connect` calls are blocked except
the listed port exceptions. This requires Landlock ABI 4 (Linux 6.7); on
older kernels with Landlock, filesystem rules still apply and agentcage
reports `sandbox partially active`. UDP is not covered by Landlock as of
ABI 6 — see "Threat model" below.

## Enforcement modes

`agentcage run` probes the kernel at runtime and reports one of:

| stderr message | meaning |
|---|---|
| `sandbox active: landlock (kernel ABI N, filesystem + network)` | all requested rules enforced |
| `sandbox partially active: landlock (kernel ABI N; ...)` | filesystem enforced, network rules unsupported on this kernel |
| `sandbox unavailable (...); running in audit mode` | no kernel enforcement; command/policy checks and audit logging still apply |

`run --strict` refuses to execute (exit 1) instead of falling back to
audit mode. Use it in CI or anywhere kernel enforcement is mandatory.

## Audit log

Every decision is appended to `.agentcage/audit.jsonl` next to the policy
file — one JSON object per line:

```json
{"ts":"2026-07-08T09:15:02Z","mode":"run","decision":"deny","cmd":"curl https://evil.example.com","rule":"curl *","reason":"segment \"curl https://evil.example.com\" matches deny rule \"curl *\""}
```

Fields `ts`, `mode`, `decision`, `cmd`, `reason` are always present;
`rule`, `sandbox`, `enforced`, `exit_code` appear when applicable. Within
schema version 1, existing fields will not be renamed or removed; new
optional fields may be added. `agentcage log` prints a human summary,
`agentcage log --json` the raw lines, and `agentcage log --replay`
re-evaluates every recorded command against the current policy — the
fastest way to test a policy edit against everything your agent actually
tried.

The `.agentcage/` directory is created with its own `.gitignore` so logs
never end up in version control.

## Threat model and limits

agentcage is a guardrail against an agent doing damage by accident or by
prompt injection — not a jail for adversarial native code:

- Command rules are string checks: a novel binary name, an alias or a
  script wrapper can evade them. Filesystem/network Landlock rules are the
  backstop and hold regardless of the command string.
- In audit mode (no kernel support) only command rules and logging apply.
  agentcage tells you loudly when that is the case; use `--strict` to make
  it fatal.
- Landlock does not cover UDP, unix sockets or already-open descriptors.
- Shell redirection (`>`) is data flow, not a segment: writes are stopped
  by the filesystem rules, not by command matching.
- agentcage never elevates privileges; it only ever drops them via
  `no_new_privs` + Landlock.
