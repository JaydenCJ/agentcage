# Claude Code integration

agentcage plugs into Claude Code's `PreToolUse` hook so every Bash command
the agent wants to run is checked against your repository's
`.agentcage.toml` before it executes. Blocked commands never run, the agent
sees the reason, and every decision lands in the audit log.

## How it works

Claude Code sends each pending tool call to the hook as JSON on stdin.
`agentcage check --hook` parses that payload itself (no `jq` needed),
evaluates `tool_input.command` against the policy, and answers with
`hookSpecificOutput` JSON:

- **denied** command → `"permissionDecision": "deny"` with the matched rule
  in the reason, so the agent can adjust instead of retrying blindly;
- **allowed** command → no output by default: Claude Code's normal
  permission flow continues to apply;
- **no policy found / policy invalid** → `"permissionDecision": "ask"`, so a
  broken setup surfaces to you instead of silently approving anything.

The hook process always exits `0`; the decision is carried in the JSON.

## Setup

1. Install agentcage and create a policy in your project root:

   ```bash
   git clone https://github.com/JaydenCJ/agentcage.git && cargo install --path agentcage --locked
   cd your-project && agentcage init
   ```

2. Add the hook to your project's `.claude/settings.json` (or your user
   `~/.claude/settings.json`):

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

3. Ask Claude Code to run something the policy denies (for example
   `curl https://example.com`). The command is blocked and the reason is
   shown to the agent; check `agentcage log` afterwards to see the record.

A copy-paste shell wrapper is provided in
[`examples/hook.sh`](../examples/hook.sh) if you prefer pointing the hook
at a script in your repository.

## Policy-driven auto-approval (optional)

By default agentcage only ever blocks; it never approves. If you want the
policy to fully drive approvals — for example to run an agent unattended
with `--dangerously-skip-permissions` disabled but no prompts for
allowlisted commands — use `--approve`:

```json
{
  "type": "command",
  "command": "agentcage check --hook --approve"
}
```

With `--approve`, commands matching an allow rule return
`"permissionDecision": "allow"` and skip the interactive prompt. Denied
commands are still denied. Treat this as a power-user mode: your allow
rules become the only gate, so keep them narrow.

## Defense in depth: hook + run

The hook stops policy violations before they start, but it can only see
the command string. For kernel-level guarantees, combine it with the `run`
prefix so the executed process is also confined by Landlock filesystem and
network rules:

```bash
agentcage run -- npm test
```

A useful pattern is a wrapper script that agents are told to use for all
commands, while the hook acts as the safety net for anything that bypasses
the wrapper.

## Troubleshooting

- **Every command asks for permission** — the hook returns `ask` when no
  `.agentcage.toml` is found walking up from the working directory, or when
  the file has a syntax error. Run `agentcage check ls` in the same
  directory to see the exact error.
- **A command you expected to pass is denied** — run
  `agentcage check -- <the command>` to see which rule matched. Remember
  that chained commands (`&&`, `;`, `|`) require every segment to pass, and
  command substitution (`$(...)`) is always denied because it cannot be
  checked statically.
- **Nothing appears in `agentcage log`** — decisions are recorded next to
  the policy file in `.agentcage/audit.jsonl`. If you use `--policy`, the
  log lives next to that file instead.
