#!/usr/bin/env bash
# Claude Code PreToolUse hook wrapper for agentcage.
#
# Claude Code pipes the pending tool call as JSON into this script;
# `agentcage check --hook` parses the payload itself (no jq required),
# evaluates tool_input.command against .agentcage.toml, and prints a
# hookSpecificOutput JSON decision:
#   - denied command      -> permissionDecision "deny" with the rule
#   - allowed command     -> no output (normal permission flow applies)
#   - missing/bad policy  -> permissionDecision "ask"
#
# Wire it up in .claude/settings.json:
#   { "hooks": { "PreToolUse": [ { "matcher": "Bash",
#     "hooks": [ { "type": "command", "command": "bash examples/hook.sh" } ] } ] } }
#
# See docs/claude-code.md for the full setup, including the optional
# --approve mode where allow rules skip the interactive prompt.

set -euo pipefail

exec agentcage check --hook
