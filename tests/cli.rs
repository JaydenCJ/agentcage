//! End-to-end tests against the compiled binary.
//!
//! Each test runs the real `agentcage` executable in its own temp
//! directory, so tests are independent and never touch the repository.
//! Kernel Landlock support is NOT assumed: `run` falls back to audit
//! mode in containers, and these tests assert behavior that holds in
//! both modes.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_agentcage");

/// Creates a unique empty working directory for one test.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("agentcage-cli-test-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn cage(dir: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to spawn agentcage")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

/// A permissive policy used by tests that need to execute commands.
const ALLOW_ECHO_POLICY: &str = r#"
version = 1
[commands]
default = "deny"
allow = ["echo *", "sh -c *", "ls*"]
deny = ["curl *"]
[filesystem]
read = ["."]
write = ["."]
[network]
allow = true
"#;

#[test]
fn version_flag_prints_version() {
    let dir = temp_dir("version");
    let out = cage(&dir, &["--version"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        stdout(&out).trim(),
        format!("agentcage {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn help_flag_prints_usage() {
    let dir = temp_dir("help");
    let out = cage(&dir, &["--help"]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert!(text.contains("USAGE"));
    assert!(text.contains("init"));
    assert!(text.contains("check"));
    assert!(text.contains("run"));
    assert!(text.contains("log"));
}

#[test]
fn no_args_shows_help_and_fails() {
    let dir = temp_dir("noargs");
    let out = cage(&dir, &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("USAGE"));
}

#[test]
fn unknown_command_errors_on_stderr() {
    let dir = temp_dir("unknown");
    let out = cage(&dir, &["bogus"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("unknown command"));
}

#[test]
fn init_creates_policy_and_refuses_overwrite() {
    let dir = temp_dir("init");
    let out = cage(&dir, &["init"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("created .agentcage.toml"));
    assert!(dir.join(".agentcage.toml").is_file());

    let again = cage(&dir, &["init"]);
    assert_eq!(again.status.code(), Some(1));
    assert!(stderr(&again).contains("already exists"));

    let forced = cage(&dir, &["init", "--force"]);
    assert_eq!(forced.status.code(), Some(0));
}

#[test]
fn check_allowed_command_exits_zero() {
    let dir = temp_dir("check-allow");
    cage(&dir, &["init"]);
    let out = cage(&dir, &["check", "--", "cargo", "test"]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert!(text.starts_with("allow: cargo test"));
    assert!(text.contains("cargo test*"));
}

#[test]
fn check_denied_command_exits_two() {
    let dir = temp_dir("check-deny");
    cage(&dir, &["init"]);
    let out = cage(&dir, &["check", "curl https://example.com"]);
    assert_eq!(out.status.code(), Some(2));
    let text = stdout(&out);
    assert!(text.starts_with("deny: curl https://example.com"));
    assert!(text.contains("curl *"));
}

#[test]
fn check_chained_command_is_denied_if_any_segment_fails() {
    let dir = temp_dir("check-chain");
    cage(&dir, &["init"]);
    let out = cage(&dir, &["check", "ls && curl https://example.com"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn check_without_policy_errors() {
    let dir = temp_dir("check-nopolicy");
    let out = cage(&dir, &["check", "ls"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains(".agentcage.toml"));
    assert!(stderr(&out).contains("agentcage init"));
}

#[test]
fn check_json_output_is_parseable() {
    let dir = temp_dir("check-json");
    cage(&dir, &["init"]);
    let out = cage(
        &dir,
        &["check", "--json", "--", "curl", "https://example.com"],
    );
    assert_eq!(out.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(value["decision"], "deny");
    assert_eq!(value["rule"], "curl *");
    assert_eq!(value["command"], "curl https://example.com");
}

#[test]
fn explicit_policy_flag_is_honored() {
    let dir = temp_dir("explicit-policy");
    let policy_path = dir.join("custom.toml");
    fs::write(&policy_path, ALLOW_ECHO_POLICY).unwrap();
    let out = cage(
        &dir,
        &[
            "--policy",
            policy_path.to_str().unwrap(),
            "check",
            "echo hi",
        ],
    );
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn run_denied_command_is_blocked_and_not_executed() {
    let dir = temp_dir("run-deny");
    fs::write(dir.join(".agentcage.toml"), ALLOW_ECHO_POLICY).unwrap();
    let marker = dir.join("marker.txt");
    let cmd = format!("curl -o {} https://example.com", marker.display());
    let out = cage(&dir, &["run", "--", &cmd]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("blocked"));
    assert!(!marker.exists(), "denied command must not run");
}

#[test]
fn run_allowed_command_executes_and_propagates_output() {
    let dir = temp_dir("run-allow");
    fs::write(dir.join(".agentcage.toml"), ALLOW_ECHO_POLICY).unwrap();
    let out = cage(&dir, &["run", "--", "echo", "hello-from-cage"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("hello-from-cage"));
    // The sandbox mode line goes to stderr, never stdout.
    assert!(stderr(&out).contains("agentcage: sandbox"));
}

#[test]
fn run_propagates_child_exit_code() {
    let dir = temp_dir("run-exit");
    fs::write(dir.join(".agentcage.toml"), ALLOW_ECHO_POLICY).unwrap();
    let out = cage(&dir, &["run", "--", "sh", "-c", "exit 7"]);
    assert_eq!(out.status.code(), Some(7));
}

#[test]
fn run_dry_run_executes_nothing() {
    let dir = temp_dir("run-dry");
    fs::write(dir.join(".agentcage.toml"), ALLOW_ECHO_POLICY).unwrap();
    let marker = dir.join("dry.txt");
    let cmd = format!("echo hi > {}", marker.display());
    let out = cage(&dir, &["run", "--dry-run", "--", &cmd]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert!(text.contains("dry-run: allow"));
    assert!(text.contains("read allowlist:"));
    assert!(text.contains("write allowlist:"));
    assert!(!marker.exists(), "dry-run must not execute the command");
}

#[test]
fn run_missing_binary_reports_readable_error() {
    let dir = temp_dir("run-missing");
    fs::write(
        dir.join(".agentcage.toml"),
        "version = 1\n[commands]\ndefault = \"allow\"\n",
    )
    .unwrap();
    let out = cage(&dir, &["run", "--", "agentcage-no-such-binary", "arg"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("cannot execute"));
}

#[test]
fn invalid_policy_reports_readable_error() {
    let dir = temp_dir("bad-policy");
    fs::write(
        dir.join(".agentcage.toml"),
        "version = 1\n[commands]\nalow = []\n",
    )
    .unwrap();
    let out = cage(&dir, &["check", "ls"]);
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("invalid policy"));
    assert!(!err.contains("panicked"), "must not panic on bad input");
}

#[test]
fn log_records_decisions_and_lists_them() {
    let dir = temp_dir("log");
    cage(&dir, &["init"]);
    cage(&dir, &["check", "curl https://example.com"]);
    cage(&dir, &["check", "--", "cargo", "test"]);
    let out = cage(&dir, &["log"]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert!(text.contains("deny"));
    assert!(text.contains("curl https://example.com"));
    assert!(text.contains("allow"));
    assert!(text.contains("cargo test"));

    let json_out = cage(&dir, &["log", "--json", "-n", "1"]);
    let line = stdout(&json_out);
    let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(value["cmd"], "cargo test");
}

#[test]
fn log_replay_reports_changed_decisions() {
    let dir = temp_dir("replay");
    // Start with a policy that denies curl, and record a deny.
    fs::write(dir.join(".agentcage.toml"), ALLOW_ECHO_POLICY).unwrap();
    cage(&dir, &["check", "curl https://example.com"]);
    // Loosen the policy: curl is no longer denied.
    fs::write(
        dir.join(".agentcage.toml"),
        "version = 1\n[commands]\ndefault = \"allow\"\n",
    )
    .unwrap();
    let out = cage(&dir, &["log", "--replay"]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert!(text.contains("deny -> allow"));
    assert!(text.contains("1 decision(s) would change"));
}

#[test]
fn log_empty_is_not_an_error() {
    let dir = temp_dir("log-empty");
    cage(&dir, &["init"]);
    let out = cage(&dir, &["log"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("audit log is empty"));
}

#[test]
fn audit_runtime_dir_has_gitignore() {
    let dir = temp_dir("gitignore");
    cage(&dir, &["init"]);
    cage(&dir, &["check", "ls"]);
    let gi = fs::read_to_string(dir.join(".agentcage").join(".gitignore")).unwrap();
    assert_eq!(gi, "*\n");
}

// ---------------------------------------------------------------------------
// Claude Code hook mode
// ---------------------------------------------------------------------------

fn cage_hook(dir: &Path, args: &[&str], stdin_payload: &str) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn agentcage");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_payload.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn hook_payload(command: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string()
}

#[test]
fn hook_denies_blocked_command_with_json() {
    let dir = temp_dir("hook-deny");
    cage(&dir, &["init"]);
    let out = cage_hook(
        &dir,
        &["check", "--hook"],
        &hook_payload("curl https://example.com"),
    );
    assert_eq!(out.status.code(), Some(0), "hook mode always exits 0");
    let value: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = value["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("curl *"));
}

#[test]
fn hook_stays_silent_for_allowed_command_by_default() {
    let dir = temp_dir("hook-allow");
    cage(&dir, &["init"]);
    let out = cage_hook(&dir, &["check", "--hook"], &hook_payload("cargo test"));
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out).trim(), "", "no opinion: defer to normal flow");
}

#[test]
fn hook_approve_emits_allow_decision() {
    let dir = temp_dir("hook-approve");
    cage(&dir, &["init"]);
    let out = cage_hook(
        &dir,
        &["check", "--hook", "--approve"],
        &hook_payload("cargo test"),
    );
    assert_eq!(out.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn hook_without_policy_asks_instead_of_failing() {
    let dir = temp_dir("hook-nopolicy");
    let out = cage_hook(&dir, &["check", "--hook"], &hook_payload("ls"));
    assert_eq!(out.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(value["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn hook_ignores_payload_without_command() {
    let dir = temp_dir("hook-nocmd");
    cage(&dir, &["init"]);
    let payload = r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/hosts"}}"#;
    let out = cage_hook(&dir, &["check", "--hook"], payload);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out).trim(), "");
}

/// Real kernel enforcement: only meaningful on hosts where Landlock is
/// actually available (Linux >= 5.13, syscall not filtered by the container
/// runtime). The test decides at runtime by looking at the sandbox banner
/// the binary prints, so it degrades to a no-op skip in restricted CI
/// containers and asserts hard kernel-level blocking everywhere else.
#[test]
fn run_enforces_filesystem_restrictions_with_kernel_landlock() {
    let dir = temp_dir("landlock-enforce");
    // Only `.` is readable/writable; /etc is outside the sandbox.
    fs::write(
        dir.join(".agentcage.toml"),
        r#"
version = 1
[commands]
default = "deny"
allow = ["cat *"]
deny = []
[filesystem]
read = ["."]
write = ["."]
[network]
allow = true
"#,
    )
    .unwrap();
    fs::write(dir.join("inside.txt"), "inside\n").unwrap();

    let out_inside = cage(&dir, &["run", "--", "cat", "inside.txt"]);
    if !stderr(&out_inside).contains("sandbox active: landlock") {
        // Kernel (or container runtime) does not enforce Landlock here:
        // the audit-mode fallback path is covered by the other tests.
        eprintln!("skipping: Landlock not enforced on this kernel/container");
        return;
    }

    // Sanity: the sandbox must not break reads that the policy allows.
    assert_eq!(out_inside.status.code(), Some(0));
    assert_eq!(stdout(&out_inside), "inside\n");

    // A read outside every allowed root must be blocked by the kernel:
    // the command itself fails with EACCES, agentcage reports its exit.
    let out_outside = cage(&dir, &["run", "--", "cat", "/etc/hostname"]);
    assert!(
        stderr(&out_outside).contains("sandbox active: landlock"),
        "second run should enforce as well: {}",
        stderr(&out_outside)
    );
    assert_ne!(
        out_outside.status.code(),
        Some(0),
        "reading /etc/hostname must fail under Landlock, got stdout: {}",
        stdout(&out_outside)
    );
    assert_eq!(stdout(&out_outside), "", "no file content may leak");

    // The audit log records the enforced run.
    let log = cage(&dir, &["log"]);
    assert!(stdout(&log).contains("landlock"), "log: {}", stdout(&log));
}

/// The degraded path is a first-class behavior, not an accident: when the
/// kernel (or the container runtime, via seccomp) does not provide
/// Landlock, `run` must say so on stderr, still execute the allowed
/// command, record the fallback backend (`sandbox: none`,
/// `enforced: false`) in the audit log, and `run --strict` must refuse to
/// execute anything at all. This branch runs — with real assertions — in
/// exactly the restricted containers where the enforcement test above has
/// to skip; on Landlock-capable hosts it defers to that test instead.
#[test]
fn run_without_landlock_records_audit_fallback_and_strict_refuses() {
    let dir = temp_dir("landlock-fallback");
    fs::write(dir.join(".agentcage.toml"), ALLOW_ECHO_POLICY).unwrap();

    let out = cage(&dir, &["run", "--", "echo", "fallback-proof"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), "fallback-proof\n");

    let err = stderr(&out);
    if err.contains("sandbox active: landlock") {
        // Landlock-capable host: kernel enforcement is asserted by
        // run_enforces_filesystem_restrictions_with_kernel_landlock.
        eprintln!("landlock available: deferring to the enforcement test");
        return;
    }
    eprintln!("landlock unavailable here: asserting the degraded path for real");

    // Degraded path: the banner must state the fallback explicitly.
    assert!(
        err.contains("sandbox unavailable") && err.contains("running in audit mode"),
        "banner must state the fallback: {err}"
    );

    // The audit log must record the run with the fallback backend.
    let log = cage(&dir, &["log", "--json"]);
    assert_eq!(log.status.code(), Some(0));
    let last = stdout(&log)
        .lines()
        .last()
        .expect("audit log must contain the run entry")
        .to_string();
    let entry: serde_json::Value = serde_json::from_str(&last).unwrap();
    assert_eq!(entry["mode"], "run");
    assert_eq!(entry["decision"], "allow");
    assert_eq!(entry["sandbox"], "none");
    assert_eq!(entry["enforced"], false);
    assert_eq!(entry["exit_code"], 0);

    // Without kernel enforcement, --strict must refuse to run anything.
    let strict = cage(&dir, &["run", "--strict", "--", "echo", "must-not-run"]);
    assert_ne!(strict.status.code(), Some(0), "--strict must fail");
    assert!(
        !stdout(&strict).contains("must-not-run"),
        "command must not execute under --strict"
    );
    assert!(
        stderr(&strict).contains("refusing to run"),
        "error must explain the refusal: {}",
        stderr(&strict)
    );
}
