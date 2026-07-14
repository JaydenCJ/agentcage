//! Command-line interface: argument parsing, subcommand dispatch and all
//! user-facing output.
//!
//! Exit code contract (also documented in `--help` and the README):
//! `0` success / command allowed; `2` command denied by policy;
//! `1` usage, IO or policy errors. `run` propagates the exit code of the
//! executed command when it is allowed to run.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::audit::{self, AuditEntry};
use crate::engine::{self, Verdict};
use crate::policy::{self, LoadedPolicy};
use crate::sandbox::{self, EnforcementLevel, Support};
use crate::timefmt;

const EXIT_OK: i32 = 0;
const EXIT_ERROR: i32 = 1;
const EXIT_DENIED: i32 = 2;

const HELP: &str = "\
agentcage — sandbox every command your AI coding agent runs

USAGE:
    agentcage [--policy <path>] <command> [options] [-- <cmd>...]

COMMANDS:
    init     Write a default .agentcage.toml policy to the current directory
    check    Evaluate a command against the policy without executing it
    run      Execute a command under the policy (Landlock sandbox when available)
    log      Show or replay the JSONL audit log

OPTIONS:
    --policy <path>    Use this policy file instead of searching parent directories
    -h, --help         Print help
    -V, --version      Print version

EXIT CODES:
    0    success / command allowed
    2    command denied by policy
    1    error (bad usage, missing or invalid policy)
    n    `run` propagates the executed command's exit code

Run `agentcage <command> --help` for command-specific options.
";

const HELP_INIT: &str = "\
agentcage init — write a default .agentcage.toml policy to the current directory

USAGE:
    agentcage init [--force]

OPTIONS:
    --force        Overwrite an existing policy file
    -h, --help     Print help
";

const HELP_CHECK: &str = "\
agentcage check — evaluate a command against the policy without executing it

USAGE:
    agentcage check [options] [--] <cmd>...
    agentcage check --hook [--approve] < hook-input.json

OPTIONS:
    --json         Print the decision as JSON
    --hook         Read a Claude Code PreToolUse JSON payload from stdin and
                   answer with hookSpecificOutput JSON (see docs/claude-code.md)
    --approve      With --hook: emit an explicit \"allow\" decision for allowed
                   commands instead of deferring to the normal permission flow
    --no-log       Do not append this decision to the audit log
    -h, --help     Print help

EXIT CODES:
    0 allowed (always 0 in --hook mode; the decision is in the JSON output)
    2 denied
    1 error
";

const HELP_RUN: &str = "\
agentcage run — execute a command under the policy

USAGE:
    agentcage run [options] [--] <cmd>...

The command is checked against .agentcage.toml first; if allowed, agentcage
applies the policy's filesystem/network allowlists with Landlock and then
executes it. A single argument is run through `/bin/sh -c`; multiple
arguments are executed directly without a shell.

OPTIONS:
    --dry-run      Print the decision and the would-be sandbox, execute nothing
    --strict       Fail (exit 1) instead of falling back to audit mode when
                   kernel enforcement is unavailable
    --no-log       Do not append this run to the audit log
    -h, --help     Print help

EXIT CODES:
    2 denied by policy; 1 error; otherwise the executed command's exit code
";

const HELP_LOG: &str = "\
agentcage log — show or replay the JSONL audit log

USAGE:
    agentcage log [options]

OPTIONS:
    -n <count>     Show the last <count> entries (default 20)
    --json         Print raw JSONL entries instead of the human summary
    --replay       Re-evaluate every logged command against the current
                   policy and report decisions that would change
    -h, --help     Print help
";

/// Entry point used by `main`; returns the process exit code.
pub fn main_entry(args: Vec<String>) -> i32 {
    match dispatch(args) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("agentcage: error: {msg}");
            EXIT_ERROR
        }
    }
}

fn dispatch(args: Vec<String>) -> Result<i32, String> {
    let mut policy_override: Option<PathBuf> = None;
    let mut iter = args.into_iter();
    let mut subcommand: Option<String> = None;
    let mut rest: Vec<String> = Vec::new();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{HELP}");
                return Ok(EXIT_OK);
            }
            "-V" | "--version" => {
                println!("agentcage {}", env!("CARGO_PKG_VERSION"));
                return Ok(EXIT_OK);
            }
            "--policy" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--policy requires a path argument".to_string())?;
                policy_override = Some(PathBuf::from(value));
            }
            _ => {
                subcommand = Some(arg);
                rest.extend(iter);
                break;
            }
        }
    }

    let Some(sub) = subcommand else {
        print!("{HELP}");
        return Ok(EXIT_ERROR);
    };

    match sub.as_str() {
        "init" => cmd_init(rest),
        "check" => cmd_check(policy_override, rest),
        "run" => cmd_run(policy_override, rest),
        "log" => cmd_log(policy_override, rest),
        other => Err(format!(
            "unknown command `{other}` (expected init, check, run or log)"
        )),
    }
}

/// Loads the policy honoring `--policy`, otherwise searching upward from
/// the current directory.
fn load_policy(policy_override: &Option<PathBuf>) -> Result<LoadedPolicy, String> {
    let loaded = match policy_override {
        Some(path) => policy::load_explicit(path),
        None => {
            let cwd = std::env::current_dir()
                .map_err(|e| format!("cannot determine current directory: {e}"))?;
            policy::find_and_load(&cwd)
        }
    };
    loaded.map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

fn cmd_init(args: Vec<String>) -> Result<i32, String> {
    let mut force = false;
    for arg in &args {
        match arg.as_str() {
            "--force" => force = true,
            "-h" | "--help" => {
                print!("{HELP_INIT}");
                return Ok(EXIT_OK);
            }
            other => return Err(format!("init: unexpected argument `{other}`")),
        }
    }
    let target = Path::new(policy::POLICY_FILE_NAME);
    if target.exists() && !force {
        return Err(format!(
            "{} already exists (use --force to overwrite)",
            policy::POLICY_FILE_NAME
        ));
    }
    std::fs::write(target, policy::DEFAULT_POLICY)
        .map_err(|e| format!("cannot write {}: {e}", policy::POLICY_FILE_NAME))?;
    println!(
        "created {} (commands default to deny; edit the allow/deny lists to fit your project)",
        policy::POLICY_FILE_NAME
    );
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

fn cmd_check(policy_override: Option<PathBuf>, args: Vec<String>) -> Result<i32, String> {
    let mut json = false;
    let mut hook = false;
    let mut approve = false;
    let mut no_log = false;
    let mut policy_override = policy_override;
    let mut words: Vec<String> = Vec::new();

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--hook" => hook = true,
            "--approve" => approve = true,
            "--no-log" => no_log = true,
            "--policy" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--policy requires a path argument".to_string())?;
                policy_override = Some(PathBuf::from(value));
            }
            "-h" | "--help" => {
                print!("{HELP_CHECK}");
                return Ok(EXIT_OK);
            }
            "--" => {
                words.extend(iter);
                break;
            }
            _ => {
                words.push(arg);
                words.extend(iter);
                break;
            }
        }
    }

    if approve && !hook {
        return Err("check: --approve only makes sense together with --hook".to_string());
    }

    if hook {
        if !words.is_empty() {
            return Err("check --hook reads the command from stdin, not arguments".to_string());
        }
        return hook_check(&policy_override, approve, no_log);
    }

    if words.is_empty() {
        return Err("check: no command given (usage: agentcage check -- <cmd>...)".to_string());
    }
    let cmd = words.join(" ");
    let loaded = load_policy(&policy_override)?;
    let verdict = engine::evaluate(&loaded.policy, &cmd);

    if !no_log {
        log_decision(&loaded.root, "check", &cmd, &verdict, None, None, None);
    }

    if json {
        let out = serde_json::json!({
            "decision": if verdict.allowed { "allow" } else { "deny" },
            "command": cmd,
            "rule": verdict.rule,
            "reason": verdict.reason,
            "policy": loaded.path.display().to_string(),
        });
        println!("{out}");
    } else if verdict.allowed {
        println!("allow: {cmd} ({})", verdict.reason);
    } else {
        println!("deny: {cmd} ({})", verdict.reason);
    }
    Ok(if verdict.allowed {
        EXIT_OK
    } else {
        EXIT_DENIED
    })
}

/// Claude Code PreToolUse hook mode: read the hook payload from stdin,
/// answer with `hookSpecificOutput` JSON on stdout, always exit 0 unless
/// stdin itself is unreadable. Policy problems degrade to an "ask"
/// decision so a broken setup surfaces to the human instead of silently
/// approving or hard-blocking every command.
fn hook_check(
    policy_override: &Option<PathBuf>,
    approve: bool,
    no_log: bool,
) -> Result<i32, String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("check --hook: cannot read stdin: {e}"))?;

    let payload: serde_json::Value = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(_) => {
            print_hook_decision("ask", "agentcage: hook input was not valid JSON");
            return Ok(EXIT_OK);
        }
    };
    let Some(cmd) = payload
        .get("tool_input")
        .and_then(|t| t.get("command"))
        .and_then(|c| c.as_str())
    else {
        // Not a command-shaped tool call: no opinion, defer entirely.
        return Ok(EXIT_OK);
    };

    let loaded = match load_policy(policy_override) {
        Ok(l) => l,
        Err(e) => {
            print_hook_decision("ask", &format!("agentcage: {e}"));
            return Ok(EXIT_OK);
        }
    };

    let verdict = engine::evaluate(&loaded.policy, cmd);
    if !no_log {
        log_decision(&loaded.root, "check", cmd, &verdict, None, None, None);
    }

    if verdict.allowed {
        if approve {
            print_hook_decision("allow", &format!("agentcage: {}", verdict.reason));
        }
        // Without --approve, stay silent: the normal permission flow decides.
    } else {
        print_hook_decision(
            "deny",
            &format!(
                "agentcage: {} (policy: {})",
                verdict.reason,
                loaded.path.display()
            ),
        );
    }
    Ok(EXIT_OK)
}

fn print_hook_decision(decision: &str, reason: &str) {
    let out = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    });
    println!("{out}");
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

fn cmd_run(policy_override: Option<PathBuf>, args: Vec<String>) -> Result<i32, String> {
    let mut dry_run = false;
    let mut strict = false;
    let mut no_log = false;
    let mut policy_override = policy_override;
    let mut words: Vec<String> = Vec::new();

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--strict" => strict = true,
            "--no-log" => no_log = true,
            "--policy" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--policy requires a path argument".to_string())?;
                policy_override = Some(PathBuf::from(value));
            }
            "-h" | "--help" => {
                print!("{HELP_RUN}");
                return Ok(EXIT_OK);
            }
            "--" => {
                words.extend(iter);
                break;
            }
            _ => {
                words.push(arg);
                words.extend(iter);
                break;
            }
        }
    }

    if words.is_empty() {
        return Err("run: no command given (usage: agentcage run -- <cmd>...)".to_string());
    }
    let cmd = words.join(" ");
    let loaded = load_policy(&policy_override)?;
    let verdict = engine::evaluate(&loaded.policy, &cmd);

    if !verdict.allowed {
        let mode = if dry_run { "dry-run" } else { "run" };
        if !no_log {
            log_decision(&loaded.root, mode, &cmd, &verdict, None, None, None);
        }
        eprintln!("agentcage: blocked: {}", verdict.reason);
        return Ok(EXIT_DENIED);
    }

    if dry_run {
        print_dry_run(&loaded, &cmd, &verdict);
        if !no_log {
            log_decision(&loaded.root, "dry-run", &cmd, &verdict, None, None, None);
        }
        return Ok(EXIT_OK);
    }

    // Create the runtime dir before restricting ourselves so the audit
    // entry can be written even under a policy without write access to
    // the project root.
    if !no_log {
        let _ = std::fs::create_dir_all(loaded.root.join(policy::RUNTIME_DIR_NAME));
    }

    let (sandbox_tag, enforced) = match sandbox::probe() {
        Support::Yes { .. } => match sandbox::enforce(&loaded.policy, &loaded.root) {
            Ok(enforcement) => {
                let enforced = enforcement.level != EnforcementLevel::None;
                match enforcement.level {
                    EnforcementLevel::Full => eprintln!(
                        "agentcage: sandbox active: landlock (kernel ABI {}, filesystem{})",
                        enforcement.abi,
                        if enforcement.net_requested { " + network" } else { "" }
                    ),
                    EnforcementLevel::Partial => eprintln!(
                        "agentcage: sandbox active: landlock (partial; kernel ABI {}; some rules unsupported, network filtering needs ABI >= 4)",
                        enforcement.abi
                    ),
                    EnforcementLevel::None => eprintln!(
                        "agentcage: sandbox not enforced by kernel; running in audit mode"
                    ),
                }
                if !enforcement.skipped_paths.is_empty() {
                    eprintln!(
                        "agentcage: note: policy paths missing on this machine were skipped: {}",
                        join_paths(&enforcement.skipped_paths)
                    );
                }
                if !enforced && strict {
                    return Err(
                        "run --strict: kernel enforcement unavailable, refusing to run".to_string(),
                    );
                }
                (enforcement.backend_tag(), enforced)
            }
            Err(e) => {
                if strict {
                    return Err(format!(
                        "run --strict: cannot apply landlock sandbox ({e}), refusing to run"
                    ));
                }
                eprintln!("agentcage: sandbox unavailable ({e}); running in audit mode");
                ("none".to_string(), false)
            }
        },
        Support::No { reason } => {
            if strict {
                return Err(format!(
                    "run --strict: kernel enforcement unavailable ({reason}), refusing to run"
                ));
            }
            eprintln!("agentcage: sandbox unavailable ({reason}); running in audit mode");
            ("none".to_string(), false)
        }
    };

    let exec_result = execute(&words);
    let exit_code = match &exec_result {
        Ok(code) => Some(*code),
        Err(_) => None,
    };
    if !no_log {
        log_decision(
            &loaded.root,
            "run",
            &cmd,
            &verdict,
            Some(sandbox_tag),
            Some(enforced),
            exit_code,
        );
    }
    exec_result
}

/// Executes the allowed command: one argument goes through `/bin/sh -c`,
/// multiple arguments are executed directly without shell interpretation.
fn execute(words: &[String]) -> Result<i32, String> {
    let mut command = if words.len() == 1 {
        let mut c = std::process::Command::new("/bin/sh");
        c.arg("-c").arg(&words[0]);
        c
    } else {
        let mut c = std::process::Command::new(&words[0]);
        c.args(&words[1..]);
        c
    };
    let status = command
        .status()
        .map_err(|e| format!("cannot execute `{}`: {e}", words[0]))?;
    if let Some(code) = status.code() {
        return Ok(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        let signal = status.signal().unwrap_or(0);
        eprintln!("agentcage: command terminated by signal {signal}");
        Ok(128 + signal)
    }
    #[cfg(not(unix))]
    Ok(EXIT_ERROR)
}

fn print_dry_run(loaded: &LoadedPolicy, cmd: &str, verdict: &Verdict) {
    println!("dry-run: allow: {cmd} ({})", verdict.reason);
    match sandbox::probe() {
        Support::Yes { abi } => println!("sandbox: landlock available (kernel ABI {abi})"),
        Support::No { reason } => {
            println!("sandbox: unavailable ({reason}); run would use audit mode")
        }
    }
    let (read_ok, read_missing) =
        sandbox::resolve_paths(&loaded.policy.filesystem.read, &loaded.root);
    let (write_ok, write_missing) =
        sandbox::resolve_paths(&loaded.policy.filesystem.write, &loaded.root);
    println!("read allowlist: {}", join_paths(&read_ok));
    println!("write allowlist: {}", join_paths(&write_ok));
    if loaded.policy.network.allow {
        println!("network: unrestricted");
    } else {
        println!(
            "network: TCP blocked (connect exceptions: {}; bind exceptions: {})",
            join_ports(&loaded.policy.network.tcp_connect),
            join_ports(&loaded.policy.network.tcp_bind)
        );
    }
    let mut missing = read_missing;
    missing.extend(write_missing);
    if !missing.is_empty() {
        println!(
            "skipped (missing on this machine): {}",
            join_paths(&missing)
        );
    }
}

fn join_paths(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return "(none)".to_string();
    }
    paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn join_ports(ports: &[u16]) -> String {
    if ports.is_empty() {
        return "none".to_string();
    }
    ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// log
// ---------------------------------------------------------------------------

fn cmd_log(policy_override: Option<PathBuf>, args: Vec<String>) -> Result<i32, String> {
    let mut json = false;
    let mut replay = false;
    let mut count: usize = 20;
    let mut policy_override = policy_override;

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--replay" => replay = true,
            "-n" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "log: -n requires a number".to_string())?;
                count = value
                    .parse()
                    .map_err(|_| format!("log: invalid count `{value}`"))?;
            }
            "--policy" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--policy requires a path argument".to_string())?;
                policy_override = Some(PathBuf::from(value));
            }
            "-h" | "--help" => {
                print!("{HELP_LOG}");
                return Ok(EXIT_OK);
            }
            other => return Err(format!("log: unexpected argument `{other}`")),
        }
    }

    let loaded = load_policy(&policy_override)?;
    let log = audit::load(&loaded.root).map_err(|e| format!("cannot read audit log: {e}"))?;

    if log.entries.is_empty() {
        println!(
            "audit log is empty ({})",
            audit::audit_path(&loaded.root).display()
        );
        return Ok(EXIT_OK);
    }

    if replay {
        return replay_log(&loaded, &log);
    }

    let start = log.entries.len().saturating_sub(count);
    for (line, entry) in &log.entries[start..] {
        if json {
            match serde_json::to_string(entry) {
                Ok(s) => println!("{s}"),
                Err(e) => eprintln!("agentcage: cannot serialize entry #{line}: {e}"),
            }
        } else {
            let mut extras = Vec::new();
            if let Some(rule) = &entry.rule {
                extras.push(format!("rule: {rule}"));
            }
            if let Some(code) = entry.exit_code {
                extras.push(format!("exit {code}"));
            }
            if let Some(sandbox_tag) = &entry.sandbox {
                extras.push(format!("sandbox: {sandbox_tag}"));
            }
            let suffix = if extras.is_empty() {
                String::new()
            } else {
                format!("  [{}]", extras.join(", "))
            };
            println!(
                "#{line:<4} {}  {:5} {:7} {}{suffix}",
                entry.ts, entry.decision, entry.mode, entry.cmd
            );
        }
    }
    if log.skipped > 0 {
        eprintln!(
            "agentcage: warning: {} malformed line(s) skipped in the audit log",
            log.skipped
        );
    }
    Ok(EXIT_OK)
}

/// Re-evaluates every recorded command against the current policy and
/// reports decisions that would change. This is how you test a policy
/// edit against everything your agent actually tried to do.
fn replay_log(loaded: &LoadedPolicy, log: &audit::LoadedLog) -> Result<i32, String> {
    let mut changed = 0usize;
    for (line, entry) in &log.entries {
        let verdict = engine::evaluate(&loaded.policy, &entry.cmd);
        let new_decision = if verdict.allowed { "allow" } else { "deny" };
        if new_decision != entry.decision {
            changed += 1;
            println!(
                "#{line:<4} {} -> {}  {}  ({})",
                entry.decision, new_decision, entry.cmd, verdict.reason
            );
        }
    }
    println!(
        "replayed {} entries against {}: {} decision(s) would change, {} unchanged",
        log.entries.len(),
        loaded.path.display(),
        changed,
        log.entries.len() - changed
    );
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

/// Appends a decision to the audit log; logging failures degrade to a
/// stderr warning because auditing must never break the actual command.
#[allow(clippy::too_many_arguments)]
fn log_decision(
    root: &Path,
    mode: &str,
    cmd: &str,
    verdict: &Verdict,
    sandbox_tag: Option<String>,
    enforced: Option<bool>,
    exit_code: Option<i32>,
) {
    let entry = AuditEntry {
        ts: timefmt::now_rfc3339(),
        mode: mode.to_string(),
        decision: if verdict.allowed { "allow" } else { "deny" }.to_string(),
        cmd: cmd.to_string(),
        rule: verdict.rule.clone(),
        reason: verdict.reason.clone(),
        sandbox: sandbox_tag,
        enforced,
        exit_code,
    };
    if let Err(e) = audit::append(root, &entry) {
        eprintln!("agentcage: warning: cannot write audit log: {e}");
    }
}
