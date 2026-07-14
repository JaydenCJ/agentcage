//! Policy file loading and validation.
//!
//! A policy lives in `.agentcage.toml` at the root of a project, next to
//! the code an agent works on, so the sandbox rules are reviewed and
//! versioned like any other file in the repository.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// File name of the policy searched for in the working directory and its
/// ancestors, like `.gitignore`.
pub const POLICY_FILE_NAME: &str = ".agentcage.toml";

/// Directory (next to the policy file) that holds runtime artifacts such
/// as the audit log. Created on demand with a `.gitignore` so logs are
/// never committed.
pub const RUNTIME_DIR_NAME: &str = ".agentcage";

/// The only policy schema version understood by this build.
pub const SUPPORTED_VERSION: u32 = 1;

/// Default policy written by `agentcage init`.
pub const DEFAULT_POLICY: &str = r#"# agentcage policy
# Command, filesystem and network rules for AI coding agents.
# Reference: https://github.com/JaydenCJ/agentcage/blob/main/docs/policy.md
version = 1

[commands]
# Decision when no rule below matches a command segment: "deny" or "allow".
default = "deny"

# Glob-style patterns: '*' matches any characters, including spaces.
# Chained commands (&&, ||, ;, |) are split into segments and every
# segment must pass on its own.
allow = [
  "ls*", "cat *", "head *", "tail *", "pwd", "echo *", "grep *", "find *",
  "which *", "wc *", "diff *", "file *", "stat *",
  "git status*", "git diff*", "git log*", "git show*", "git grep*", "git branch*",
  "cargo build*", "cargo test*", "cargo check*", "cargo fmt*", "cargo clippy*",
  "npm test*", "npm run *", "node *",
  "python3 *", "pytest*",
  "make", "make test*", "make build*",
]

# Deny rules always win over allow rules.
deny = [
  "rm -rf /*", "rm -rf ~*", "rm -rf .*",
  "sudo *", "su *",
  "curl *", "wget *", "nc *", "ssh *", "scp *",
  "git push*",
  "chmod 777 *", "chown *",
  "dd *", "mkfs*", "shutdown*", "reboot*",
]

[filesystem]
# Paths the sandboxed process may read from and execute binaries under.
# Relative paths resolve against the directory containing this file.
# Paths that do not exist on a machine are skipped.
read = [".", "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/opt",
        "/proc", "/sys", "/dev/null", "/dev/urandom", "/dev/tty"]
# Paths the sandboxed process may create, modify or delete files under.
write = [".", "/tmp", "/dev/null"]

[network]
# false blocks all TCP bind/connect for the sandboxed process
# (requires Landlock ABI >= 4, Linux >= 6.7; older kernels fall back
# to filesystem-only enforcement and agentcage reports it).
allow = false
# Ports that stay reachable even when allow = false.
tcp_connect = []
tcp_bind = []
"#;

/// Errors produced while locating, reading or validating a policy file.
#[derive(Debug)]
pub enum PolicyError {
    /// No `.agentcage.toml` found walking up from the start directory.
    NotFound { start: PathBuf },
    /// The policy file exists but could not be read.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The policy file is not valid TOML or fails schema validation.
    Invalid { path: PathBuf, message: String },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::NotFound { start } => write!(
                f,
                "no {} found in {} or any parent directory (run `agentcage init` to create one)",
                POLICY_FILE_NAME,
                start.display()
            ),
            PolicyError::Io { path, source } => {
                write!(f, "cannot read {}: {}", path.display(), source)
            }
            PolicyError::Invalid { path, message } => {
                write!(f, "invalid policy {}: {}", path.display(), message)
            }
        }
    }
}

/// Decision applied when no allow/deny rule matches a command segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultDecision {
    Allow,
    #[default]
    Deny,
}

/// `[commands]` section: glob rules evaluated by the decision engine.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commands {
    #[serde(default)]
    pub default: DefaultDecision,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

/// `[filesystem]` section: path allowlists enforced with Landlock.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filesystem {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
}

/// `[network]` section: TCP restrictions enforced with Landlock ABI >= 4.
/// The derived default is deny-by-default: `allow` is false and no port
/// exceptions are granted when the section is omitted.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    #[serde(default)]
    pub allow: bool,
    #[serde(default)]
    pub tcp_connect: Vec<u16>,
    #[serde(default)]
    pub tcp_bind: Vec<u16>,
}

/// A parsed and validated `.agentcage.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default)]
    pub commands: Commands,
    #[serde(default)]
    pub filesystem: Filesystem,
    #[serde(default)]
    pub network: Network,
}

impl Policy {
    /// Parses policy text and validates the schema version and rules.
    pub fn parse(text: &str, path: &Path) -> Result<Policy, PolicyError> {
        let policy: Policy = toml::from_str(text).map_err(|e| PolicyError::Invalid {
            path: path.to_path_buf(),
            message: e.message().to_string(),
        })?;
        if policy.version != SUPPORTED_VERSION {
            return Err(PolicyError::Invalid {
                path: path.to_path_buf(),
                message: format!(
                    "unsupported version {} (this build supports version {})",
                    policy.version, SUPPORTED_VERSION
                ),
            });
        }
        for rule in policy
            .commands
            .allow
            .iter()
            .chain(policy.commands.deny.iter())
        {
            if rule.trim().is_empty() {
                return Err(PolicyError::Invalid {
                    path: path.to_path_buf(),
                    message: "command rules must not be empty strings".to_string(),
                });
            }
        }
        Ok(policy)
    }

    /// Reads and parses a policy file from disk.
    pub fn load(path: &Path) -> Result<Policy, PolicyError> {
        let text = std::fs::read_to_string(path).map_err(|e| PolicyError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Policy::parse(&text, path)
    }
}

/// A policy together with where it was found, so callers can resolve
/// relative filesystem rules and locate the audit log.
pub struct LoadedPolicy {
    pub policy: Policy,
    /// Absolute path of the policy file itself.
    pub path: PathBuf,
    /// Directory containing the policy file (the "project root").
    pub root: PathBuf,
}

/// Finds `.agentcage.toml` starting at `start` and walking up parent
/// directories, then loads it.
pub fn find_and_load(start: &Path) -> Result<LoadedPolicy, PolicyError> {
    let mut dir = Some(start.to_path_buf());
    while let Some(d) = dir {
        let candidate = d.join(POLICY_FILE_NAME);
        if candidate.is_file() {
            let policy = Policy::load(&candidate)?;
            return Ok(LoadedPolicy {
                policy,
                path: candidate,
                root: d,
            });
        }
        dir = d.parent().map(|p| p.to_path_buf());
    }
    Err(PolicyError::NotFound {
        start: start.to_path_buf(),
    })
}

/// Loads a policy from an explicit path (the `--policy` flag).
pub fn load_explicit(path: &Path) -> Result<LoadedPolicy, PolicyError> {
    let policy = Policy::load(path)?;
    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let root = abs
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    Ok(LoadedPolicy {
        policy,
        path: abs,
        root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(text: &str) -> Result<Policy, PolicyError> {
        Policy::parse(text, Path::new("test.toml"))
    }

    #[test]
    fn default_policy_template_parses() {
        let policy = p(DEFAULT_POLICY).expect("default policy must parse");
        assert_eq!(policy.version, 1);
        assert_eq!(policy.commands.default, DefaultDecision::Deny);
        assert!(policy.commands.allow.iter().any(|r| r == "cargo test*"));
        assert!(policy.commands.deny.iter().any(|r| r == "curl *"));
        assert!(policy.filesystem.read.iter().any(|r| r == "/usr"));
        assert!(!policy.network.allow);
    }

    #[test]
    fn minimal_policy_gets_safe_defaults() {
        let policy = p("version = 1").unwrap();
        assert_eq!(policy.commands.default, DefaultDecision::Deny);
        assert!(policy.commands.allow.is_empty());
        assert!(policy.filesystem.read.is_empty());
        assert!(!policy.network.allow);
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let err = p("version = 2").unwrap_err();
        assert!(err.to_string().contains("unsupported version 2"));
    }

    #[test]
    fn unknown_keys_are_rejected() {
        // Typos in a security policy must fail loudly, not be ignored.
        let err = p("version = 1\n[commands]\nalow = [\"ls\"]").unwrap_err();
        assert!(err.to_string().contains("invalid policy"));
    }

    #[test]
    fn bad_default_value_is_rejected() {
        let err = p("version = 1\n[commands]\ndefault = \"maybe\"").unwrap_err();
        assert!(err.to_string().contains("invalid policy"));
    }

    #[test]
    fn empty_rule_is_rejected() {
        let err = p("version = 1\n[commands]\nallow = [\" \"]").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn network_ports_parse() {
        let policy = p("version = 1\n[network]\nallow = false\ntcp_connect = [443, 80]").unwrap();
        assert_eq!(policy.network.tcp_connect, vec![443, 80]);
        assert!(policy.network.tcp_bind.is_empty());
    }

    #[test]
    fn not_toml_is_invalid() {
        let err = p("this is not toml {").unwrap_err();
        assert!(matches!(err, PolicyError::Invalid { .. }));
    }
}
