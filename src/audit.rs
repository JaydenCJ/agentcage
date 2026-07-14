//! JSONL audit log: every decision agentcage makes is appended to
//! `.agentcage/audit.jsonl` next to the policy file.
//!
//! The log is append-only, one JSON object per line, so it can be tailed,
//! shipped or diffed with standard tools. `agentcage log --replay`
//! re-evaluates recorded commands against the current policy to show how
//! a policy change would have altered past decisions.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::policy::RUNTIME_DIR_NAME;

/// One decision record. Field names are part of the on-disk format;
/// see docs/policy.md for the stability contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// UTC timestamp, RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).
    pub ts: String,
    /// Which code path produced the record: `check`, `run` or `dry-run`.
    pub mode: String,
    /// `allow` or `deny`.
    pub decision: String,
    /// The raw command as received.
    pub cmd: String,
    /// Policy rule that decided the outcome, when one did.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rule: Option<String>,
    /// Human-readable explanation of the decision.
    pub reason: String,
    /// Sandbox backend used for `run`: `landlock:<abi>` or `none`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sandbox: Option<String>,
    /// Whether kernel enforcement was active when the command ran.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub enforced: Option<bool>,
    /// Exit code of the executed command (`run` with execution only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exit_code: Option<i32>,
}

/// Absolute path of the audit log for a project root.
pub fn audit_path(root: &Path) -> PathBuf {
    root.join(RUNTIME_DIR_NAME).join("audit.jsonl")
}

/// Appends one entry to the audit log, creating the runtime directory
/// (with a `.gitignore` so logs are never committed) on first use.
pub fn append(root: &Path, entry: &AuditEntry) -> std::io::Result<()> {
    let dir = root.join(RUNTIME_DIR_NAME);
    if !dir.is_dir() {
        fs::create_dir_all(&dir)?;
        // Best effort: mark the runtime dir as never-committed.
        let _ = fs::write(dir.join(".gitignore"), "*\n");
    }
    let line = serde_json::to_string(entry).map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_path(root))?;
    writeln!(file, "{line}")
}

/// Result of reading the audit log.
pub struct LoadedLog {
    /// (1-based line number, entry) pairs in file order.
    pub entries: Vec<(usize, AuditEntry)>,
    /// Number of lines that could not be parsed (corruption, truncation).
    pub skipped: usize,
}

/// Reads all entries from the audit log. A missing file yields an empty
/// log rather than an error, since "nothing recorded yet" is normal.
pub fn load(root: &Path) -> std::io::Result<LoadedLog> {
    let path = audit_path(root);
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let mut entries = Vec::new();
    let mut skipped = 0usize;
    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEntry>(line) {
            Ok(entry) => entries.push((idx + 1, entry)),
            Err(_) => skipped += 1,
        }
    }
    Ok(LoadedLog { entries, skipped })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("agentcage-audit-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entry(decision: &str, cmd: &str) -> AuditEntry {
        AuditEntry {
            ts: "2026-07-08T00:00:00Z".to_string(),
            mode: "check".to_string(),
            decision: decision.to_string(),
            cmd: cmd.to_string(),
            rule: Some("curl *".to_string()),
            reason: "test".to_string(),
            sandbox: None,
            enforced: None,
            exit_code: None,
        }
    }

    #[test]
    fn append_then_load_round_trips() {
        let root = temp_root("roundtrip");
        append(&root, &entry("deny", "curl https://example.com")).unwrap();
        append(&root, &entry("allow", "ls")).unwrap();
        let log = load(&root).unwrap();
        assert_eq!(log.entries.len(), 2);
        assert_eq!(log.skipped, 0);
        assert_eq!(log.entries[0].0, 1);
        assert_eq!(log.entries[0].1.decision, "deny");
        assert_eq!(log.entries[1].1.cmd, "ls");
        // The runtime dir must protect itself from being committed.
        let gi = fs::read_to_string(root.join(RUNTIME_DIR_NAME).join(".gitignore")).unwrap();
        assert_eq!(gi, "*\n");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_missing_file_is_empty() {
        let root = temp_root("missing");
        let log = load(&root).unwrap();
        assert!(log.entries.is_empty());
        assert_eq!(log.skipped, 0);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_skips_malformed_lines() {
        let root = temp_root("malformed");
        append(&root, &entry("deny", "curl x")).unwrap();
        let path = audit_path(&root);
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(file, "not json at all").unwrap();
        drop(file);
        append(&root, &entry("allow", "ls")).unwrap();
        let log = load(&root).unwrap();
        assert_eq!(log.entries.len(), 2);
        assert_eq!(log.skipped, 1);
        // Line numbers still refer to the physical file.
        assert_eq!(log.entries[1].0, 3);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn optional_fields_serialize_compactly() {
        let json = serde_json::to_string(&entry("deny", "curl x")).unwrap();
        assert!(!json.contains("exit_code"));
        assert!(!json.contains("sandbox"));
        assert!(json.contains("\"rule\":\"curl *\""));
    }
}
