//! Landlock sandbox wrapper, isolated from all pure-logic modules.
//!
//! Everything kernel-specific lives here so the policy parser, decision
//! engine and audit log can be tested on any machine. The wrapper probes
//! kernel support at runtime and reports exactly what is enforced; when
//! Landlock is unavailable (old kernel, seccomp-filtered container),
//! callers fall back to audit mode instead of failing.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::policy::Policy;

/// Runtime Landlock availability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Support {
    /// Kernel accepts Landlock rulesets; `abi` is the kernel's ABI level.
    Yes { abi: i32 },
    /// Kernel (or the surrounding container runtime) refuses Landlock.
    No { reason: String },
}

impl fmt::Display for Support {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Support::Yes { abi } => write!(f, "landlock available (kernel ABI {abi})"),
            Support::No { reason } => write!(f, "landlock unavailable: {reason}"),
        }
    }
}

/// How strongly the kernel ended up enforcing the requested rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementLevel {
    /// All requested restrictions (filesystem and network) are active.
    Full,
    /// Filesystem rules are active but some requested restrictions
    /// (typically TCP rules on ABI < 4) are not supported by this kernel.
    Partial,
    /// Nothing is enforced.
    None,
}

/// Outcome of applying the sandbox to the current process.
#[derive(Debug)]
pub struct Enforcement {
    pub level: EnforcementLevel,
    /// Kernel ABI the ruleset was created against.
    pub abi: i32,
    /// Policy paths skipped because they do not exist on this machine.
    pub skipped_paths: Vec<PathBuf>,
    /// True if TCP restrictions were requested by the policy.
    pub net_requested: bool,
}

impl Enforcement {
    /// Short backend tag recorded in audit entries, e.g. `landlock:4`.
    pub fn backend_tag(&self) -> String {
        match self.level {
            EnforcementLevel::None => "none".to_string(),
            _ => format!("landlock:{}", self.abi),
        }
    }
}

/// Resolves policy filesystem entries against the project root.
/// Relative paths are joined to `root`; missing paths are separated out
/// so callers can surface them.
pub fn resolve_paths(entries: &[String], root: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut existing = Vec::new();
    let mut missing = Vec::new();
    for entry in entries {
        let raw = Path::new(entry);
        let joined = if raw.is_absolute() {
            raw.to_path_buf()
        } else {
            root.join(raw)
        };
        if joined.exists() {
            existing.push(joined);
        } else {
            missing.push(joined);
        }
    }
    (existing, missing)
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use landlock::{
        Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath, PathFd,
        Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
    };

    /// Asks the kernel for its Landlock ABI version without creating a
    /// ruleset. Cheap and side-effect free.
    pub fn probe() -> Support {
        // LANDLOCK_CREATE_RULESET_VERSION = 1 << 0.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0usize,
                1u32,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            let reason = match err.raw_os_error() {
                Some(libc::ENOSYS) => {
                    "kernel does not implement Landlock (needs Linux >= 5.13) or the container runtime filters the syscall".to_string()
                }
                Some(libc::EOPNOTSUPP) => {
                    "Landlock is disabled in this kernel (lsm= boot parameter)".to_string()
                }
                _ => format!("landlock_create_ruleset failed: {err}"),
            };
            Support::No { reason }
        } else {
            Support::Yes { abi: ret as i32 }
        }
    }

    /// Applies the policy's filesystem and network rules to the current
    /// process (and everything it will spawn). Must be called after the
    /// audit-log directory is known writable paths-wise: the runtime dir
    /// is added to the write allowlist automatically so the post-run
    /// audit entry can still be written.
    pub fn enforce(policy: &Policy, root: &Path) -> Result<Enforcement, String> {
        let kernel_abi = match probe() {
            Support::Yes { abi } => abi,
            Support::No { reason } => return Err(reason),
        };
        // Target the newest feature set we use (fs + TCP); BestEffort
        // degrades gracefully on older kernels and reports it.
        let abi = ABI::V4;
        let net_requested = !policy.network.allow;

        let mut ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(abi))
            .map_err(|e| e.to_string())?;
        if net_requested {
            ruleset = ruleset
                .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
                .map_err(|e| e.to_string())?;
        }
        let mut created = ruleset.create().map_err(|e| e.to_string())?;

        let mut skipped_paths = Vec::new();

        let (read_paths, missing_read) = resolve_paths(&policy.filesystem.read, root);
        skipped_paths.extend(missing_read);
        for path in &read_paths {
            let fd = match PathFd::new(path) {
                Ok(fd) => fd,
                Err(_) => {
                    skipped_paths.push(path.clone());
                    continue;
                }
            };
            created = created
                .add_rule(PathBeneath::new(fd, AccessFs::from_read(abi)))
                .map_err(|e| e.to_string())?;
        }

        // Write paths get the full access set (read + write) and always
        // include the runtime dir so audit logging keeps working under
        // enforcement.
        let mut write_entries = policy.filesystem.write.clone();
        write_entries.push(crate::policy::RUNTIME_DIR_NAME.to_string());
        let (write_paths, missing_write) = resolve_paths(&write_entries, root);
        skipped_paths.extend(missing_write);
        for path in &write_paths {
            let fd = match PathFd::new(path) {
                Ok(fd) => fd,
                Err(_) => {
                    skipped_paths.push(path.clone());
                    continue;
                }
            };
            created = created
                .add_rule(PathBeneath::new(fd, AccessFs::from_all(abi)))
                .map_err(|e| e.to_string())?;
        }

        if net_requested {
            for port in &policy.network.tcp_connect {
                created = created
                    .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
                    .map_err(|e| e.to_string())?;
            }
            for port in &policy.network.tcp_bind {
                created = created
                    .add_rule(NetPort::new(*port, AccessNet::BindTcp))
                    .map_err(|e| e.to_string())?;
            }
        }

        let status = created.restrict_self().map_err(|e| e.to_string())?;
        let level = match status.ruleset {
            RulesetStatus::FullyEnforced => EnforcementLevel::Full,
            RulesetStatus::PartiallyEnforced => EnforcementLevel::Partial,
            RulesetStatus::NotEnforced => EnforcementLevel::None,
        };
        Ok(Enforcement {
            level,
            abi: kernel_abi,
            skipped_paths,
            net_requested,
        })
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub fn probe() -> Support {
        Support::No {
            reason: "Landlock requires Linux (macOS sandbox-exec backend is on the roadmap)"
                .to_string(),
        }
    }

    pub fn enforce(_policy: &Policy, _root: &Path) -> Result<Enforcement, String> {
        Err("Landlock requires Linux".to_string())
    }
}

pub use imp::{enforce, probe};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_paths_splits_existing_and_missing() {
        let root = std::env::temp_dir();
        let entries = vec![
            ".".to_string(),
            "/definitely-not-a-real-path-agentcage".to_string(),
        ];
        let (existing, missing) = resolve_paths(&entries, &root);
        assert_eq!(existing, vec![root.join(".")]);
        assert_eq!(
            missing,
            vec![PathBuf::from("/definitely-not-a-real-path-agentcage")]
        );
    }

    #[test]
    fn probe_reports_a_definite_answer() {
        // We cannot assume kernel support in CI containers; we can assert
        // the probe never panics and produces a displayable answer.
        let support = probe();
        let text = support.to_string();
        assert!(text.contains("landlock"));
    }

    #[test]
    fn backend_tag_formats() {
        let e = Enforcement {
            level: EnforcementLevel::Full,
            abi: 4,
            skipped_paths: vec![],
            net_requested: true,
        };
        assert_eq!(e.backend_tag(), "landlock:4");
        let none = Enforcement {
            level: EnforcementLevel::None,
            abi: 0,
            skipped_paths: vec![],
            net_requested: false,
        };
        assert_eq!(none.backend_tag(), "none");
    }
}
