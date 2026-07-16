//! Read-only command catalog for Linux audits.
//!
//! This is the core of the read-only guarantee. On a general-purpose Linux shell
//! a charset filter alone is not enough to prove a command is read-only, so every
//! command a check issues must be an *exact* member of a curated catalog. Anything
//! not in the catalog is refused before it is ever sent.
//!
//! Two layers, deny by default:
//!   1. a positive character set, so shell metacharacters that could chain or
//!      inject a second command (`; & | ` $ < > ( ) * ? ' "` …) can never appear
//!      — the remote sshd still runs the command through a login shell;
//!   2. exact membership in [`READONLY_COMMANDS`] — the only commands allowed.
//!
//! Keep the remote vocabulary tiny: prefer dumb readers (`cat <fixed file>`,
//! `sysctl -a`, `ss -tuln`) and do all parsing in Rust. Fewer commands means a
//! smaller, auditable surface. Commands requiring root are intentionally absent.
//!
//! Wired into the SSH transport ([`crate::ssh`]); checks arrive in Stage 3.
#![allow(dead_code)]

use std::error::Error;
use std::fmt;

/// Every read-only command the auditor may run. A check's command must appear
/// here verbatim (after trimming). This set grows as checks are added; each
/// entry must be readable by an unprivileged user and must not change state.
pub const READONLY_COMMANDS: &[&str] = &[
    "cat /etc/os-release",
    "cat /etc/ssh/sshd_config",
    "cat /etc/login.defs",
    "getent passwd",
    "sysctl -a",
    "ss -tuln",
    "systemctl list-unit-files --type=service --no-pager",
    "uname -a",
];

/// Characters permitted in a command. A positive character set (not a denylist)
/// guarantees no metacharacter that could chain or inject a command can appear.
fn is_allowed_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || " /-_.=,:".contains(c)
}

#[derive(Debug, PartialEq, Eq)]
pub enum CatalogError {
    /// The command is empty.
    Empty,
    /// A character outside the permitted set was found.
    IllegalCharacter(char),
    /// The command is not an exact member of the read-only catalog.
    NotInCatalog(String),
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty command"),
            Self::IllegalCharacter(c) => write!(f, "illegal character {c:?} in command"),
            Self::NotInCatalog(cmd) => {
                write!(f, "command {cmd:?} is not in the read-only catalog")
            }
        }
    }
}

impl Error for CatalogError {}

/// Validate that `command` is a read-only command safe to send.
pub fn validate(command: &str) -> Result<(), CatalogError> {
    let cmd = command.trim();
    if cmd.is_empty() {
        return Err(CatalogError::Empty);
    }
    if let Some(c) = cmd.chars().find(|c| !is_allowed_char(*c)) {
        return Err(CatalogError::IllegalCharacter(c));
    }
    if !READONLY_COMMANDS.contains(&cmd) {
        return Err(CatalogError::NotInCatalog(cmd.to_string()));
    }
    Ok(())
}

/// Convenience predicate: `true` iff [`validate`] accepts `command`.
pub fn is_allowed(command: &str) -> bool {
    validate(command).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_every_catalog_command() {
        for cmd in READONLY_COMMANDS {
            assert!(is_allowed(cmd), "should allow catalog command: {cmd}");
        }
        // Surrounding whitespace is trimmed.
        assert!(is_allowed("  uname -a  "));
    }

    #[test]
    fn rejects_commands_outside_the_catalog() {
        // Charset-clean, but not read-only / not listed → refused.
        for cmd in [
            "systemctl restart sshd", // write action
            "cat /etc/shadow",        // root-only, deliberately absent
            "rm -rf /tmp",            // destructive
            "ss -tulnp",              // near-miss on a catalog entry
        ] {
            assert!(
                matches!(validate(cmd), Err(CatalogError::NotInCatalog(_))),
                "should reject via catalog: {cmd}"
            );
        }
    }

    #[test]
    fn rejects_command_chaining_and_injection() {
        for cmd in [
            "cat /etc/passwd; rm -rf /",
            "sysctl -a && reboot",
            "ss -tuln | sh",
            "uname -a `id`",
            "cat /etc/os-release $(id)",
            "sysctl -a > /tmp/x",
            "cat \"/etc/passwd\"",
        ] {
            assert!(
                matches!(validate(cmd), Err(CatalogError::IllegalCharacter(_))),
                "should reject via charset: {cmd}"
            );
        }
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(validate(""), Err(CatalogError::Empty));
        assert_eq!(validate("   "), Err(CatalogError::Empty));
    }
}
