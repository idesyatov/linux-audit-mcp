//! Tolerant parsers for Linux command output.
//!
//! Pure functions over text captured via SSH, so checks are unit-tested against
//! fixtures without a host. Keeping the remote vocabulary to dumb readers (see
//! [`crate::catalog`]) means all structure is recovered here, in Rust.

use std::collections::HashMap;

/// Parse `sshd_config` into a lowercased-key → value map.
///
/// Comments (`#`) and blank lines are ignored; keys are case-insensitive and
/// the FIRST occurrence wins (matching sshd's own precedence). `Match` blocks
/// are not interpreted — only global directives are considered, which is the
/// documented limitation of a file-based (non-`sshd -T`) read.
pub fn parse_sshd_config(output: &str) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let Some(key) = parts.next() else {
            continue;
        };
        let value = parts.next().unwrap_or("").trim().to_string();
        map.entry(key.to_ascii_lowercase()).or_insert(value);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = "# a comment\n\
        PermitRootLogin no\n\
        PasswordAuthentication yes\n\
        \n\
        MaxAuthTries   4\n";

    #[test]
    fn parses_and_lowercases_keys() {
        let m = parse_sshd_config(CFG);
        assert_eq!(m.get("permitrootlogin").map(String::as_str), Some("no"));
        assert_eq!(m.get("maxauthtries").map(String::as_str), Some("4"));
        assert_eq!(
            m.get("passwordauthentication").map(String::as_str),
            Some("yes")
        );
        assert_eq!(m.get("x11forwarding"), None);
    }

    #[test]
    fn first_occurrence_wins() {
        let m = parse_sshd_config("PermitRootLogin yes\nPermitRootLogin no\n");
        assert_eq!(m.get("permitrootlogin").map(String::as_str), Some("yes"));
    }
}
