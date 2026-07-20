//! Tolerant parsers for Linux command output.
//!
//! Pure functions over text captured via SSH, so checks are unit-tested against
//! fixtures without a host. Keeping the remote vocabulary to dumb readers (see
//! [`crate::catalog`]) means all structure is recovered here, in Rust.

use std::collections::HashMap;

/// Parse whitespace-separated `KEY value` config - the shape of `sshd_config`,
/// `login.defs` and similar files.
///
/// Comments (`#`) and blank lines are ignored; keys are lowercased and the
/// FIRST occurrence wins. For sshd this matches its own precedence; note that
/// `Match` blocks are not interpreted (only global directives are considered).
pub fn parse_keyword_map(output: &str) -> HashMap<String, String> {
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

/// `sshd_config` is keyword config (see [`parse_keyword_map`]).
pub fn parse_sshd_config(output: &str) -> HashMap<String, String> {
    parse_keyword_map(output)
}

/// One `/etc/passwd` entry (from `getent passwd`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub shell: String,
}

/// Parse colon-separated passwd lines. Malformed rows are skipped.
pub fn parse_passwd(output: &str) -> Vec<PasswdEntry> {
    output
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 7 {
                return None;
            }
            Some(PasswdEntry {
                name: f[0].to_string(),
                uid: f[2].parse().ok()?,
                gid: f[3].parse().ok()?,
                shell: f[6].trim().to_string(),
            })
        })
        .collect()
}

/// Usernames from `/etc/shadow` whose password field (index 1) is empty - the
/// account can authenticate with no password. Locked (`!`, `*`) and hashed
/// entries are fine and excluded; malformed/short lines are skipped.
pub fn shadow_empty_password_accounts(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 2 || f[0].trim().is_empty() {
                return None;
            }
            f[1].is_empty().then(|| f[0].trim().to_string())
        })
        .collect()
}

/// Parse `sysctl -a` output (`key = value` lines) into a map.
pub fn parse_sysctl(output: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in output.lines() {
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            if key.is_empty() {
                continue;
            }
            map.insert(key.to_string(), v.trim().to_string());
        }
    }
    map
}

/// Parse `systemctl list-unit-files` into a `unit -> state` map, e.g.
/// `{"firewalld.service": "enabled"}`. The header and footer lines don't match
/// the `unit state ...` shape and are skipped.
pub fn parse_unit_files(output: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in output.lines() {
        let mut it = line.split_whitespace();
        let (Some(unit), Some(state)) = (it.next(), it.next()) else {
            continue;
        };
        if unit.contains('.') {
            map.insert(unit.to_string(), state.to_string());
        }
    }
    map
}

/// `true` if `<service>.service` is `enabled` in a [`parse_unit_files`] map.
pub fn service_enabled(units: &HashMap<String, String>, service: &str) -> bool {
    units
        .get(&format!("{service}.service"))
        .map(|s| s == "enabled")
        .unwrap_or(false)
}

/// Local listening ports from `ss -tuln` (the port of each row's local address).
pub fn parse_listen_ports(output: &str) -> Vec<u16> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // Rows: Netid State Recv-Q Send-Q <Local> <Peer> [Process]. Skip the
            // header (first column "Netid"/"State") and anything shorter.
            if fields.len() < 6 || fields[0] == "Netid" || fields[0] == "State" {
                return None;
            }
            fields[4].rsplit(':').next()?.parse::<u16>().ok()
        })
        .collect()
}

/// The input-filtering posture of an `nft list ruleset` dump.
#[derive(Debug, PartialEq, Eq)]
pub enum NftInput {
    /// No ruleset at all (empty output) - the kernel firewall is empty.
    NoRuleset,
    /// A ruleset exists but no base chain is hooked to `input`.
    NoInputHook,
    /// Input-hook chain(s) exist but none deny by default (all accept).
    AcceptAll,
    /// An input-hook chain denies by default: `policy drop`, or the chain body
    /// carries a `drop`/`reject` verdict (ufw/firewalld's catch-all).
    DefaultDeny,
}

/// Classify the input-hook posture of `nft list ruleset` output. Brace depth is
/// tracked so a rule is attributed to the chain that contains it; a chain counts
/// as denying if its header is `policy drop` or its body has a `drop`/`reject`.
pub fn nft_input_policy(output: &str) -> NftInput {
    if output.trim().is_empty() {
        return NftInput::NoRuleset;
    }
    let mut depth: i32 = 0;
    // Current chain: (brace depth at its start, is_input, denies).
    let mut chain: Option<(i32, bool, bool)> = None;
    let mut any_input = false;
    let mut deny_found = false;

    for line in output.lines() {
        let tokens: Vec<String> = line
            .split_whitespace()
            .map(|t| {
                t.trim_matches(|c| c == ';' || c == ',')
                    .to_ascii_lowercase()
            })
            .collect();

        // Enter a chain (base or regular) at `chain <name> {`.
        if chain.is_none() && tokens.first().map(String::as_str) == Some("chain") {
            chain = Some((depth, false, false));
        }
        if let Some((_, is_input, denies)) = chain.as_mut() {
            if line.contains("hook input") {
                *is_input = true;
            }
            if tokens.iter().any(|t| t == "drop" || t == "reject") {
                *denies = true;
            }
        }

        depth += line.matches('{').count() as i32;
        depth -= line.matches('}').count() as i32;

        // Close the chain once depth falls back to its start level.
        if let Some((start, is_input, denies)) = chain {
            if depth <= start {
                if is_input {
                    any_input = true;
                    deny_found |= denies;
                }
                chain = None;
            }
        }
    }

    if deny_found {
        NftInput::DefaultDeny
    } else if any_input {
        NftInput::AcceptAll
    } else {
        NftInput::NoInputHook
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_map_lowercases_and_first_wins() {
        let m = parse_keyword_map("# c\nPermitRootLogin no\nPermitRootLogin yes\nUMASK 027\n");
        assert_eq!(m.get("permitrootlogin").map(String::as_str), Some("no"));
        assert_eq!(m.get("umask").map(String::as_str), Some("027"));
    }

    #[test]
    fn parses_passwd() {
        let out = "root:x:0:0:root:/root:/bin/bash\n\
                   backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n\
                   bad-line\n";
        let e = parse_passwd(out);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].name, "root");
        assert_eq!(e[0].uid, 0);
        assert_eq!(e[1].shell, "/usr/sbin/nologin");
    }

    #[test]
    fn shadow_empty_passwords() {
        let out = "root:$6$abc$hash:19000:0:99999:7:::\n\
                   daemon:*:19000:0:99999:7:::\n\
                   locked:!:19000:0:99999:7:::\n\
                   nopass::19000:0:99999:7:::\n\
                   also_nopass::19000:0:99999:7:::\n";
        let empty = shadow_empty_password_accounts(out);
        assert_eq!(empty, vec!["nopass", "also_nopass"]);
        // A normal shadow yields nothing.
        assert!(shadow_empty_password_accounts("root:$6$x:19000::::::\n").is_empty());
    }

    #[test]
    fn parses_sysctl() {
        let m = parse_sysctl("kernel.randomize_va_space = 2\nnet.ipv4.ip_forward = 0\n");
        assert_eq!(
            m.get("kernel.randomize_va_space").map(String::as_str),
            Some("2")
        );
        assert_eq!(m.get("net.ipv4.ip_forward").map(String::as_str), Some("0"));
    }

    #[test]
    fn parses_unit_files_and_enabled() {
        let out = "UNIT FILE            STATE    PRESET\n\
                   firewalld.service    enabled  enabled\n\
                   rpcbind.service      disabled disabled\n\
                   \n\
                   2 unit files listed.\n";
        let m = parse_unit_files(out);
        assert!(service_enabled(&m, "firewalld"));
        assert!(!service_enabled(&m, "rpcbind"));
        assert!(!service_enabled(&m, "ufw"));
    }

    #[test]
    fn parses_listen_ports() {
        let out = "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n\
                   tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*\n\
                   tcp   LISTEN 0      128    [::]:23            [::]:*\n\
                   udp   UNCONN 0      0      0.0.0.0:53         0.0.0.0:*\n";
        let mut ports = parse_listen_ports(out);
        ports.sort_unstable();
        assert_eq!(ports, vec![22, 23, 53]);
    }

    #[test]
    fn nft_empty_is_no_ruleset() {
        assert_eq!(nft_input_policy(""), NftInput::NoRuleset);
        assert_eq!(nft_input_policy("  \n"), NftInput::NoRuleset);
    }

    #[test]
    fn nft_policy_drop_is_default_deny() {
        // ufw / hand-rolled nft: the input base chain drops by default.
        let out = "table inet filter {\n\
                   \tchain input {\n\
                   \t\ttype filter hook input priority filter; policy drop;\n\
                   \t\tct state established,related accept\n\
                   \t}\n\
                   \tchain output {\n\
                   \t\ttype filter hook output priority filter; policy accept;\n\
                   \t}\n\
                   }\n";
        assert_eq!(nft_input_policy(out), NftInput::DefaultDeny);
    }

    #[test]
    fn nft_accept_policy_with_reject_rule_is_default_deny() {
        // firewalld pattern: policy accept, but a catch-all reject at the end.
        let out = "table inet firewalld {\n\
                   \tchain filter_INPUT {\n\
                   \t\ttype filter hook input priority filter + 10; policy accept;\n\
                   \t\tct state established,related accept\n\
                   \t\treject with icmpx admin-prohibited\n\
                   \t}\n\
                   }\n";
        assert_eq!(nft_input_policy(out), NftInput::DefaultDeny);
    }

    #[test]
    fn nft_accept_policy_no_deny_is_accept_all() {
        let out = "table inet filter {\n\
                   \tchain input {\n\
                   \t\ttype filter hook input priority filter; policy accept;\n\
                   \t\tct state established,related accept\n\
                   \t}\n\
                   }\n";
        assert_eq!(nft_input_policy(out), NftInput::AcceptAll);
    }

    #[test]
    fn nft_no_input_hook() {
        // A ruleset that only filters output/forward - nothing guards input. A
        // drop in the output chain must not be mistaken for input filtering.
        let out = "table inet filter {\n\
                   \tchain output {\n\
                   \t\ttype filter hook output priority filter; policy accept;\n\
                   \t\tdrop\n\
                   \t}\n\
                   }\n";
        assert_eq!(nft_input_policy(out), NftInput::NoInputHook);
    }
}
