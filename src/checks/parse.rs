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

/// Traditional DES `crypt`: exactly 13 chars from the crypt base64 alphabet,
/// or a BSDI extended-DES hash (leading `_`). Both are legacy and weak.
fn is_des_crypt(hash: &str) -> bool {
    hash.starts_with('_')
        || (hash.len() == 13
            && hash
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'/'))
}

/// From `/etc/shadow`, the accounts whose password hash uses a weak algorithm,
/// as `(user, algo)` pairs. Weak = MD5 (`$1$`) or legacy DES `crypt`. Empty
/// fields are ignored (they're the concern of
/// [`shadow_empty_password_accounts`]); locked/disabled accounts (`!`, `*`) and
/// modern hashes (bcrypt `$2*$`, SHA-256 `$5$`, SHA-512 `$6$`, yescrypt `$y$`,
/// …) are fine and excluded; malformed/short lines are skipped.
pub fn shadow_weak_hash_accounts(output: &str) -> Vec<(String, &'static str)> {
    output
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 2 {
                return None;
            }
            let user = f[0].trim();
            let hash = f[1];
            // Empty (no password) and locked/disabled accounts aren't weak hashes.
            if user.is_empty() || hash.is_empty() || hash.starts_with(['!', '*']) {
                return None;
            }
            if let Some(rest) = hash.strip_prefix('$') {
                // `$id$salt$hash` - only MD5 (`1`) is weak among the `$id$` schemes.
                let id = rest.split('$').next().unwrap_or("");
                (id == "1").then(|| (user.to_string(), "MD5"))
            } else if is_des_crypt(hash) {
                Some((user.to_string(), "DES"))
            } else {
                None
            }
        })
        .collect()
}

/// From `/etc/shadow`, accounts with a usable password whose maximum password
/// age (field 4) is unset or greater than `max_days` - the password effectively
/// never has to be rotated. Returns `(user, max_display)` where `max_display` is
/// `"unset"` for an empty field or the number (annotated `(never)` for the
/// 99999 sentinel). Locked (`!`, `*`), empty-password and malformed/short rows
/// are excluded, so only accounts that can actually log in with a password are
/// considered. Complements [`crate::checks::accounts::PassMaxDays`], which only
/// sees the `login.defs` default applied to *new* passwords.
pub fn shadow_nonexpiring_password_accounts(output: &str, max_days: u32) -> Vec<(String, String)> {
    output
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 5 {
                return None;
            }
            let user = f[0].trim();
            let hash = f[1];
            // Only usable-password accounts: skip empty (no password), locked
            // (`!`) and disabled (`*`) entries - those can't password-authenticate.
            if user.is_empty() || hash.is_empty() || hash.starts_with(['!', '*']) {
                return None;
            }
            let max_raw = f[4].trim();
            if max_raw.is_empty() {
                return Some((user.to_string(), "unset".to_string()));
            }
            match max_raw.parse::<u32>() {
                Ok(days) if days > max_days => {
                    // 99999 is the conventional "never expires" sentinel.
                    let disp = if days >= 99999 {
                        format!("{days} (never)")
                    } else {
                        days.to_string()
                    };
                    Some((user.to_string(), disp))
                }
                _ => None,
            }
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

/// Parse `/proc/mounts` into a `mountpoint -> options` map. Each line is
/// `device mountpoint fstype options dump pass`; the mount options are the 4th
/// whitespace field, comma-separated (e.g. `rw,nosuid,nodev`). A later mount of
/// the same path shadows an earlier one, so the LAST entry wins (matches the
/// kernel's effective view). Paths with escaped spaces (`\040`) are rare on the
/// dirs we check and left as-is.
pub fn parse_proc_mounts(output: &str) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();
    for line in output.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let opts = f[3].split(',').map(|o| o.to_string()).collect();
        map.insert(f[1].to_string(), opts);
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
    /// An input-hook chain denies: `policy drop`, or its body carries a
    /// `drop`/`reject` verdict. Heuristic - a *targeted* deny rule counts too, so
    /// an accept-policy chain that drops only some traffic is leniently treated as
    /// denying (we would rather not false-fail a real firewall than be strict).
    DefaultDeny,
}

/// Classify the input-hook posture of `nft list ruleset` output. Brace depth is
/// tracked so a rule is attributed to the chain that contains it; a chain counts
/// as denying if its header is `policy drop` or its body has any `drop`/`reject`
/// verdict (catch-all or targeted - see [`NftInput::DefaultDeny`]).
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

/// Classify the INPUT-chain posture of `iptables -S` output, reusing
/// [`NftInput`]. This covers the iptables-legacy backend that
/// [`nft_input_policy`] cannot see. `iptables -S` prints one directive per line:
/// a policy `-P INPUT DROP|ACCEPT` and rules `-A INPUT ... -j TARGET`. Mirroring
/// the lenient nft classifier, the chain "denies" if its policy is `DROP`/`REJECT`
/// or any INPUT rule has a `DROP`/`REJECT` verdict (targeted or catch-all - we
/// would rather not false-fail a real firewall). Targets stay UPPERCASE (unlike
/// nft), so tokens are matched as-is.
///
/// A subtlety guards against a false positive: an nft-native host still lists the
/// legacy tables with a bare `-P INPUT ACCEPT` and **no** INPUT rules. That is
/// inconclusive (nft is likely the active backend), so a bare accept policy with
/// zero INPUT rules is treated as [`NftInput::NoInputHook`] (defer), not
/// `AcceptAll`. `AcceptAll` is reported only when the legacy INPUT chain is
/// actually populated (≥1 `-A INPUT` rule) yet nothing denies. Empty output →
/// [`NftInput::NoRuleset`].
pub fn iptables_input_policy(output: &str) -> NftInput {
    if output.trim().is_empty() {
        return NftInput::NoRuleset;
    }
    let mut denies = false;
    let mut input_rules = 0usize;
    for line in output.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        // Policy: `-P INPUT DROP|ACCEPT`.
        if t.len() >= 3 && t[0] == "-P" && t[1] == "INPUT" {
            if matches!(t[2], "DROP" | "REJECT") {
                denies = true;
            }
            continue;
        }
        // Rule targeting the INPUT chain: `-A INPUT ... -j DROP|REJECT`.
        if t.len() >= 2 && t[0] == "-A" && t[1] == "INPUT" {
            input_rules += 1;
            if t.iter().any(|&x| x == "DROP" || x == "REJECT") {
                denies = true;
            }
        }
    }
    if denies {
        NftInput::DefaultDeny
    } else if input_rules > 0 {
        // Legacy INPUT chain is populated but nothing denies -> open.
        NftInput::AcceptAll
    } else {
        // Only a bare policy (or unrelated chains): inconclusive -> defer.
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
    fn parses_proc_mounts() {
        let out = "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n\
                   tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n\
                   tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n\
                   garbage\n";
        let m = parse_proc_mounts(out);
        assert_eq!(
            m.get("/dev/shm").unwrap(),
            &vec!["rw".to_string(), "nosuid".to_string(), "nodev".to_string()]
        );
        assert!(m.get("/tmp").unwrap().contains(&"noexec".to_string()));
        assert!(!m.contains_key("garbage")); // short line skipped
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
    fn shadow_weak_hashes() {
        // `desuser` carries a 13-char traditional DES crypt hash.
        let out = "root:$6$abc$hash:19000:0:99999:7:::\n\
                   sha256:$5$abc$hash:19000:0:99999:7:::\n\
                   bcrypt:$2b$10$abcdefghijklmnopqrstuv:19000:0:99999:7:::\n\
                   md5user:$1$Xy9z8W7v$0123456789AbCdEfGhIjK.:19000:0:99999:7:::\n\
                   desuser:abcABC123./xy:19000:0:99999:7:::\n\
                   locked:!:19000:0:99999:7:::\n\
                   nopass::19000:0:99999:7:::\n";
        let weak = shadow_weak_hash_accounts(out);
        assert_eq!(
            weak,
            vec![
                ("md5user".to_string(), "MD5"),
                ("desuser".to_string(), "DES"),
            ]
        );
        // Strong hashes, locked and empty accounts are not weak-hash findings.
        assert!(shadow_weak_hash_accounts("root:$6$x$h:19000::::::\n").is_empty());
    }

    #[test]
    fn shadow_nonexpiring_passwords() {
        let out = "root:$6$abc$hash:19700:0:99999:7:::\n\
                   alice:$6$def$hash:19700:0:90:7:::\n\
                   bob:$6$ghi$hash:19700:0::7:::\n\
                   carol:$6$jkl$hash:19700:0:500:7:::\n\
                   daemon:*:19700:0:99999:7:::\n\
                   sshd:!:19700:0:99999:7:::\n\
                   nopass::19700:0:99999:7:::\n";
        let flagged = shadow_nonexpiring_password_accounts(out, 365);
        // root (99999 -> never), bob (unset), carol (500 > 365); NOT alice (90),
        // NOT locked/disabled/empty accounts.
        assert_eq!(
            flagged,
            vec![
                ("root".to_string(), "99999 (never)".to_string()),
                ("bob".to_string(), "unset".to_string()),
                ("carol".to_string(), "500".to_string()),
            ]
        );
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

    #[test]
    fn iptables_policy_drop_is_default_deny() {
        let out = "-P INPUT DROP\n\
                   -P FORWARD DROP\n\
                   -P OUTPUT ACCEPT\n\
                   -A INPUT -i lo -j ACCEPT\n\
                   -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n";
        assert_eq!(iptables_input_policy(out), NftInput::DefaultDeny);
    }

    #[test]
    fn iptables_accept_policy_with_final_drop_is_default_deny() {
        // Default-accept policy but a catch-all DROP rule at the end.
        let out = "-P INPUT ACCEPT\n\
                   -A INPUT -p tcp --dport 22 -j ACCEPT\n\
                   -A INPUT -j DROP\n";
        assert_eq!(iptables_input_policy(out), NftInput::DefaultDeny);
    }

    #[test]
    fn iptables_accept_policy_no_deny_is_accept_all() {
        let out = "-P INPUT ACCEPT\n\
                   -P OUTPUT ACCEPT\n\
                   -A INPUT -p tcp --dport 22 -j ACCEPT\n";
        assert_eq!(iptables_input_policy(out), NftInput::AcceptAll);
    }

    #[test]
    fn iptables_no_input_chain_and_empty() {
        assert_eq!(iptables_input_policy(""), NftInput::NoRuleset);
        // Only FORWARD/OUTPUT mentioned -> nothing guards INPUT.
        let out = "-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A FORWARD -j DROP\n";
        assert_eq!(iptables_input_policy(out), NftInput::NoInputHook);
    }

    #[test]
    fn iptables_bare_accept_policy_defers() {
        // nft-native host: legacy tables list a bare accept policy with no INPUT
        // rules -> inconclusive, defer (not a false AcceptAll).
        let out = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n";
        assert_eq!(iptables_input_policy(out), NftInput::NoInputHook);
    }
}
