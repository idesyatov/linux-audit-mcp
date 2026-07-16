//! Tolerant parsers for Linux command output.
//!
//! Pure functions over text captured via SSH, so checks are unit-tested against
//! fixtures without a host. Keeping the remote vocabulary to dumb readers (see
//! [`crate::catalog`]) means all structure is recovered here, in Rust.

use std::collections::HashMap;

/// Parse whitespace-separated `KEY value` config — the shape of `sshd_config`,
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
/// the `unit state …` shape and are skipped.
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
}
