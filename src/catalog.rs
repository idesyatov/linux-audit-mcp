//! Read-only command catalog for Linux audits.
//!
//! This is the core of the read-only guarantee. On a general-purpose Linux shell
//! a charset filter alone is not enough to prove a command is read-only, so every
//! command a check issues must be an *exact* member of a curated catalog. Anything
//! not in the catalog is refused before it is ever sent.
//!
//! Two layers, deny by default:
//!   1. a positive character set, so shell metacharacters that could chain or
//!      inject a second command (`; & | ` $ < > ( ) * ? ' "` ...) can never
//!      appear (the remote sshd still runs the command through a login shell);
//!   2. exact membership in [`READONLY_COMMANDS`] - the only commands allowed.
//!
//! Keep the remote vocabulary tiny: prefer dumb readers (`cat <fixed file>`,
//! `sysctl -a`, `ss -tuln`) and do all parsing in Rust. Fewer commands means a
//! smaller, auditable surface. The only root-requiring readers are the explicit
//! `sudo -n ...` entries, sent solely to targets opted in with `privileged`.
//!
//! Wired into the SSH transport ([`crate::ssh`]) and consumed by the audit
//! checks ([`crate::checks`]).
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
    // Mounted filesystems + their options; read-only view of the kernel's mount
    // table (checked for nosuid/nodev/noexec on sensitive tmpfs mounts).
    "cat /proc/mounts",
    "ss -tuln",
    "systemctl list-unit-files --type=service --no-pager",
    // `-s` (simulate) performs no actions and needs no root - read-only.
    "apt-get -s upgrade",
    // RHEL/dnf equivalent: list pending security advisories. Read-only, exits 0
    // (unlike `check-update`, which exits 100 when updates exist).
    "dnf -q updateinfo list security",
    "uname -a",
    // Operational health probes: all unprivileged, read-only snapshots.
    "uptime",
    "nproc",
    "free -b",
    "df -P",
    // Inode usage per filesystem (`-i`); a disk with free space but no free inodes
    // still can't create files. Portable (`-P`) columns match `df -P`.
    "df -Pi",
    "ps -eo pid,comm,pcpu,pmem --sort=-pcpu",
    // Process state codes only (`stat`), one per line, no header. The STAT field's
    // leading letter is the state; `Z` marks a zombie (a dead child not reaped by
    // its parent). Kept separate from the hot-process `ps` so the zombie count and
    // the top-CPU/MEM listing can't break each other.
    "ps -eo stat --no-headers",
    "ss -s",
    // System-wide open file descriptors: `allocated  unused  max`. Nearing the max
    // means "too many open files" for new sockets/files.
    "cat /proc/sys/fs/file-nr",
    // Netfilter connection-tracking table: current count and max. A full table
    // ("nf_conntrack: table full") drops new connections - a NAT/firewall/proxy
    // outage. Both files vanish when the module isn't loaded (then: Unknown).
    "cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max",
    // TCP socket/memory pressure: /proc/net/sockstat (TCP mem pages, orphan and
    // TIME_WAIT counts) plus their ceilings (tcp_mem max, tcp_max_orphans,
    // tcp_max_tw_buckets). Nearing any ceiling drops/throttles connections.
    "cat /proc/net/sockstat /proc/sys/net/ipv4/tcp_mem /proc/sys/net/ipv4/tcp_max_orphans /proc/sys/net/ipv4/tcp_max_tw_buckets",
    // Task saturation: /proc/loadavg (its 4th field is running/total tasks) and the
    // PID ceiling. Near the ceiling, fork()/clone() fail and nothing new can start.
    "cat /proc/loadavg /proc/sys/kernel/pid_max",
    // Network interface counters; sampled twice to derive throughput.
    "cat /proc/net/dev",
    // TCP extended counters; sampled twice for the accept-queue overflow rate
    // (ListenOverflows/ListenDrops) - the server failing to accept connections.
    "cat /proc/net/netstat",
    // Netfilter conntrack per-CPU stat counters (drop/early_drop/insert_failed);
    // sampled twice for the connection-drop rate. `early_drop` rising means the
    // table was full enough to evict entries - the NAT/firewall/proxy dropping
    // connections. Unprivileged, read-only.
    "cat /proc/net/stat/nf_conntrack",
    // TCP stack pressure counters (SNMP MIB); sampled twice for the error rate.
    // /proc/net/snmp holds `Tcp: RetransSegs` (retransmits) for context;
    // /proc/net/netstat holds `TcpExt:` TCPAbortOnMemory/PruneCalled/TCPRcvQDrop -
    // the stack shedding connections under memory/backlog pressure. Unprivileged.
    "cat /proc/net/snmp",
    // System time state (health-clock-sync): `NTPSynchronized=yes/no`. An unsynced
    // clock breaks TLS validity windows, log correlation and time-based auth.
    "timedatectl show",
    // /run listing (health-reboot-required): the Debian/Ubuntu `reboot-required`
    // flag file lives here after a kernel/library update. `/run` always exists, so
    // this exits 0; read-only.
    "ls /run",
    // CPU/IO pressure: `1 2` = one 1-second sample; the last row is
    // the current delta. Unprivileged and read-only.
    "vmstat 1 2",
    // Failed systemd services: a zero-config "something is broken" signal.
    // `--no-legend`/`--no-pager` give a clean, script-parseable list.
    "systemctl list-units --type=service --state=failed --no-legend --no-pager",
    // Container state: crash-looping (`Restarting`) or failing-healthcheck
    // (`unhealthy`) containers are a zero-config "a service is broken" signal.
    // `-a` lists all states, so a container caught mid-backoff is still seen. Both
    // runtimes are probed; a missing one just errors and is ignored.
    "docker ps -a",
    "podman ps -a",
    // Privileged read-only checks (run only on targets opted in with
    // `privileged = true`; the operator grants NOPASSWD sudo for exactly these).
    // `sudo -n` never prompts - it fails fast if not permitted.
    "sudo -n cat /etc/shadow",
    // Kernel ring buffer (health): the OOM-killer logs `Out of memory: Killed
    // process ...` here. Root-only when `kernel.dmesg_restrict=1` (the common
    // default), hence the `sudo -n` form. `dmesg` with no args only prints.
    "sudo -n dmesg",
    // SUID-root binaries. `-xdev` keeps the scan on the root filesystem (never
    // descending into other mounts or pseudo-filesystems like /proc, /sys), so it
    // is bounded and can't hang on a network mount. A transient per-path error
    // sets a non-zero exit; the SUID check opts into tolerating that (partial
    // stdout is still authoritative for what was found). Read-only: `find`
    // without an action only prints.
    "sudo -n find / -xdev -perm -4000 -type f",
    // World-writable regular files on the root filesystem (`-perm -0002`, `-type f`).
    // A world-writable file anyone can overwrite is a tampering/backdoor vector;
    // `-type f` skips world-writable dirs (e.g. sticky /tmp), which are benign.
    // Same `-xdev`/tolerate-nonzero discipline as the SUID scan.
    "sudo -n find / -xdev -type f -perm -0002",
    // World-writable cron drop-in directories: a writable /etc/cron.d (etc.) lets
    // any local user schedule a root command. Literal paths (no glob, which the
    // catalog forbids); `-type d` so this doesn't overlap the world-writable-files
    // scan. Missing paths just error per-path (tolerated); read-only.
    "sudo -n find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -type d -perm -0002",
    // Effective SSH config: `sshd -T` dumps the *resolved* directives (compiled
    // defaults + Match blocks). On an opted-in target its output supersedes the
    // file read for every ssh-domain check, making them authoritative.
    "sudo -n sshd -T",
    // Live nftables ruleset: the effective inbound firewall posture (ufw,
    // firewalld and raw nft all render here). Root-only; read-only dump.
    "sudo -n nft list ruleset",
    // Live iptables-legacy ruleset (`-S` = dump rules, no counters). Covers hosts
    // on the xtables backend that `nft list ruleset` can't see. Root-only; read-only.
    "sudo -n iptables -S",
    // Container state as root: on many hosts `docker`/`podman` need root or
    // docker-group membership, so the unprivileged `docker ps -a` returns nothing
    // and the health metric goes blind. On an opted-in target these authoritative
    // variants supersede the plain read for `health-containers`.
    "sudo -n docker ps -a",
    "sudo -n podman ps -a",
];

/// Characters permitted in a command. A positive character set (not a denylist)
/// guarantees no metacharacter that could chain or inject a command can appear.
fn is_allowed_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || " /-_.=,:".contains(c)
}

/// Fixed prefix/suffix of the parameterized certificate-expiry read.
const CERT_READ_PREFIX: &str = "openssl x509 -in ";
const CERT_READ_SUFFIX: &str = " -noout -enddate";

/// `true` if `command` is a certificate-expiry read for a single absolute path
/// (`openssl x509 -in <path> -noout -enddate`). This is the one parameterized
/// command the catalog allows: operator-configured `cert_paths` vary per host, so a
/// fixed per-path entry is impossible. It stays safe because the prefix/suffix are
/// fixed, `openssl x509 ... -noout -enddate` only prints (read-only), the global
/// charset check already forbids every shell metacharacter, and the path must be
/// absolute with no `..` traversal or embedded space.
fn is_cert_read(command: &str) -> bool {
    let Some(rest) = command.strip_prefix(CERT_READ_PREFIX) else {
        return false;
    };
    let Some(path) = rest.strip_suffix(CERT_READ_SUFFIX) else {
        return false;
    };
    path.starts_with('/') && !path.contains("..") && !path.contains(' ')
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
    // The one parameterized command: a certificate-expiry read for a configured
    // absolute path (the exact-membership list can't enumerate per-host paths).
    if is_cert_read(cmd) {
        return Ok(());
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
        // Charset-clean, but not read-only / not listed -> refused.
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

    #[test]
    fn allows_cert_read_for_absolute_paths_only() {
        // A cert-expiry read for an absolute path is allowed (parameterized).
        assert!(is_allowed(
            "openssl x509 -in /etc/letsencrypt/live/example.com/fullchain.pem -noout -enddate"
        ));
        assert!(is_allowed(
            "openssl x509 -in /etc/ssl/certs/site.pem -noout -enddate"
        ));
        // Relative path, `..` traversal, or a different openssl subcommand: rejected.
        assert!(!is_allowed(
            "openssl x509 -in etc/ssl/site.pem -noout -enddate"
        ));
        assert!(!is_allowed(
            "openssl x509 -in /etc/ssl/../shadow -noout -enddate"
        ));
        assert!(!is_allowed("openssl x509 -in /etc/ssl/site.pem -text"));
        assert!(!is_allowed(
            "openssl req -in /etc/ssl/site.pem -noout -enddate"
        ));
        // Chars are still enforced first: a metacharacter never reaches is_cert_read.
        assert!(matches!(
            validate("openssl x509 -in /etc/ssl/a;b.pem -noout -enddate"),
            Err(CatalogError::IllegalCharacter(';'))
        ));
    }
}
