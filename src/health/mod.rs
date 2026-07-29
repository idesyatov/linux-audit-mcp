//! Operational-health probes: a point-in-time snapshot of load, memory, disk,
//! hot processes and socket counts over the same read-only SSH channel as the
//! security audit.
//!
//! Deliberately kept separate from [`crate::checks`]/[`crate::scoring`]: health
//! is momentary and workload-dependent, not a hardening fact, so it produces
//! `Ok`/`Warn`/`Crit` metrics against thresholds and never feeds the 0-100
//! security score. Baselining and anomaly detection over the recorded history
//! live in [`crate::anomaly`] (wired in by [`crate::run::annotate_anomalies`]).

pub mod parse;
pub mod report;

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::audit::{CmdError, Outputs};
use crate::ssh::{SshConfig, SshError};
use parse::ProcInfo;

const UPTIME: &str = "uptime";
const NPROC: &str = "nproc";
const FREE: &str = "free -b";
const DF: &str = "df -P";
/// Inode usage (`-i`); portable columns identical to [`DF`], so [`parse::parse_df`]
/// reads it too (the percent is the same column).
const DF_INODES: &str = "df -Pi";
/// System-wide open file descriptors: `allocated  unused  max`.
const FILE_NR: &str = "cat /proc/sys/fs/file-nr";
/// Netfilter conntrack table: current `count` then `max` (two lines). Absent when
/// the module isn't loaded.
const CONNTRACK: &str =
    "cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max";
/// Task saturation: `/proc/loadavg` (running/total tasks) then the PID ceiling.
const PIDS: &str = "cat /proc/loadavg /proc/sys/kernel/pid_max";
/// TCP socket/memory pressure: `/proc/net/sockstat` then the three ceilings
/// (`tcp_mem`, `tcp_max_orphans`, `tcp_max_tw_buckets`), in that order.
const SOCKSTAT: &str =
    "cat /proc/net/sockstat /proc/sys/net/ipv4/tcp_mem /proc/sys/net/ipv4/tcp_max_orphans /proc/sys/net/ipv4/tcp_max_tw_buckets";
const PS: &str = "ps -eo pid,comm,pcpu,pmem --sort=-pcpu";
/// Process state codes (`stat`), one per line. A leading `Z` marks a zombie.
/// Separate from [`PS`] so the zombie count and the hot-process listing are
/// independently parsed (a change to one can't regress the other).
const PS_STAT: &str = "ps -eo stat --no-headers";
const SS: &str = "ss -s";
/// `1 2` = one 1-second sample; vmstat does its own timing, so this is a normal
/// single-shot command whose last row is the current delta (parsed in [`evaluate`]).
const VMSTAT: &str = "vmstat 1 2";
/// Failed systemd services - a zero-config "something is broken" signal.
const SYSTEMCTL_FAILED: &str =
    "systemctl list-units --type=service --state=failed --no-legend --no-pager";
/// Container state via docker and podman (either may be absent). `-a` lists all
/// states so a crash-looping container caught mid-backoff is still seen.
const DOCKER_PS: &str = "docker ps -a";
const PODMAN_PS: &str = "podman ps -a";
/// Privileged variants: on many hosts `docker`/`podman` need root or docker-group
/// membership, so the plain command returns nothing and the metric goes blind. On
/// a `privileged` target these are tried first (see [`container_command`]).
const SUDO_DOCKER_PS: &str = "sudo -n docker ps -a";
const SUDO_PODMAN_PS: &str = "sudo -n podman ps -a";
/// Kernel ring buffer, for OOM-killer events. Privileged-only (`dmesg_restrict`
/// is on by default), so it is sent solely to `privileged` targets; elsewhere the
/// metric reports `Unknown`.
const OOM_DMESG: &str = "sudo -n dmesg";
/// Sampled twice (not single-shot) to derive throughput and error rate, so it is
/// handled apart from [`SINGLE_SHOT`] in [`collect`] and yields no metric in
/// [`evaluate`].
const NETDEV: &str = "cat /proc/net/dev";
/// TCP extended counters; sampled twice (alongside [`NETDEV`]) for the
/// accept-queue overflow rate. Handled in [`collect`], not [`evaluate`].
const NETSTAT: &str = "cat /proc/net/netstat";
/// Netfilter conntrack per-CPU stat counters; sampled twice (alongside
/// [`NETDEV`]) for the connection-drop rate. Handled in [`collect`], not
/// [`evaluate`]. Unprivileged.
const CONNTRACK_STAT: &str = "cat /proc/net/stat/nf_conntrack";
/// TCP SNMP MIB counters (`Tcp: RetransSegs`); sampled twice (alongside
/// [`NETDEV`]) for the retransmit rate shown as context on `health-tcp-errors`.
/// Handled in [`collect`], not [`evaluate`]. Unprivileged.
const SNMP: &str = "cat /proc/net/snmp";
/// systemd time state (`health-clock-sync`); `NTPSynchronized=yes/no`. Unprivileged.
const TIMEDATECTL: &str = "timedatectl show";
/// `/run` listing (`health-reboot-required`); the Debian/Ubuntu `reboot-required`
/// flag file lives here. `/run` always exists, so this exits 0. Unprivileged.
const LS_RUN: &str = "ls /run";
/// Mount table (`health-fs-readonly`); a `/dev/*` filesystem mounted `ro` means the
/// kernel remounted it read-only after disk errors. Already in the catalog (shared
/// with the `kernel-mount-options` security check). Unprivileged.
const PROC_MOUNTS: &str = "cat /proc/mounts";

/// Commands snapped exactly once per snapshot.
const SINGLE_SHOT: &[&str] = &[
    UPTIME,
    NPROC,
    FREE,
    DF,
    DF_INODES,
    FILE_NR,
    CONNTRACK,
    PIDS,
    SOCKSTAT,
    PS,
    PS_STAT,
    SS,
    VMSTAT,
    SYSTEMCTL_FAILED,
    OOM_DMESG,
    DOCKER_PS,
    PODMAN_PS,
    TIMEDATECTL,
    LS_RUN,
    PROC_MOUNTS,
];

/// Every read-only command the health snapshot may issue (each must be in the
/// catalog; see the invariant test). Consumed only by the invariant test and
/// evals; the run path uses [`SINGLE_SHOT`] plus [`NETDEV`].
#[allow(dead_code)]
pub const HEALTH_COMMANDS: &[&str] = &[
    UPTIME,
    NPROC,
    FREE,
    DF,
    DF_INODES,
    FILE_NR,
    CONNTRACK,
    PIDS,
    SOCKSTAT,
    PS,
    PS_STAT,
    SS,
    VMSTAT,
    SYSTEMCTL_FAILED,
    OOM_DMESG,
    DOCKER_PS,
    PODMAN_PS,
    SUDO_DOCKER_PS,
    SUDO_PODMAN_PS,
    NETDEV,
    NETSTAT,
    CONNTRACK_STAT,
    SNMP,
    TIMEDATECTL,
    LS_RUN,
    PROC_MOUNTS,
];

/// The wire command for a container probe: on a `privileged` target the `sudo -n`
/// variant is authoritative (many hosts need root/docker-group to run the CLI);
/// otherwise the plain command. Returns `(preferred, fallback)` - the fallback is
/// the plain command, tried if the privileged read fails (a missing sudo grant
/// must not regress a host where the plain command already worked). A non-privileged
/// target has no fallback.
fn container_command(cmd: &str, privileged: bool) -> (&'static str, Option<&'static str>) {
    match (cmd, privileged) {
        (DOCKER_PS, true) => (SUDO_DOCKER_PS, Some(DOCKER_PS)),
        (PODMAN_PS, true) => (SUDO_PODMAN_PS, Some(PODMAN_PS)),
        (DOCKER_PS, false) => (DOCKER_PS, None),
        (PODMAN_PS, false) => (PODMAN_PS, None),
        _ => (DOCKER_PS, None), // unreachable: only called for the two container cmds
    }
}

/// A metric's verdict against its thresholds. `Unknown` means the input was
/// missing or unparseable - it never counts toward the overall status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Ok,
    Warn,
    Crit,
    Unknown,
}

impl HealthStatus {
    /// Rank for picking the worst status (Unknown is neutral).
    fn rank(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Ok => 1,
            Self::Warn => 2,
            Self::Crit => 3,
        }
    }

    /// Short uppercase tag for text reports (`OK`/`WARN`/`CRIT`/`UNKN`).
    pub fn tag(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Crit => "CRIT",
            Self::Unknown => "UNKN",
        }
    }
}

/// A single health reading.
#[derive(Debug, Clone, Serialize)]
pub struct Metric {
    pub id: &'static str,
    pub title: &'static str,
    pub status: HealthStatus,
    /// Human-readable measured value.
    pub value: String,
    /// Extra context (worst mount, thresholds crossed, ...).
    pub detail: String,
    /// Primary numeric reading, if this metric has one (load per core, memory
    /// percent, worst-disk percent, ...). Used only to persist history
    /// ([`crate::history`]); skipped in the report JSON so the wire format and
    /// the evals stay unchanged. `None` for `Unknown` metrics.
    #[serde(skip)]
    pub numeric: Option<f64>,
}

/// A metric reading that deviates from this host's *own* recent norm, detected
/// by comparing the current value against a robust baseline (median + MAD) over
/// the stored history (see [`crate::anomaly`]).
///
/// Purely informational: an anomaly reflects an unusual workload, not a
/// hardening regression, so it never changes `overall` nor the exit code.
#[derive(Debug, Clone, Serialize)]
pub struct Anomaly {
    pub metric_id: String,
    /// The current reading.
    pub current: f64,
    /// Robust baseline: median of the recent history window.
    pub median: f64,
    /// Signed change versus the baseline, in percent.
    pub pct_change: f64,
    /// Modified z-score: deviation from the median in scaled-MAD units.
    pub z: f64,
}

/// The full operational-health snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct HealthReport {
    pub metrics: Vec<Metric>,
    pub top_cpu: Vec<ProcInfo>,
    pub top_mem: Vec<ProcInfo>,
    /// Worst status across all metrics (`Unknown` if nothing could be measured).
    pub overall: HealthStatus,
    /// Metrics that deviate from this host's recent norm. Empty when nothing is
    /// anomalous, detection is disabled, or the baseline is still warming up.
    /// Filled in after collection by [`crate::run::annotate_anomalies`].
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub anomalies: Vec<Anomaly>,
    /// Human note when no detection ran (disabled, or baseline warming up); a
    /// transparency hint so an empty `anomalies` is never ambiguous.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anomaly_note: Option<String>,
    /// Between-run changes versus this host's previous snapshot: a container that
    /// restarted (its uptime dropped) or a systemd unit that newly failed. Filled
    /// in after collection by [`crate::run::annotate_changes`]. Informational -
    /// like anomalies, it never changes `overall` nor the exit code.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<String>,
    /// Running containers -> coarse uptime (seconds), carried to the stored
    /// history so the next run can spot a restart (uptime dropping). Internal
    /// state, not part of the wire report.
    #[serde(skip)]
    pub container_uptimes: BTreeMap<String, u64>,
    /// Currently-failed systemd units, carried to history so the next run can
    /// flag a unit that newly failed. Internal state, not part of the wire report.
    #[serde(skip)]
    pub failed_units: Vec<String>,
    /// Cumulative since-boot event counters (conntrack table-pressure total, kernel
    /// log event counts per category), carried to history so the next run can report
    /// how many new events accrued since the last check. Internal state, not part of
    /// the wire report.
    #[serde(skip)]
    pub event_counters: BTreeMap<String, u64>,
}

/// Thresholds for turning raw readings into `Ok`/`Warn`/`Crit`. Each field has a
/// sensible default; a target may override any subset via `[targets.x.health]`.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Thresholds {
    /// 1-minute load average per core.
    pub la_per_core_warn: f64,
    pub la_per_core_crit: f64,
    /// Memory in use (percent).
    pub mem_used_warn_pct: u8,
    pub mem_used_crit_pct: u8,
    /// Swap in use (percent).
    pub swap_used_warn_pct: u8,
    pub swap_used_crit_pct: u8,
    /// Filesystem capacity (percent). Also bounds inode usage (`health-inodes`) -
    /// both are "this filesystem is filling up", just blocks vs inodes.
    pub disk_warn_pct: u8,
    pub disk_crit_pct: u8,
    /// Open file descriptors as a percent of the system-wide max (`health-fd`).
    pub fd_warn_pct: u8,
    pub fd_crit_pct: u8,
    /// Conntrack table fill as a percent of `nf_conntrack_max` (`health-conntrack`).
    pub conntrack_warn_pct: u8,
    pub conntrack_crit_pct: u8,
    /// Kernel tasks as a percent of `pid_max` (`health-pids`).
    pub pid_warn_pct: u8,
    pub pid_crit_pct: u8,
    /// Worst of TCP memory / orphan / TIME_WAIT usage as a percent of its ceiling
    /// (`health-tcp-mem`).
    pub tcp_warn_pct: u8,
    pub tcp_crit_pct: u8,
    /// CPU time waiting on I/O (`wa`, percent); a sustained high value means the
    /// host is disk-bound.
    pub iowait_warn_pct: f64,
    pub iowait_crit_pct: f64,
    /// Per-interface network throughput (MiB/s). `0` disables that bound, so
    /// network is informational (always `Ok`) unless a threshold is set.
    pub net_rx_warn_mibps: f64,
    pub net_rx_crit_mibps: f64,
    pub net_tx_warn_mibps: f64,
    pub net_tx_crit_mibps: f64,
    /// Interface error+drop rate (packets/s) over the sample window. Errors/drops
    /// on a healthy NIC are ~0, so a low bound is meaningful; a bad link/driver
    /// or saturated queue shows a sustained nonzero rate.
    pub net_err_warn_pps: f64,
    pub net_err_crit_pps: f64,
    /// TCP accept-queue overflow rate (events/s) over the sample window. A healthy
    /// server accepts fast enough that this stays 0; a sustained rate means the
    /// listen backlog is overflowing and connections are being dropped.
    pub listen_overflow_warn_pps: f64,
    pub listen_overflow_crit_pps: f64,
    /// Conntrack connection-drop rate (events/s) over the sample window
    /// (`health-conntrack-drops`). A healthy host holds this at 0; a sustained
    /// rate means the conntrack table is full and dropping connections.
    pub conntrack_drop_warn_pps: f64,
    pub conntrack_drop_crit_pps: f64,
    /// TCP stack error rate (events/s) over the sample window (`health-tcp-errors`).
    /// Gates on memory/backlog-pressure counters (TCPAbortOnMemory + PruneCalled +
    /// TCPRcvQDrop), which hold at 0 on a healthy host; retransmits are noisy on any
    /// internet-facing host and are shown as context only, never gated.
    pub tcp_err_warn_pps: f64,
    pub tcp_err_crit_pps: f64,
    /// Days until the nearest configured TLS certificate expires (`health-cert-expiry`).
    /// At/below `warn` → Warn, at/below `crit` (or already expired) → Crit.
    pub cert_expiry_warn_days: i64,
    pub cert_expiry_crit_days: i64,
    /// Gap between the two `/proc/net/dev` samples, in seconds.
    pub net_sample_secs: u64,
    /// Failed systemd services: any failed unit is a `Warn`; this many or more
    /// escalate to `Crit`. `0` disables the escalation (failed units stay `Warn`),
    /// which is the default - a single benign oneshot failure shouldn't be `Crit`.
    pub failed_units_crit: u32,
    /// Zombie (defunct) processes: any zombie is a `Warn`; this many or more
    /// escalate to `Crit`. `0` disables the escalation (zombies stay `Warn`),
    /// which is the default - a transient zombie mid-reap shouldn't be `Crit`.
    pub zombie_crit: u32,
    /// How many hot processes to list per resource.
    pub top_n: usize,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            la_per_core_warn: 1.0,
            la_per_core_crit: 2.0,
            mem_used_warn_pct: 85,
            mem_used_crit_pct: 95,
            swap_used_warn_pct: 50,
            swap_used_crit_pct: 90,
            disk_warn_pct: 85,
            disk_crit_pct: 95,
            fd_warn_pct: 80,
            fd_crit_pct: 95,
            conntrack_warn_pct: 80,
            conntrack_crit_pct: 90,
            pid_warn_pct: 80,
            pid_crit_pct: 90,
            tcp_warn_pct: 80,
            tcp_crit_pct: 90,
            iowait_warn_pct: 20.0,
            iowait_crit_pct: 50.0,
            net_rx_warn_mibps: 0.0,
            net_rx_crit_mibps: 0.0,
            net_tx_warn_mibps: 0.0,
            net_tx_crit_mibps: 0.0,
            net_err_warn_pps: 1.0,
            net_err_crit_pps: 10.0,
            listen_overflow_warn_pps: 1.0,
            listen_overflow_crit_pps: 10.0,
            conntrack_drop_warn_pps: 1.0,
            conntrack_drop_crit_pps: 10.0,
            tcp_err_warn_pps: 1.0,
            tcp_err_crit_pps: 10.0,
            cert_expiry_warn_days: 21,
            cert_expiry_crit_days: 7,
            net_sample_secs: 1,
            failed_units_crit: 0,
            zombie_crit: 0,
            top_n: 5,
        }
    }
}

fn unknown(id: &'static str, title: &'static str, why: impl Into<String>) -> Metric {
    Metric {
        id,
        title,
        status: HealthStatus::Unknown,
        value: "n/a".to_string(),
        detail: why.into(),
        numeric: None,
    }
}

/// Ok/Warn/Crit for a value where higher is worse.
fn threshold_status(value: f64, warn: f64, crit: f64) -> HealthStatus {
    if value >= crit {
        HealthStatus::Crit
    } else if value >= warn {
        HealthStatus::Warn
    } else {
        HealthStatus::Ok
    }
}

fn out<'a>(outputs: &'a Outputs, cmd: &str) -> Option<&'a str> {
    match outputs.get(cmd) {
        Some(Ok(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn load_metric(outputs: &Outputs, thr: &Thresholds) -> Metric {
    const ID: &str = "health-load";
    const TITLE: &str = "Load average";
    let (Some(up), Some(np)) = (out(outputs, UPTIME), out(outputs, NPROC)) else {
        return unknown(ID, TITLE, "uptime/nproc unavailable");
    };
    let Some(la) = parse::parse_load_average(up) else {
        return unknown(ID, TITLE, "could not parse load average");
    };
    let Some(cores) = parse::parse_nproc(np).filter(|&c| c > 0) else {
        return unknown(ID, TITLE, "could not parse cpu count");
    };
    let per_core = la[0] / cores as f64;
    Metric {
        id: ID,
        title: TITLE,
        status: threshold_status(per_core, thr.la_per_core_warn, thr.la_per_core_crit),
        value: format!("{per_core:.2} per core"),
        detail: format!(
            "1m {:.2}, 5m {:.2}, 15m {:.2} over {cores} core(s)",
            la[0], la[1], la[2]
        ),
        numeric: Some(per_core),
    }
}

fn memory_metrics(outputs: &Outputs, thr: &Thresholds) -> Vec<Metric> {
    const MEM_ID: &str = "health-memory";
    const SWAP_ID: &str = "health-swap";
    let Some(free) = out(outputs, FREE).and_then(parse::parse_free) else {
        return vec![
            unknown(MEM_ID, "Memory usage", "free unavailable"),
            unknown(SWAP_ID, "Swap usage", "free unavailable"),
        ];
    };
    // Prefer `available` for real pressure; fall back to `used` on old procps.
    // One `used_bytes` drives both the percent and the detail so they agree.
    let used_bytes = if free.mem_available > 0 {
        free.mem_total.saturating_sub(free.mem_available)
    } else {
        free.mem_used
    };
    let mem_used_pct = if free.mem_total == 0 {
        0.0
    } else {
        used_bytes as f64 / free.mem_total as f64 * 100.0
    };
    let mem = Metric {
        id: MEM_ID,
        title: "Memory usage",
        status: threshold_status(
            mem_used_pct,
            thr.mem_used_warn_pct as f64,
            thr.mem_used_crit_pct as f64,
        ),
        value: format!("{mem_used_pct:.0}% used"),
        detail: format!(
            "{} of {} in use (available {})",
            human_bytes(used_bytes),
            human_bytes(free.mem_total),
            human_bytes(free.mem_available)
        ),
        numeric: Some(mem_used_pct),
    };
    let swap = if free.swap_total == 0 {
        Metric {
            id: SWAP_ID,
            title: "Swap usage",
            status: HealthStatus::Ok,
            value: "no swap".to_string(),
            detail: "no swap configured".to_string(),
            numeric: Some(0.0),
        }
    } else {
        let swap_pct = free.swap_used as f64 / free.swap_total as f64 * 100.0;
        Metric {
            id: SWAP_ID,
            title: "Swap usage",
            status: threshold_status(
                swap_pct,
                thr.swap_used_warn_pct as f64,
                thr.swap_used_crit_pct as f64,
            ),
            value: format!("{swap_pct:.0}% used"),
            detail: format!(
                "{} of {} in use",
                human_bytes(free.swap_used),
                human_bytes(free.swap_total)
            ),
            numeric: Some(swap_pct),
        }
    };
    vec![mem, swap]
}

fn disk_metric(outputs: &Outputs, thr: &Thresholds) -> Metric {
    const ID: &str = "health-disk";
    const TITLE: &str = "Disk usage";
    let Some(mounts) = out(outputs, DF).map(parse::parse_df) else {
        return unknown(ID, TITLE, "df unavailable");
    };
    let Some(worst) = mounts.iter().max_by_key(|m| m.use_pct) else {
        return unknown(ID, TITLE, "no real filesystems reported");
    };
    let mut detail: Vec<String> = mounts
        .iter()
        .map(|m| format!("{} {}%", m.mount, m.use_pct))
        .collect();
    detail.sort();
    Metric {
        id: ID,
        title: TITLE,
        status: threshold_status(
            worst.use_pct as f64,
            thr.disk_warn_pct as f64,
            thr.disk_crit_pct as f64,
        ),
        value: format!("{}% on {}", worst.use_pct, worst.mount),
        detail: detail.join(", "),
        numeric: Some(worst.use_pct as f64),
    }
}

/// Inode usage per filesystem, from `df -Pi`. A filesystem can exhaust its inodes
/// while blocks are free (lots of tiny files), and then no file can be created -
/// so this is tracked alongside, but separately from, block capacity. Reuses the
/// disk thresholds (same "filesystem filling up" nature) and [`parse::parse_df`]
/// (the portable inode columns place the percent in the same position).
fn inodes_metric(outputs: &Outputs, thr: &Thresholds) -> Metric {
    const ID: &str = "health-inodes";
    const TITLE: &str = "Inode usage";
    let Some(mounts) = out(outputs, DF_INODES).map(parse::parse_df) else {
        return unknown(ID, TITLE, "df -i unavailable");
    };
    let Some(worst) = mounts.iter().max_by_key(|m| m.use_pct) else {
        return unknown(ID, TITLE, "no real filesystems reported");
    };
    let mut detail: Vec<String> = mounts
        .iter()
        .map(|m| format!("{} {}%", m.mount, m.use_pct))
        .collect();
    detail.sort();
    Metric {
        id: ID,
        title: TITLE,
        status: threshold_status(
            worst.use_pct as f64,
            thr.disk_warn_pct as f64,
            thr.disk_crit_pct as f64,
        ),
        value: format!("{}% on {}", worst.use_pct, worst.mount),
        detail: detail.join(", "),
        numeric: Some(worst.use_pct as f64),
    }
}

/// System-wide open file descriptors as a percent of the kernel max, from
/// `/proc/sys/fs/file-nr`. Nearing the max means new sockets/files fail with
/// "too many open files" - a fleet-wide outage cause independent of CPU/memory.
fn fd_metric(outputs: &Outputs, thr: &Thresholds) -> Metric {
    const ID: &str = "health-fd";
    const TITLE: &str = "Open file descriptors";
    let Some((allocated, max)) = out(outputs, FILE_NR).and_then(parse::parse_file_nr) else {
        return unknown(ID, TITLE, "file-nr unavailable");
    };
    if max == 0 {
        return unknown(ID, TITLE, "file-nr reports no maximum");
    }
    let pct = allocated as f64 / max as f64 * 100.0;
    Metric {
        id: ID,
        title: TITLE,
        status: threshold_status(pct, thr.fd_warn_pct as f64, thr.fd_crit_pct as f64),
        value: format!("{pct:.0}% used"),
        detail: format!("{allocated} of {max} file descriptors allocated"),
        numeric: Some(pct),
    }
}

/// Netfilter connection-tracking table fill, from `nf_conntrack_count` /
/// `nf_conntrack_max`. A full table drops new connections ("nf_conntrack: table
/// full") - a NAT/firewall/proxy outage that CPU and memory metrics miss. Absent
/// (module not loaded, e.g. a host with no connection tracking) reports `Unknown`.
fn conntrack_metric(outputs: &Outputs, thr: &Thresholds) -> Metric {
    const ID: &str = "health-conntrack";
    const TITLE: &str = "Conntrack table";
    let Some((count, max)) = out(outputs, CONNTRACK).and_then(parse::parse_conntrack) else {
        return unknown(ID, TITLE, "conntrack not available (module not loaded)");
    };
    if max == 0 {
        return unknown(ID, TITLE, "nf_conntrack_max is zero");
    }
    let pct = count as f64 / max as f64 * 100.0;
    Metric {
        id: ID,
        title: TITLE,
        status: threshold_status(
            pct,
            thr.conntrack_warn_pct as f64,
            thr.conntrack_crit_pct as f64,
        ),
        value: format!("{pct:.0}% used"),
        detail: format!("{count} of {max} tracked connections"),
        numeric: Some(pct),
    }
}

/// Task/PID saturation, from `/proc/loadavg` (total tasks) and `pid_max`. As tasks
/// approach the ceiling, `fork()`/`clone()` fail and nothing new can start (a
/// runaway thread/process leak or fork bomb) - independent of CPU/memory.
fn pids_metric(outputs: &Outputs, thr: &Thresholds) -> Metric {
    const ID: &str = "health-pids";
    const TITLE: &str = "Process/PID saturation";
    let Some((tasks, pid_max)) = out(outputs, PIDS).and_then(parse::parse_pid_usage) else {
        return unknown(ID, TITLE, "loadavg/pid_max unavailable");
    };
    if pid_max == 0 {
        return unknown(ID, TITLE, "pid_max is zero");
    }
    let pct = tasks as f64 / pid_max as f64 * 100.0;
    Metric {
        id: ID,
        title: TITLE,
        status: threshold_status(pct, thr.pid_warn_pct as f64, thr.pid_crit_pct as f64),
        value: format!("{pct:.0}% used"),
        detail: format!("{tasks} of {pid_max} max PIDs (tasks/threads)"),
        numeric: Some(pct),
    }
}

/// TCP socket/memory pressure, from `/proc/net/sockstat` and the kernel ceilings.
/// Reports the worst of three exhaustion modes: TCP memory (pages vs `tcp_mem`
/// max), orphaned sockets (vs `tcp_max_orphans`) and TIME_WAIT sockets (vs
/// `tcp_max_tw_buckets`). Any of them filling up drops or throttles connections -
/// a proxy/web outage independent of CPU and memory. Missing input -> `Unknown`.
fn tcp_mem_metric(outputs: &Outputs, thr: &Thresholds) -> Metric {
    const ID: &str = "health-tcp-mem";
    const TITLE: &str = "TCP memory/socket pressure";
    let Some(s) = out(outputs, SOCKSTAT).and_then(parse::parse_sockstat) else {
        return unknown(ID, TITLE, "sockstat/tcp limits unavailable");
    };
    if s.tcp_mem_max == 0 || s.max_orphans == 0 || s.max_tw == 0 {
        return unknown(ID, TITLE, "a TCP ceiling is zero");
    }
    let pct = |used: u64, max: u64| used as f64 / max as f64 * 100.0;
    let dims = [
        ("mem", pct(s.tcp_mem, s.tcp_mem_max)),
        ("orphan", pct(s.orphan, s.max_orphans)),
        ("tw", pct(s.tw, s.max_tw)),
    ];
    let (label, worst) = dims
        .iter()
        .copied()
        .fold(("mem", 0.0), |a, b| if b.1 > a.1 { b } else { a });
    Metric {
        id: ID,
        title: TITLE,
        status: threshold_status(worst, thr.tcp_warn_pct as f64, thr.tcp_crit_pct as f64),
        value: format!("{label} {worst:.0}% of limit"),
        detail: format!(
            "mem {}/{} ({:.0}%), orphan {}/{} ({:.0}%), tw {}/{} ({:.0}%)",
            s.tcp_mem,
            s.tcp_mem_max,
            dims[0].1,
            s.orphan,
            s.max_orphans,
            dims[1].1,
            s.tw,
            s.max_tw,
            dims[2].1,
        ),
        numeric: Some(worst),
    }
}

fn iowait_metric(outputs: &Outputs, thr: &Thresholds) -> Metric {
    const ID: &str = "health-iowait";
    const TITLE: &str = "IO wait";
    let Some(v) = out(outputs, VMSTAT).and_then(parse::parse_vmstat) else {
        return unknown(ID, TITLE, "vmstat unavailable");
    };
    Metric {
        id: ID,
        title: TITLE,
        status: threshold_status(v.iowait, thr.iowait_warn_pct, thr.iowait_crit_pct),
        value: format!("{:.0}% iowait", v.iowait),
        detail: format!("{} proc(s) blocked, {:.0}% steal", v.blocked, v.steal),
        numeric: Some(v.iowait),
    }
}

fn network_metric(outputs: &Outputs) -> Metric {
    const ID: &str = "health-connections";
    const TITLE: &str = "Network connections";
    let Some(s) = out(outputs, SS).and_then(parse::parse_ss_summary) else {
        return unknown(ID, TITLE, "ss unavailable");
    };
    // Informational: the raw connection count has no universal threshold, so it
    // reports as Ok; an unusual count is surfaced by the anomaly layer instead.
    Metric {
        id: ID,
        title: TITLE,
        status: HealthStatus::Ok,
        value: format!("{} established", s.tcp_estab),
        detail: format!("{} sockets total", s.total),
        numeric: Some(s.tcp_estab as f64),
    }
}

/// Failed systemd services. A zero-config liveness signal: any failed unit is a
/// `Warn` (something that should be running isn't); `failed_units_crit` or more
/// escalate to `Crit`. Missing `systemctl` (non-systemd host) reports `Unknown`,
/// so it never gates. `numeric` is the failed count, so a jump vs this host's
/// history is picked up by the anomaly layer.
fn failed_units_metric(outputs: &Outputs, thr: &Thresholds) -> Metric {
    const ID: &str = "health-failed-units";
    const TITLE: &str = "Failed services";
    let Some(text) = out(outputs, SYSTEMCTL_FAILED) else {
        return unknown(ID, TITLE, "systemctl unavailable");
    };
    let units = parse::parse_failed_units(text);
    let n = units.len();
    let status = if n == 0 {
        HealthStatus::Ok
    } else if thr.failed_units_crit > 0 && n as u32 >= thr.failed_units_crit {
        HealthStatus::Crit
    } else {
        HealthStatus::Warn
    };
    Metric {
        id: ID,
        title: TITLE,
        status,
        value: if n == 0 {
            "no failed units".to_string()
        } else {
            format!("{n} failed unit(s)")
        },
        detail: if units.is_empty() {
            "no systemd services in failed state".to_string()
        } else {
            units.join(", ")
        },
        numeric: Some(n as f64),
    }
}

/// Recent OOM-killer events from the kernel log. When memory is exhausted the
/// kernel kills a process to survive; that a service was OOM-killed is a
/// zero-config "something went badly wrong" signal even if the host looks fine
/// now. Any kill since boot → `Warn`. Privileged (`sudo -n dmesg`): on a
/// non-opted-in host the log is uncollected and the metric is `Unknown` (never
/// gates). `numeric` is the kill count, for history/anomaly baselining.
fn oom_metric(outputs: &Outputs) -> Metric {
    const ID: &str = "health-oom";
    const TITLE: &str = "OOM-killer events";
    let Some(text) = out(outputs, OOM_DMESG) else {
        return unknown(
            ID,
            TITLE,
            "kernel log unavailable (needs privileged sudo -n dmesg)",
        );
    };
    let n = parse::parse_oom_kills(text);
    let status = if n == 0 {
        HealthStatus::Ok
    } else {
        HealthStatus::Warn
    };
    Metric {
        id: ID,
        title: TITLE,
        status,
        value: if n == 0 {
            "no OOM kills".to_string()
        } else {
            format!("{n} OOM kill(s) since boot")
        },
        detail: if n == 0 {
            "no out-of-memory kills in the kernel log".to_string()
        } else {
            format!("{n} process(es) killed by the OOM-killer (kernel log)")
        },
        numeric: Some(n as f64),
    }
}

/// Zombie (defunct) processes: a dead child whose parent never reaped it. A few
/// transient zombies are normal, but a growing count means a parent process is
/// leaking children (it isn't calling `wait()`), which eventually exhausts the
/// PID table. `numeric` is the count, for history/anomaly baselining. Missing
/// `ps` output → `Unknown`.
fn zombie_metric(outputs: &Outputs, thr: &Thresholds) -> Metric {
    const ID: &str = "health-zombies";
    const TITLE: &str = "Zombie processes";
    let Some(text) = out(outputs, PS_STAT) else {
        return unknown(ID, TITLE, "ps unavailable");
    };
    let n = parse::parse_zombie_count(text);
    let status = if n == 0 {
        HealthStatus::Ok
    } else if thr.zombie_crit > 0 && n as u32 >= thr.zombie_crit {
        HealthStatus::Crit
    } else {
        HealthStatus::Warn
    };
    Metric {
        id: ID,
        title: TITLE,
        status,
        value: if n == 0 {
            "no zombies".to_string()
        } else {
            format!("{n} zombie process(es)")
        },
        detail: if n == 0 {
            "no defunct processes".to_string()
        } else {
            format!("{n} process(es) in Z (defunct) state - a parent isn't reaping children")
        },
        numeric: Some(n as f64),
    }
}

/// Container liveness across docker and podman: a zero-config signal that a
/// containerised service is broken. A `Restarting` container (crash loop) is
/// `Crit`; an `unhealthy` one (failing healthcheck) is `Warn`. Neither runtime
/// present (or reachable) reports `Unknown`, so hosts without containers - or
/// where the audit user can't run the CLI - never gate. `numeric` is the count of
/// broken containers, for history/anomaly baselining.
fn containers_metric(outputs: &Outputs) -> Metric {
    const ID: &str = "health-containers";
    const TITLE: &str = "Container health";
    let (docker, podman) = (out(outputs, DOCKER_PS), out(outputs, PODMAN_PS));
    if docker.is_none() && podman.is_none() {
        return unknown(ID, TITLE, "no docker/podman available");
    }
    let mut problems: Vec<(String, &'static str)> = Vec::new();
    for text in [docker, podman].into_iter().flatten() {
        problems.extend(parse::parse_container_problems(text));
    }
    let restarting = problems.iter().filter(|(_, s)| *s == "restarting").count();
    let unhealthy = problems.len() - restarting;
    let status = if restarting > 0 {
        HealthStatus::Crit
    } else if unhealthy > 0 {
        HealthStatus::Warn
    } else {
        HealthStatus::Ok
    };
    Metric {
        id: ID,
        title: TITLE,
        status,
        value: if problems.is_empty() {
            "all containers healthy".to_string()
        } else {
            format!("{restarting} restarting, {unhealthy} unhealthy")
        },
        detail: if problems.is_empty() {
            "no containers restarting or unhealthy".to_string()
        } else {
            problems
                .iter()
                .map(|(n, s)| format!("{n} ({s})"))
                .collect::<Vec<_>>()
                .join(", ")
        },
        numeric: Some(problems.len() as f64),
    }
}

/// Ok/Warn/Crit for one throughput bound; a threshold of `0` disables it.
fn bound_status(value: f64, warn: f64, crit: f64) -> HealthStatus {
    if crit > 0.0 && value >= crit {
        HealthStatus::Crit
    } else if warn > 0.0 && value >= warn {
        HealthStatus::Warn
    } else {
        HealthStatus::Ok
    }
}

/// Interfaces present in both `/proc/net/dev` samples, paired as
/// `(name, before, after)`. Shared by the throughput and error metrics, which
/// derive different per-second rates from the same counter deltas.
fn net_deltas(s1: &str, s2: &str) -> Vec<(String, parse::NetCounters, parse::NetCounters)> {
    let (before, after) = (parse::parse_net_dev(s1), parse::parse_net_dev(s2));
    after
        .into_iter()
        .filter_map(|(name, now)| before.get(&name).map(|&prev| (name, prev, now)))
        .collect()
}

/// Per-interface RX/TX throughput from two `/proc/net/dev` samples `dt_secs`
/// apart. Pure: `collect` does the timing and sampling. Informational unless
/// the per-direction MiB/s thresholds are set.
fn net_throughput_metric(s1: &str, s2: &str, dt_secs: f64, thr: &Thresholds) -> Metric {
    const ID: &str = "health-net-throughput";
    const TITLE: &str = "Network throughput";
    if dt_secs <= 0.0 {
        return unknown(ID, TITLE, "no measurable interval between samples");
    }
    let deltas = net_deltas(s1, s2);
    if deltas.is_empty() {
        return unknown(ID, TITLE, "no interfaces seen in both samples");
    }
    const MIB: f64 = 1024.0 * 1024.0;
    // Idle interfaces are dropped (0 throughput isn't interesting); the error
    // metric keeps them, since a quiet link can still err.
    let mut ifaces: Vec<(String, f64, f64)> = deltas
        .iter()
        .filter_map(|(name, prev, now)| {
            // saturating: a counter reset (reboot/wrap) yields 0 rather than a spike.
            let rx = now.rx_bytes.saturating_sub(prev.rx_bytes) as f64 / dt_secs / MIB;
            let tx = now.tx_bytes.saturating_sub(prev.tx_bytes) as f64 / dt_secs / MIB;
            if now.rx_bytes == 0 && now.tx_bytes == 0 {
                return None; // down/unused
            }
            Some((name.clone(), rx, tx))
        })
        .collect();
    if ifaces.is_empty() {
        return unknown(ID, TITLE, "no active interfaces");
    }
    // Busiest by combined throughput leads the value line.
    ifaces.sort_by(|a, b| {
        (b.1 + b.2)
            .partial_cmp(&(a.1 + a.2))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let status = ifaces
        .iter()
        .map(|(_, rx, tx)| {
            let r = bound_status(*rx, thr.net_rx_warn_mibps, thr.net_rx_crit_mibps);
            let t = bound_status(*tx, thr.net_tx_warn_mibps, thr.net_tx_crit_mibps);
            if r.rank() >= t.rank() {
                r
            } else {
                t
            }
        })
        .max_by_key(|s| s.rank())
        .unwrap_or(HealthStatus::Ok);
    let (name, rx, tx) = &ifaces[0];
    let detail = ifaces
        .iter()
        .map(|(n, r, t)| format!("{n} rx {r:.2} tx {t:.2}"))
        .collect::<Vec<_>>()
        .join(", ");
    Metric {
        id: ID,
        title: TITLE,
        status,
        value: format!("{name} rx {rx:.2} / tx {tx:.2} MiB/s"),
        detail: format!("MiB/s over {dt_secs:.1}s: {detail}"),
        // Busiest interface's combined MiB/s - one scalar for history/baselining.
        numeric: Some(rx + tx),
    }
}

/// Per-interface RX/TX error and drop rate from two `/proc/net/dev` samples
/// `dt_secs` apart. A healthy link produces ~0 errors, so a sustained nonzero
/// rate flags a bad NIC/driver or a saturated queue. Status is driven by the
/// *error* rate (drops can be benign under load, so they are shown as context
/// only). Informational - never touches the score - but it feeds `overall` and,
/// via `numeric`, the history/anomaly baseline (a rate spike vs this host's norm
/// is flagged by the anomaly layer).
fn net_errors_metric(s1: &str, s2: &str, dt_secs: f64, thr: &Thresholds) -> Metric {
    const ID: &str = "health-net-errors";
    const TITLE: &str = "Network errors";
    if dt_secs <= 0.0 {
        return unknown(ID, TITLE, "no measurable interval between samples");
    }
    let deltas = net_deltas(s1, s2);
    if deltas.is_empty() {
        return unknown(ID, TITLE, "no interfaces seen in both samples");
    }
    // name, err/s, drop/s, cumulative errs, cumulative drops (since boot). Unlike
    // throughput, idle interfaces are kept: a quiet link can still show errors.
    let mut ifaces: Vec<(String, f64, f64, u64, u64)> = deltas
        .iter()
        .map(|(name, prev, now)| {
            // saturating: a counter reset (reboot/wrap) yields 0 rather than a spike.
            let rate = |a: u64, b: u64| a.saturating_sub(b) as f64 / dt_secs;
            let err_ps = rate(now.rx_errs, prev.rx_errs) + rate(now.tx_errs, prev.tx_errs);
            let drop_ps = rate(now.rx_drop, prev.rx_drop) + rate(now.tx_drop, prev.tx_drop);
            (
                name.clone(),
                err_ps,
                drop_ps,
                now.rx_errs + now.tx_errs,
                now.rx_drop + now.tx_drop,
            )
        })
        .collect();
    // Worst error rate leads (drops break ties).
    ifaces.sort_by(|a, b| {
        (b.1, b.2)
            .partial_cmp(&(a.1, a.2))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let worst_err = ifaces[0].1; // sorted err-desc, so the first is the max
    let status = threshold_status(worst_err, thr.net_err_warn_pps, thr.net_err_crit_pps);

    let (name, err_ps, drop_ps, _, _) = &ifaces[0];
    let cum_err: u64 = ifaces.iter().map(|i| i.3).sum();
    let cum_drop: u64 = ifaces.iter().map(|i| i.4).sum();
    let detail = ifaces
        .iter()
        .map(|(n, e, d, ce, cd)| {
            format!("{n} err {e:.1}/s drop {d:.1}/s (since boot: err {ce}, drop {cd})")
        })
        .collect::<Vec<_>>()
        .join(", ");
    Metric {
        id: ID,
        title: TITLE,
        status,
        value: if worst_err > 0.0 {
            format!("{name} err {err_ps:.1}/s (drop {drop_ps:.1}/s)")
        } else {
            format!("no interface errors (since boot: err {cum_err}, drop {cum_drop})")
        },
        detail: format!("per-interface over {dt_secs:.1}s: {detail}"),
        // Total error rate across interfaces - one scalar for history/baselining.
        numeric: Some(ifaces.iter().map(|i| i.1).sum()),
    }
}

/// TCP accept-queue overflow rate from two `/proc/net/netstat` samples `dt_secs`
/// apart. `ListenOverflows` counts times a completed connection couldn't be queued
/// because the listen backlog was full - the server not accepting fast enough (a
/// proxy/web outage that CPU and memory metrics miss). A healthy server holds this
/// at 0, so any sustained rate is meaningful; `ListenDrops` is shown as context.
/// Missing/unparseable netstat reports `Unknown`.
fn net_listen_metric(s1: &str, s2: &str, dt_secs: f64, thr: &Thresholds) -> Metric {
    const ID: &str = "health-listen-overflows";
    const TITLE: &str = "TCP accept-queue overflows";
    if dt_secs <= 0.0 {
        return unknown(ID, TITLE, "no measurable interval between samples");
    }
    let (Some((ovf1, drop1)), Some((ovf2, drop2))) = (
        parse::parse_netstat_listen(s1),
        parse::parse_netstat_listen(s2),
    ) else {
        return unknown(ID, TITLE, "netstat ListenOverflows unavailable");
    };
    // saturating: a counter reset (reboot) yields 0 rather than a spike.
    let ovf_rate = ovf2.saturating_sub(ovf1) as f64 / dt_secs;
    let drop_rate = drop2.saturating_sub(drop1) as f64 / dt_secs;
    Metric {
        id: ID,
        title: TITLE,
        status: threshold_status(
            ovf_rate,
            thr.listen_overflow_warn_pps,
            thr.listen_overflow_crit_pps,
        ),
        value: if ovf_rate > 0.0 {
            format!("{ovf_rate:.1} overflow/s (drop {drop_rate:.1}/s)")
        } else {
            format!("no accept-queue overflows (since boot: {ovf2})")
        },
        detail: format!("over {dt_secs:.1}s; since boot: overflows {ovf2}, drops {drop2}"),
        numeric: Some(ovf_rate),
    }
}

/// Rate of conntrack table-pressure events over the sample window, from
/// `/proc/net/stat/nf_conntrack`. When the table fills, the kernel evicts entries
/// early (`early_drop`) and fails to insert new ones (`insert_failed`) - a
/// NAT/firewall/proxy dropping connections that the count-vs-max gauge only warns
/// is *near* full. The rate gates on `early_drop + insert_failed`; the generic
/// `drop` counter ticks routinely on high-churn hosts even when the table is far
/// from full (seen on the mtproto proxies), so it's shown as context but never
/// gates. A healthy host holds the gated rate at 0; the since-boot totals answer
/// "were there drops already this boot?". Missing/unparseable stat (or module not
/// loaded) reports `Unknown`.
fn net_conntrack_drops_metric(s1: &str, s2: &str, dt_secs: f64, thr: &Thresholds) -> Metric {
    const ID: &str = "health-conntrack-drops";
    const TITLE: &str = "Conntrack drops";
    if dt_secs <= 0.0 {
        return unknown(ID, TITLE, "no measurable interval between samples");
    }
    let (Some((_d1, e1, i1)), Some((d2, e2, i2))) = (
        parse::parse_conntrack_drops(s1),
        parse::parse_conntrack_drops(s2),
    ) else {
        return unknown(
            ID,
            TITLE,
            "nf_conntrack stats unavailable (module not loaded?)",
        );
    };
    // Gate on table-pressure events only; the generic `drop` is noisy on busy hosts.
    let pressure1 = e1 + i1;
    let pressure2 = e2 + i2;
    // saturating: a counter reset (reboot) yields 0 rather than a spike.
    let rate = pressure2.saturating_sub(pressure1) as f64 / dt_secs;
    let since_boot = format!("since boot: early_drop {e2}, insert_failed {i2}, drop {d2}");
    Metric {
        id: ID,
        title: TITLE,
        status: threshold_status(
            rate,
            thr.conntrack_drop_warn_pps,
            thr.conntrack_drop_crit_pps,
        ),
        value: if rate > 0.0 {
            format!("{rate:.1} conn-drop/s ({since_boot})")
        } else {
            format!("no conntrack table pressure ({since_boot})")
        },
        detail: format!("over {dt_secs:.1}s; {since_boot}"),
        numeric: Some(rate),
    }
}

/// Rate of TCP stack pressure events over the sample window. `TcpExt`
/// (`/proc/net/netstat`) exposes `TCPAbortOnMemory` (connection aborted, no
/// memory), `PruneCalled` (receive queue pruned under pressure) and `TCPRcvQDrop`
/// (segment dropped from a full receive queue) - the stack shedding connections,
/// the failure this metric watches for. It gates on their sum; retransmits
/// (`Tcp: RetransSegs` from `/proc/net/snmp`) tick routinely on any internet-facing
/// host (packet loss, not host pressure), so - like the generic conntrack `drop` -
/// they are shown as context but never gate. A healthy host holds the gated rate at
/// 0; the since-boot totals answer "did the stack shed connections this boot?".
/// Missing/unparseable `TcpExt` reports `Unknown`.
fn net_tcp_errors_metric(
    snmp1: &str,
    snmp2: &str,
    stat1: &str,
    stat2: &str,
    dt_secs: f64,
    thr: &Thresholds,
) -> Metric {
    const ID: &str = "health-tcp-errors";
    const TITLE: &str = "TCP stack errors";
    if dt_secs <= 0.0 {
        return unknown(ID, TITLE, "no measurable interval between samples");
    }
    let (Some((a1, p1, q1)), Some((a2, p2, q2))) = (
        parse::parse_netstat_tcp_errors(stat1),
        parse::parse_netstat_tcp_errors(stat2),
    ) else {
        return unknown(ID, TITLE, "netstat TcpExt counters unavailable");
    };
    // Gate on memory/backlog-pressure events only.
    let pressure1 = a1 + p1 + q1;
    let pressure2 = a2 + p2 + q2;
    // saturating: a counter reset (reboot) yields 0 rather than a spike.
    let rate = pressure2.saturating_sub(pressure1) as f64 / dt_secs;
    // Retransmits are context (network loss, not host pressure); absent SNMP just
    // omits the note.
    let retrans_ctx = match (parse::parse_snmp_tcp(snmp1), parse::parse_snmp_tcp(snmp2)) {
        (Some(r1), Some(r2)) => {
            format!(", retrans {:.1}/s", r2.saturating_sub(r1) as f64 / dt_secs)
        }
        _ => String::new(),
    };
    let since_boot = format!("since boot: abort-on-mem {a2}, prune {p2}, rcvq-drop {q2}");
    Metric {
        id: ID,
        title: TITLE,
        status: threshold_status(rate, thr.tcp_err_warn_pps, thr.tcp_err_crit_pps),
        value: if rate > 0.0 {
            format!("{rate:.1} tcp-err/s ({since_boot})")
        } else {
            format!("no TCP stack errors ({since_boot})")
        },
        detail: format!("over {dt_secs:.1}s; {since_boot}{retrans_ctx}"),
        numeric: Some(rate),
    }
}

/// Scan the kernel ring buffer (`sudo -n dmesg`, shared with `health-oom`) for a
/// curated set of failure signatures - filesystem/block-I/O errors, conntrack and
/// neighbour-table overflows, and hard faults (panic/BUG/oops/soft-lockup/hung-task/
/// MCE). A hard fault is `Crit`; softer events (FS/table pressure) are `Warn`; a
/// clean log is `Ok`. Privileged-only, like `health-oom`: absent kernel log (a
/// non-privileged target) reports `Unknown` and never gates. Best-effort - kernel
/// wording drifts, so the signature set is conservative (see [`parse::parse_kernel_events`]).
fn kernel_events_metric(outputs: &Outputs) -> Metric {
    const ID: &str = "health-kernel-events";
    const TITLE: &str = "Kernel log events";
    let Some(text) = out(outputs, OOM_DMESG) else {
        return unknown(
            ID,
            TITLE,
            "kernel log unavailable (needs privileged sudo -n dmesg)",
        );
    };
    let ev = parse::parse_kernel_events(text);
    let total = ev.total();
    if total == 0 {
        return Metric {
            id: ID,
            title: TITLE,
            status: HealthStatus::Ok,
            value: "no notable kernel events".to_string(),
            detail: "no matching failure signatures in the kernel log since boot".to_string(),
            numeric: Some(0.0),
        };
    }
    let status = if ev.any_critical() {
        HealthStatus::Crit
    } else {
        HealthStatus::Warn
    };
    let summary = ev
        .categories
        .iter()
        .map(|c| format!("{} {}", c.count, c.label))
        .collect::<Vec<_>>()
        .join(", ");
    let detail = ev
        .categories
        .iter()
        .map(|c| format!("{}: {}", c.label, c.last_line))
        .collect::<Vec<_>>()
        .join(" | ");
    Metric {
        id: ID,
        title: TITLE,
        status,
        value: format!("{total} kernel event(s) since boot ({summary})"),
        detail,
        numeric: Some(total as f64),
    }
}

/// System clock NTP synchronization from `timedatectl show`. An unsynchronized
/// clock breaks TLS validity windows, log correlation and time-based auth, so
/// `NTPSynchronized=no` is a `Warn`. Absent field (no systemd time daemon / not
/// reported) → `Unknown`.
fn clock_sync_metric(outputs: &Outputs) -> Metric {
    const ID: &str = "health-clock-sync";
    const TITLE: &str = "Clock synchronization";
    let Some(text) = out(outputs, TIMEDATECTL) else {
        return unknown(ID, TITLE, "timedatectl unavailable");
    };
    match parse::parse_timedatectl_synced(text) {
        Some(true) => Metric {
            id: ID,
            title: TITLE,
            status: HealthStatus::Ok,
            value: "clock synchronized".to_string(),
            detail: "NTPSynchronized=yes".to_string(),
            numeric: Some(1.0),
        },
        Some(false) => Metric {
            id: ID,
            title: TITLE,
            status: HealthStatus::Warn,
            value: "clock NOT synchronized".to_string(),
            detail: "NTPSynchronized=no (NTP disabled or time source unreachable)".to_string(),
            numeric: Some(0.0),
        },
        None => unknown(ID, TITLE, "NTPSynchronized not reported"),
    }
}

/// Pending reboot after a kernel/library update, from the Debian/Ubuntu
/// `/run/reboot-required` flag (seen via `ls /run`). Present → `Warn` (the host is
/// running the old kernel/libraries). RHEL has no equivalent flag file - its
/// `needs-restarting -r` reports via exit code, which the health engine can't read -
/// so this is Debian-family only; a host without the flag simply reports `Ok`.
/// Absent `/run` listing → `Unknown`.
fn reboot_required_metric(outputs: &Outputs) -> Metric {
    const ID: &str = "health-reboot-required";
    const TITLE: &str = "Pending reboot";
    let Some(text) = out(outputs, LS_RUN) else {
        return unknown(ID, TITLE, "/run listing unavailable");
    };
    if parse::parse_reboot_required(text) {
        Metric {
            id: ID,
            title: TITLE,
            status: HealthStatus::Warn,
            value: "reboot required".to_string(),
            detail: "/run/reboot-required present (kernel/libraries updated, not yet rebooted)"
                .to_string(),
            numeric: Some(1.0),
        }
    } else {
        Metric {
            id: ID,
            title: TITLE,
            status: HealthStatus::Ok,
            value: "no reboot required".to_string(),
            detail: "no /run/reboot-required flag".to_string(),
            numeric: Some(0.0),
        }
    }
}

/// Normally-writable disk filesystems remounted read-only, from `/proc/mounts`. The
/// kernel remounts a filesystem `ro` after I/O/metadata errors, so an ext*/xfs/btrfs
/// filesystem mounted `ro` is a strong sign of a failing disk / ongoing outage -
/// writes silently fail. Read-only-by-design filesystems (squashfs snaps, iso9660)
/// are excluded (see [`parse::parse_readonly_mounts`]). Any → `Crit` (naming the
/// mounts); none → `Ok`. Absent output → `Unknown`.
fn fs_readonly_metric(outputs: &Outputs) -> Metric {
    const ID: &str = "health-fs-readonly";
    const TITLE: &str = "Read-only filesystems";
    let Some(text) = out(outputs, PROC_MOUNTS) else {
        return unknown(ID, TITLE, "/proc/mounts unavailable");
    };
    let ro = parse::parse_readonly_mounts(text);
    if ro.is_empty() {
        return Metric {
            id: ID,
            title: TITLE,
            status: HealthStatus::Ok,
            value: "all filesystems writable".to_string(),
            detail: "no block-device filesystem mounted read-only".to_string(),
            numeric: Some(0.0),
        };
    }
    let mounts = ro
        .iter()
        .map(|(mp, _)| mp.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let detail = ro
        .iter()
        .map(|(mp, dev)| format!("{mp} ({dev})"))
        .collect::<Vec<_>>()
        .join(", ");
    Metric {
        id: ID,
        title: TITLE,
        status: HealthStatus::Crit,
        value: format!("read-only: {mounts} (disk errors? kernel remounted ro)"),
        detail,
        numeric: Some(ro.len() as f64),
    }
}

/// Days until the nearest configured TLS certificate expires. `certs` pairs each
/// configured path with its `openssl x509 -noout -enddate` output (or `None` if the
/// read failed). Reports the minimum days-remaining across all readable certs; at or
/// below `cert_expiry_crit_days` (or already expired) → `Crit`, at or below
/// `cert_expiry_warn_days` → `Warn`. Unreadable/unparseable certs are noted but don't
/// gate as long as at least one cert parsed. No configured paths → `Unknown`.
fn cert_expiry_metric(certs: &[(String, Option<String>)], thr: &Thresholds, now: i64) -> Metric {
    const ID: &str = "health-cert-expiry";
    const TITLE: &str = "TLS certificate expiry";
    if certs.is_empty() {
        return unknown(ID, TITLE, "no cert_paths configured");
    }
    let mut nearest: Option<(i64, &str)> = None;
    let mut unreadable = 0usize;
    for (path, output) in certs {
        match output.as_deref().and_then(parse::parse_cert_notafter) {
            Some(notafter) => {
                let days = (notafter - now).div_euclid(86_400);
                if nearest.map_or(true, |(m, _)| days < m) {
                    nearest = Some((days, path));
                }
            }
            None => unreadable += 1,
        }
    }
    let Some((days, path)) = nearest else {
        return unknown(
            ID,
            TITLE,
            format!("no readable certificate ({unreadable} unreadable)"),
        );
    };
    let status = if days <= thr.cert_expiry_crit_days {
        HealthStatus::Crit
    } else if days <= thr.cert_expiry_warn_days {
        HealthStatus::Warn
    } else {
        HealthStatus::Ok
    };
    let note = if unreadable > 0 {
        format!(", {unreadable} unreadable")
    } else {
        String::new()
    };
    let value = if days < 0 {
        format!("EXPIRED {} day(s) ago ({path})", -days)
    } else {
        format!("{days} day(s) until expiry ({path})")
    };
    Metric {
        id: ID,
        title: TITLE,
        status,
        value,
        detail: format!("nearest of {} configured cert(s){note}", certs.len()),
        numeric: Some(days as f64),
    }
}

/// Worst status across metrics (`Unknown` is neutral; `Unknown` overall only if
/// nothing could be measured).
fn worst(metrics: &[Metric]) -> HealthStatus {
    metrics
        .iter()
        .map(|m| m.status)
        .max_by_key(|s| s.rank())
        .unwrap_or(HealthStatus::Unknown)
}

/// Build a health report from pre-collected command outputs. Pure (no I/O):
/// shared by [`collect`] and the evals. Does not include the network throughput
/// or error metrics, which need two timed samples (added in [`collect`]).
pub fn evaluate(outputs: &Outputs, thr: &Thresholds) -> HealthReport {
    let mut metrics = vec![load_metric(outputs, thr)];
    metrics.extend(memory_metrics(outputs, thr));
    metrics.push(disk_metric(outputs, thr));
    metrics.push(inodes_metric(outputs, thr));
    metrics.push(fd_metric(outputs, thr));
    metrics.push(conntrack_metric(outputs, thr));
    metrics.push(pids_metric(outputs, thr));
    metrics.push(tcp_mem_metric(outputs, thr));
    metrics.push(iowait_metric(outputs, thr));
    metrics.push(network_metric(outputs));
    metrics.push(failed_units_metric(outputs, thr));
    metrics.push(zombie_metric(outputs, thr));
    metrics.push(oom_metric(outputs));
    metrics.push(kernel_events_metric(outputs));
    metrics.push(clock_sync_metric(outputs));
    metrics.push(reboot_required_metric(outputs));
    metrics.push(fs_readonly_metric(outputs));
    metrics.push(containers_metric(outputs));

    let procs = out(outputs, PS).map(parse::parse_ps).unwrap_or_default();
    let top_cpu: Vec<ProcInfo> = procs.iter().take(thr.top_n).cloned().collect();
    let mut by_mem = procs.clone();
    by_mem.sort_by(|a, b| {
        b.mem
            .partial_cmp(&a.mem)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let top_mem: Vec<ProcInfo> = by_mem.into_iter().take(thr.top_n).collect();

    let overall = worst(&metrics);

    // Carried to history so the next run can detect between-run changes (a
    // restarted container, a newly-failed unit); the detection itself needs the
    // stored history and runs in the orchestration layer.
    let failed_units = out(outputs, SYSTEMCTL_FAILED)
        .map(parse::parse_failed_units)
        .unwrap_or_default();
    let mut container_uptimes = BTreeMap::new();
    for text in [out(outputs, DOCKER_PS), out(outputs, PODMAN_PS)]
        .into_iter()
        .flatten()
    {
        container_uptimes.extend(parse::parse_container_uptimes(text));
    }

    // Since-boot kernel-event counts per category, carried to history so the next
    // run can report newly-accrued events. The conntrack table-pressure total is
    // added in `collect` (it needs the sampled counter file). Absent kernel log
    // (non-privileged) contributes nothing.
    let mut event_counters = BTreeMap::new();
    if let Some(text) = out(outputs, OOM_DMESG) {
        for c in parse::parse_kernel_events(text).categories {
            event_counters.insert(format!("kernel: {}", c.label), c.count as u64);
        }
    }

    HealthReport {
        metrics,
        top_cpu,
        top_mem,
        overall,
        // Anomalies and between-run changes need the stored history + per-target
        // config, neither of which this pure function has; they are filled in by
        // the run orchestration.
        anomalies: Vec::new(),
        anomaly_note: None,
        changes: Vec::new(),
        container_uptimes,
        failed_units,
        event_counters,
    }
}

/// Snap each single-shot command once over SSH, sample `/proc/net/dev` twice for
/// throughput, then evaluate.
///
/// Host-level failures (auth, connection, timeout) abort. A per-command remote
/// failure becomes an `Unknown` metric for whatever needed it; the rest run.
pub async fn collect(
    ssh: &SshConfig,
    thr: &Thresholds,
    privileged: bool,
    cert_paths: &[String],
) -> Result<HealthReport, SshError> {
    let mut outputs: Outputs = HashMap::new();
    for &cmd in SINGLE_SHOT {
        // The OOM probe reads the kernel log via `sudo -n dmesg`; only send it to
        // an opted-in target. On a non-privileged host it is left uncollected, so
        // `oom_metric` reports Unknown (never gates) - mirroring privileged checks.
        if cmd == OOM_DMESG && !privileged {
            continue;
        }
        let value = if cmd == DOCKER_PS || cmd == PODMAN_PS {
            // Container probes may need privilege; the result is stored under the
            // canonical key (`docker ps -a`) so evaluate()/parsing stay unaware of
            // which variant ran. Prefer the privileged read, then fall back to the
            // plain command so a missing sudo grant never regresses a docker-group
            // host that already worked unprivileged.
            let (preferred, fallback) = container_command(cmd, privileged);
            match run_single(ssh, preferred).await? {
                Some(stdout) => Ok(stdout),
                None => match fallback {
                    Some(plain) => run_single(ssh, plain)
                        .await?
                        .ok_or_else(|| CmdError::other("container runtime unavailable")),
                    None => Err(CmdError::other("container runtime unavailable")),
                },
            }
        } else {
            match ssh.run(cmd).await {
                Ok(out) => Ok(out.stdout),
                Err(SshError::RemoteCommand { code, stderr, .. }) => Err(CmdError::other(format!(
                    "remote command failed (code {code:?}): {stderr}"
                ))),
                Err(host_level) => return Err(host_level),
            }
        };
        outputs.insert(cmd, value);
    }

    let mut report = evaluate(&outputs, thr);

    // Two timed samples of the counter files -> throughput, error and accept-queue
    // overflow rates. A remote error on the `dev` reads degrades to Unknown metrics;
    // host-level errors abort.
    let samples = sample_net(ssh, thr).await?;
    let (throughput, errors, listen, conntrack_drops, tcp_errors) = match &samples {
        Some(s) => (
            net_throughput_metric(&s.dev1, &s.dev2, s.dt, thr),
            net_errors_metric(&s.dev1, &s.dev2, s.dt, thr),
            net_listen_metric(&s.stat1, &s.stat2, s.dt, thr),
            net_conntrack_drops_metric(&s.ct1, &s.ct2, s.dt, thr),
            net_tcp_errors_metric(&s.snmp1, &s.snmp2, &s.stat1, &s.stat2, s.dt, thr),
        ),
        None => (
            unknown(
                "health-net-throughput",
                "Network throughput",
                "/proc/net/dev unavailable",
            ),
            unknown(
                "health-net-errors",
                "Network errors",
                "/proc/net/dev unavailable",
            ),
            unknown(
                "health-listen-overflows",
                "TCP accept-queue overflows",
                "/proc/net/dev unavailable",
            ),
            unknown(
                "health-conntrack-drops",
                "Conntrack drops",
                "/proc/net/dev unavailable",
            ),
            unknown(
                "health-tcp-errors",
                "TCP stack errors",
                "/proc/net/dev unavailable",
            ),
        ),
    };
    report.metrics.push(throughput);
    report.metrics.push(errors);
    report.metrics.push(listen);
    report.metrics.push(conntrack_drops);
    report.metrics.push(tcp_errors);

    // Cumulative conntrack table-pressure total (early_drop + insert_failed) for the
    // between-run event delta; the rate metric only carries the intra-run rate.
    if let Some(s) = &samples {
        if let Some((_, early, insf)) = parse::parse_conntrack_drops(&s.ct2) {
            report
                .event_counters
                .insert("conntrack table pressure".to_string(), early + insf);
        }
    }

    // TLS certificate expiry: read each configured cert path (the command is a
    // parameterized catalog entry, see `catalog::is_cert_read`). A read failure just
    // marks that cert unreadable; the metric is Unknown only when nothing is configured.
    let mut certs: Vec<(String, Option<String>)> = Vec::with_capacity(cert_paths.len());
    for path in cert_paths {
        let cmd = format!("openssl x509 -in {path} -noout -enddate");
        certs.push((path.clone(), run_single(ssh, &cmd).await?));
    }
    let now = now_unix_secs();
    report.metrics.push(cert_expiry_metric(&certs, thr, now));

    report.overall = worst(&report.metrics);
    Ok(report)
}

/// Current Unix time in whole seconds (0 if the clock is before the epoch). Local
/// helper so cert-expiry math needn't reach into the history module.
fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Run one command: `Ok(Some(stdout))` on success, `Ok(None)` if it failed
/// remotely (absent binary, permission denied) so the caller can fall back, and
/// `Err` only for a host-level failure (auth/connection/timeout) that must abort.
async fn run_single(ssh: &SshConfig, cmd: &str) -> Result<Option<String>, SshError> {
    match ssh.run(cmd).await {
        Ok(out) => Ok(Some(out.stdout)),
        Err(SshError::RemoteCommand { .. }) => Ok(None),
        Err(host_level) => Err(host_level),
    }
}

/// Two timed samples of the network counter files.
struct NetSamples {
    dev1: String,
    dev2: String,
    /// `/proc/net/netstat` at each point; empty if that read failed remotely
    /// (the throughput/error metrics need only the `dev` pair).
    stat1: String,
    stat2: String,
    /// `/proc/net/stat/nf_conntrack` at each point; empty if that read failed
    /// remotely (the conntrack-drops metric then reports `Unknown`).
    ct1: String,
    ct2: String,
    /// `/proc/net/snmp` at each point; empty if that read failed remotely. Only
    /// feeds the tcp-errors metric's retransmit *context* (it gates on `TcpExt`
    /// from `netstat`), so an empty read just drops that note.
    snmp1: String,
    snmp2: String,
    dt: f64,
}

/// Read `/proc/net/dev`, `/proc/net/netstat`, `/proc/net/stat/nf_conntrack` and
/// `/proc/net/snmp` twice, `net_sample_secs` apart. `Ok(None)` if a `dev` read
/// fails remotely; a failed read of any other file just leaves its sample empty
/// (the metric that needs it then reports `Unknown`).
async fn sample_net(ssh: &SshConfig, thr: &Thresholds) -> Result<Option<NetSamples>, SshError> {
    let dev1 = match ssh.run(NETDEV).await {
        Ok(out) => out.stdout,
        Err(SshError::RemoteCommand { .. }) => return Ok(None),
        Err(host_level) => return Err(host_level),
    };
    let stat1 = run_single(ssh, NETSTAT).await?.unwrap_or_default();
    let ct1 = run_single(ssh, CONNTRACK_STAT).await?.unwrap_or_default();
    let snmp1 = run_single(ssh, SNMP).await?.unwrap_or_default();
    let start = std::time::Instant::now();
    tokio::time::sleep(std::time::Duration::from_secs(thr.net_sample_secs.max(1))).await;
    let dev2 = match ssh.run(NETDEV).await {
        Ok(out) => out.stdout,
        Err(SshError::RemoteCommand { .. }) => return Ok(None),
        Err(host_level) => return Err(host_level),
    };
    let stat2 = run_single(ssh, NETSTAT).await?.unwrap_or_default();
    let ct2 = run_single(ssh, CONNTRACK_STAT).await?.unwrap_or_default();
    let snmp2 = run_single(ssh, SNMP).await?.unwrap_or_default();
    Ok(Some(NetSamples {
        dev1,
        dev2,
        stat1,
        stat2,
        ct1,
        ct2,
        snmp1,
        snmp2,
        dt: start.elapsed().as_secs_f64(),
    }))
}

fn human_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outputs(pairs: &[(&'static str, &str)]) -> Outputs {
        pairs.iter().map(|(k, v)| (*k, Ok(v.to_string()))).collect()
    }

    #[test]
    fn all_health_commands_are_in_catalog() {
        for cmd in HEALTH_COMMANDS {
            assert!(
                crate::catalog::validate(cmd).is_ok(),
                "health command not in catalog: {cmd:?}"
            );
        }
    }

    #[test]
    fn load_thresholds() {
        let thr = Thresholds::default();
        // 3.0 over 4 cores = 0.75/core -> Ok.
        let ok = outputs(&[("uptime", "load average: 3.0, 1.0, 0.5"), ("nproc", "4")]);
        assert_eq!(load_metric(&ok, &thr).status, HealthStatus::Ok);
        // 6.0 over 4 cores = 1.5/core -> Warn.
        let warn = outputs(&[("uptime", "load average: 6.0, 1.0, 0.5"), ("nproc", "4")]);
        assert_eq!(load_metric(&warn, &thr).status, HealthStatus::Warn);
        // 10.0 over 4 cores = 2.5/core -> Crit.
        let crit = outputs(&[("uptime", "load average: 10.0, 1.0, 0.5"), ("nproc", "4")]);
        assert_eq!(load_metric(&crit, &thr).status, HealthStatus::Crit);
    }

    #[test]
    fn missing_input_is_unknown_not_a_failure() {
        let thr = Thresholds::default();
        let m = load_metric(&outputs(&[]), &thr);
        assert_eq!(m.status, HealthStatus::Unknown);
    }

    #[test]
    fn net_errors_flag_rising_errors_not_drops() {
        let thr = Thresholds::default();
        // rx/tx: bytes pkts errs drop fifo frame comp mcast | bytes pkts errs drop ...
        let s1 = "  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n";
        // +50 rx errors over 1s -> 50/s -> Crit (>= 10).
        let s2 = "  eth0: 2000 20 50 0 0 0 0 0 3000 30 0 0 0 0 0 0\n";
        let m = net_errors_metric(s1, s2, 1.0, &thr);
        assert_eq!(m.status, HealthStatus::Crit);
        assert_eq!(m.numeric, Some(50.0));

        // No change -> Ok, and the value states there are no errors.
        let ok = net_errors_metric(s1, s1, 1.0, &thr);
        assert_eq!(ok.status, HealthStatus::Ok);
        assert!(ok.value.contains("no interface errors"), "{}", ok.value);

        // Drops alone (no errors) must not raise the status.
        let dropping = "  eth0: 2000 20 0 99 0 0 0 0 3000 30 0 0 0 0 0 0\n";
        let d = net_errors_metric(s1, dropping, 1.0, &thr);
        assert_eq!(d.status, HealthStatus::Ok);

        // A counter reset (second sample lower) yields 0, not a spike.
        let reset = net_errors_metric(s2, s1, 1.0, &thr);
        assert_eq!(reset.status, HealthStatus::Ok);
    }

    #[test]
    fn net_listen_flags_rising_overflows() {
        let thr = Thresholds::default(); // warn 1/s, crit 10/s
        let hdr = "TcpExt: SyncookiesSent ListenOverflows ListenDrops\n";
        let s1 = format!("{hdr}TcpExt: 3 100 200\n");
        // +50 overflows over 1s -> 50/s -> Crit.
        let s2 = format!("{hdr}TcpExt: 3 150 260\n");
        let m = net_listen_metric(&s1, &s2, 1.0, &thr);
        assert_eq!(m.status, HealthStatus::Crit);
        assert_eq!(m.numeric, Some(50.0));
        // No change -> Ok, value says no overflows.
        let ok = net_listen_metric(&s1, &s1, 1.0, &thr);
        assert_eq!(ok.status, HealthStatus::Ok);
        assert!(
            ok.value.contains("no accept-queue overflows"),
            "{}",
            ok.value
        );
        // Counter reset (second lower) -> 0, not a spike.
        assert_eq!(
            net_listen_metric(&s2, &s1, 1.0, &thr).status,
            HealthStatus::Ok
        );
        // Missing netstat -> Unknown (never gates).
        assert_eq!(
            net_listen_metric("", "", 1.0, &thr).status,
            HealthStatus::Unknown
        );
    }

    #[test]
    fn net_conntrack_drops_flags_table_pressure_not_generic_drop() {
        let thr = Thresholds::default(); // warn 1/s, crit 10/s
        let hdr = "entries found drop early_drop insert_failed\n";
        // Gate = early_drop + insert_failed. s1: e=2,i=1 -> 3; s2: e=9,i=4 -> 13.
        let s1 = format!("{hdr}00000064 00000000 0000000a 00000002 00000001\n");
        // +10 pressure over 1s -> 10/s -> Crit. (drop also jumps but is ignored.)
        let s2 = format!("{hdr}00000064 00000000 00000064 00000009 00000004\n");
        let m = net_conntrack_drops_metric(&s1, &s2, 1.0, &thr);
        assert_eq!(m.status, HealthStatus::Crit);
        assert_eq!(m.numeric, Some(10.0));

        // A big generic `drop` delta with NO early_drop/insert_failed change ->
        // Ok (the noisy-drop case that WARN'd mt3 in live-verify).
        let noisy = format!("{hdr}00000064 00000000 00010000 00000002 00000001\n");
        let nm = net_conntrack_drops_metric(&s1, &noisy, 1.0, &thr);
        assert_eq!(nm.status, HealthStatus::Ok);
        assert!(
            nm.value.contains("no conntrack table pressure"),
            "{}",
            nm.value
        );
        assert!(nm.value.contains("early_drop 2"), "{}", nm.value);

        // Counter reset (second lower) -> 0, not a spike.
        assert_eq!(
            net_conntrack_drops_metric(&s2, &s1, 1.0, &thr).status,
            HealthStatus::Ok
        );
        // Module not loaded / unparseable -> Unknown (never gates).
        assert_eq!(
            net_conntrack_drops_metric("", "", 1.0, &thr).status,
            HealthStatus::Unknown
        );
    }

    #[test]
    fn net_tcp_errors_flags_pressure_not_retransmits() {
        let thr = Thresholds::default(); // warn 1/s, crit 10/s
        let ext = "TcpExt: TCPAbortOnMemory PruneCalled TCPRcvQDrop TCPHPHits\n";
        // Gate = abort + prune + rcvq. s1: 2+1+0=3; s2: 8+4+1=13 -> +10/s -> Crit.
        let s1 = format!("{ext}TcpExt: 2 1 0 999\n");
        let s2 = format!("{ext}TcpExt: 8 4 1 999\n");
        // Retransmits jump hugely but must NOT gate (context only).
        let snmp1 = "Tcp: RetransSegs InErrs\nTcp: 100 0\n";
        let snmp2 = "Tcp: RetransSegs InErrs\nTcp: 9999 0\n";
        let m = net_tcp_errors_metric(snmp1, snmp2, &s1, &s2, 1.0, &thr);
        assert_eq!(m.status, HealthStatus::Crit);
        assert_eq!(m.numeric, Some(10.0));
        assert!(m.detail.contains("retrans"), "{}", m.detail);

        // Only retransmits rising (no pressure delta) -> Ok.
        let ok = net_tcp_errors_metric(snmp1, snmp2, &s1, &s1, 1.0, &thr);
        assert_eq!(ok.status, HealthStatus::Ok);
        assert!(ok.value.contains("no TCP stack errors"), "{}", ok.value);

        // Counter reset (second lower) -> 0, not a spike.
        assert_eq!(
            net_tcp_errors_metric(snmp1, snmp2, &s2, &s1, 1.0, &thr).status,
            HealthStatus::Ok
        );
        // Missing TcpExt -> Unknown (never gates); absent SNMP just drops the note.
        assert_eq!(
            net_tcp_errors_metric("", "", "", "", 1.0, &thr).status,
            HealthStatus::Unknown
        );
        let no_snmp = net_tcp_errors_metric("", "", &s1, &s2, 1.0, &thr);
        assert_eq!(no_snmp.status, HealthStatus::Crit);
        assert!(!no_snmp.detail.contains("retrans"), "{}", no_snmp.detail);
    }

    #[test]
    fn kernel_events_metric_ranks_and_gates() {
        // Absent dmesg (non-privileged) -> Unknown (never gates).
        assert_eq!(
            kernel_events_metric(&outputs(&[])).status,
            HealthStatus::Unknown
        );
        // Clean log -> Ok.
        let clean = kernel_events_metric(&outputs(&[("sudo -n dmesg", "[0.0] booting\n")]));
        assert_eq!(clean.status, HealthStatus::Ok);
        assert_eq!(clean.numeric, Some(0.0));
        // A soft (FS) event only -> Warn.
        let warn = kernel_events_metric(&outputs(&[(
            "sudo -n dmesg",
            "[1.0] EXT4-fs error (device vda1): reading directory\n",
        )]));
        assert_eq!(warn.status, HealthStatus::Warn);
        // A hard fault -> Crit.
        let crit = kernel_events_metric(&outputs(&[(
            "sudo -n dmesg",
            "[1.0] Kernel panic - not syncing: Attempted to kill init!\n",
        )]));
        assert_eq!(crit.status, HealthStatus::Crit);
        assert_eq!(crit.numeric, Some(1.0));
    }

    #[test]
    fn clock_sync_flags_unsynchronized() {
        let m = |v: &str| clock_sync_metric(&outputs(&[("timedatectl show", v)]));
        assert_eq!(m("NTPSynchronized=yes\n").status, HealthStatus::Ok);
        assert_eq!(m("NTPSynchronized=no\n").status, HealthStatus::Warn);
        // Field absent -> Unknown (never gates); no output -> Unknown.
        assert_eq!(m("Timezone=UTC\n").status, HealthStatus::Unknown);
        assert_eq!(
            clock_sync_metric(&outputs(&[])).status,
            HealthStatus::Unknown
        );
    }

    #[test]
    fn reboot_required_flags_pending() {
        let m = |v: &str| reboot_required_metric(&outputs(&[("ls /run", v)]));
        assert_eq!(
            m("systemd\nreboot-required\nlock\n").status,
            HealthStatus::Warn
        );
        assert_eq!(m("systemd\nlock\n").status, HealthStatus::Ok);
        assert_eq!(
            reboot_required_metric(&outputs(&[])).status,
            HealthStatus::Unknown
        );
    }

    #[test]
    fn fs_readonly_flags_block_device_ro() {
        // A /dev-backed ro filesystem -> Crit, naming the mountpoint.
        let ro = fs_readonly_metric(&outputs(&[(
            "cat /proc/mounts",
            "/dev/sda1 / ext4 rw,relatime 0 0\n/dev/sdb1 /data ext4 ro,relatime 0 0\n",
        )]));
        assert_eq!(ro.status, HealthStatus::Crit);
        assert!(ro.value.contains("/data"), "{}", ro.value);
        // All writable (pseudo ro fs ignored) -> Ok.
        let ok = fs_readonly_metric(&outputs(&[(
            "cat /proc/mounts",
            "/dev/sda1 / ext4 rw,relatime 0 0\ntmpfs /dev/shm tmpfs ro,nosuid 0 0\n",
        )]));
        assert_eq!(ok.status, HealthStatus::Ok);
        // No output -> Unknown.
        assert_eq!(
            fs_readonly_metric(&outputs(&[])).status,
            HealthStatus::Unknown
        );
    }

    #[test]
    fn cert_expiry_gates_on_nearest() {
        let thr = Thresholds::default(); // warn 21, crit 7 days
        let na = 1_794_744_000_i64; // Nov 15 2026 12:00 UTC
        let day = 86_400_i64;
        let cert = |p: &str| {
            (
                p.to_string(),
                Some("notAfter=Nov 15 12:00:00 2026 GMT\n".to_string()),
            )
        };
        // 30 / 14 / 3 days out -> Ok / Warn / Crit.
        assert_eq!(
            cert_expiry_metric(&[cert("/a")], &thr, na - 30 * day).status,
            HealthStatus::Ok
        );
        assert_eq!(
            cert_expiry_metric(&[cert("/a")], &thr, na - 14 * day).status,
            HealthStatus::Warn
        );
        assert_eq!(
            cert_expiry_metric(&[cert("/a")], &thr, na - 3 * day).status,
            HealthStatus::Crit
        );
        // Already expired -> Crit, value says EXPIRED.
        let exp = cert_expiry_metric(&[cert("/a")], &thr, na + 5 * day);
        assert_eq!(exp.status, HealthStatus::Crit);
        assert!(exp.value.contains("EXPIRED"), "{}", exp.value);
        // The nearest cert gates: a far cert plus a near one -> Crit.
        let far = (
            "/far".to_string(),
            Some("notAfter=Nov 15 12:00:00 2027 GMT\n".to_string()),
        );
        assert_eq!(
            cert_expiry_metric(&[far, cert("/near")], &thr, na - 3 * day).status,
            HealthStatus::Crit
        );
        // No configured paths -> Unknown; all unreadable -> Unknown.
        assert_eq!(
            cert_expiry_metric(&[], &thr, na).status,
            HealthStatus::Unknown
        );
        assert_eq!(
            cert_expiry_metric(&[("/x".to_string(), None)], &thr, na).status,
            HealthStatus::Unknown
        );
        // One unreadable + one good -> uses the good one, notes the unreadable.
        let mixed = cert_expiry_metric(
            &[("/x".to_string(), None), cert("/ok")],
            &thr,
            na - 30 * day,
        );
        assert_eq!(mixed.status, HealthStatus::Ok);
        assert!(mixed.detail.contains("unreadable"), "{}", mixed.detail);
    }

    #[test]
    fn iowait_thresholds() {
        let thr = Thresholds::default();
        let vm = |wa: u32| {
            format!(
                "r b swpd free buff cache si so bi bo in cs us sy id wa st\n\
                 1 0 0 100 100 100 0 0 10 20 100 200 5 2 90 {wa} 0\n"
            )
        };
        let (ok, warn, crit) = (vm(5), vm(30), vm(60));
        assert_eq!(
            iowait_metric(&outputs(&[("vmstat 1 2", ok.as_str())]), &thr).status,
            HealthStatus::Ok
        );
        assert_eq!(
            iowait_metric(&outputs(&[("vmstat 1 2", warn.as_str())]), &thr).status,
            HealthStatus::Warn
        );
        assert_eq!(
            iowait_metric(&outputs(&[("vmstat 1 2", crit.as_str())]), &thr).status,
            HealthStatus::Crit
        );
        // Missing vmstat -> Unknown (never gates).
        assert_eq!(
            iowait_metric(&outputs(&[]), &thr).status,
            HealthStatus::Unknown
        );
    }

    #[test]
    fn failed_units_status() {
        let thr = Thresholds::default();
        const CMD: &str =
            "systemctl list-units --type=service --state=failed --no-legend --no-pager";
        // No failed units (empty output) -> Ok.
        assert_eq!(
            failed_units_metric(&outputs(&[(CMD, "")]), &thr).status,
            HealthStatus::Ok
        );
        // One failed unit -> Warn (default: crit escalation disabled).
        let one = "nginx.service loaded failed failed A web server\n";
        let m = failed_units_metric(&outputs(&[(CMD, one)]), &thr);
        assert_eq!(m.status, HealthStatus::Warn);
        assert!(m.detail.contains("nginx.service"));
        assert_eq!(m.numeric, Some(1.0));
        // With a crit threshold, enough failed units escalate to Crit.
        let strict = Thresholds {
            failed_units_crit: 2,
            ..Thresholds::default()
        };
        let two = "a.service x x x d\nb.service x x x d\n";
        assert_eq!(
            failed_units_metric(&outputs(&[(CMD, two)]), &strict).status,
            HealthStatus::Crit
        );
        // Missing systemctl -> Unknown (never gates).
        assert_eq!(
            failed_units_metric(&outputs(&[]), &thr).status,
            HealthStatus::Unknown
        );
    }

    #[test]
    fn container_command_prefers_sudo_when_privileged() {
        // Privileged: sudo variant is preferred, plain is the fallback.
        assert_eq!(
            container_command(DOCKER_PS, true),
            (SUDO_DOCKER_PS, Some(DOCKER_PS))
        );
        assert_eq!(
            container_command(PODMAN_PS, true),
            (SUDO_PODMAN_PS, Some(PODMAN_PS))
        );
        // Unprivileged: plain command, no fallback.
        assert_eq!(container_command(DOCKER_PS, false), (DOCKER_PS, None));
        assert_eq!(container_command(PODMAN_PS, false), (PODMAN_PS, None));
        // Every wire variant is a catalog member.
        for cmd in [SUDO_DOCKER_PS, SUDO_PODMAN_PS] {
            assert!(crate::catalog::validate(cmd).is_ok(), "{cmd:?}");
        }
    }

    #[test]
    fn containers_status() {
        let hdr = "CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES\n";
        // No runtime at all -> Unknown (never gates).
        assert_eq!(
            containers_metric(&outputs(&[])).status,
            HealthStatus::Unknown
        );
        // Docker present, everything Up -> Ok.
        let healthy = format!("{hdr}a img x x Up 2 days 80/tcp web\n");
        assert_eq!(
            containers_metric(&outputs(&[("docker ps -a", &healthy)])).status,
            HealthStatus::Ok
        );
        // An unhealthy container -> Warn.
        let unhealthy = format!("{hdr}b img x x Up 3 days (unhealthy) 5432/tcp db\n");
        assert_eq!(
            containers_metric(&outputs(&[("docker ps -a", &unhealthy)])).status,
            HealthStatus::Warn
        );
        // A restarting (crash-looping) container -> Crit, named in detail. Podman
        // path also works.
        let looping = format!("{hdr}c img x x Restarting (2) 5 seconds ago 443/tcp mtproxy\n");
        let m = containers_metric(&outputs(&[("podman ps -a", &looping)]));
        assert_eq!(m.status, HealthStatus::Crit);
        assert!(m.detail.contains("mtproxy"));
    }

    #[test]
    fn disk_reports_worst_mount() {
        let thr = Thresholds::default();
        let df = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                  /dev/sda1 100 50 50 50% /\n\
                  /dev/sdb1 100 97 3 97% /data\n";
        let m = disk_metric(&outputs(&[("df -P", df)]), &thr);
        assert_eq!(m.status, HealthStatus::Crit);
        assert!(m.value.contains("/data"));
    }

    #[test]
    fn inodes_worst_mount_and_unknown() {
        let thr = Thresholds::default();
        // Blocks free but inodes nearly gone on / -> Crit (reuses disk thresholds).
        let dfi = "Filesystem Inodes IUsed IFree IUse% Mounted on\n\
                   /dev/sda1 1000000 980000 20000 98% /\n\
                   tmpfs 100000 5 99995 1% /run\n";
        let m = inodes_metric(&outputs(&[("df -Pi", dfi)]), &thr);
        assert_eq!(m.status, HealthStatus::Crit);
        assert!(m.value.contains("98%"), "{}", m.value);
        // Missing df -Pi -> Unknown (never gates).
        assert_eq!(
            inodes_metric(&outputs(&[]), &thr).status,
            HealthStatus::Unknown
        );
    }

    #[test]
    fn fd_thresholds_and_unknown() {
        let thr = Thresholds::default(); // fd warn 80, crit 95
        let m = |a: &str| fd_metric(&outputs(&[("cat /proc/sys/fs/file-nr", a)]), &thr).status;
        assert_eq!(m("4096 0 400000"), HealthStatus::Ok); // ~1%
        assert_eq!(m("170000 0 200000"), HealthStatus::Warn); // 85%
        assert_eq!(m("196000 0 200000"), HealthStatus::Crit); // 98%
                                                              // Missing input or a zero maximum -> Unknown (never gates).
        assert_eq!(fd_metric(&outputs(&[]), &thr).status, HealthStatus::Unknown);
        assert_eq!(m("5 0 0"), HealthStatus::Unknown); // max 0
    }

    #[test]
    fn conntrack_thresholds_and_unknown() {
        let thr = Thresholds::default(); // warn 80, crit 90
        let m = |a: &str| {
            conntrack_metric(
                &outputs(&[(
                    "cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max",
                    a,
                )]),
                &thr,
            )
            .status
        };
        assert_eq!(m("5000\n262144\n"), HealthStatus::Ok); // ~2%
        assert_eq!(m("170000\n200000\n"), HealthStatus::Warn); // 85%
        assert_eq!(m("195000\n200000\n"), HealthStatus::Crit); // 97%
                                                               // Module not loaded (files absent) -> Unknown, never gates.
        assert_eq!(
            conntrack_metric(&outputs(&[]), &thr).status,
            HealthStatus::Unknown
        );
    }

    #[test]
    fn pids_thresholds_and_unknown() {
        let thr = Thresholds::default(); // warn 80, crit 90
        let m = |a: &str| {
            pids_metric(
                &outputs(&[("cat /proc/loadavg /proc/sys/kernel/pid_max", a)]),
                &thr,
            )
            .status
        };
        assert_eq!(m("0.1 0.1 0.1 1/150 900\n32768\n"), HealthStatus::Ok); // ~0.5%
        assert_eq!(m("5 5 5 3/27000 900\n32768\n"), HealthStatus::Warn); // 82%
        assert_eq!(m("9 9 9 5/31000 900\n32768\n"), HealthStatus::Crit); // 95%
        assert_eq!(
            pids_metric(&outputs(&[]), &thr).status,
            HealthStatus::Unknown
        );
    }

    #[test]
    fn tcp_mem_worst_of_three_dimensions() {
        let thr = Thresholds::default(); // warn 80, crit 90
        const CMD: &str = "cat /proc/net/sockstat /proc/sys/net/ipv4/tcp_mem /proc/sys/net/ipv4/tcp_max_orphans /proc/sys/net/ipv4/tcp_max_tw_buckets";
        let sock = |mem: u64, orphan: u64, tw: u64| {
            format!(
                "sockets: used 1\n\
                 TCP: inuse 1 orphan {orphan} tw {tw} alloc 1 mem {mem}\n\
                 4096 6144 9216\n65536\n65536\n"
            )
        };
        let m = |a: String| tcp_mem_metric(&outputs(&[(CMD, a.as_str())]), &thr).status;
        // All low -> Ok.
        assert_eq!(m(sock(100, 100, 100)), HealthStatus::Ok);
        // TIME_WAIT near its bucket max (55000/65536 = 84%) -> Warn.
        assert_eq!(m(sock(100, 100, 55000)), HealthStatus::Warn);
        // TCP memory near tcp_mem max (9000/9216 = 98%) -> Crit, even if others low.
        let crit = tcp_mem_metric(&outputs(&[(CMD, sock(9000, 100, 100).as_str())]), &thr);
        assert_eq!(crit.status, HealthStatus::Crit);
        assert!(crit.value.contains("mem"), "{}", crit.value);
        // Missing input -> Unknown.
        assert_eq!(
            tcp_mem_metric(&outputs(&[]), &thr).status,
            HealthStatus::Unknown
        );
    }

    #[test]
    fn overall_is_worst_and_ignores_unknown() {
        let thr = Thresholds::default();
        // df crit, everything else unknown -> overall Crit.
        let df = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                  /dev/sda1 100 99 1 99% /\n";
        let r = evaluate(&outputs(&[("df -P", df)]), &thr);
        assert_eq!(r.overall, HealthStatus::Crit);
    }

    // rx grows by 2 MiB, tx flat, over the given interface.
    fn netdev(iface: &str, rx: u64, tx: u64) -> String {
        format!("Inter-|\n face |\n {iface}: {rx} 5 0 0 0 0 0 0 {tx} 4 0 0 0 0 0 0\n")
    }

    #[test]
    fn net_throughput_computes_rate_and_is_informational_by_default() {
        let thr = Thresholds::default();
        let s1 = netdev("eth0", 1_000_000, 500_000);
        let s2 = netdev("eth0", 1_000_000 + 2 * 1024 * 1024, 500_000);
        let m = net_throughput_metric(&s1, &s2, 1.0, &thr);
        assert_eq!(m.status, HealthStatus::Ok); // no thresholds set
        assert!(m.value.contains("eth0 rx 2.00 / tx 0.00"), "{}", m.value);
    }

    #[test]
    fn net_throughput_crosses_threshold() {
        let thr = Thresholds {
            net_rx_crit_mibps: 1.0,
            ..Thresholds::default()
        };
        let s1 = netdev("eth0", 0, 0);
        let s2 = netdev("eth0", 2 * 1024 * 1024, 0);
        assert_eq!(
            net_throughput_metric(&s1, &s2, 1.0, &thr).status,
            HealthStatus::Crit
        );
    }

    #[test]
    fn net_throughput_counter_reset_is_not_a_spike() {
        let thr = Thresholds {
            net_rx_warn_mibps: 1.0,
            ..Thresholds::default()
        };
        // s2 < s1 (reboot/wrap): saturating delta -> 0, so no false Warn.
        let s1 = netdev("eth0", 5_000_000, 5_000_000);
        let s2 = netdev("eth0", 1000, 1000);
        assert_eq!(
            net_throughput_metric(&s1, &s2, 1.0, &thr).status,
            HealthStatus::Ok
        );
    }

    #[test]
    fn net_throughput_unknown_without_data() {
        let thr = Thresholds::default();
        assert_eq!(
            net_throughput_metric("", "", 1.0, &thr).status,
            HealthStatus::Unknown
        );
        assert_eq!(
            net_throughput_metric(&netdev("eth0", 1, 1), &netdev("eth0", 2, 2), 0.0, &thr).status,
            HealthStatus::Unknown // no measurable interval
        );
    }

    #[test]
    fn top_processes_split_by_resource() {
        let thr = Thresholds {
            top_n: 2,
            ..Thresholds::default()
        };
        let ps = "PID COMMAND %CPU %MEM\n\
                  1 a 90.0 1.0\n\
                  2 b 10.0 80.0\n\
                  3 c 5.0 40.0\n";
        let r = evaluate(
            &outputs(&[("ps -eo pid,comm,pcpu,pmem --sort=-pcpu", ps)]),
            &thr,
        );
        assert_eq!(r.top_cpu[0].comm, "a"); // highest cpu
        assert_eq!(r.top_mem[0].comm, "b"); // highest mem
        assert_eq!(r.top_cpu.len(), 2);
    }
}
