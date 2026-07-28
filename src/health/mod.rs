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

use crate::audit::Outputs;
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
const PS: &str = "ps -eo pid,comm,pcpu,pmem --sort=-pcpu";
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
/// Sampled twice (not single-shot) to derive throughput and error rate, so it is
/// handled apart from [`SINGLE_SHOT`] in [`collect`] and yields no metric in
/// [`evaluate`].
const NETDEV: &str = "cat /proc/net/dev";
/// TCP extended counters; sampled twice (alongside [`NETDEV`]) for the
/// accept-queue overflow rate. Handled in [`collect`], not [`evaluate`].
const NETSTAT: &str = "cat /proc/net/netstat";

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
    PS,
    SS,
    VMSTAT,
    SYSTEMCTL_FAILED,
    DOCKER_PS,
    PODMAN_PS,
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
    PS,
    SS,
    VMSTAT,
    SYSTEMCTL_FAILED,
    DOCKER_PS,
    PODMAN_PS,
    SUDO_DOCKER_PS,
    SUDO_PODMAN_PS,
    NETDEV,
    NETSTAT,
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
    /// Gap between the two `/proc/net/dev` samples, in seconds.
    pub net_sample_secs: u64,
    /// Failed systemd services: any failed unit is a `Warn`; this many or more
    /// escalate to `Crit`. `0` disables the escalation (failed units stay `Warn`),
    /// which is the default - a single benign oneshot failure shouldn't be `Crit`.
    pub failed_units_crit: u32,
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
            net_sample_secs: 1,
            failed_units_crit: 0,
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
    metrics.push(iowait_metric(outputs, thr));
    metrics.push(network_metric(outputs));
    metrics.push(failed_units_metric(outputs, thr));
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
) -> Result<HealthReport, SshError> {
    let mut outputs: Outputs = HashMap::new();
    for &cmd in SINGLE_SHOT {
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
                        .ok_or_else(|| "container runtime unavailable".to_string()),
                    None => Err("container runtime unavailable".to_string()),
                },
            }
        } else {
            match ssh.run(cmd).await {
                Ok(out) => Ok(out.stdout),
                Err(SshError::RemoteCommand { code, stderr }) => {
                    Err(format!("remote command failed (code {code:?}): {stderr}"))
                }
                Err(host_level) => return Err(host_level),
            }
        };
        outputs.insert(cmd, value);
    }

    let mut report = evaluate(&outputs, thr);

    // Two timed samples of the counter files -> throughput, error and accept-queue
    // overflow rates. A remote error on the `dev` reads degrades to Unknown metrics;
    // host-level errors abort.
    let (throughput, errors, listen) = match sample_net(ssh, thr).await? {
        Some(s) => (
            net_throughput_metric(&s.dev1, &s.dev2, s.dt, thr),
            net_errors_metric(&s.dev1, &s.dev2, s.dt, thr),
            net_listen_metric(&s.stat1, &s.stat2, s.dt, thr),
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
        ),
    };
    report.metrics.push(throughput);
    report.metrics.push(errors);
    report.metrics.push(listen);
    report.overall = worst(&report.metrics);
    Ok(report)
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
    dt: f64,
}

/// Read `/proc/net/dev` (and `/proc/net/netstat`) twice, `net_sample_secs` apart.
/// `Ok(None)` if a `dev` read fails remotely; a failed `netstat` read just leaves
/// its sample empty (that metric then reports `Unknown`).
async fn sample_net(ssh: &SshConfig, thr: &Thresholds) -> Result<Option<NetSamples>, SshError> {
    let dev1 = match ssh.run(NETDEV).await {
        Ok(out) => out.stdout,
        Err(SshError::RemoteCommand { .. }) => return Ok(None),
        Err(host_level) => return Err(host_level),
    };
    let stat1 = run_single(ssh, NETSTAT).await?.unwrap_or_default();
    let start = std::time::Instant::now();
    tokio::time::sleep(std::time::Duration::from_secs(thr.net_sample_secs.max(1))).await;
    let dev2 = match ssh.run(NETDEV).await {
        Ok(out) => out.stdout,
        Err(SshError::RemoteCommand { .. }) => return Ok(None),
        Err(host_level) => return Err(host_level),
    };
    let stat2 = run_single(ssh, NETSTAT).await?.unwrap_or_default();
    Ok(Some(NetSamples {
        dev1,
        dev2,
        stat1,
        stat2,
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
