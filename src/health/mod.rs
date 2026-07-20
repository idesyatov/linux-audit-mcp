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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::audit::Outputs;
use crate::ssh::{SshConfig, SshError};
use parse::ProcInfo;

const UPTIME: &str = "uptime";
const NPROC: &str = "nproc";
const FREE: &str = "free -b";
const DF: &str = "df -P";
const PS: &str = "ps -eo pid,comm,pcpu,pmem --sort=-pcpu";
const SS: &str = "ss -s";
/// `1 2` = one 1-second sample; vmstat does its own timing, so this is a normal
/// single-shot command whose last row is the current delta (parsed in [`evaluate`]).
const VMSTAT: &str = "vmstat 1 2";
/// Sampled twice (not single-shot) to derive throughput and error rate, so it is
/// handled apart from [`SINGLE_SHOT`] in [`collect`] and yields no metric in
/// [`evaluate`].
const NETDEV: &str = "cat /proc/net/dev";

/// Commands snapped exactly once per snapshot.
const SINGLE_SHOT: &[&str] = &[UPTIME, NPROC, FREE, DF, PS, SS, VMSTAT];

/// Every read-only command the health snapshot may issue (each must be in the
/// catalog; see the invariant test). Consumed only by the invariant test and
/// evals; the run path uses [`SINGLE_SHOT`] plus [`NETDEV`].
#[allow(dead_code)]
pub const HEALTH_COMMANDS: &[&str] = &[UPTIME, NPROC, FREE, DF, PS, SS, VMSTAT, NETDEV];

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
    /// Filesystem capacity (percent).
    pub disk_warn_pct: u8,
    pub disk_crit_pct: u8,
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
    /// Gap between the two `/proc/net/dev` samples, in seconds.
    pub net_sample_secs: u64,
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
            iowait_warn_pct: 20.0,
            iowait_crit_pct: 50.0,
            net_rx_warn_mibps: 0.0,
            net_rx_crit_mibps: 0.0,
            net_tx_warn_mibps: 0.0,
            net_tx_crit_mibps: 0.0,
            net_err_warn_pps: 1.0,
            net_err_crit_pps: 10.0,
            net_sample_secs: 1,
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
    metrics.push(iowait_metric(outputs, thr));
    metrics.push(network_metric(outputs));

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

    HealthReport {
        metrics,
        top_cpu,
        top_mem,
        overall,
        // Anomalies need the stored history + per-target config, neither of which
        // this pure function has; they are filled in by the run orchestration.
        anomalies: Vec::new(),
        anomaly_note: None,
    }
}

/// Snap each single-shot command once over SSH, sample `/proc/net/dev` twice for
/// throughput, then evaluate.
///
/// Host-level failures (auth, connection, timeout) abort. A per-command remote
/// failure becomes an `Unknown` metric for whatever needed it; the rest run.
pub async fn collect(ssh: &SshConfig, thr: &Thresholds) -> Result<HealthReport, SshError> {
    let mut outputs: Outputs = HashMap::new();
    for &cmd in SINGLE_SHOT {
        match ssh.run(cmd).await {
            Ok(out) => {
                outputs.insert(cmd, Ok(out.stdout));
            }
            Err(SshError::RemoteCommand { code, stderr }) => {
                outputs.insert(
                    cmd,
                    Err(format!("remote command failed (code {code:?}): {stderr}")),
                );
            }
            Err(host_level) => return Err(host_level),
        }
    }

    let mut report = evaluate(&outputs, thr);

    // Two timed samples of the interface counters -> throughput and error rate.
    // A remote error on either read degrades to Unknown metrics; host-level errors
    // abort.
    let (throughput, errors) = match sample_net(ssh, thr).await? {
        Some((s1, s2, dt)) => (
            net_throughput_metric(&s1, &s2, dt, thr),
            net_errors_metric(&s1, &s2, dt, thr),
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
        ),
    };
    report.metrics.push(throughput);
    report.metrics.push(errors);
    report.overall = worst(&report.metrics);
    Ok(report)
}

/// Read `/proc/net/dev` twice, `net_sample_secs` apart, returning both samples
/// and the elapsed seconds. `Ok(None)` if either read fails remotely.
async fn sample_net(
    ssh: &SshConfig,
    thr: &Thresholds,
) -> Result<Option<(String, String, f64)>, SshError> {
    let first = match ssh.run(NETDEV).await {
        Ok(out) => out.stdout,
        Err(SshError::RemoteCommand { .. }) => return Ok(None),
        Err(host_level) => return Err(host_level),
    };
    let start = std::time::Instant::now();
    tokio::time::sleep(std::time::Duration::from_secs(thr.net_sample_secs.max(1))).await;
    let second = match ssh.run(NETDEV).await {
        Ok(out) => out.stdout,
        Err(SshError::RemoteCommand { .. }) => return Ok(None),
        Err(host_level) => return Err(host_level),
    };
    Ok(Some((first, second, start.elapsed().as_secs_f64())))
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
