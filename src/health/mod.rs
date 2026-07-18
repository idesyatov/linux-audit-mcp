//! Operational-health probes: a point-in-time snapshot of load, memory, disk,
//! hot processes and socket counts over the same read-only SSH channel as the
//! security audit.
//!
//! Deliberately kept separate from [`crate::checks`]/[`crate::scoring`]: health
//! is momentary and workload-dependent, not a hardening fact, so it produces
//! `Ok`/`Warn`/`Crit` metrics against thresholds and never feeds the 0-100
//! security score. True baselining/anomaly detection is a later stage.

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

/// Every read-only command the health snapshot issues (each must be in the
/// catalog; see the invariant test).
pub const HEALTH_COMMANDS: &[&str] = &[UPTIME, NPROC, FREE, DF, PS, SS];

/// A metric's verdict against its thresholds. `Unknown` means the input was
/// missing or unparseable - it never counts toward the overall status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
}

/// The full operational-health snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct HealthReport {
    pub metrics: Vec<Metric>,
    pub top_cpu: Vec<ProcInfo>,
    pub top_mem: Vec<ProcInfo>,
    /// Worst status across all metrics (`Unknown` if nothing could be measured).
    pub overall: HealthStatus,
}

/// Thresholds for turning raw readings into `Ok`/`Warn`/`Crit`. Each field has a
/// sensible default; a target may override any subset via `[targets.x.health]`.
#[derive(Debug, Clone, Copy, Deserialize)]
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
    let mem_used_pct = if free.mem_total == 0 {
        0.0
    } else if free.mem_available > 0 {
        (free.mem_total.saturating_sub(free.mem_available)) as f64 / free.mem_total as f64 * 100.0
    } else {
        free.mem_used as f64 / free.mem_total as f64 * 100.0
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
            human_bytes(
                free.mem_total
                    .saturating_sub(free.mem_available)
                    .max(free.mem_used)
            ),
            human_bytes(free.mem_total),
            human_bytes(free.mem_available)
        ),
    };
    let swap = if free.swap_total == 0 {
        Metric {
            id: SWAP_ID,
            title: "Swap usage",
            status: HealthStatus::Ok,
            value: "no swap".to_string(),
            detail: "no swap configured".to_string(),
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
    }
}

fn network_metric(outputs: &Outputs) -> Metric {
    const ID: &str = "health-connections";
    const TITLE: &str = "Network connections";
    let Some(s) = out(outputs, SS).and_then(parse::parse_ss_summary) else {
        return unknown(ID, TITLE, "ss unavailable");
    };
    // Informational in Stage A: without a per-host baseline there is no
    // meaningful threshold, so this reports the count as Ok.
    Metric {
        id: ID,
        title: TITLE,
        status: HealthStatus::Ok,
        value: format!("{} established", s.tcp_estab),
        detail: format!("{} sockets total", s.total),
    }
}

/// Build a health report from pre-collected command outputs. Pure (no I/O):
/// shared by [`collect`] and the evals.
pub fn evaluate(outputs: &Outputs, thr: &Thresholds) -> HealthReport {
    let mut metrics = vec![load_metric(outputs, thr)];
    metrics.extend(memory_metrics(outputs, thr));
    metrics.push(disk_metric(outputs, thr));
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

    let overall = metrics
        .iter()
        .map(|m| m.status)
        .max_by_key(|s| s.rank())
        .unwrap_or(HealthStatus::Unknown);

    HealthReport {
        metrics,
        top_cpu,
        top_mem,
        overall,
    }
}

/// Snap each health command once over SSH, then evaluate.
///
/// Host-level failures (auth, connection, timeout) abort. A per-command remote
/// failure becomes an `Unknown` metric for whatever needed it; the rest run.
pub async fn collect(ssh: &SshConfig, thr: &Thresholds) -> Result<HealthReport, SshError> {
    let mut outputs: Outputs = HashMap::new();
    for &cmd in HEALTH_COMMANDS {
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
    Ok(evaluate(&outputs, thr))
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
