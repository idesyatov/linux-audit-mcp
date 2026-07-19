//! Fan-out orchestration: run the audit or the health snapshot against one or
//! many targets (a group), concurrently, capturing per-host runtime failures so
//! one unreachable host does not sink the whole group.
//!
//! UI-agnostic: returns structured per-host outcomes that `cli`/`server` render.
//! Config problems (unknown group/member, conflicting group vars) fail fast; a
//! per-host connection/auth error is captured as that host's `Err`.

use serde_json::json;
use tokio::task::JoinSet;

use crate::anomaly;
use crate::audit;
use crate::checks::Finding;
use crate::config::{Config, ConfigError};
use crate::health::{self, HealthReport, HealthStatus};
use crate::history;
use crate::scoring::{self, Profile, Score};

/// Result of auditing one host: its score+findings, or a runtime error message.
pub struct AuditOutcome {
    pub alias: String,
    pub result: Result<(Score, Vec<Finding>), String>,
}

/// Result of a health snapshot of one host, or a runtime error message.
pub struct HealthOutcome {
    pub alias: String,
    pub result: Result<HealthReport, String>,
}

/// Resolve each alias up front (config errors abort), then run all hosts
/// concurrently, preserving the input order in the returned vec.
pub async fn audit_targets(
    cfg: &Config,
    aliases: &[String],
    profile_override: Option<Profile>,
) -> Result<Vec<AuditOutcome>, ConfigError> {
    let mut jobs = Vec::with_capacity(aliases.len());
    for alias in aliases {
        let resolved = cfg.resolve(alias)?;
        let profile = profile_override.or(resolved.profile).unwrap_or_default();
        jobs.push((alias.clone(), resolved.to_ssh_config(), profile));
    }

    let mut set = JoinSet::new();
    for (i, (alias, ssh, profile)) in jobs.into_iter().enumerate() {
        set.spawn(async move {
            let result = match audit::run_audit(&ssh).await {
                Ok(findings) => {
                    let score = scoring::score(&findings, profile);
                    Ok((score, findings))
                }
                Err(e) => Err(e.to_string()),
            };
            (i, AuditOutcome { alias, result })
        });
    }
    Ok(collect_ordered(set).await)
}

pub async fn health_targets(
    cfg: &Config,
    aliases: &[String],
) -> Result<Vec<HealthOutcome>, ConfigError> {
    let mut jobs = Vec::with_capacity(aliases.len());
    for alias in aliases {
        let resolved = cfg.resolve(alias)?;
        jobs.push((alias.clone(), resolved.to_ssh_config(), resolved.health));
    }

    let mut set = JoinSet::new();
    for (i, (alias, ssh, thr)) in jobs.into_iter().enumerate() {
        set.spawn(async move {
            let result = health::collect(&ssh, &thr).await.map_err(|e| e.to_string());
            (i, HealthOutcome { alias, result })
        });
    }
    Ok(collect_ordered(set).await)
}

/// Fill in `report.anomalies` for each successful outcome by comparing the fresh
/// reading against this host's stored history (Stage B2). Must run BEFORE the
/// new snapshot is recorded, so the current run is not part of its own baseline.
///
/// Best-effort: a history-read error, an unresolvable alias, or a warming-up
/// baseline leaves `anomalies` empty (with a note) and never fails the run.
pub fn annotate_anomalies(cfg: &Config, outcomes: &mut [HealthOutcome]) {
    for o in outcomes.iter_mut() {
        let Ok(report) = &mut o.result else { continue };
        let acfg = match cfg.resolve(&o.alias) {
            Ok(r) => r.anomaly,
            Err(_) => continue, // resolved once already during the run; skip quietly
        };
        if !acfg.enabled {
            report.anomaly_note = Some("anomaly detection disabled".to_string());
            continue;
        }
        let hist = match history::read_recent(&o.alias, acfg.window) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("anomaly: could not read history for '{}': {e}", o.alias);
                continue;
            }
        };
        if hist.len() < acfg.min_samples {
            report.anomaly_note = Some(format!(
                "baseline warming up ({}/{})",
                hist.len(),
                acfg.min_samples
            ));
            continue;
        }
        let found = anomaly::detect(report, &hist, &acfg);
        report.anomalies = found;
    }
}

/// Drain a `JoinSet<(index, T)>` and return the `T`s in ascending index order.
async fn collect_ordered<T: Send + 'static>(mut set: JoinSet<(usize, T)>) -> Vec<T> {
    let mut buf: Vec<(usize, T)> = Vec::new();
    while let Some(joined) = set.join_next().await {
        // A spawned task only panics if the probe code itself panics; surface it.
        buf.push(joined.expect("audit/health task panicked"));
    }
    buf.sort_by_key(|(i, _)| *i);
    buf.into_iter().map(|(_, t)| t).collect()
}

fn status_tag(s: HealthStatus) -> &'static str {
    match s {
        HealthStatus::Ok => "OK",
        HealthStatus::Warn => "WARN",
        HealthStatus::Crit => "CRIT",
        HealthStatus::Unknown => "UNKN",
    }
}

// ---- group rendering (text + JSON) --------------------------------------

/// Human-readable group health report: a summary line, then each host's block.
pub fn health_group_text(group: &str, outcomes: &[HealthOutcome]) -> String {
    use std::fmt::Write;
    let (mut ok, mut warn, mut crit, mut unknown, mut errored) = (0, 0, 0, 0, 0);
    for o in outcomes {
        match &o.result {
            Ok(r) => match r.overall {
                HealthStatus::Ok => ok += 1,
                HealthStatus::Warn => warn += 1,
                HealthStatus::Crit => crit += 1,
                HealthStatus::Unknown => unknown += 1,
            },
            Err(_) => errored += 1,
        }
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Health group '{group}' ({} hosts): {ok} OK, {warn} WARN, {crit} CRIT, {unknown} UNKN, {errored} error",
        outcomes.len()
    );
    for o in outcomes {
        match &o.result {
            Ok(r) => {
                let _ = writeln!(out, "=== {} [{}] ===", o.alias, status_tag(r.overall));
                out.push_str(&health::report::text(&o.alias, r));
            }
            Err(e) => {
                let _ = writeln!(out, "=== {} [ERROR] ===\n  {e}", o.alias);
            }
        }
    }
    out
}

pub fn health_group_json(group: &str, outcomes: &[HealthOutcome]) -> serde_json::Result<String> {
    let hosts: Vec<_> = outcomes
        .iter()
        .map(|o| match &o.result {
            Ok(r) => json!({ "alias": o.alias, "status": r.overall, "report": r }),
            Err(e) => json!({ "alias": o.alias, "error": e }),
        })
        .collect();
    serde_json::to_string_pretty(&json!({
        "group": group,
        "kind": "health-group",
        "hosts": hosts,
    }))
}

/// Human-readable group audit report: a summary line, then each host's block.
pub fn audit_group_text(group: &str, outcomes: &[AuditOutcome]) -> String {
    use std::fmt::Write;
    let scored: Vec<u8> = outcomes
        .iter()
        .filter_map(|o| o.result.as_ref().ok().map(|(s, _)| s.total))
        .collect();
    let errored = outcomes.iter().filter(|o| o.result.is_err()).count();
    let lowest = scored.iter().min().copied();
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Audit group '{group}' ({} hosts): lowest score {}, {errored} error",
        outcomes.len(),
        lowest
            .map(|s| s.to_string())
            .unwrap_or_else(|| "n/a".into())
    );
    for o in outcomes {
        match &o.result {
            Ok((score, findings)) => {
                let _ = writeln!(out, "=== {} ===", o.alias);
                out.push_str(&crate::report::text(&o.alias, score, findings));
            }
            Err(e) => {
                let _ = writeln!(out, "=== {} [ERROR] ===\n  {e}", o.alias);
            }
        }
    }
    out
}

pub fn audit_group_json(group: &str, outcomes: &[AuditOutcome]) -> serde_json::Result<String> {
    let hosts: Vec<_> = outcomes
        .iter()
        .map(|o| match &o.result {
            Ok((score, findings)) => {
                json!({ "alias": o.alias, "score": score, "findings": findings })
            }
            Err(e) => json!({ "alias": o.alias, "error": e }),
        })
        .collect();
    serde_json::to_string_pretty(&json!({
        "group": group,
        "kind": "audit-group",
        "hosts": hosts,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::Metric;
    use crate::history::{record_in, Snapshot};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    // Only this test touches $LINUX_AUDIT_DATA_DIR (history tests use explicit
    // dirs), so setting it process-wide here does not race other tests.
    fn temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("lah-run-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn load_report(current: f64) -> HealthReport {
        HealthReport {
            metrics: vec![Metric {
                id: "health-load",
                title: "Load average",
                status: HealthStatus::Ok,
                value: String::new(),
                detail: String::new(),
                numeric: Some(current),
            }],
            top_cpu: vec![],
            top_mem: vec![],
            overall: HealthStatus::Ok,
            anomalies: vec![],
            anomaly_note: None,
        }
    }

    fn snap(ts: u64, load: f64) -> Snapshot {
        let mut m = BTreeMap::new();
        m.insert("health-load".to_string(), load);
        Snapshot {
            ts,
            overall: HealthStatus::Ok,
            metrics: m,
        }
    }

    fn outcome(current: f64) -> Vec<HealthOutcome> {
        vec![HealthOutcome {
            alias: "web".to_string(),
            result: Ok(load_report(current)),
        }]
    }

    #[test]
    fn annotate_warms_up_then_flags_spike() {
        let dir = temp_dir("anom");
        std::env::set_var("LINUX_AUDIT_DATA_DIR", &dir);
        let cfg: Config = toml::from_str("[targets.web]\nhost = \"1.1.1.1\"").unwrap();

        // Too little history (< min_samples): a note, no anomalies.
        for i in 0..3 {
            record_in(&dir, "web", &snap(i, 0.3), 0).unwrap();
        }
        let mut warming = outcome(9.0);
        annotate_anomalies(&cfg, &mut warming);
        let r = warming[0].result.as_ref().unwrap();
        assert!(r.anomalies.is_empty());
        assert!(r.anomaly_note.as_deref().unwrap().contains("warming up"));

        // Enough stable history + a spike current reading: flagged.
        for i in 3..12 {
            record_in(&dir, "web", &snap(i, 0.3), 0).unwrap();
        }
        let mut hot = outcome(9.0);
        annotate_anomalies(&cfg, &mut hot);
        let r = hot[0].result.as_ref().unwrap();
        assert_eq!(r.anomalies.len(), 1);
        assert_eq!(r.anomalies[0].metric_id, "health-load");
        assert!(r.anomaly_note.is_none());

        std::env::remove_var("LINUX_AUDIT_DATA_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
