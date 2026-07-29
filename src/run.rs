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
use crate::checks::{CheckFilter, Finding};
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
    filter: &CheckFilter,
) -> Result<Vec<AuditOutcome>, ConfigError> {
    let mut jobs = Vec::with_capacity(aliases.len());
    for alias in aliases {
        let resolved = cfg.resolve(alias)?;
        let profile = profile_override.or(resolved.profile).unwrap_or_default();
        jobs.push((
            alias.clone(),
            resolved.to_ssh_config(),
            profile,
            resolved.privileged,
        ));
    }

    let mut set = JoinSet::new();
    for (i, (alias, ssh, profile, privileged)) in jobs.into_iter().enumerate() {
        let filter = filter.clone();
        set.spawn(async move {
            let result = match audit::run_audit(&ssh, privileged, &filter).await {
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
        jobs.push((
            alias.clone(),
            resolved.to_ssh_config(),
            resolved.health,
            resolved.privileged,
            resolved.cert_paths,
        ));
    }

    let mut set = JoinSet::new();
    for (i, (alias, ssh, thr, privileged, cert_paths)) in jobs.into_iter().enumerate() {
        set.spawn(async move {
            let result = health::collect(&ssh, &thr, privileged, &cert_paths)
                .await
                .map_err(|e| e.to_string());
            (i, HealthOutcome { alias, result })
        });
    }
    Ok(collect_ordered(set).await)
}

/// Fill in `report.anomalies` for each successful outcome by comparing the fresh
/// reading against this host's stored history. Must run BEFORE the new snapshot
/// is recorded, so the current run is not part of its own baseline.
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

/// Flag between-run changes for each successful outcome by comparing the fresh
/// reading against this host's most recent stored snapshot: a container whose
/// uptime dropped (restarted since the last check) or a systemd unit that newly
/// entered the failed state. Must run BEFORE the new snapshot is recorded, so
/// "previous" is genuinely the prior run.
///
/// Informational only - like anomalies, these never change `overall` nor the
/// exit code. Best-effort: no history yet (first run) or a read error leaves
/// `changes` empty and never fails the run. Zero-config: unlike anomalies this
/// needs only one prior snapshot, so it works from the second run onward.
pub fn annotate_changes(outcomes: &mut [HealthOutcome]) {
    for o in outcomes.iter_mut() {
        let Ok(report) = &mut o.result else { continue };
        let prev = match history::read_recent(&o.alias, 1) {
            Ok(mut v) => v.pop(),
            Err(e) => {
                tracing::warn!("changes: could not read history for '{}': {e}", o.alias);
                continue;
            }
        };
        let Some(prev) = prev else { continue };
        let mut changes = Vec::new();
        // A container restarted iff its uptime dropped versus last check. Uptime
        // is monotonic within a container's life, so a drop is unambiguous - no
        // false positives from the coarse humanized value.
        for (name, &up) in &report.container_uptimes {
            if let Some(&prev_up) = prev.containers.get(name) {
                if up < prev_up {
                    changes.push(format!(
                        "container {name} restarted since last check (up {}, was up {})",
                        fmt_dur(up),
                        fmt_dur(prev_up)
                    ));
                }
            }
        }
        // A unit newly failed iff it is failed now but was not last check.
        for u in &report.failed_units {
            if !prev.failed_units.contains(u) {
                changes.push(format!("unit {u} newly failed since last check"));
            }
        }
        // Cumulative since-boot event counters that rose versus last check
        // (conntrack table pressure, kernel-log events per category). saturating_sub
        // ignores a counter reset (reboot). A category present now but absent last
        // check counts as fully new - but only when the previous snapshot actually
        // tracked counters, so upgrading from a pre-0.28 snapshot doesn't report the
        // whole since-boot backlog as "new".
        let prev_tracked = !prev.event_counters.is_empty();
        for (key, &cur) in &report.event_counters {
            match prev.event_counters.get(key) {
                Some(&was) => {
                    let delta = cur.saturating_sub(was);
                    if delta > 0 {
                        changes.push(format!("since last check: +{delta} {key}"));
                    }
                }
                None if prev_tracked && cur > 0 => {
                    changes.push(format!("since last check: +{cur} {key} (new)"));
                }
                None => {}
            }
        }
        changes.sort();
        report.changes = changes;
    }
}

/// Compact human duration for whole seconds (`90` -> `1m`, `172800` -> `2d`).
/// Coarse on purpose: it only annotates a restart note.
fn fmt_dur(secs: u64) -> String {
    for (size, suffix) in [(86_400, 'd'), (3_600, 'h'), (60, 'm')] {
        if secs >= size {
            return format!("{}{suffix}", secs / size);
        }
    }
    format!("{secs}s")
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
                let _ = writeln!(out, "=== {} [{}] ===", o.alias, r.overall.tag());
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

/// A run of hosts whose audit result is identical (same score + findings, or the
/// same error message), so a homogeneous fleet renders once instead of per host.
struct HostGroup<'a> {
    aliases: Vec<&'a str>,
    repr: &'a AuditOutcome,
}

/// Bucket hosts by an alias-independent signature, preserving first-appearance
/// order (both of the buckets and of the aliases within each). The signature is
/// the rendered report with an empty alias, so two hosts collapse iff their
/// profile, score and every finding match; it is used only as a key and never
/// surfaced. Keeps `Finding`/`Score` free of extra derives.
fn group_identical(outcomes: &[AuditOutcome]) -> Vec<HostGroup<'_>> {
    let mut groups: Vec<HostGroup<'_>> = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    for o in outcomes {
        let key = match &o.result {
            Ok((score, findings)) => crate::report::text("", score, findings),
            Err(e) => format!("__err__{e}"),
        };
        match keys.iter().position(|k| *k == key) {
            Some(i) => groups[i].aliases.push(o.alias.as_str()),
            None => {
                keys.push(key);
                groups.push(HostGroup {
                    aliases: vec![o.alias.as_str()],
                    repr: o,
                });
            }
        }
    }
    groups
}

/// Human-readable group audit report: a summary line, then one block per set of
/// identical hosts (a homogeneous fleet renders its shared findings once).
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
    for g in group_identical(outcomes) {
        let header = if g.aliases.len() > 1 {
            format!(
                "{} ({} hosts, identical)",
                g.aliases.join(", "),
                g.aliases.len()
            )
        } else {
            g.aliases[0].to_string()
        };
        match &g.repr.result {
            Ok((score, findings)) => {
                let _ = writeln!(out, "=== {header} ===");
                out.push_str(&crate::report::text(g.aliases[0], score, findings));
            }
            Err(e) => {
                let _ = writeln!(out, "=== {header} [ERROR] ===\n  {e}");
            }
        }
    }
    out
}

pub fn audit_group_json(group: &str, outcomes: &[AuditOutcome]) -> serde_json::Result<String> {
    let groups: Vec<_> = group_identical(outcomes)
        .into_iter()
        .map(|g| match &g.repr.result {
            Ok((score, findings)) => {
                json!({ "aliases": g.aliases, "score": score, "findings": findings })
            }
            Err(e) => json!({ "aliases": g.aliases, "error": e }),
        })
        .collect();
    serde_json::to_string_pretty(&json!({
        "group": group,
        "kind": "audit-group",
        "groups": groups,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::Metric;
    use crate::history::{record_in, Snapshot};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::Mutex;

    // $LINUX_AUDIT_DATA_DIR is process-global; the tests that set it must not run
    // concurrently, so they serialize on this lock (history tests use explicit
    // dirs and don't need it).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
            changes: vec![],
            container_uptimes: BTreeMap::new(),
            failed_units: vec![],
            event_counters: BTreeMap::new(),
        }
    }

    fn snap(ts: u64, load: f64) -> Snapshot {
        let mut m = BTreeMap::new();
        m.insert("health-load".to_string(), load);
        Snapshot {
            ts,
            overall: HealthStatus::Ok,
            metrics: m,
            containers: BTreeMap::new(),
            failed_units: Vec::new(),
            event_counters: BTreeMap::new(),
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
        let _guard = ENV_LOCK.lock().unwrap();
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

    /// A snapshot carrying container uptimes, failed units and event counters, for
    /// the changes test.
    fn snap_state(
        ts: u64,
        containers: &[(&str, u64)],
        failed: &[&str],
        events: &[(&str, u64)],
    ) -> Snapshot {
        Snapshot {
            ts,
            overall: HealthStatus::Ok,
            metrics: BTreeMap::new(),
            containers: containers
                .iter()
                .map(|(n, u)| (n.to_string(), *u))
                .collect(),
            failed_units: failed.iter().map(|s| s.to_string()).collect(),
            event_counters: events.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        }
    }

    fn state_report(
        containers: &[(&str, u64)],
        failed: &[&str],
        events: &[(&str, u64)],
    ) -> Vec<HealthOutcome> {
        let mut r = load_report(0.3);
        r.container_uptimes = containers
            .iter()
            .map(|(n, u)| (n.to_string(), *u))
            .collect();
        r.failed_units = failed.iter().map(|s| s.to_string()).collect();
        r.event_counters = events.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        vec![HealthOutcome {
            alias: "web".to_string(),
            result: Ok(r),
        }]
    }

    #[test]
    fn annotate_changes_flags_restart_and_new_failure() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = temp_dir("changes");
        std::env::set_var("LINUX_AUDIT_DATA_DIR", &dir);

        // No history yet -> nothing flagged (first run is silent).
        let mut first = state_report(&[("proxy", 40)], &[], &[]);
        annotate_changes(&mut first);
        assert!(first[0].result.as_ref().unwrap().changes.is_empty());

        // Previous run: proxy up 2 days, web up 1 hour, no failed units; conntrack
        // pressure at 100, one ext4 error already seen.
        record_in(
            &dir,
            "web",
            &snap_state(
                1,
                &[("proxy", 172_800), ("web", 3_600)],
                &[],
                &[("conntrack table pressure", 100), ("kernel: ext4 error", 1)],
            ),
            0,
        )
        .unwrap();

        // Now: proxy uptime dropped (restarted), web grew (fine), nginx failed;
        // conntrack pressure rose by 30, ext4 unchanged, a new block-I/O error class.
        let mut cur = state_report(
            &[("proxy", 40), ("web", 7_200)],
            &["nginx.service"],
            &[
                ("conntrack table pressure", 130),
                ("kernel: ext4 error", 1),
                ("kernel: block I/O error", 2),
            ],
        );
        annotate_changes(&mut cur);
        let changes = &cur[0].result.as_ref().unwrap().changes;
        assert_eq!(changes.len(), 4, "{changes:?}");
        assert!(changes.iter().any(|c| c.contains("proxy restarted")));
        assert!(changes
            .iter()
            .any(|c| c.contains("nginx.service newly failed")));
        // web's uptime grew, so it is not reported as restarted.
        assert!(!changes.iter().any(|c| c.contains("web restarted")));
        // Conntrack pressure rose by 30; a new event class is flagged fully; an
        // unchanged counter (ext4) is silent.
        assert!(changes
            .iter()
            .any(|c| c.contains("+30 conntrack table pressure")));
        assert!(changes
            .iter()
            .any(|c| c.contains("+2 kernel: block I/O error (new)")));
        assert!(!changes.iter().any(|c| c.contains("ext4")));

        std::env::remove_var("LINUX_AUDIT_DATA_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn audit_host(alias: &str, status: crate::checks::Status) -> AuditOutcome {
        use crate::checks::{Domain, Severity};
        let findings = vec![Finding {
            id: "ssh-x",
            domain: Domain::Ssh,
            title: "t",
            severity: Severity::Low,
            status,
            detail: "d".to_string(),
            recommendation: "fix it",
        }];
        let score = scoring::score(&findings, Profile::Baseline);
        AuditOutcome {
            alias: alias.to_string(),
            result: Ok((score, findings)),
        }
    }

    #[test]
    fn audit_group_collapses_identical_hosts() {
        use crate::checks::Status;
        // web1 and web2 are identical; web3 differs (a passing check vs a failing one).
        let outcomes = vec![
            audit_host("web1", Status::Fail),
            audit_host("web2", Status::Fail),
            audit_host("web3", Status::Pass),
        ];

        // Text: web1+web2 collapse into one block; web3 renders separately.
        let text = audit_group_text("prod", &outcomes);
        assert!(
            text.contains("=== web1, web2 (2 hosts, identical) ==="),
            "{text}"
        );
        assert!(text.contains("=== web3 ==="), "{text}");
        // The shared findings appear once per block (twice total), not once per host.
        assert_eq!(text.matches("ssh-x").count(), 2, "{text}");

        // JSON: groups[] with merged aliases, in first-appearance order.
        let json = audit_group_json("prod", &outcomes).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "audit-group");
        let groups = v["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["aliases"], json!(["web1", "web2"]));
        assert_eq!(groups[1]["aliases"], json!(["web3"]));
    }

    #[test]
    fn audit_group_errors_collapse_and_report_separately() {
        use crate::checks::Status;
        let outcomes = vec![
            AuditOutcome {
                alias: "web1".into(),
                result: Err("connection refused".into()),
            },
            AuditOutcome {
                alias: "web2".into(),
                result: Err("connection refused".into()),
            },
            audit_host("web3", Status::Fail),
        ];
        let text = audit_group_text("prod", &outcomes);
        assert!(
            text.contains("=== web1, web2 (2 hosts, identical) [ERROR] ==="),
            "{text}"
        );
        let json = audit_group_json("prod", &outcomes).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let groups = v["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["aliases"], json!(["web1", "web2"]));
        assert_eq!(groups[0]["error"], "connection refused");
    }
}
