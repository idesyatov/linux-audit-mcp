//! Fan-out orchestration: run the audit or the health snapshot against one or
//! many targets (a group), concurrently, capturing per-host runtime failures so
//! one unreachable host does not sink the whole group.
//!
//! UI-agnostic: returns structured per-host outcomes that `cli`/`server` render.
//! Config problems (unknown group/member, conflicting group vars) fail fast; a
//! per-host connection/auth error is captured as that host's `Err`.

use serde_json::json;
use tokio::task::JoinSet;

use crate::audit;
use crate::checks::Finding;
use crate::config::{Config, ConfigError};
use crate::health::{self, HealthReport, HealthStatus};
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
