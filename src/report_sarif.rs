//! SARIF 2.1.0 rendering of audit results, for GitHub code scanning and other
//! dashboards that ingest the Static Analysis Results Interchange Format.
//!
//! One audited host is one SARIF `run`; a group is one `sarifLog` with several
//! `runs`. Every check becomes a `rule` in the tool driver; only failing checks
//! become `results` (SARIF is a findings format - passes/skips/errors are not
//! defects). The security [`Score`] rides in each run's `properties`.

use serde_json::{json, Value};

use crate::checks::{Domain, Finding, Severity, Status};
use crate::run::AuditOutcome;
use crate::scoring::Score;

const TOOL_NAME: &str = "linux-audit-mcp";
const TOOL_URI: &str = "https://github.com/idesyatov/linux-audit-mcp";
const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// SARIF result level for a severity: Critical/High are errors, Medium a warning,
/// the rest notes.
fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// GitHub's `security-severity` score (0.0-10.0) for a severity, as a string -
/// what code scanning uses to bucket alerts.
fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.0",
        Severity::High => "7.0",
        Severity::Medium => "5.0",
        Severity::Low => "3.0",
        Severity::Info => "1.0",
    }
}

fn severity_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn domain_str(domain: Domain) -> &'static str {
    match domain {
        Domain::Ssh => "ssh",
        Domain::Accounts => "accounts",
        Domain::Kernel => "kernel",
        Domain::Firewall => "firewall",
        Domain::Updates => "updates",
        Domain::Services => "services",
        Domain::Logging => "logging",
    }
}

/// One SARIF `run` for a single host: every check is a rule, every failing check
/// a result. The score is attached as run properties.
fn run_value(target: &str, score: &Score, findings: &[Finding]) -> Value {
    let rules: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "id": f.id,
                "name": f.title,
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": f.recommendation },
                "defaultConfiguration": { "level": level(f.severity) },
                "properties": {
                    "security-severity": security_severity(f.severity),
                    "severity": severity_str(f.severity),
                    "domain": domain_str(f.domain),
                }
            })
        })
        .collect();

    let results: Vec<Value> = findings
        .iter()
        .filter(|f| f.status == Status::Fail)
        .map(|f| {
            json!({
                "ruleId": f.id,
                "level": level(f.severity),
                "message": { "text": f.detail },
                "partialFingerprints": { "findingId": f.id },
                "properties": {
                    "severity": severity_str(f.severity),
                    "domain": domain_str(f.domain),
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": target }
                    }
                }]
            })
        })
        .collect();

    json!({
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "informationUri": TOOL_URI,
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rules,
            }
        },
        "results": results,
        "properties": {
            "target": target,
            "score": score.total,
            "profile": score.profile,
        }
    })
}

/// SARIF log for one host.
pub fn sarif(target: &str, score: &Score, findings: &[Finding]) -> serde_json::Result<String> {
    let log = json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run_value(target, score, findings)],
    });
    serde_json::to_string_pretty(&log)
}

/// SARIF log for a group: one `run` per successfully-audited host. Hosts that
/// errored are skipped (a connection failure is not a code-scanning finding); the
/// text/JSON renderers still surface them.
pub fn sarif_group(outcomes: &[AuditOutcome]) -> serde_json::Result<String> {
    let runs: Vec<Value> = outcomes
        .iter()
        .filter_map(|o| {
            o.result
                .as_ref()
                .ok()
                .map(|(score, findings)| run_value(&o.alias, score, findings))
        })
        .collect();
    let log = json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": runs,
    });
    serde_json::to_string_pretty(&log)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Domain;
    use crate::scoring::{score, Profile};

    fn finding(id: &'static str, sev: Severity, status: Status) -> Finding {
        Finding {
            id,
            domain: Domain::Ssh,
            title: "t",
            severity: sev,
            status,
            detail: "d".to_string(),
            recommendation: "r",
        }
    }

    #[test]
    fn sarif_has_schema_and_one_result_per_fail() {
        let findings = vec![
            finding("ssh-permit-root-login", Severity::High, Status::Fail),
            finding("ssh-password-authentication", Severity::High, Status::Pass),
            finding("ssh-x11-forwarding", Severity::Low, Status::Skipped),
        ];
        let s = score(&findings, Profile::Baseline);
        let out = sarif("web", &s, &findings).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();

        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].is_string());
        let runs = v["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        // Rules cover every check; results only the single fail.
        let rules = runs[0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 3);
        let results = runs[0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "ssh-permit-root-login");
        assert_eq!(results[0]["level"], "error");
        assert_eq!(runs[0]["properties"]["target"], "web");
    }
}
