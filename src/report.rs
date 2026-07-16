//! Rendering of audit results: a compact text summary and machine-readable
//! JSON, both including the security [`Score`].

use serde::Serialize;

use crate::checks::{Finding, Severity, Status};
use crate::scoring::Score;

fn severity_tag(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn domain_tag(domain: crate::checks::Domain) -> &'static str {
    use crate::checks::Domain::*;
    match domain {
        Ssh => "ssh",
        Accounts => "accounts",
        Kernel => "kernel",
        Firewall => "firewall",
        Updates => "updates",
        Services => "services",
        Logging => "logging",
    }
}

#[derive(Serialize)]
struct Report<'a> {
    target: &'a str,
    score: &'a Score,
    findings: &'a [Finding],
}

/// Human-readable summary: headline score, per-domain scores, then findings.
pub fn text(target: &str, score: &Score, findings: &[Finding]) -> String {
    use std::fmt::Write;

    let passed = findings.iter().filter(|f| f.status == Status::Pass).count();
    let failed = findings.iter().filter(|f| f.status == Status::Fail).count();
    let errored = findings
        .iter()
        .filter(|f| f.status == Status::Error)
        .count();

    let profile = match score.profile {
        crate::scoring::Profile::Baseline => "baseline",
        crate::scoring::Profile::Hardened => "hardened",
    };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Audit of '{target}' [{profile}]: score {}/100 ({passed} passed, {failed} failed, {errored} errored)",
        score.total
    );

    let domains: Vec<String> = score
        .domains
        .iter()
        .map(|d| format!("{} {}", domain_tag(d.domain), d.score))
        .collect();
    let _ = writeln!(out, "  domains: {}", domains.join(", "));

    for f in findings {
        let mark = match f.status {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Error => "ERR ",
        };
        let _ = writeln!(
            out,
            "  [{mark}] {:<8} {} — {}",
            severity_tag(f.severity),
            f.id,
            f.detail
        );
        if f.status == Status::Fail {
            let _ = writeln!(out, "           ↳ {}", f.recommendation);
        }
    }
    out
}

/// Machine-readable JSON: `{ target, score, findings }`.
pub fn json(target: &str, score: &Score, findings: &[Finding]) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&Report {
        target,
        score,
        findings,
    })
}
