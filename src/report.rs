//! Rendering of audit findings: a compact text summary and machine-readable
//! JSON. Scoring is added in a later stage; for now a report is the findings
//! plus pass/fail/error counts.

use serde::Serialize;

use crate::checks::{Finding, Severity, Status};

fn severity_tag(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

#[derive(Serialize)]
struct Summary {
    passed: usize,
    failed: usize,
    errored: usize,
}

impl Summary {
    fn of(findings: &[Finding]) -> Self {
        let mut s = Summary {
            passed: 0,
            failed: 0,
            errored: 0,
        };
        for f in findings {
            match f.status {
                Status::Pass => s.passed += 1,
                Status::Fail => s.failed += 1,
                Status::Error => s.errored += 1,
            }
        }
        s
    }
}

#[derive(Serialize)]
struct Report<'a> {
    target: &'a str,
    summary: Summary,
    findings: &'a [Finding],
}

/// Human-readable summary.
pub fn text(target: &str, findings: &[Finding]) -> String {
    use std::fmt::Write;

    let s = Summary::of(findings);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Audit of '{target}': {} passed, {} failed, {} errored",
        s.passed, s.failed, s.errored
    );
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

/// Machine-readable JSON: `{ target, summary, findings }`.
pub fn json(target: &str, findings: &[Finding]) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&Report {
        target,
        summary: Summary::of(findings),
        findings,
    })
}
