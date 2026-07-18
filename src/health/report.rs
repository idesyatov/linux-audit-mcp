//! Rendering of the operational-health snapshot: a compact text summary and
//! machine-readable JSON.
//!
//! Deliberately distinct from [`crate::report`]: there is no 0-100 score here,
//! only an overall `Ok`/`Warn`/`Crit` status, so nobody is tempted to fold
//! workload into the security score.

use serde::Serialize;

use super::{HealthReport, HealthStatus};

fn status_tag(s: HealthStatus) -> &'static str {
    match s {
        HealthStatus::Ok => "OK",
        HealthStatus::Warn => "WARN",
        HealthStatus::Crit => "CRIT",
        HealthStatus::Unknown => "UNKN",
    }
}

#[derive(Serialize)]
struct Envelope<'a> {
    target: &'a str,
    kind: &'static str,
    report: &'a HealthReport,
}

/// Human-readable snapshot: headline status, per-metric lines, hot processes.
pub fn text(target: &str, report: &HealthReport) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    let _ = writeln!(
        out,
        "Health of '{target}': {} (operational, not a security score)",
        status_tag(report.overall)
    );

    for m in &report.metrics {
        let _ = writeln!(
            out,
            "  [{:<4}] {:<20} {} ({})",
            status_tag(m.status),
            m.id,
            m.value,
            m.detail
        );
    }

    let _ = writeln!(out, "  top CPU:");
    for p in &report.top_cpu {
        let _ = writeln!(out, "    {:>7.1}%  {} (pid {})", p.cpu, p.comm, p.pid);
    }
    let _ = writeln!(out, "  top MEM:");
    for p in &report.top_mem {
        let _ = writeln!(out, "    {:>7.1}%  {} (pid {})", p.mem, p.comm, p.pid);
    }
    out
}

/// Machine-readable JSON: `{ target, kind: "health", report }`.
pub fn json(target: &str, report: &HealthReport) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&Envelope {
        target,
        kind: "health",
        report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::Thresholds;

    fn sample() -> HealthReport {
        crate::health::evaluate(
            &[
                ("uptime", "load average: 6.0, 5.0, 4.0"),
                ("nproc", "4"),
                ("df -P", "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 100 90 10 90% /\n"),
                ("ps -eo pid,comm,pcpu,pmem --sort=-pcpu", "PID COMMAND %CPU %MEM\n1 mysqld 80.0 40.0\n"),
            ]
            .iter()
            .map(|(k, v)| (*k, Ok(v.to_string())))
            .collect(),
            &Thresholds::default(),
        )
    }

    #[test]
    fn text_flags_status_and_is_not_a_score() {
        let out = text("web", &sample());
        assert!(out.contains("WARN"));
        assert!(out.contains("not a security score"));
        assert!(out.contains("top CPU:"));
        assert!(out.contains("mysqld"));
    }

    #[test]
    fn json_tags_kind_and_overall() {
        let json = json("web", &sample()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "health");
        assert_eq!(v["target"], "web");
        assert_eq!(v["report"]["overall"], "warn");
    }
}
