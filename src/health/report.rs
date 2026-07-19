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

    // Anomalies (deviation from this host's own norm) - informational only.
    if !report.anomalies.is_empty() {
        let _ = writeln!(
            out,
            "  ANOMALY vs baseline ({}), informational:",
            report.anomalies.len()
        );
        for a in &report.anomalies {
            let _ = writeln!(
                out,
                "    {:<20} {:.2} vs median {:.2} ({:+.0}%, z={:.1})",
                a.metric_id, a.current, a.median, a.pct_change, a.z
            );
        }
    } else if let Some(note) = &report.anomaly_note {
        let _ = writeln!(out, "  (anomaly: {note})");
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
    fn text_renders_anomaly_section() {
        use crate::health::Anomaly;
        let mut r = sample();
        r.anomalies.push(Anomaly {
            metric_id: "health-load".to_string(),
            current: 4.0,
            median: 0.3,
            pct_change: 1233.0,
            z: 12.5,
        });
        let out = text("web", &r);
        assert!(out.contains("ANOMALY vs baseline (1)"));
        assert!(out.contains("health-load"));
        assert!(out.contains("z=12.5"));
    }

    #[test]
    fn text_shows_warming_up_note_when_no_anomalies() {
        let mut r = sample();
        r.anomaly_note = Some("baseline warming up (3/8)".to_string());
        let out = text("web", &r);
        assert!(out.contains("baseline warming up (3/8)"));
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
