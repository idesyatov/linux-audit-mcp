//! Logging-domain checks (`systemctl list-unit-files`).

use super::parse::{parse_unit_files, service_enabled};
use super::{Check, Domain, Outcome, Severity, UNITS_CMD};

/// The kernel audit daemon (`auditd`) is not enabled.
pub struct AuditdEnabled;

impl Check for AuditdEnabled {
    fn id(&self) -> &'static str {
        "logging-auditd"
    }
    fn domain(&self) -> Domain {
        Domain::Logging
    }
    fn title(&self) -> &'static str {
        "Audit daemon not enabled"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn recommendation(&self) -> &'static str {
        "Enable the audit trail: systemctl enable --now auditd."
    }
    fn command(&self) -> &'static str {
        UNITS_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        if service_enabled(&parse_unit_files(output), "auditd") {
            Outcome::pass("auditd is enabled.")
        } else {
            Outcome::fail("auditd is not enabled (no kernel audit trail).")
        }
    }
}

/// A persistent syslog daemon (`rsyslog`/`syslog-ng`) is not enabled.
pub struct SyslogEnabled;

impl Check for SyslogEnabled {
    fn id(&self) -> &'static str {
        "logging-syslog"
    }
    fn domain(&self) -> Domain {
        Domain::Logging
    }
    fn title(&self) -> &'static str {
        "No persistent syslog daemon"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn recommendation(&self) -> &'static str {
        "Enable rsyslog (or syslog-ng), or configure persistent journald storage."
    }
    fn command(&self) -> &'static str {
        UNITS_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        let units = parse_unit_files(output);
        if service_enabled(&units, "rsyslog") || service_enabled(&units, "syslog-ng") {
            Outcome::pass("A syslog daemon is enabled.")
        } else {
            Outcome::fail("Neither rsyslog nor syslog-ng is enabled.")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Status;
    use super::*;

    #[test]
    fn auditd() {
        assert_eq!(
            AuditdEnabled
                .evaluate("auditd.service enabled enabled\n")
                .status,
            Status::Pass
        );
        assert_eq!(AuditdEnabled.evaluate("").status, Status::Fail);
    }

    #[test]
    fn syslog() {
        assert_eq!(
            SyslogEnabled
                .evaluate("rsyslog.service enabled enabled\n")
                .status,
            Status::Pass
        );
        assert_eq!(
            SyslogEnabled
                .evaluate("syslog-ng.service enabled enabled\n")
                .status,
            Status::Pass
        );
        assert_eq!(SyslogEnabled.evaluate("").status, Status::Fail);
    }
}
