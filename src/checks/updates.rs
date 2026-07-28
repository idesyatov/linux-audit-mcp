//! Updates-domain checks: pending security updates (apt and dnf) and whether
//! automatic updates are enabled.
//!
//! `apt`/`dnf` are per-distro: on the other family's host the tool is absent, so
//! the command exits 127 and the check is reported `Skipped` (not applicable,
//! excluded from the score) via [`Check::skip_if_tool_missing`]. A Debian host is
//! judged by the apt check and a RHEL host by the dnf check.

use super::parse::{parse_unit_files, service_enabled};
use super::{Check, Domain, Outcome, Severity, UNITS_CMD};

const APT_SIM_CMD: &str = "apt-get -s upgrade";
const DNF_SEC_CMD: &str = "dnf -q updateinfo list security";

/// Pending security updates (simulated apt upgrade lists `Inst` from -security).
pub struct SecurityUpdatesPending;

impl Check for SecurityUpdatesPending {
    fn id(&self) -> &'static str {
        "updates-security-pending"
    }
    fn domain(&self) -> Domain {
        Domain::Updates
    }
    fn title(&self) -> &'static str {
        "Pending security updates"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn recommendation(&self) -> &'static str {
        "Apply security updates: apt-get update && apt-get upgrade."
    }
    fn command(&self) -> &'static str {
        APT_SIM_CMD
    }
    fn skip_if_tool_missing(&self) -> bool {
        true
    }
    fn evaluate(&self, output: &str) -> Outcome {
        // `Inst <pkg> (... Debian-Security ...)` marks a security upgrade.
        let count = output
            .lines()
            .filter(|l| l.starts_with("Inst ") && l.to_ascii_lowercase().contains("security"))
            .count();
        if count == 0 {
            Outcome::pass("No pending security updates.")
        } else {
            Outcome::fail(format!("{count} pending security update(s)."))
        }
    }
}

/// Pending security updates on RHEL/dnf hosts (`dnf updateinfo list security`).
/// Each output line is one security advisory affecting one package (`ADVISORY
/// Severity/Sec. package-nvr`); `-q` strips headers, and the command exits 0 with
/// empty output when none are pending. On an apt host the command errors, so the
/// audit records an `Error` finding instead of a pass/fail.
pub struct SecurityUpdatesPendingDnf;

impl Check for SecurityUpdatesPendingDnf {
    fn id(&self) -> &'static str {
        "updates-security-pending-dnf"
    }
    fn domain(&self) -> Domain {
        Domain::Updates
    }
    fn title(&self) -> &'static str {
        "Pending security updates (dnf)"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn recommendation(&self) -> &'static str {
        "Apply security updates: dnf upgrade --security."
    }
    fn command(&self) -> &'static str {
        DNF_SEC_CMD
    }
    fn skip_if_tool_missing(&self) -> bool {
        true
    }
    fn evaluate(&self, output: &str) -> Outcome {
        // Each advisory row has at least three fields (advisory, severity, package);
        // blank lines have none, so this counts exactly the pending advisories.
        let count = output
            .lines()
            .filter(|l| l.split_whitespace().count() >= 3)
            .count();
        if count == 0 {
            Outcome::pass("No pending security updates.")
        } else {
            Outcome::fail(format!("{count} pending security update(s)."))
        }
    }
}

/// Known service units that apply automatic updates, across package managers.
/// (RHEL's `dnf-automatic` is timer-driven; the install service unit is the
/// closest read-only, service-scoped signal we can see without listing timers.)
const AUTO_UPDATE_UNITS: &[&str] = &[
    "unattended-upgrades",
    "dnf-automatic-install",
    "dnf-automatic",
    "yum-cron",
];

/// Automatic (unattended) security updates are not enabled. Best-effort across
/// package managers: passes if any known auto-update service unit is enabled.
pub struct AutoUpdatesEnabled;

impl Check for AutoUpdatesEnabled {
    fn id(&self) -> &'static str {
        "updates-auto-updates"
    }
    fn domain(&self) -> Domain {
        Domain::Updates
    }
    fn title(&self) -> &'static str {
        "Automatic security updates disabled"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn recommendation(&self) -> &'static str {
        "Enable unattended security updates: apt install unattended-upgrades && \
         dpkg-reconfigure -plow unattended-upgrades (or the distro equivalent)."
    }
    fn command(&self) -> &'static str {
        UNITS_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        let units = parse_unit_files(output);
        match AUTO_UPDATE_UNITS
            .iter()
            .find(|u| service_enabled(&units, u))
        {
            Some(u) => Outcome::pass(format!("Automatic updates enabled ({u}).")),
            None => Outcome::fail("No automatic security-update service is enabled."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Status;
    use super::*;

    #[test]
    fn security_updates() {
        let none = "Reading package lists...\nBuilding dependency tree...\n";
        let some = "Inst libc6 [2.36] (2.36-9+deb12u4 Debian-Security:12/stable [amd64])\n\
                    Inst tzdata [2024a] (2024b Debian:stable [all])\n";
        assert_eq!(SecurityUpdatesPending.evaluate(none).status, Status::Pass);
        // One of the two Inst lines is from -Security.
        assert_eq!(SecurityUpdatesPending.evaluate(some).status, Status::Fail);
    }

    #[test]
    fn security_updates_dnf() {
        // Empty output (also the exit-0 "none pending" case) -> pass.
        assert_eq!(SecurityUpdatesPendingDnf.evaluate("").status, Status::Pass);
        assert_eq!(
            SecurityUpdatesPendingDnf.evaluate("\n\n").status,
            Status::Pass
        );
        // Two security advisory rows -> fail (count 2).
        let some = "RLSA-2024:1234 Important/Sec. kernel-4.18.0-553.el8.x86_64\n\
                    RLSA-2024:5678 Moderate/Sec.  openssl-1.1.1k-12.el8.x86_64\n";
        let out = SecurityUpdatesPendingDnf.evaluate(some);
        assert_eq!(out.status, Status::Fail);
        assert!(out.detail.contains('2'), "{}", out.detail);
    }

    #[test]
    fn auto_updates() {
        assert_eq!(
            AutoUpdatesEnabled
                .evaluate("unattended-upgrades.service enabled enabled\n")
                .status,
            Status::Pass
        );
        // Absent unit -> not enabled -> fail.
        assert_eq!(
            AutoUpdatesEnabled
                .evaluate("sshd.service enabled enabled\n")
                .status,
            Status::Fail
        );
    }
}
