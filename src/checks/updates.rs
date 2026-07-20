//! Updates-domain checks (`apt-get -s upgrade`).
//!
//! Debian/Ubuntu only. On non-apt hosts the command errors and the audit
//! records this as an `Error` finding (not a pass/fail). Broader per-distro
//! coverage (dnf) is not implemented yet.

use super::parse::{parse_unit_files, service_enabled};
use super::{Check, Domain, Outcome, Severity, UNITS_CMD};

const APT_SIM_CMD: &str = "apt-get -s upgrade";

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
