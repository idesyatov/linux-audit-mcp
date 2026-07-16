//! Updates-domain checks (`apt-get -s upgrade`).
//!
//! Debian/Ubuntu only. On non-apt hosts the command errors and the audit
//! records this as an `Error` finding (not a pass/fail). Broader per-distro
//! coverage (dnf) comes with the Stage 8 fixtures.

use super::{Check, Domain, Outcome, Severity};

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
}
