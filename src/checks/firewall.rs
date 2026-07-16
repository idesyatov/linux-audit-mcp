//! Firewall-domain checks (`systemctl list-unit-files`).
//!
//! A non-root, file-state view: we confirm a host firewall is enabled at boot.
//! Inspecting live rulesets (`nft list ruleset`) needs root and is out of scope.

use super::parse::{parse_unit_files, service_enabled};
use super::{Check, Domain, Outcome, Severity};

const UNITS_CMD: &str = "systemctl list-unit-files --type=service --no-pager";

/// No recognised host firewall service is enabled.
pub struct FirewallEnabled;

impl Check for FirewallEnabled {
    fn id(&self) -> &'static str {
        "firewall-enabled"
    }
    fn domain(&self) -> Domain {
        Domain::Firewall
    }
    fn title(&self) -> &'static str {
        "No host firewall enabled"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn recommendation(&self) -> &'static str {
        "Enable a host firewall (firewalld, ufw or nftables) and set a default-deny input policy."
    }
    fn command(&self) -> &'static str {
        UNITS_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        let units = parse_unit_files(output);
        let active: Vec<&str> = ["firewalld", "ufw", "nftables"]
            .into_iter()
            .filter(|s| service_enabled(&units, s))
            .collect();
        if active.is_empty() {
            Outcome::fail("No firewalld/ufw/nftables service is enabled.")
        } else {
            Outcome::pass(format!("Firewall enabled: {}.", active.join(", ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Status;
    use super::*;

    #[test]
    fn firewall_enabled() {
        let on = "ufw.service enabled enabled\n";
        let off = "ufw.service disabled disabled\nnftables.service disabled disabled\n";
        assert_eq!(FirewallEnabled.evaluate(on).status, Status::Pass);
        assert_eq!(FirewallEnabled.evaluate(off).status, Status::Fail);
    }
}
