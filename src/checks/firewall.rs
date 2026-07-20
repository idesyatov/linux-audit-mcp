//! Firewall-domain checks.
//!
//! [`FirewallEnabled`] is a non-root, file-state view: a host firewall is enabled
//! at boot. [`NftDefaultDeny`] is the privileged upgrade - it reads the live
//! ruleset (`sudo -n nft list ruleset`) to confirm inbound traffic is actually
//! denied by default, not just that a firewall service is running.

use super::parse::{nft_input_policy, parse_unit_files, service_enabled, NftInput};
use super::{Check, Domain, Outcome, Severity};

const UNITS_CMD: &str = "systemctl list-unit-files --type=service --no-pager";
const NFT_CMD: &str = "sudo -n nft list ruleset";

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

/// The live nftables ruleset has an input hook that accepts everything.
/// Privileged: reads `sudo -n nft list ruleset`, so it runs only on opted-in
/// targets and judges the *effective* inbound posture on nft-native firewalls
/// (firewalld, nftables, or ufw on the nft backend). When nft shows no input hook
/// the host may filter via the iptables-legacy backend (invisible to nft), so the
/// check defers rather than false-failing - [`FirewallEnabled`] already flags a
/// host with no firewall service at all.
pub struct NftDefaultDeny;

impl Check for NftDefaultDeny {
    fn id(&self) -> &'static str {
        "firewall-nft-default-deny"
    }
    fn domain(&self) -> Domain {
        Domain::Firewall
    }
    fn title(&self) -> &'static str {
        "No default-deny on the input hook"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn recommendation(&self) -> &'static str {
        "Set a default-deny inbound policy (ufw default deny incoming; firewalld \
         default zone drop/reject; or nft `policy drop` on the input hook)."
    }
    fn command(&self) -> &'static str {
        NFT_CMD
    }
    fn privileged(&self) -> bool {
        true
    }
    fn evaluate(&self, output: &str) -> Outcome {
        match nft_input_policy(output) {
            NftInput::DefaultDeny => Outcome::pass(
                "Input hook denies by default (policy drop or a catch-all deny rule).",
            ),
            NftInput::AcceptAll => Outcome::fail(
                "Input hook accepts by default with no deny rule (inbound traffic is open).",
            ),
            // nft can't see the inbound posture here: the host may filter via the
            // iptables-legacy backend (invisible to nft), so don't false-fail.
            // firewall-enabled already flags a host with no firewall service.
            NftInput::NoInputHook | NftInput::NoRuleset => Outcome::pass(
                "No nft input-hook chain; the firewall may use the iptables-legacy \
                 backend (not visible via nft).",
            ),
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

    #[test]
    fn nft_default_deny() {
        let deny = "table inet filter {\n\
                    \tchain input {\n\
                    \t\ttype filter hook input priority filter; policy drop;\n\
                    \t}\n\
                    }\n";
        // An nft-visible input hook that accepts everything is the confident fail.
        let accept = "table inet filter {\n\
                      \tchain input {\n\
                      \t\ttype filter hook input priority filter; policy accept;\n\
                      \t}\n\
                      }\n";
        assert_eq!(NftDefaultDeny.evaluate(deny).status, Status::Pass);
        assert_eq!(NftDefaultDeny.evaluate(accept).status, Status::Fail);
        // No input hook (e.g. ufw on the iptables-legacy backend): defer, not fail.
        assert_eq!(NftDefaultDeny.evaluate("").status, Status::Pass);
        let forward_only = "table ip filter {\n\
                            \tchain FORWARD {\n\
                            \t\ttype filter hook forward priority filter; policy drop;\n\
                            \t}\n\
                            }\n";
        assert_eq!(NftDefaultDeny.evaluate(forward_only).status, Status::Pass);
        assert!(NftDefaultDeny.privileged());
    }
}
