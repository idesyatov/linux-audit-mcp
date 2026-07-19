//! Services-domain checks: listening ports (`ss -tuln`) and risky units.

use super::parse::{parse_listen_ports, parse_unit_files, service_enabled};
use super::{Check, Domain, Outcome, Severity};

const SS_CMD: &str = "ss -tuln";
const UNITS_CMD: &str = "systemctl list-unit-files --type=service --no-pager";

/// Cleartext / legacy services listening: (port, name).
const CLEARTEXT_PORTS: &[(u16, &str)] = &[
    (21, "ftp"),
    (23, "telnet"),
    (512, "rexec"),
    (513, "rlogin"),
    (514, "rsh"),
];

/// A cleartext/legacy service is listening.
pub struct CleartextPorts;

impl Check for CleartextPorts {
    fn id(&self) -> &'static str {
        "services-cleartext-ports"
    }
    fn domain(&self) -> Domain {
        Domain::Services
    }
    fn title(&self) -> &'static str {
        "Cleartext service listening"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn recommendation(&self) -> &'static str {
        "Disable telnet/ftp/r-services and use encrypted equivalents (ssh, sftp/ftps)."
    }
    fn command(&self) -> &'static str {
        SS_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        let ports = parse_listen_ports(output);
        let found: Vec<&str> = CLEARTEXT_PORTS
            .iter()
            .filter(|(p, _)| ports.contains(p))
            .map(|(_, name)| *name)
            .collect();
        if found.is_empty() {
            Outcome::pass("No cleartext/legacy services listening.")
        } else {
            Outcome::fail(format!(
                "Cleartext services listening: {}.",
                found.join(", ")
            ))
        }
    }
}

/// The RPC portmapper (`rpcbind`) is enabled - a common attack surface.
pub struct RpcbindDisabled;

impl Check for RpcbindDisabled {
    fn id(&self) -> &'static str {
        "services-rpcbind"
    }
    fn domain(&self) -> Domain {
        Domain::Services
    }
    fn title(&self) -> &'static str {
        "rpcbind (portmapper) enabled"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn recommendation(&self) -> &'static str {
        "Disable it unless NFS/RPC is needed: systemctl disable --now rpcbind."
    }
    fn command(&self) -> &'static str {
        UNITS_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        if service_enabled(&parse_unit_files(output), "rpcbind") {
            Outcome::fail("rpcbind is enabled.")
        } else {
            Outcome::pass("rpcbind is not enabled.")
        }
    }
}

/// fail2ban (brute-force throttling) is not enabled.
pub struct Fail2banEnabled;

impl Check for Fail2banEnabled {
    fn id(&self) -> &'static str {
        "services-fail2ban"
    }
    fn domain(&self) -> Domain {
        Domain::Services
    }
    fn title(&self) -> &'static str {
        "fail2ban not enabled"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn recommendation(&self) -> &'static str {
        "Enable fail2ban to throttle brute-force attempts: systemctl enable --now fail2ban \
         (defense-in-depth; most useful where password auth is reachable)."
    }
    fn command(&self) -> &'static str {
        UNITS_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        if service_enabled(&parse_unit_files(output), "fail2ban") {
            Outcome::pass("fail2ban is enabled.")
        } else {
            Outcome::fail("fail2ban is not enabled (no brute-force throttling).")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Status;
    use super::*;

    #[test]
    fn cleartext_ports() {
        let ssh_only = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n";
        let telnet = "tcp LISTEN 0 128 0.0.0.0:23 0.0.0.0:*\n";
        assert_eq!(CleartextPorts.evaluate(ssh_only).status, Status::Pass);
        assert_eq!(CleartextPorts.evaluate(telnet).status, Status::Fail);
    }

    #[test]
    fn rpcbind() {
        assert_eq!(
            RpcbindDisabled
                .evaluate("rpcbind.service enabled enabled\n")
                .status,
            Status::Fail
        );
        assert_eq!(
            RpcbindDisabled
                .evaluate("rpcbind.service disabled disabled\n")
                .status,
            Status::Pass
        );
    }

    #[test]
    fn fail2ban() {
        assert_eq!(
            Fail2banEnabled
                .evaluate("fail2ban.service enabled enabled\n")
                .status,
            Status::Pass
        );
        // Absent -> not enabled -> fail.
        assert_eq!(
            Fail2banEnabled
                .evaluate("sshd.service enabled enabled\n")
                .status,
            Status::Fail
        );
    }
}
