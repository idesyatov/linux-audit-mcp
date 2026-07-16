//! Audit checks: a check declares the read-only command it needs and a pure
//! `evaluate(output) -> Outcome`. Separating I/O from logic keeps every check
//! unit-testable against fixtures without a host (and feeds later-stage evals).

pub mod accounts;
pub mod firewall;
pub mod kernel;
pub mod logging;
pub mod parse;
pub mod services;
pub mod ssh;
pub mod updates;

use serde::Serialize;

// Ordering follows declaration order: Info < Low < Medium < High < Critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
// The full scale is defined up front; not every level is used yet.
#[allow(dead_code)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
// The full domain set is defined up front; checks are added domain by domain.
#[allow(dead_code)]
pub enum Domain {
    Ssh,
    Accounts,
    Kernel,
    Firewall,
    Updates,
    Services,
    Logging,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Fail,
    Error,
}

/// A single audit result.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub domain: Domain,
    pub title: &'static str,
    pub severity: Severity,
    pub status: Status,
    pub detail: String,
    pub recommendation: &'static str,
}

/// The verdict a check returns for a given host output.
pub struct Outcome {
    pub status: Status,
    pub detail: String,
}

impl Outcome {
    pub fn pass(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Pass,
            detail: detail.into(),
        }
    }

    pub fn fail(detail: impl Into<String>) -> Self {
        Self {
            status: Status::Fail,
            detail: detail.into(),
        }
    }
}

pub trait Check: Send + Sync {
    /// Stable identifier, e.g. `ssh-permit-root-login`.
    fn id(&self) -> &'static str;
    fn domain(&self) -> Domain;
    fn title(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn recommendation(&self) -> &'static str;
    /// The read-only command this check needs (must be in the catalog).
    fn command(&self) -> &'static str;
    /// Pure evaluation of the command's output.
    fn evaluate(&self, output: &str) -> Outcome;
}

/// Every check the auditor runs.
pub fn all_checks() -> Vec<Box<dyn Check>> {
    vec![
        // ssh
        Box::new(ssh::PermitRootLogin),
        Box::new(ssh::PasswordAuthentication),
        Box::new(ssh::PermitEmptyPasswords),
        Box::new(ssh::X11Forwarding),
        Box::new(ssh::MaxAuthTries),
        // accounts
        Box::new(accounts::NonRootUid0),
        Box::new(accounts::PassMaxDays),
        Box::new(accounts::DefaultUmask),
        // kernel
        Box::new(kernel::Aslr),
        Box::new(kernel::TcpSyncookies),
        Box::new(kernel::RpFilter),
        Box::new(kernel::IpForward),
        Box::new(kernel::AcceptRedirects),
        Box::new(kernel::AcceptSourceRoute),
        // firewall
        Box::new(firewall::FirewallEnabled),
        // updates
        Box::new(updates::SecurityUpdatesPending),
        // services
        Box::new(services::CleartextPorts),
        Box::new(services::RpcbindDisabled),
        // logging
        Box::new(logging::AuditdEnabled),
        Box::new(logging::SyslogEnabled),
    ]
}

#[cfg(test)]
mod registry_tests {
    use super::all_checks;
    use crate::catalog;

    /// Every command a check issues must be in the read-only catalog, so a
    /// future catalog change can never silently break the audit.
    #[test]
    fn all_check_commands_are_in_catalog() {
        for check in all_checks() {
            assert!(
                catalog::validate(check.command()).is_ok(),
                "check {} uses a non-catalog command: {:?}",
                check.id(),
                check.command()
            );
        }
    }

    #[test]
    fn check_ids_are_unique() {
        let checks = all_checks();
        let total = checks.len();
        let mut ids: Vec<&str> = checks.iter().map(|c| c.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "duplicate check ids");
    }
}
