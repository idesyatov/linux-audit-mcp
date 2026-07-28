//! Audit checks: a check declares the read-only command it needs and a pure
//! `evaluate(output) -> Outcome`. Separating I/O from logic keeps every check
//! unit-testable against fixtures without a host (and by the evals).

pub mod accounts;
pub mod firewall;
pub mod kernel;
pub mod logging;
pub mod parse;
pub mod services;
pub mod ssh;
pub mod updates;

use serde::{Deserialize, Serialize};

/// The `systemctl list-unit-files` listing shared by the firewall, services,
/// logging and updates checks (each reads it via [`parse::parse_unit_files`]).
pub(crate) const UNITS_CMD: &str = "systemctl list-unit-files --type=service --no-pager";

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
pub enum Domain {
    Ssh,
    Accounts,
    Kernel,
    Firewall,
    Updates,
    Services,
    Logging,
}

impl Domain {
    /// The kebab-case domain names accepted by `--domain` (and used in output).
    pub const NAMES: &'static [&'static str] = &[
        "ssh", "accounts", "kernel", "firewall", "updates", "services", "logging",
    ];

    /// Parse a domain name (case-insensitive); `None` if unknown.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "ssh" => Some(Self::Ssh),
            "accounts" => Some(Self::Accounts),
            "kernel" => Some(Self::Kernel),
            "firewall" => Some(Self::Firewall),
            "updates" => Some(Self::Updates),
            "services" => Some(Self::Services),
            "logging" => Some(Self::Logging),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Fail,
    Error,
    /// A privileged check that didn't run because the target isn't opted in
    /// (`privileged = false`). Excluded from the score, like `Error`, but it is
    /// a deliberate skip rather than a failure.
    Skipped,
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
    /// `true` if the check needs root (its command is a `sudo -n ...` reader).
    /// Such checks run only on targets opted in with `privileged = true`, and
    /// are otherwise reported as [`Status::Skipped`].
    fn privileged(&self) -> bool {
        false
    }
    /// An optional privileged command whose output *supersedes* [`command`] when
    /// the target is opted in (`privileged = true`) and the command succeeded -
    /// e.g. `sudo -n sshd -T` yields the effective SSH config. When the target
    /// isn't opted in, or the command failed (no sudo grant), the check falls
    /// back to its normal [`command`], so the audit never breaks. Must be in the
    /// catalog. `None` = the check has no privileged upgrade.
    fn effective_command(&self) -> Option<&'static str> {
        None
    }
}

/// Selects which checks an audit runs. Empty = every check. A positive selector
/// (`only` ids or `domains`) restricts the run to matching checks; `skip` removes
/// ids from whatever the selectors chose (skip always wins). Built from the CLI
/// `--check`/`--domain`/`--skip` flags; [`Default`] (all checks) is what the MCP
/// server and evals use.
#[derive(Debug, Clone, Default)]
pub struct CheckFilter {
    /// Run only these exact check ids (`--check`).
    pub only: Vec<String>,
    /// Run only checks in these domains (`--domain`).
    pub domains: Vec<Domain>,
    /// Exclude these check ids (`--skip`).
    pub skip: Vec<String>,
}

impl CheckFilter {
    /// A positive selector is present, so unlisted checks are excluded.
    fn has_positive(&self) -> bool {
        !self.only.is_empty() || !self.domains.is_empty()
    }

    /// `true` if this check should run under the filter.
    pub fn selects(&self, check: &dyn Check) -> bool {
        if self.skip.iter().any(|s| s == check.id()) {
            return false;
        }
        if !self.has_positive() {
            return true;
        }
        self.only.iter().any(|o| o == check.id()) || self.domains.contains(&check.domain())
    }

    /// `true` if the filter narrows the run at all (any flag set).
    pub fn is_active(&self) -> bool {
        self.has_positive() || !self.skip.is_empty()
    }
}

/// The checks an audit runs under `filter`, in registry order.
pub fn selected_checks(filter: &CheckFilter) -> Vec<Box<dyn Check>> {
    all_checks()
        .into_iter()
        .filter(|c| filter.selects(c.as_ref()))
        .collect()
}

/// Every registered check's id (for validating `--check`/`--skip` against typos).
pub fn all_check_ids() -> Vec<&'static str> {
    all_checks().iter().map(|c| c.id()).collect()
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
        Box::new(ssh::LoginGraceTime),
        Box::new(ssh::ClientAliveInterval),
        Box::new(ssh::PermitTunnel),
        Box::new(ssh::WeakCrypto),
        // accounts
        Box::new(accounts::NonRootUid0),
        Box::new(accounts::PassMaxDays),
        Box::new(accounts::DefaultUmask),
        Box::new(accounts::DuplicateUid),
        Box::new(accounts::SystemLoginShells),
        Box::new(accounts::ShadowEmptyPassword), // privileged (sudo)
        Box::new(accounts::ShadowWeakHash),      // privileged (sudo)
        // kernel
        Box::new(kernel::Aslr),
        Box::new(kernel::TcpSyncookies),
        Box::new(kernel::RpFilter),
        Box::new(kernel::IpForward),
        Box::new(kernel::AcceptRedirects),
        Box::new(kernel::AcceptSourceRoute),
        Box::new(kernel::PtraceScope),
        Box::new(kernel::DmesgRestrict),
        Box::new(kernel::KptrRestrict),
        Box::new(kernel::SuidDumpable),
        Box::new(kernel::UnprivilegedBpf),
        Box::new(kernel::MountOptions),
        // firewall
        Box::new(firewall::FirewallEnabled),
        Box::new(firewall::NftDefaultDeny), // privileged (sudo)
        // updates
        Box::new(updates::SecurityUpdatesPending),
        Box::new(updates::AutoUpdatesEnabled),
        // services
        Box::new(services::CleartextPorts),
        Box::new(services::RpcbindDisabled),
        Box::new(services::Fail2banEnabled),
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
            if let Some(cmd) = check.effective_command() {
                assert!(
                    catalog::validate(cmd).is_ok(),
                    "check {} uses a non-catalog effective command: {cmd:?}",
                    check.id(),
                );
            }
        }
    }

    #[test]
    fn filter_selects_expected_checks() {
        use super::{selected_checks, CheckFilter, Domain};

        // Empty filter -> every check.
        let all = super::all_checks().len();
        assert_eq!(selected_checks(&CheckFilter::default()).len(), all);
        assert!(!CheckFilter::default().is_active());

        // Only a domain -> just that domain's checks (all with the right domain).
        let ssh_only = CheckFilter {
            domains: vec![Domain::Ssh],
            ..Default::default()
        };
        let ssh = selected_checks(&ssh_only);
        assert!(!ssh.is_empty());
        assert!(ssh.iter().all(|c| c.domain() == Domain::Ssh));

        // An explicit id plus a domain -> the union.
        let mixed = CheckFilter {
            only: vec!["kernel-aslr".to_string()],
            domains: vec![Domain::Ssh],
            ..Default::default()
        };
        let sel = selected_checks(&mixed);
        assert!(sel.iter().any(|c| c.id() == "kernel-aslr"));
        assert!(sel.iter().any(|c| c.domain() == Domain::Ssh));

        // Skip always wins, even over an explicit --check of the same id.
        let skipped = CheckFilter {
            only: vec!["kernel-aslr".to_string()],
            skip: vec!["kernel-aslr".to_string()],
            ..Default::default()
        };
        assert!(!selected_checks(&skipped)
            .iter()
            .any(|c| c.id() == "kernel-aslr"));
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
