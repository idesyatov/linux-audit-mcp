//! Security scoring: turn findings into a 0-100 score with a per-domain
//! breakdown.
//!
//! `S = clamp( sum(weight_i x domain_score_i) - penalties, 0, 100 )`
//!
//! Each failed check deducts from its domain's score by severity, and High /
//! Critical failures add a *global* penalty so a single severe issue drags the
//! total even when its domain is lightly weighted (otherwise averaging would
//! dilute it). Checks that errored (command didn't run) are excluded.
//!
//! Two profiles select the weighting and how hard severe issues are penalized:
//! `baseline` (balanced) and `hardened` (stricter on accounts/kernel/ssh, with
//! heavier penalties).

use serde::{Deserialize, Serialize};

use crate::checks::{Domain, Finding, Severity, Status};

/// Domain weights. Each set sums to 1.0.
pub type Weights = &'static [(Domain, f64)];

/// Balanced defaults for a general-purpose server.
const BASELINE_WEIGHTS: Weights = &[
    (Domain::Ssh, 0.20),
    (Domain::Firewall, 0.15),
    (Domain::Accounts, 0.15),
    (Domain::Kernel, 0.15),
    (Domain::Services, 0.15),
    (Domain::Updates, 0.10),
    (Domain::Logging, 0.10),
];

/// Stricter: more weight on accounts, kernel and ssh; less on updates/logging.
const HARDENED_WEIGHTS: Weights = &[
    (Domain::Ssh, 0.22),
    (Domain::Firewall, 0.15),
    (Domain::Accounts, 0.20),
    (Domain::Kernel, 0.18),
    (Domain::Services, 0.13),
    (Domain::Updates, 0.06),
    (Domain::Logging, 0.06),
];

/// Audit profile: selects the domain weighting and the penalty multiplier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    #[default]
    Baseline,
    Hardened,
}

impl Profile {
    pub fn weights(self) -> Weights {
        match self {
            Self::Baseline => BASELINE_WEIGHTS,
            Self::Hardened => HARDENED_WEIGHTS,
        }
    }

    /// Multiplier applied to global High/Critical penalties.
    fn penalty_scale(self) -> f64 {
        match self {
            Self::Baseline => 1.0,
            Self::Hardened => 1.5,
        }
    }

    /// Parse a profile name (case-insensitive); `None` if unknown.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "baseline" => Some(Self::Baseline),
            "hardened" => Some(Self::Hardened),
            _ => None,
        }
    }
}

/// Points a failed check subtracts from its domain's score.
fn deduction(severity: Severity) -> f64 {
    match severity {
        Severity::Info => 0.0,
        Severity::Low => 5.0,
        Severity::Medium => 15.0,
        Severity::High => 30.0,
        Severity::Critical => 50.0,
    }
}

/// Extra global penalty a severe failed check subtracts from the total.
fn penalty(severity: Severity) -> u32 {
    match severity {
        Severity::High => 8,
        Severity::Critical => 20,
        _ => 0,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainScore {
    pub domain: Domain,
    pub weight: f64,
    pub score: u8,
    /// Evaluable (non-errored) checks in the domain.
    pub checks: usize,
    pub failed: usize,
    pub errored: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Score {
    pub total: u8,
    pub profile: Profile,
    /// Weighted sum of domain scores, before penalties.
    pub base: f64,
    pub penalties: u32,
    pub domains: Vec<DomainScore>,
}

/// Compute the score for `findings` under `profile`.
pub fn score(findings: &[Finding], profile: Profile) -> Score {
    let weights = profile.weights();
    let mut domains = Vec::with_capacity(weights.len());
    let mut base = 0.0;
    let mut raw_penalties = 0u32;

    for &(domain, weight) in weights {
        let in_domain = findings.iter().filter(|f| f.domain == domain);

        let mut checks = 0usize;
        let mut failed = 0usize;
        let mut errored = 0usize;
        let mut deducted = 0.0;

        for f in in_domain {
            match f.status {
                Status::Error => errored += 1,
                Status::Pass => checks += 1,
                Status::Fail => {
                    checks += 1;
                    failed += 1;
                    deducted += deduction(f.severity);
                    raw_penalties += penalty(f.severity);
                }
            }
        }

        let domain_score = (100.0 - deducted).clamp(0.0, 100.0);
        base += weight * domain_score;

        domains.push(DomainScore {
            domain,
            weight,
            score: domain_score.round() as u8,
            checks,
            failed,
            errored,
        });
    }

    let penalties = (f64::from(raw_penalties) * profile.penalty_scale()).round() as u32;
    let total = (base - f64::from(penalties)).clamp(0.0, 100.0).round() as u8;

    Score {
        total,
        profile,
        base,
        penalties,
        domains,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(domain: Domain, severity: Severity, status: Status) -> Finding {
        Finding {
            id: "test",
            domain,
            title: "test",
            severity,
            status,
            detail: String::new(),
            recommendation: "",
        }
    }

    #[test]
    fn profile_weights_sum_to_one() {
        for profile in [Profile::Baseline, Profile::Hardened] {
            let sum: f64 = profile.weights().iter().map(|&(_, w)| w).sum();
            assert!((sum - 1.0).abs() < 1e-9, "{profile:?} weights sum to {sum}");
        }
    }

    #[test]
    fn parse_profile() {
        assert_eq!(Profile::parse("baseline"), Some(Profile::Baseline));
        assert_eq!(Profile::parse("HARDENED"), Some(Profile::Hardened));
        assert_eq!(Profile::parse("nope"), None);
        assert_eq!(Profile::default(), Profile::Baseline);
    }

    #[test]
    fn empty_is_100() {
        assert_eq!(score(&[], Profile::Baseline).total, 100);
    }

    #[test]
    fn all_pass_is_100() {
        let findings = vec![
            finding(Domain::Ssh, Severity::High, Status::Pass),
            finding(Domain::Accounts, Severity::Critical, Status::Pass),
        ];
        assert_eq!(score(&findings, Profile::Baseline).total, 100);
    }

    #[test]
    fn single_high_failure_applies_domain_and_penalty() {
        // Ssh (weight 0.20) with one High fail: domain 70, base = 0.20*70 + 0.80*100 = 94,
        // minus penalty 8 -> 86.
        let findings = vec![finding(Domain::Ssh, Severity::High, Status::Fail)];
        let s = score(&findings, Profile::Baseline);
        assert_eq!(s.penalties, 8);
        assert_eq!(s.total, 86);
        let ssh = s.domains.iter().find(|d| d.domain == Domain::Ssh).unwrap();
        assert_eq!(ssh.score, 70);
        assert_eq!(ssh.failed, 1);
    }

    #[test]
    fn critical_failure_penalized_hard() {
        // Accounts one Critical.
        // Baseline (0.15): domain 50, base = 92.5, penalty 20 -> 72.5 -> 73.
        // Hardened (0.20): domain 50, base = 90, penalty 20*1.5=30 -> 60.
        let findings = vec![finding(Domain::Accounts, Severity::Critical, Status::Fail)];
        let base = score(&findings, Profile::Baseline);
        assert_eq!(base.penalties, 20);
        assert_eq!(base.total, 73);
        let hard = score(&findings, Profile::Hardened);
        assert_eq!(hard.penalties, 30);
        assert_eq!(hard.total, 60);
        assert!(hard.total < base.total);
    }

    #[test]
    fn domain_score_clamps_at_zero() {
        let findings = vec![
            finding(Domain::Kernel, Severity::High, Status::Fail),
            finding(Domain::Kernel, Severity::High, Status::Fail),
            finding(Domain::Kernel, Severity::High, Status::Fail),
            finding(Domain::Kernel, Severity::Critical, Status::Fail),
        ];
        let s = score(&findings, Profile::Baseline);
        let k = s
            .domains
            .iter()
            .find(|d| d.domain == Domain::Kernel)
            .unwrap();
        assert_eq!(k.score, 0);
    }

    #[test]
    fn errored_checks_do_not_deduct() {
        let findings = vec![finding(Domain::Accounts, Severity::Critical, Status::Error)];
        let s = score(&findings, Profile::Baseline);
        assert_eq!(s.total, 100);
        assert_eq!(s.penalties, 0);
        let a = s
            .domains
            .iter()
            .find(|d| d.domain == Domain::Accounts)
            .unwrap();
        assert_eq!(a.errored, 1);
        assert_eq!(a.failed, 0);
    }

    #[test]
    fn total_never_below_zero() {
        let findings: Vec<Finding> = [
            Domain::Ssh,
            Domain::Firewall,
            Domain::Accounts,
            Domain::Kernel,
            Domain::Services,
            Domain::Updates,
            Domain::Logging,
        ]
        .into_iter()
        .flat_map(|d| {
            std::iter::repeat_with(move || finding(d, Severity::Critical, Status::Fail)).take(5)
        })
        .collect();
        assert_eq!(score(&findings, Profile::Hardened).total, 0);
    }
}
