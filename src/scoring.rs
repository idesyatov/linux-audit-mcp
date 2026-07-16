//! Security scoring: turn findings into a 0–100 score with a per-domain
//! breakdown.
//!
//! `S = clamp( Σ(weight_i × domain_score_i) − penalties, 0, 100 )`
//!
//! Each failed check deducts from its domain's score by severity, and High /
//! Critical failures add a *global* penalty so a single severe issue drags the
//! total even when its domain is lightly weighted (otherwise averaging would
//! dilute it). Checks that errored (command didn't run) are excluded.
//!
//! A single baseline weight set is used for now; selectable profiles arrive in
//! the next stage.

use serde::Serialize;

use crate::checks::{Domain, Finding, Severity, Status};

/// Domain weights. The set sums to 1.0.
pub type Weights = &'static [(Domain, f64)];

/// Baseline weights for a general-purpose server.
const BASELINE_WEIGHTS: Weights = &[
    (Domain::Ssh, 0.20),
    (Domain::Firewall, 0.15),
    (Domain::Accounts, 0.15),
    (Domain::Kernel, 0.15),
    (Domain::Services, 0.15),
    (Domain::Updates, 0.10),
    (Domain::Logging, 0.10),
];

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
    /// Weighted sum of domain scores, before penalties.
    pub base: f64,
    pub penalties: u32,
    pub domains: Vec<DomainScore>,
}

/// Compute the score for `findings` under the baseline weights.
pub fn score(findings: &[Finding]) -> Score {
    let weights = BASELINE_WEIGHTS;
    let mut domains = Vec::with_capacity(weights.len());
    let mut base = 0.0;
    let mut penalties = 0u32;

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
                    penalties += penalty(f.severity);
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

    let total = (base - f64::from(penalties)).clamp(0.0, 100.0).round() as u8;

    Score {
        total,
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
    fn weights_sum_to_one() {
        let sum: f64 = BASELINE_WEIGHTS.iter().map(|&(_, w)| w).sum();
        assert!((sum - 1.0).abs() < 1e-9, "weights sum to {sum}");
    }

    #[test]
    fn empty_is_100() {
        assert_eq!(score(&[]).total, 100);
    }

    #[test]
    fn all_pass_is_100() {
        let findings = vec![
            finding(Domain::Ssh, Severity::High, Status::Pass),
            finding(Domain::Accounts, Severity::Critical, Status::Pass),
        ];
        assert_eq!(score(&findings).total, 100);
    }

    #[test]
    fn single_high_failure_applies_domain_and_penalty() {
        // Ssh (weight 0.20) with one High fail: domain 70, base = 0.20*70 + 0.80*100 = 94,
        // minus penalty 8 → 86.
        let findings = vec![finding(Domain::Ssh, Severity::High, Status::Fail)];
        let s = score(&findings);
        assert_eq!(s.penalties, 8);
        assert_eq!(s.total, 86);
        let ssh = s.domains.iter().find(|d| d.domain == Domain::Ssh).unwrap();
        assert_eq!(ssh.score, 70);
        assert_eq!(ssh.failed, 1);
    }

    #[test]
    fn critical_failure_penalized_hard() {
        // Accounts (0.15) one Critical: domain 50, base = 0.15*50 + 0.85*100 = 92.5,
        // minus penalty 20 → 72.5 → 73.
        let findings = vec![finding(Domain::Accounts, Severity::Critical, Status::Fail)];
        let s = score(&findings);
        assert_eq!(s.penalties, 20);
        assert_eq!(s.total, 73);
    }

    #[test]
    fn domain_score_clamps_at_zero() {
        let findings = vec![
            finding(Domain::Kernel, Severity::High, Status::Fail),
            finding(Domain::Kernel, Severity::High, Status::Fail),
            finding(Domain::Kernel, Severity::High, Status::Fail),
            finding(Domain::Kernel, Severity::Critical, Status::Fail),
        ];
        let s = score(&findings);
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
        let s = score(&findings);
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
        assert_eq!(score(&findings).total, 0);
    }
}
