//! Command-line interface for the `audit` subcommand (cron/CI use).
//!
//! The default (no subcommand) is the MCP stdio server, so existing clients
//! that launch the bare binary keep working.

use std::path::PathBuf;

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::checks::{Finding, Severity, Status};
use crate::health::{self, HealthStatus};
use crate::scoring::{self, Profile, Score};
use crate::{audit, config, report};

#[derive(Parser)]
#[command(
    name = "linux-audit-mcp",
    version,
    about = "Read-only Linux server security audit"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run the MCP server over stdio (this is also the default with no subcommand).
    Serve,
    /// Audit a configured target and print a report (for cron/CI).
    Audit(AuditArgs),
    /// Take an operational-health snapshot of a configured target (for cron/CI).
    Health(HealthArgs),
}

#[derive(Args)]
pub struct AuditArgs {
    /// Target alias defined in the operator config.
    #[arg(long)]
    target: String,

    /// Override the target's audit profile.
    #[arg(long)]
    profile: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: Format,

    /// Path to the target config (defaults to $LINUX_AUDIT_CONFIG or the standard location).
    #[arg(long)]
    config: Option<PathBuf>,

    /// Exit 2 if any failed check is at least this severity (`off` disables).
    #[arg(long, value_enum, default_value = "high")]
    fail_on: FailOn,

    /// Exit 2 if the total score is below this value (0-100).
    #[arg(long)]
    fail_under: Option<u8>,
}

#[derive(Args)]
pub struct HealthArgs {
    /// Target alias defined in the operator config.
    #[arg(long)]
    target: String,

    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: Format,

    /// Path to the target config (defaults to $LINUX_AUDIT_CONFIG or the standard location).
    #[arg(long)]
    config: Option<PathBuf>,

    /// Exit 2 when the overall health status is at least this severe (`off` disables).
    #[arg(long, value_enum, default_value = "off")]
    fail_on_status: FailOnStatus,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum FailOnStatus {
    Off,
    Warn,
    Crit,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Format {
    Text,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum FailOn {
    Off,
    Low,
    Medium,
    High,
    Critical,
}

impl FailOn {
    fn min_severity(self) -> Option<Severity> {
        match self {
            Self::Off => None,
            Self::Low => Some(Severity::Low),
            Self::Medium => Some(Severity::Medium),
            Self::High => Some(Severity::High),
            Self::Critical => Some(Severity::Critical),
        }
    }
}

/// Exit code from the gates: 2 if either gate trips, else 0.
fn exit_code(score: &Score, findings: &[Finding], fail_on: FailOn, fail_under: Option<u8>) -> i32 {
    let severity_gate = fail_on.min_severity().is_some_and(|min| {
        findings
            .iter()
            .any(|f| f.status == Status::Fail && f.severity >= min)
    });
    let score_gate = fail_under.is_some_and(|n| score.total < n);
    if severity_gate || score_gate {
        2
    } else {
        0
    }
}

/// Run an audit and print the report. Returns the process exit code.
pub async fn run_audit(args: AuditArgs) -> anyhow::Result<i32> {
    let cfg = match &args.config {
        Some(path) => config::load_from(path),
        None => config::load(),
    }
    .context("loading target config")?;

    let target = cfg.target(&args.target)?;

    let profile = match args.profile.as_deref() {
        Some(name) => Profile::parse(name).with_context(|| format!("unknown profile {name:?}"))?,
        None => target.profile.unwrap_or_default(),
    };

    let findings = audit::run_audit(&target.to_ssh_config())
        .await
        .context("running audit")?;
    let score = scoring::score(&findings, profile);

    match args.format {
        Format::Text => print!("{}", report::text(&args.target, &score, &findings)),
        Format::Json => println!("{}", report::json(&args.target, &score, &findings)?),
    }

    Ok(exit_code(&score, &findings, args.fail_on, args.fail_under))
}

/// Exit code for the health gate: 2 if `overall` meets `fail_on`, else 0.
fn health_exit_code(overall: HealthStatus, fail_on: FailOnStatus) -> i32 {
    let trips = match fail_on {
        FailOnStatus::Off => false,
        FailOnStatus::Warn => matches!(overall, HealthStatus::Warn | HealthStatus::Crit),
        FailOnStatus::Crit => matches!(overall, HealthStatus::Crit),
    };
    if trips {
        2
    } else {
        0
    }
}

/// Take a health snapshot and print the report. Returns the process exit code.
pub async fn run_health(args: HealthArgs) -> anyhow::Result<i32> {
    let cfg = match &args.config {
        Some(path) => config::load_from(path),
        None => config::load(),
    }
    .context("loading target config")?;

    let target = cfg.target(&args.target)?;

    let report = health::collect(&target.to_ssh_config(), &target.health)
        .await
        .context("collecting health snapshot")?;

    match args.format {
        Format::Text => print!("{}", health::report::text(&args.target, &report)),
        Format::Json => println!("{}", health::report::json(&args.target, &report)?),
    }

    Ok(health_exit_code(report.overall, args.fail_on_status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Domain;
    use crate::scoring::score;

    fn finding(severity: Severity, status: Status) -> Finding {
        Finding {
            id: "t",
            domain: Domain::Ssh,
            title: "t",
            severity,
            status,
            detail: String::new(),
            recommendation: "",
        }
    }

    #[test]
    fn parses_audit_subcommand() {
        let cli = Cli::try_parse_from(["linux-audit-mcp", "audit", "--target", "web"]).unwrap();
        match cli.command {
            Some(Command::Audit(a)) => {
                assert_eq!(a.target, "web");
                assert!(matches!(a.fail_on, FailOn::High)); // secure default
            }
            _ => panic!("expected audit subcommand"),
        }
    }

    #[test]
    fn no_subcommand_defaults_to_serve() {
        let cli = Cli::try_parse_from(["linux-audit-mcp"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn severity_gate_defaults_to_high() {
        let findings = vec![finding(Severity::High, Status::Fail)];
        let s = score(&findings, Profile::Baseline);
        assert_eq!(exit_code(&s, &findings, FailOn::High, None), 2);
        // A medium failure does not trip the High gate.
        let med = vec![finding(Severity::Medium, Status::Fail)];
        let s2 = score(&med, Profile::Baseline);
        assert_eq!(exit_code(&s2, &med, FailOn::High, None), 0);
    }

    #[test]
    fn fail_on_off_disables_severity_gate() {
        let findings = vec![finding(Severity::Critical, Status::Fail)];
        let s = score(&findings, Profile::Baseline);
        assert_eq!(exit_code(&s, &findings, FailOn::Off, None), 0);
    }

    #[test]
    fn score_gate() {
        let findings = vec![finding(Severity::Low, Status::Fail)];
        let s = score(&findings, Profile::Baseline); // total ~99
        assert_eq!(exit_code(&s, &findings, FailOn::Off, Some(100)), 2);
        assert_eq!(exit_code(&s, &findings, FailOn::Off, Some(50)), 0);
    }

    #[test]
    fn parses_health_subcommand() {
        let cli = Cli::try_parse_from(["linux-audit-mcp", "health", "--target", "web"]).unwrap();
        match cli.command {
            Some(Command::Health(a)) => {
                assert_eq!(a.target, "web");
                assert!(matches!(a.fail_on_status, FailOnStatus::Off)); // cron-friendly default
            }
            _ => panic!("expected health subcommand"),
        }
    }

    #[test]
    fn health_gate() {
        // off never trips; warn trips on Warn/Crit; crit only on Crit.
        assert_eq!(health_exit_code(HealthStatus::Crit, FailOnStatus::Off), 0);
        assert_eq!(health_exit_code(HealthStatus::Warn, FailOnStatus::Warn), 2);
        assert_eq!(health_exit_code(HealthStatus::Ok, FailOnStatus::Warn), 0);
        assert_eq!(health_exit_code(HealthStatus::Warn, FailOnStatus::Crit), 0);
        assert_eq!(health_exit_code(HealthStatus::Crit, FailOnStatus::Crit), 2);
        // Unknown is neutral - never gates.
        assert_eq!(
            health_exit_code(HealthStatus::Unknown, FailOnStatus::Warn),
            0
        );
    }
}
