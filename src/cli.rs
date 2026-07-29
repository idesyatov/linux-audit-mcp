//! Command-line interface for the `audit` and `health` subcommands (cron/CI use).
//!
//! The default (no subcommand) is the MCP stdio server, so existing clients
//! that launch the bare binary keep working. Each subcommand targets a single
//! host (`--target`) or a whole group (`--group`, fanned out concurrently).

use std::path::PathBuf;

use anyhow::Context;
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

use crate::checks::{all_check_ids, CheckFilter, Domain, Finding, Severity, Status};
use crate::config::{self, Config};
use crate::health::{self, HealthStatus};
use crate::history;
use crate::report;
use crate::report_sarif;
use crate::run::{self, AuditOutcome, HealthOutcome};
use crate::scoring::{Profile, Score};

#[derive(Parser)]
#[command(
    name = "linux-audit-mcp",
    version,
    about = "Read-only security audit and operational-health checks for Linux servers"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run the MCP server over stdio (this is also the default with no subcommand).
    Serve,
    /// Audit a configured target or group and print a report (for cron/CI).
    Audit(AuditArgs),
    /// Take an operational-health snapshot of a target or group (for cron/CI).
    Health(HealthArgs),
    /// Show the recorded health-snapshot history for a target (trend inspection).
    History(HistoryArgs),
    /// Show the recorded security-audit history for a target (score trend).
    AuditHistory(HistoryArgs),
}

#[derive(Args)]
#[command(group(ArgGroup::new("audit_sel").required(true).args(["target", "group"])))]
pub struct AuditArgs {
    /// Target alias defined in the operator config.
    #[arg(long)]
    target: Option<String>,

    /// Group name from the config; audits every member (or `all` for every target).
    #[arg(long)]
    group: Option<String>,

    /// Override the target's audit profile.
    #[arg(long)]
    profile: Option<String>,

    /// Run only these check ids (repeatable or comma-separated). Combined with
    /// `--domain` as a union; the score then reflects only the checks that ran.
    #[arg(long = "check", value_name = "ID", value_delimiter = ',')]
    checks: Vec<String>,

    /// Run only checks in these domains (repeatable or comma-separated):
    /// ssh, accounts, kernel, firewall, updates, services, logging.
    #[arg(long = "domain", value_name = "NAME", value_delimiter = ',')]
    domains: Vec<String>,

    /// Skip these check ids (repeatable or comma-separated); wins over `--check`.
    #[arg(long = "skip", value_name = "ID", value_delimiter = ',')]
    skip: Vec<String>,

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

    /// After the report, show what changed versus this target's previous audit
    /// (score delta, regressions, fixes). Text format only.
    #[arg(long)]
    diff: bool,

    /// With `--diff`, compare against the Nth most recent prior audit instead of
    /// the immediately previous one (1 = previous, 2 = the one before, ...).
    #[arg(long, value_name = "N", default_value = "1")]
    against: usize,

    /// Do not append this audit to the on-disk history (used by `--diff`).
    #[arg(long)]
    no_store: bool,
}

#[derive(Args)]
#[command(group(ArgGroup::new("health_sel").required(true).args(["target", "group"])))]
pub struct HealthArgs {
    /// Target alias defined in the operator config.
    #[arg(long)]
    target: Option<String>,

    /// Group name from the config; snapshots every member (or `all` for every target).
    #[arg(long)]
    group: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: Format,

    /// Path to the target config (defaults to $LINUX_AUDIT_CONFIG or the standard location).
    #[arg(long)]
    config: Option<PathBuf>,

    /// Exit 2 when the overall health status is at least this severe (`off` disables).
    #[arg(long, value_enum, default_value = "off")]
    fail_on_status: FailOnStatus,

    /// Do not append these snapshots to the on-disk health history.
    #[arg(long)]
    no_store: bool,
}

#[derive(Args)]
#[command(group(ArgGroup::new("history_sel").required(true).args(["target", "group"])))]
pub struct HistoryArgs {
    /// Target alias whose recorded history to show.
    #[arg(long)]
    target: Option<String>,

    /// Group name from the config; shows the history of every member (or `all`).
    #[arg(long)]
    group: Option<String>,

    /// Show at most this many most-recent snapshots (0 for all).
    #[arg(long, default_value = "20")]
    limit: usize,

    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: Format,

    /// Path to the target config (defaults to $LINUX_AUDIT_CONFIG or the standard location).
    #[arg(long)]
    config: Option<PathBuf>,
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
    /// SARIF 2.1.0 - for GitHub code scanning / dashboards (audit only).
    Sarif,
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

fn load_config(path: &Option<PathBuf>) -> anyhow::Result<Config> {
    match path {
        Some(path) => config::load_from(path),
        None => config::load(),
    }
    .context("loading target config")
}

/// Expand a `--target`/`--group` selection into aliases plus the group name (if
/// any). Clap guarantees exactly one of the two is set.
fn select(
    cfg: &Config,
    target: Option<&str>,
    group: Option<&str>,
) -> anyhow::Result<(Vec<String>, Option<String>)> {
    match (target, group) {
        (Some(t), None) => Ok((vec![t.to_string()], None)),
        (None, Some(g)) => Ok((cfg.group_members(g)?, Some(g.to_string()))),
        _ => anyhow::bail!("exactly one of --target or --group is required"),
    }
}

/// Single-host severity/score gate: 2 if either trips, else 0.
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

/// Group exit code: a tripped gate (2) dominates; else an unreachable host (1);
/// else clean (0).
fn audit_exit(outcomes: &[AuditOutcome], fail_on: FailOn, fail_under: Option<u8>) -> i32 {
    let gate = outcomes
        .iter()
        .any(|o| matches!(&o.result, Ok((s, f)) if exit_code(s, f, fail_on, fail_under) == 2));
    let errored = outcomes.iter().any(|o| o.result.is_err());
    if gate {
        2
    } else if errored {
        1
    } else {
        0
    }
}

/// Build a [`CheckFilter`] from the CLI selectors, erroring on any unknown check
/// id or domain name so a typo fails fast instead of silently selecting nothing.
fn build_filter(
    checks: &[String],
    domains: &[String],
    skip: &[String],
) -> anyhow::Result<CheckFilter> {
    let known = all_check_ids();
    let validate_id = |id: &String| -> anyhow::Result<String> {
        if known.contains(&id.as_str()) {
            Ok(id.clone())
        } else {
            anyhow::bail!("unknown check id {id:?} (see the README check table for valid ids)")
        }
    };
    let only = checks
        .iter()
        .map(validate_id)
        .collect::<anyhow::Result<_>>()?;
    let skip = skip
        .iter()
        .map(validate_id)
        .collect::<anyhow::Result<_>>()?;
    let domains = domains
        .iter()
        .map(|d| {
            Domain::parse(d).ok_or_else(|| {
                anyhow::anyhow!("unknown domain {d:?} (valid: {})", Domain::NAMES.join(", "))
            })
        })
        .collect::<anyhow::Result<_>>()?;
    Ok(CheckFilter {
        only,
        domains,
        skip,
    })
}

/// Run the audit against a target or group and print the report.
pub async fn run_audit(args: AuditArgs) -> anyhow::Result<i32> {
    let cfg = load_config(&args.config)?;
    let profile_override = match args.profile.as_deref() {
        Some(name) => {
            Some(Profile::parse(name).with_context(|| format!("unknown profile {name:?}"))?)
        }
        None => None,
    };
    let filter = build_filter(&args.checks, &args.domains, &args.skip)?;
    if filter.is_active() {
        // A partial run: unselected domains contribute no deductions, so the score
        // reflects only the checks that ran. Note it on stderr so stdout/JSON stay clean.
        eprintln!(
            "note: filtered run - only selected checks ran; the score reflects only those checks"
        );
    }
    let (aliases, group) = select(&cfg, args.target.as_deref(), args.group.as_deref())?;
    let outcomes = run::audit_targets(&cfg, &aliases, profile_override, &filter).await?;

    // Diff each host against its previous stored audit BEFORE recording this one,
    // so "previous" is genuinely the prior run (None = no history yet).
    let diffs: Vec<(String, Option<history::AuditDiff>)> = if args.diff {
        outcomes
            .iter()
            .filter_map(|o| {
                let (score, findings) = o.result.as_ref().ok()?;
                let cur = history::AuditSnapshot::from_audit(score, findings, 0);
                // Read the N newest prior snapshots (oldest -> newest); the first is
                // the Nth most recent = the requested baseline. `against` runs before
                // this run is recorded, so the stored newest is the previous run.
                let n = args.against.max(1);
                let hist = history::read_recent_audit(&o.alias, n).ok()?;
                if !hist.is_empty() && hist.len() < n {
                    eprintln!(
                        "note: requested {n} audit(s) back for '{}', but only {} stored; \
                         diffing against the oldest",
                        o.alias,
                        hist.len()
                    );
                }
                let prev = hist.into_iter().next();
                Some((o.alias.clone(), prev.map(|p| history::audit_diff(&p, &cur))))
            })
            .collect()
    } else {
        Vec::new()
    };

    match &group {
        None => {
            let o = &outcomes[0];
            match &o.result {
                Ok((score, findings)) => match args.format {
                    Format::Text => print!("{}", report::text(&o.alias, score, findings)),
                    Format::Json => println!("{}", report::json(&o.alias, score, findings)?),
                    Format::Sarif => {
                        println!("{}", report_sarif::sarif(&o.alias, score, findings)?)
                    }
                },
                Err(e) => eprintln!("audit of '{}' failed: {e}", o.alias),
            }
        }
        Some(g) => match args.format {
            Format::Text => print!("{}", run::audit_group_text(g, &outcomes)),
            Format::Json => println!("{}", run::audit_group_json(g, &outcomes)?),
            Format::Sarif => println!("{}", report_sarif::sarif_group(&outcomes)?),
        },
    }

    if args.diff {
        match args.format {
            Format::Json => {
                for (alias, diff) in &diffs {
                    println!("{}", history::audit_diff_json(alias, diff.as_ref())?);
                }
            }
            Format::Sarif => {
                eprintln!("note: --diff is not represented in SARIF; ignored for --format sarif")
            }
            Format::Text => {
                for (alias, diff) in &diffs {
                    match diff {
                        Some(d) => print!("{}", history::audit_diff_text(alias, d)),
                        None => println!(
                            "Audit changes for '{alias}': no prior audit snapshot to compare."
                        ),
                    }
                }
            }
        }
    }

    // Persist this audit so future `--diff` runs have a baseline (best-effort).
    history::record_audit_outcomes(&outcomes, !args.no_store);

    Ok(audit_exit(&outcomes, args.fail_on, args.fail_under))
}

/// Single-host health gate: 2 if `overall` meets `fail_on`, else 0.
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

fn health_exit(outcomes: &[HealthOutcome], fail_on: FailOnStatus) -> i32 {
    let gate = outcomes
        .iter()
        .any(|o| matches!(&o.result, Ok(r) if health_exit_code(r.overall, fail_on) == 2));
    let errored = outcomes.iter().any(|o| o.result.is_err());
    if gate {
        2
    } else if errored {
        1
    } else {
        0
    }
}

/// Take a health snapshot of a target or group and print the report.
pub async fn run_health(args: HealthArgs) -> anyhow::Result<i32> {
    let cfg = load_config(&args.config)?;
    let (aliases, group) = select(&cfg, args.target.as_deref(), args.group.as_deref())?;
    let mut outcomes = run::health_targets(&cfg, &aliases).await?;

    // Detect anomalies against stored history BEFORE recording this run, so the
    // fresh reading is never part of its own baseline.
    run::annotate_anomalies(&cfg, &mut outcomes);
    // Flag between-run changes (a container restarted, a unit newly failed) vs
    // the previous snapshot - also before recording, so "previous" is the prior run.
    run::annotate_changes(&mut outcomes);
    // Persist each successful snapshot for later trend inspection / baselining.
    // Best-effort: a storage error is logged, never fails the health run.
    history::record_outcomes(&outcomes, !args.no_store);

    match &group {
        None => {
            let o = &outcomes[0];
            match &o.result {
                Ok(report) => match args.format {
                    Format::Text => print!("{}", health::report::text(&o.alias, report)),
                    Format::Json => println!("{}", health::report::json(&o.alias, report)?),
                    Format::Sarif => anyhow::bail!("SARIF format is only supported by `audit`"),
                },
                Err(e) => eprintln!("health snapshot of '{}' failed: {e}", o.alias),
            }
        }
        Some(g) => match args.format {
            Format::Text => print!("{}", run::health_group_text(g, &outcomes)),
            Format::Json => println!("{}", run::health_group_json(g, &outcomes)?),
            Format::Sarif => anyhow::bail!("SARIF format is only supported by `audit`"),
        },
    }

    Ok(health_exit(&outcomes, args.fail_on_status))
}

/// Print the recorded health-snapshot history for a target. Reads local files
/// only (no SSH); the alias is validated against the config to catch typos.
pub fn run_history(args: HistoryArgs) -> anyhow::Result<i32> {
    let cfg = load_config(&args.config)?;
    let (aliases, group) = select(&cfg, args.target.as_deref(), args.group.as_deref())?;
    let mut entries = Vec::with_capacity(aliases.len());
    for alias in &aliases {
        if !cfg.targets.contains_key(alias) {
            anyhow::bail!("unknown target {alias:?}");
        }
        let snaps = history::read_recent(alias, args.limit)
            .with_context(|| format!("reading health history for {alias:?}"))?;
        entries.push((alias.clone(), snaps));
    }
    match (&group, args.format) {
        (_, Format::Sarif) => anyhow::bail!("SARIF format is only supported by `audit`"),
        (Some(g), Format::Text) => print!("{}", history::group_text(g, &entries)),
        (Some(g), Format::Json) => println!("{}", history::group_json(g, &entries)?),
        (None, Format::Text) => print!("{}", history::text(&entries[0].0, &entries[0].1)),
        (None, Format::Json) => println!("{}", history::json(&entries[0].0, &entries[0].1)?),
    }
    Ok(0)
}

/// Print the recorded security-audit history for a target or group (score trend).
/// Reads local files only (no SSH); each alias is validated against the config.
pub fn run_audit_history(args: HistoryArgs) -> anyhow::Result<i32> {
    let cfg = load_config(&args.config)?;
    let (aliases, group) = select(&cfg, args.target.as_deref(), args.group.as_deref())?;
    let mut entries = Vec::with_capacity(aliases.len());
    for alias in &aliases {
        if !cfg.targets.contains_key(alias) {
            anyhow::bail!("unknown target {alias:?}");
        }
        let snaps = history::read_recent_audit(alias, args.limit)
            .with_context(|| format!("reading audit history for {alias:?}"))?;
        entries.push((alias.clone(), snaps));
    }
    match (&group, args.format) {
        (_, Format::Sarif) => anyhow::bail!("SARIF format is only supported by `audit`"),
        (Some(g), Format::Text) => print!("{}", history::audit_group_text(g, &entries)),
        (Some(g), Format::Json) => println!("{}", history::audit_group_json(g, &entries)?),
        (None, Format::Text) => print!("{}", history::audit_text(&entries[0].0, &entries[0].1)),
        (None, Format::Json) => println!("{}", history::audit_json(&entries[0].0, &entries[0].1)?),
    }
    Ok(0)
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
    fn parses_audit_target_and_group() {
        let a = Cli::try_parse_from(["linux-audit-mcp", "audit", "--target", "web"]).unwrap();
        match a.command {
            Some(Command::Audit(a)) => {
                assert_eq!(a.target.as_deref(), Some("web"));
                assert!(a.group.is_none());
                assert!(matches!(a.fail_on, FailOn::High)); // secure default
                assert_eq!(a.against, 1); // diff baseline defaults to the previous run
            }
            _ => panic!("expected audit subcommand"),
        }
        let g = Cli::try_parse_from(["linux-audit-mcp", "audit", "--group", "mtproto"]).unwrap();
        match g.command {
            Some(Command::Audit(a)) => assert_eq!(a.group.as_deref(), Some("mtproto")),
            _ => panic!("expected audit subcommand"),
        }
        // --diff --against N selects an older baseline.
        let d = Cli::try_parse_from([
            "linux-audit-mcp",
            "audit",
            "--target",
            "web",
            "--diff",
            "--against",
            "3",
        ])
        .unwrap();
        match d.command {
            Some(Command::Audit(a)) => {
                assert!(a.diff);
                assert_eq!(a.against, 3);
            }
            _ => panic!("expected audit subcommand"),
        }
    }

    #[test]
    fn target_and_group_are_mutually_exclusive() {
        // Neither -> error.
        assert!(Cli::try_parse_from(["linux-audit-mcp", "audit"]).is_err());
        // Both -> error.
        assert!(
            Cli::try_parse_from(["linux-audit-mcp", "audit", "--target", "a", "--group", "b"])
                .is_err()
        );
    }

    #[test]
    fn no_subcommand_defaults_to_serve() {
        let cli = Cli::try_parse_from(["linux-audit-mcp"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn build_filter_validates_and_parses() {
        // Valid ids + domain -> populated filter.
        let f = build_filter(
            &["kernel-aslr".to_string()],
            &["ssh".to_string()],
            &["ssh-max-auth-tries".to_string()],
        )
        .unwrap();
        assert_eq!(f.only, vec!["kernel-aslr".to_string()]);
        assert_eq!(f.domains, vec![Domain::Ssh]);
        assert!(f.is_active());
        // Empty selectors -> inactive (runs everything).
        assert!(!build_filter(&[], &[], &[]).unwrap().is_active());
        // Unknown check id and unknown domain both error (typo protection).
        assert!(build_filter(&["nope-check".to_string()], &[], &[]).is_err());
        assert!(build_filter(&[], &["nope-domain".to_string()], &[]).is_err());
        assert!(build_filter(&[], &[], &["nope-skip".to_string()]).is_err());
    }

    #[test]
    fn audit_parses_check_domain_skip() {
        let a = Cli::try_parse_from([
            "linux-audit-mcp",
            "audit",
            "--target",
            "web",
            "--check",
            "kernel-aslr,ssh-weak-crypto",
            "--domain",
            "firewall",
            "--skip",
            "updates-security-pending",
        ])
        .unwrap();
        match a.command {
            Some(Command::Audit(a)) => {
                assert_eq!(a.checks, vec!["kernel-aslr", "ssh-weak-crypto"]); // comma-split
                assert_eq!(a.domains, vec!["firewall"]);
                assert_eq!(a.skip, vec!["updates-security-pending"]);
                assert!(!a.diff && !a.no_store); // default off
            }
            _ => panic!("expected audit subcommand"),
        }
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
    fn group_exit_prefers_gate_then_error() {
        let clean = AuditOutcome {
            alias: "a".into(),
            result: Ok((score(&[], Profile::Baseline), vec![])),
        };
        let failing = AuditOutcome {
            alias: "b".into(),
            result: Ok((
                score(&[finding(Severity::High, Status::Fail)], Profile::Baseline),
                vec![finding(Severity::High, Status::Fail)],
            )),
        };
        let errored = AuditOutcome {
            alias: "c".into(),
            result: Err("connection failed".into()),
        };
        // gate (2) dominates even with an errored host present.
        assert_eq!(
            audit_exit(std::slice::from_ref(&failing), FailOn::High, None),
            2
        );
        assert_eq!(audit_exit(&[clean, errored], FailOn::High, None), 1);
    }

    #[test]
    fn parses_health_subcommand() {
        let cli = Cli::try_parse_from(["linux-audit-mcp", "health", "--target", "web"]).unwrap();
        match cli.command {
            Some(Command::Health(a)) => {
                assert_eq!(a.target.as_deref(), Some("web"));
                assert!(matches!(a.fail_on_status, FailOnStatus::Off)); // cron-friendly default
            }
            _ => panic!("expected health subcommand"),
        }
    }

    #[test]
    fn parses_history_subcommand() {
        let cli = Cli::try_parse_from(["linux-audit-mcp", "history", "--target", "web"]).unwrap();
        match cli.command {
            Some(Command::History(a)) => {
                assert_eq!(a.target.as_deref(), Some("web"));
                assert!(a.group.is_none());
                assert_eq!(a.limit, 20); // default
            }
            _ => panic!("expected history subcommand"),
        }
        // --group is accepted too.
        let g = Cli::try_parse_from(["linux-audit-mcp", "history", "--group", "mtproto"]).unwrap();
        match g.command {
            Some(Command::History(a)) => assert_eq!(a.group.as_deref(), Some("mtproto")),
            _ => panic!("expected history subcommand"),
        }
        // exactly one of --target/--group is required.
        assert!(Cli::try_parse_from(["linux-audit-mcp", "history"]).is_err());
        assert!(Cli::try_parse_from([
            "linux-audit-mcp",
            "history",
            "--target",
            "web",
            "--group",
            "mtproto"
        ])
        .is_err());
    }

    #[test]
    fn health_no_store_defaults_off() {
        let on = Cli::try_parse_from(["linux-audit-mcp", "health", "--target", "web"]).unwrap();
        match on.command {
            Some(Command::Health(a)) => assert!(!a.no_store), // stores by default
            _ => panic!("expected health subcommand"),
        }
        let off =
            Cli::try_parse_from(["linux-audit-mcp", "health", "--target", "web", "--no-store"])
                .unwrap();
        match off.command {
            Some(Command::Health(a)) => assert!(a.no_store),
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
