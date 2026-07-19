//! Stage 8 evals: run every check and the scoring engine against captured
//! command output stored under `tests/fixtures/<distro>/`, asserting the
//! expected per-check status and per-profile score.
//!
//! Guards against regressions in parsing, check logic and scoring on realistic,
//! per-distribution output - without a host. A fixture directory holds one
//! `<command-slug>.txt` per command a check issues (see [`command_slug`]) and an
//! `expected.json`. A command whose file is *absent* is treated as unavailable
//! on that distro (an `Error` finding) - e.g. `apt-get` on a non-Debian host.
//! The runner discovers every fixture, so adding a distro needs no code change.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::audit::{self, Outputs};
use crate::checks::{all_checks, Status};
use crate::health::{self, HealthStatus, Thresholds, HEALTH_COMMANDS};
use crate::scoring::{score, Profile};

/// A fixture's expected results.
#[derive(Deserialize)]
struct Expected {
    /// What the scenario represents (documentation only).
    #[allow(dead_code)]
    description: String,
    /// check id -> expected status ("pass" | "fail" | "error").
    findings: HashMap<String, String>,
    /// profile name -> expected total score.
    scores: HashMap<String, u8>,
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Turn a command into the fixture filename holding its output, collapsing every
/// run of non-alphanumerics to `_`, e.g. `cat /etc/ssh/sshd_config` ->
/// `cat_etc_ssh_sshd_config.txt`. The mapping is unique across all commands.
fn command_slug(command: &str) -> String {
    let slug = command
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    format!("{slug}.txt")
}

fn status_name(status: Status) -> &'static str {
    match status {
        Status::Pass => "pass",
        Status::Fail => "fail",
        Status::Error => "error",
        Status::Skipped => "skipped",
    }
}

fn run_scenario(scenario: &Path, name: &str) {
    let expected: Expected = serde_json::from_str(
        &std::fs::read_to_string(scenario.join("expected.json"))
            .unwrap_or_else(|e| panic!("[{name}] read expected.json: {e}")),
    )
    .unwrap_or_else(|e| panic!("[{name}] parse expected.json: {e}"));

    // Load each distinct command's output. A missing file means the command is
    // unavailable: for a normal check that's an Error finding; for a *privileged*
    // check it models a target not opted in, so the command is left uncollected
    // (evaluate() then reports it as Skipped) - mirroring the real run path.
    let mut outputs: Outputs = HashMap::new();
    for check in all_checks() {
        let cmd = check.command();
        if outputs.contains_key(cmd) {
            continue;
        }
        let file = scenario.join(command_slug(cmd));
        if file.exists() {
            let text = std::fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("[{name}] read {}: {e}", file.display()));
            outputs.insert(cmd, Ok(text));
        } else if check.privileged() {
            continue; // not opted in -> Skipped
        } else {
            outputs.insert(
                cmd,
                Err(format!("command not available on this fixture: {cmd}")),
            );
        }
    }

    let findings = audit::evaluate(&outputs);

    // The fixture must pin exactly the checks the audit produces.
    assert_eq!(
        findings.len(),
        expected.findings.len(),
        "[{name}] expected.findings pins {} checks, audit produced {}",
        expected.findings.len(),
        findings.len()
    );

    for f in &findings {
        let want = expected
            .findings
            .get(f.id)
            .unwrap_or_else(|| panic!("[{name}] no expectation for check '{}'", f.id));
        assert_eq!(
            status_name(f.status),
            want,
            "[{name}] check '{}': expected {want}, got {} - {}",
            f.id,
            status_name(f.status),
            f.detail
        );
    }

    for (profile_name, &want) in &expected.scores {
        let profile = Profile::parse(profile_name)
            .unwrap_or_else(|| panic!("[{name}] unknown profile '{profile_name}'"));
        let got = score(&findings, profile).total;
        assert_eq!(
            got, want,
            "[{name}] {profile_name} score: expected {want}, got {got}"
        );
    }
}

#[test]
fn fixtures_match_expected_findings_and_scores() {
    let dir = fixtures_dir();
    let mut scenarios = 0;
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_dir() {
            continue;
        }
        let path = entry.path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        run_scenario(&path, &name);
        scenarios += 1;
    }
    assert!(scenarios > 0, "no fixtures found in {}", dir.display());
}

/// A fixture's expected operational-health results (default thresholds).
#[derive(Deserialize)]
struct ExpectedHealth {
    #[allow(dead_code)]
    description: String,
    /// metric id -> expected status ("ok" | "warn" | "crit" | "unknown").
    metrics: HashMap<String, String>,
    overall: String,
}

fn health_status_name(status: HealthStatus) -> &'static str {
    match status {
        HealthStatus::Ok => "ok",
        HealthStatus::Warn => "warn",
        HealthStatus::Crit => "crit",
        HealthStatus::Unknown => "unknown",
    }
}

fn run_health_scenario(scenario: &Path, name: &str) {
    let expected: ExpectedHealth = serde_json::from_str(
        &std::fs::read_to_string(scenario.join("expected_health.json"))
            .unwrap_or_else(|e| panic!("[{name}] read expected_health.json: {e}")),
    )
    .unwrap_or_else(|e| panic!("[{name}] parse expected_health.json: {e}"));

    let mut outputs: Outputs = HashMap::new();
    for &cmd in HEALTH_COMMANDS {
        let file = scenario.join(command_slug(cmd));
        let value = if file.exists() {
            Ok(std::fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("[{name}] read {}: {e}", file.display())))
        } else {
            Err(format!("command not available on this fixture: {cmd}"))
        };
        outputs.insert(cmd, value);
    }

    let report = health::evaluate(&outputs, &Thresholds::default());

    assert_eq!(
        report.metrics.len(),
        expected.metrics.len(),
        "[{name}] expected.metrics pins {} metrics, health produced {}",
        expected.metrics.len(),
        report.metrics.len()
    );
    for m in &report.metrics {
        let want = expected
            .metrics
            .get(m.id)
            .unwrap_or_else(|| panic!("[{name}] no expectation for metric '{}'", m.id));
        assert_eq!(
            health_status_name(m.status),
            want,
            "[{name}] metric '{}': expected {want}, got {} - {}",
            m.id,
            health_status_name(m.status),
            m.detail
        );
    }
    assert_eq!(
        health_status_name(report.overall),
        expected.overall,
        "[{name}] overall: expected {}, got {}",
        expected.overall,
        health_status_name(report.overall)
    );
}

#[test]
fn fixtures_match_expected_health() {
    let dir = fixtures_dir();
    let mut scenarios = 0;
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_dir() || !path.join("expected_health.json").exists() {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        run_health_scenario(&path, &name);
        scenarios += 1;
    }
    assert!(
        scenarios > 0,
        "no health fixtures found in {}",
        dir.display()
    );
}

#[test]
fn command_slugs_are_unique() {
    let mut slugs: Vec<String> = all_checks()
        .iter()
        .map(|c| command_slug(c.command()))
        .collect();
    let distinct_commands = {
        let mut cmds: Vec<&str> = all_checks().iter().map(|c| c.command()).collect();
        cmds.sort_unstable();
        cmds.dedup();
        cmds.len()
    };
    slugs.sort_unstable();
    slugs.dedup();
    assert_eq!(
        slugs.len(),
        distinct_commands,
        "command_slug collides: {distinct_commands} commands map to {} slugs",
        slugs.len()
    );
}
