//! Persistence of per-target snapshots: operational-health (`<alias>.jsonl`) and
//! security-audit posture (`<alias>.audit.jsonl`).
//!
//! Append-only JSONL, one file per target alias, one snapshot per line.
//! Deliberately file-based - no database dependency - so the static musl build
//! (no C bindings) and the non-root Docker image stay simple, and the history is
//! human-inspectable and trivially mounted as a volume.
//!
//! Health baselining/anomaly detection over the health history lives in
//! [`crate::anomaly`]; the audit run-over-run diff lives here ([`audit_diff`]).

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::checks::{Finding, Status};
use crate::health::{HealthReport, HealthStatus};
use crate::run::{AuditOutcome, HealthOutcome};
use crate::scoring::{Profile, Score};

/// Default cap on stored snapshots per target; override with
/// `$LINUX_AUDIT_HISTORY_MAX` (`0` disables trimming). At an hourly cadence 1000
/// snapshots is about six weeks.
const DEFAULT_MAX: usize = 1000;

/// One persisted health reading: when it was taken (unix seconds), the overall
/// verdict, and the primary numeric value of each metric that had one, keyed by
/// metric id (e.g. `health-load` -> load per core).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub ts: u64,
    pub overall: HealthStatus,
    #[serde(default)]
    pub metrics: BTreeMap<String, f64>,
    /// Running containers -> uptime seconds at snapshot time; lets the next run
    /// detect a restart (uptime dropping). Absent in pre-0.16 snapshots -> empty.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub containers: BTreeMap<String, u64>,
    /// Systemd units in the failed state at snapshot time; lets the next run flag
    /// a unit that newly failed. Absent in pre-0.16 snapshots -> empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_units: Vec<String>,
}

impl Snapshot {
    /// Derive a snapshot from a report and a collection timestamp. `Unknown`
    /// metrics carry no number and are simply absent from the map.
    pub fn from_report(report: &HealthReport, ts: u64) -> Self {
        let metrics = report
            .metrics
            .iter()
            .filter_map(|m| m.numeric.map(|v| (m.id.to_string(), v)))
            .collect();
        Snapshot {
            ts,
            overall: report.overall,
            metrics,
            containers: report.container_uptimes.clone(),
            failed_units: report.failed_units.clone(),
        }
    }
}

/// Current unix time in whole seconds (0 if the clock is before the epoch).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// History directory: `$LINUX_AUDIT_DATA_DIR`, else
/// `~/.local/share/linux-audit-mcp/history`.
fn data_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("LINUX_AUDIT_DATA_DIR") {
        return PathBuf::from(p);
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .unwrap_or_default();
    PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("linux-audit-mcp")
        .join("history")
}

/// Configured retention cap (`$LINUX_AUDIT_HISTORY_MAX`), else [`DEFAULT_MAX`].
fn max_snapshots() -> usize {
    std::env::var("LINUX_AUDIT_HISTORY_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX)
}

/// Reject aliases that would escape the history directory or collide once mapped
/// to a filename. Aliases come from the operator config, but a stray `/` or `..`
/// must never become a path - so we allowlist rather than silently mangle (which
/// could map two aliases onto one file).
fn safe_alias(alias: &str) -> io::Result<&str> {
    let ok = !alias.is_empty()
        && alias != "."
        && alias != ".."
        && alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(alias)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("alias {alias:?} is not a safe history filename (allowed: A-Z a-z 0-9 . _ -)"),
        ))
    }
}

fn file_in(dir: &Path, alias: &str) -> io::Result<PathBuf> {
    Ok(dir.join(format!("{}.jsonl", safe_alias(alias)?)))
}

/// Append one snapshot to a target's JSONL file under `dir` (creating the
/// directory if needed), then trim to the newest `max` snapshots (`max == 0`
/// keeps everything).
pub fn record_in(dir: &Path, alias: &str, snap: &Snapshot, max: usize) -> io::Result<()> {
    let path = file_in(dir, alias)?;
    fs::create_dir_all(dir)?;
    let line = serde_json::to_string(snap).map_err(io::Error::other)? + "\n";
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        f.write_all(line.as_bytes())?;
    }
    if max > 0 {
        trim(&path, max)?;
    }
    Ok(())
}

/// Keep only the last `max` lines of `path`, rewriting via a temp file + rename
/// so a crash mid-write never leaves a truncated history.
fn trim(path: &Path, max: usize) -> io::Result<()> {
    let text = fs::read_to_string(path)?;
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() <= max {
        return Ok(());
    }
    let tail = &lines[lines.len() - max..];
    let tmp = path.with_extension("jsonl.tmp");
    fs::write(&tmp, tail.join("\n") + "\n")?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Read the most recent `limit` snapshots (chronological order) for a target
/// under `dir`. A missing file yields an empty vec; unparseable lines are
/// skipped so one bad line does not sink the whole history. `limit == 0` returns
/// everything.
pub fn read_recent_in(dir: &Path, alias: &str, limit: usize) -> io::Result<Vec<Snapshot>> {
    let path = file_in(dir, alias)?;
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut snaps: Vec<Snapshot> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    if limit > 0 && snaps.len() > limit {
        snaps.drain(0..snaps.len() - limit);
    }
    Ok(snaps)
}

/// Record every successful outcome to the default history directory. Storage
/// failures are logged, not propagated: the report is already produced, and a
/// full disk must not turn a successful snapshot into a failed health run.
pub fn record_outcomes(outcomes: &[HealthOutcome], store: bool) {
    if !store {
        return;
    }
    let dir = data_dir();
    let max = max_snapshots();
    let ts = now_unix();
    for o in outcomes {
        if let Ok(report) = &o.result {
            let snap = Snapshot::from_report(report, ts);
            if let Err(e) = record_in(&dir, &o.alias, &snap, max) {
                tracing::warn!("could not record health history for '{}': {e}", o.alias);
            }
        }
    }
}

/// Read recent snapshots for a target from the default history directory.
pub fn read_recent(alias: &str, limit: usize) -> io::Result<Vec<Snapshot>> {
    read_recent_in(&data_dir(), alias, limit)
}

/// Drop the `health-` prefix for compact column headers.
fn short_id(id: &str) -> &str {
    id.strip_prefix("health-").unwrap_or(id)
}

/// Format a unix timestamp as `YYYY-MM-DD HH:MM:SSZ` (UTC), without pulling in a
/// date crate.
pub fn fmt_utc(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    let sod = ts % 86_400;
    let (h, m, s) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}Z")
}

/// Howard Hinnant's `civil_from_days`: unix day number -> (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Human-readable history table: one row per snapshot, columns are the union of
/// metric ids seen (sorted), plus time and overall status.
pub fn text(alias: &str, snaps: &[Snapshot]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    if snaps.is_empty() {
        let _ = writeln!(out, "No health history recorded for '{alias}'.");
        return out;
    }
    let mut ids: Vec<&str> = snaps
        .iter()
        .flat_map(|s| s.metrics.keys().map(|k| k.as_str()))
        .collect();
    ids.sort_unstable();
    ids.dedup();

    let _ = writeln!(
        out,
        "Health history of '{alias}' ({} snapshot(s), operational, not a security score):",
        snaps.len()
    );
    let _ = write!(out, "  {:<20} {:<5}", "time (UTC)", "stat");
    for id in &ids {
        let _ = write!(out, " {:>14}", short_id(id));
    }
    out.push('\n');
    for s in snaps {
        let _ = write!(out, "  {:<20} {:<5}", fmt_utc(s.ts), s.overall.tag());
        for id in &ids {
            match s.metrics.get(*id) {
                Some(v) => {
                    let _ = write!(out, " {v:>14.2}");
                }
                None => {
                    let _ = write!(out, " {:>14}", "-");
                }
            }
        }
        out.push('\n');
    }
    out
}

/// Machine-readable history: `{ target, kind: "health-history", count, snapshots }`.
pub fn json(alias: &str, snaps: &[Snapshot]) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&serde_json::json!({
        "target": alias,
        "kind": "health-history",
        "count": snaps.len(),
        "snapshots": snaps,
    }))
}

// ---- audit snapshots + run-over-run diff --------------------------------

/// One persisted security-audit reading: when it was taken, the overall score,
/// the profile it was scored under, and the status of every check by id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditSnapshot {
    pub ts: u64,
    pub total: u8,
    pub profile: Profile,
    #[serde(default)]
    pub findings: BTreeMap<String, Status>,
}

impl AuditSnapshot {
    pub fn from_audit(score: &Score, findings: &[Finding], ts: u64) -> Self {
        AuditSnapshot {
            ts,
            total: score.total,
            profile: score.profile,
            findings: findings
                .iter()
                .map(|f| (f.id.to_string(), f.status))
                .collect(),
        }
    }
}

fn audit_file_in(dir: &Path, alias: &str) -> io::Result<PathBuf> {
    Ok(dir.join(format!("{}.audit.jsonl", safe_alias(alias)?)))
}

/// Append one audit snapshot to `<alias>.audit.jsonl` under `dir`, then trim to
/// the newest `max` (`max == 0` keeps everything).
pub fn record_audit_in(
    dir: &Path,
    alias: &str,
    snap: &AuditSnapshot,
    max: usize,
) -> io::Result<()> {
    let path = audit_file_in(dir, alias)?;
    fs::create_dir_all(dir)?;
    let line = serde_json::to_string(snap).map_err(io::Error::other)? + "\n";
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        f.write_all(line.as_bytes())?;
    }
    if max > 0 {
        trim(&path, max)?;
    }
    Ok(())
}

/// Read the most recent `limit` audit snapshots (chronological) for a target
/// under `dir`. Missing file -> empty; unparseable lines skipped.
pub fn read_recent_audit_in(
    dir: &Path,
    alias: &str,
    limit: usize,
) -> io::Result<Vec<AuditSnapshot>> {
    let path = audit_file_in(dir, alias)?;
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut snaps: Vec<AuditSnapshot> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    if limit > 0 && snaps.len() > limit {
        snaps.drain(0..snaps.len() - limit);
    }
    Ok(snaps)
}

/// Read recent audit snapshots for a target from the default history directory.
pub fn read_recent_audit(alias: &str, limit: usize) -> io::Result<Vec<AuditSnapshot>> {
    read_recent_audit_in(&data_dir(), alias, limit)
}

/// Record each successful audit outcome to the default history directory
/// (best-effort; a storage error is logged, never fails the audit).
pub fn record_audit_outcomes(outcomes: &[AuditOutcome], store: bool) {
    if !store {
        return;
    }
    let (dir, max, ts) = (data_dir(), max_snapshots(), now_unix());
    for o in outcomes {
        if let Ok((score, findings)) = &o.result {
            let snap = AuditSnapshot::from_audit(score, findings, ts);
            if let Err(e) = record_audit_in(&dir, &o.alias, &snap, max) {
                tracing::warn!("could not record audit history for '{}': {e}", o.alias);
            }
        }
    }
}

/// A single check's status change between two audit snapshots.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FindingChange {
    pub id: String,
    pub from: Status,
    pub to: Status,
}

/// What changed between a previous audit snapshot and the current one.
#[derive(Debug, Clone, Serialize)]
pub struct AuditDiff {
    pub prev_ts: u64,
    pub profile: Profile,
    /// `true` if the two runs used different profiles (scores not comparable).
    pub profile_changed: bool,
    pub score_from: u8,
    pub score_to: u8,
    /// Checks that started failing (was not `fail`, now `fail`).
    pub regressions: Vec<FindingChange>,
    /// Checks that were fixed (was `fail`, now `pass`).
    pub fixes: Vec<FindingChange>,
    /// Any other status transition (e.g. pass->error, skipped->pass).
    pub other_changes: Vec<FindingChange>,
    /// Checks present now but not in the previous snapshot (e.g. tool upgraded).
    pub new_checks: usize,
    /// Checks present before but gone now.
    pub removed_checks: usize,
}

impl AuditDiff {
    /// `true` if nothing of substance changed (same score, no finding transitions).
    pub fn is_unchanged(&self) -> bool {
        self.score_from == self.score_to
            && self.regressions.is_empty()
            && self.fixes.is_empty()
            && self.other_changes.is_empty()
    }
}

/// Compute what changed from `prev` to `cur`.
pub fn audit_diff(prev: &AuditSnapshot, cur: &AuditSnapshot) -> AuditDiff {
    let (mut regressions, mut fixes, mut other) = (Vec::new(), Vec::new(), Vec::new());
    for (id, &to) in &cur.findings {
        match prev.findings.get(id) {
            Some(&from) if from != to => {
                let change = FindingChange {
                    id: id.clone(),
                    from,
                    to,
                };
                if to == Status::Fail {
                    regressions.push(change);
                } else if from == Status::Fail && to == Status::Pass {
                    fixes.push(change);
                } else {
                    other.push(change);
                }
            }
            _ => {}
        }
    }
    for v in [&mut regressions, &mut fixes, &mut other] {
        v.sort_by(|a, b| a.id.cmp(&b.id));
    }
    let new_checks = cur
        .findings
        .keys()
        .filter(|id| !prev.findings.contains_key(*id))
        .count();
    let removed_checks = prev
        .findings
        .keys()
        .filter(|id| !cur.findings.contains_key(*id))
        .count();
    AuditDiff {
        prev_ts: prev.ts,
        profile: cur.profile,
        profile_changed: prev.profile != cur.profile,
        score_from: prev.total,
        score_to: cur.total,
        regressions,
        fixes,
        other_changes: other,
        new_checks,
        removed_checks,
    }
}

/// Short status label for text rendering.
fn status_label(s: Status) -> &'static str {
    match s {
        Status::Pass => "pass",
        Status::Fail => "fail",
        Status::Error => "error",
        Status::Skipped => "skipped",
    }
}

/// Human-readable audit diff.
pub fn audit_diff_text(alias: &str, d: &AuditDiff) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let delta = i32::from(d.score_to) - i32::from(d.score_from);
    let _ = writeln!(
        out,
        "Audit changes for '{alias}' since {} ({}): score {} -> {} ({delta:+})",
        fmt_utc(d.prev_ts),
        d.profile_name(),
        d.score_from,
        d.score_to,
    );
    if d.profile_changed {
        let _ = writeln!(
            out,
            "  note: profile changed since the last run - scores are not comparable"
        );
    }
    if d.is_unchanged() {
        let _ = writeln!(out, "  no changes in findings.");
    }
    let mut section = |title: &str, changes: &[FindingChange]| {
        if !changes.is_empty() {
            let _ = writeln!(out, "  {title} ({}):", changes.len());
            for c in changes {
                let _ = writeln!(
                    out,
                    "    {}: {} -> {}",
                    c.id,
                    status_label(c.from),
                    status_label(c.to)
                );
            }
        }
    };
    section("regressions (now failing)", &d.regressions);
    section("fixes (now passing)", &d.fixes);
    section("other changes", &d.other_changes);
    if d.new_checks > 0 || d.removed_checks > 0 {
        let _ = writeln!(
            out,
            "  ({} check(s) added, {} removed since then)",
            d.new_checks, d.removed_checks
        );
    }
    out
}

impl AuditDiff {
    fn profile_name(&self) -> &'static str {
        match self.profile {
            Profile::Baseline => "baseline",
            Profile::Hardened => "hardened",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// A unique scratch directory (no `tempfile` dependency), removed on drop.
    /// Each test gets its own so they never race on a shared path.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("lah-hist-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn snap(ts: u64, la: f64) -> Snapshot {
        let mut metrics = BTreeMap::new();
        metrics.insert("health-load".to_string(), la);
        Snapshot {
            ts,
            overall: HealthStatus::Ok,
            metrics,
            containers: BTreeMap::new(),
            failed_units: Vec::new(),
        }
    }

    #[test]
    fn round_trips_and_preserves_order() {
        let d = TempDir::new();
        for i in 0..3 {
            record_in(d.path(), "web", &snap(1000 + i, i as f64), 0).unwrap();
        }
        let got = read_recent_in(d.path(), "web", 10).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].ts, 1000);
        assert_eq!(got[2].ts, 1002);
    }

    #[test]
    fn retention_keeps_newest() {
        let d = TempDir::new();
        for i in 0..10 {
            record_in(d.path(), "web", &snap(i, i as f64), 3).unwrap();
        }
        let got = read_recent_in(d.path(), "web", 100).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].ts, 7);
        assert_eq!(got[2].ts, 9);
    }

    #[test]
    fn read_limit_returns_newest() {
        let d = TempDir::new();
        for i in 0..10 {
            record_in(d.path(), "web", &snap(i, 0.0), 0).unwrap();
        }
        let got = read_recent_in(d.path(), "web", 2).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].ts, 8);
        assert_eq!(got[1].ts, 9);
    }

    #[test]
    fn missing_file_is_empty_not_error() {
        let d = TempDir::new();
        assert!(read_recent_in(d.path(), "nope", 10).unwrap().is_empty());
    }

    fn asnap(ts: u64, total: u8, findings: &[(&str, Status)]) -> AuditSnapshot {
        AuditSnapshot {
            ts,
            total,
            profile: Profile::Baseline,
            findings: findings.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        }
    }

    #[test]
    fn audit_snapshot_round_trips() {
        let d = TempDir::new();
        let s = asnap(1000, 79, &[("ssh-x", Status::Pass), ("fw-y", Status::Fail)]);
        record_audit_in(d.path(), "web", &s, 0).unwrap();
        let got = read_recent_audit_in(d.path(), "web", 10).unwrap();
        assert_eq!(got, vec![s]);
        // Health and audit files are separate (health read stays empty).
        assert!(read_recent_in(d.path(), "web", 10).unwrap().is_empty());
    }

    #[test]
    fn audit_diff_flags_regressions_fixes_and_delta() {
        let prev = asnap(
            100,
            79,
            &[
                ("ssh-weak-crypto", Status::Pass),
                ("accounts-umask", Status::Fail),
                ("firewall-enabled", Status::Pass),
            ],
        );
        let cur = asnap(
            200,
            61,
            &[
                ("ssh-weak-crypto", Status::Fail),  // regression
                ("accounts-umask", Status::Pass),   // fix
                ("firewall-enabled", Status::Pass), // unchanged
                ("kernel-new", Status::Pass),       // new check
            ],
        );
        let d = audit_diff(&prev, &cur);
        assert_eq!((d.score_from, d.score_to), (79, 61));
        assert_eq!(d.regressions.len(), 1);
        assert_eq!(d.regressions[0].id, "ssh-weak-crypto");
        assert_eq!(d.fixes.len(), 1);
        assert_eq!(d.fixes[0].id, "accounts-umask");
        assert_eq!(d.new_checks, 1);
        assert_eq!(d.removed_checks, 0);
        assert!(!d.is_unchanged());
        let text = audit_diff_text("web", &d);
        assert!(text.contains("79 -> 61 (-18)"), "{text}");
        assert!(text.contains("ssh-weak-crypto: pass -> fail"), "{text}");

        // Identical snapshot -> unchanged.
        let same = audit_diff(&prev, &prev);
        assert!(same.is_unchanged());
        assert!(audit_diff_text("web", &same).contains("no changes"));
    }

    #[test]
    fn rejects_unsafe_alias() {
        let d = TempDir::new();
        assert!(record_in(d.path(), "../evil", &snap(1, 0.0), 0).is_err());
        assert!(record_in(d.path(), "a/b", &snap(1, 0.0), 0).is_err());
        assert!(read_recent_in(d.path(), "..", 1).is_err());
        assert!(safe_alias("ok.host_1-2").is_ok());
    }

    #[test]
    fn skips_malformed_lines() {
        let d = TempDir::new();
        record_in(d.path(), "web", &snap(1, 0.0), 0).unwrap();
        let path = file_in(d.path(), "web").unwrap();
        let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"not json\n").unwrap();
        record_in(d.path(), "web", &snap(2, 0.0), 0).unwrap();
        let got = read_recent_in(d.path(), "web", 10).unwrap();
        assert_eq!(got.len(), 2); // the junk line is skipped, the two snapshots survive
    }

    #[test]
    fn round_trips_containers_and_failed_units() {
        let d = TempDir::new();
        let mut s = snap(1, 0.5);
        s.containers.insert("mtproxy".to_string(), 172_800);
        s.failed_units.push("nginx.service".to_string());
        record_in(d.path(), "web", &s, 0).unwrap();
        let got = read_recent_in(d.path(), "web", 10).unwrap();
        assert_eq!(got[0].containers.get("mtproxy"), Some(&172_800));
        assert_eq!(got[0].failed_units, vec!["nginx.service".to_string()]);
    }

    #[test]
    fn pre_0_16_snapshot_without_new_fields_defaults_empty() {
        let d = TempDir::new();
        let path = file_in(d.path(), "web").unwrap();
        fs::create_dir_all(d.path()).unwrap();
        // A snapshot line from before the containers/failed_units fields existed.
        fs::write(
            &path,
            "{\"ts\":1,\"overall\":\"ok\",\"metrics\":{\"health-load\":0.5}}\n",
        )
        .unwrap();
        let got = read_recent_in(d.path(), "web", 10).unwrap();
        assert_eq!(got.len(), 1);
        assert!(got[0].containers.is_empty());
        assert!(got[0].failed_units.is_empty());
    }

    #[test]
    fn from_report_extracts_numerics() {
        let report = crate::health::evaluate(
            &[("uptime", "load average: 2.0, 1.0, 1.0"), ("nproc", "2")]
                .iter()
                .map(|(k, v)| (*k, Ok(v.to_string())))
                .collect(),
            &crate::health::Thresholds::default(),
        );
        let s = Snapshot::from_report(&report, 42);
        assert_eq!(s.ts, 42);
        assert_eq!(s.metrics.get("health-load"), Some(&1.0)); // 2.0 over 2 cores
        assert!(!s.metrics.contains_key("health-disk")); // unknown -> absent
    }

    #[test]
    fn fmt_utc_known_epochs() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00:00Z");
        // 2021-07-19 12:00:00 UTC
        assert_eq!(fmt_utc(1_626_696_000), "2021-07-19 12:00:00Z");
    }

    #[test]
    fn text_and_json_render() {
        let snaps = vec![snap(0, 0.5), snap(3600, 1.5)];
        let t = text("web", &snaps);
        assert!(t.contains("web"));
        assert!(t.contains("load"));
        assert!(t.contains("1970-01-01"));
        let j = json("web", &snaps).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["kind"], "health-history");
        assert_eq!(v["count"], 2);
        assert_eq!(v["snapshots"][1]["ts"], 3600);
    }

    #[test]
    fn empty_history_text_is_clear() {
        assert!(text("web", &[]).contains("No health history"));
    }
}
