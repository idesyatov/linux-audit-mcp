//! Audit engine: run each check's command once (cached), then evaluate.

use std::collections::HashMap;

use crate::checks::{selected_checks, Check, CheckFilter, Finding, Status};
use crate::ssh::{SshConfig, SshError};

/// Why a command produced no usable output. `not_found` marks "the tool isn't
/// installed on this host" (remote exit 127), as opposed to a genuine runtime
/// failure; a package-manager check ([`Check::skip_if_tool_missing`]) uses it to
/// skip (not applicable) rather than error.
#[derive(Debug, Clone)]
pub struct CmdError {
    pub message: String,
    pub not_found: bool,
}

impl CmdError {
    /// A failure that is not a missing tool (the common case).
    pub fn other(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            not_found: false,
        }
    }
}

/// Command output collected once per distinct command: `Ok` stdout, or `Err`
/// with a [`CmdError`] when the command ran but failed on the host.
pub type Outputs = HashMap<&'static str, Result<String, CmdError>>;

/// Build findings by evaluating every check against pre-collected command
/// outputs. Pure (no I/O): shared by [`run_audit`] and the evals. An `Err`
/// output becomes an `Error` finding for every check that needs it.
///
/// `privileged` mirrors the target's opt-in: when set, a check's
/// [`effective_command`](crate::checks::Check::effective_command) output (e.g.
/// `sshd -T`) supersedes its normal command if it was collected successfully;
/// otherwise the check falls back to its normal command, so the audit is robust
/// when the sudo grant is missing.
///
/// The full-catalog convenience wrapper (used by the evals and unit tests); the
/// run path uses [`evaluate_with`] over the [`CheckFilter`]-selected subset.
#[cfg(test)]
pub fn evaluate(outputs: &Outputs, privileged: bool) -> Vec<Finding> {
    evaluate_with(&crate::checks::all_checks(), outputs, privileged)
}

/// Like [`evaluate`], but over an explicit check list (e.g. the subset selected
/// by a [`CheckFilter`]). Only these checks produce findings, so a filtered-out
/// check is simply absent rather than reported as skipped.
pub fn evaluate_with(
    checks: &[Box<dyn Check>],
    outputs: &Outputs,
    privileged: bool,
) -> Vec<Finding> {
    checks
        .iter()
        .map(|check| {
            // On an opted-in target, prefer the effective (privileged) source
            // when it succeeded; fall back to the normal command otherwise.
            let effective = check
                .effective_command()
                .filter(|_| privileged)
                .and_then(|cmd| match outputs.get(cmd) {
                    Some(Ok(output)) => Some(output.as_str()),
                    _ => None,
                });

            // A command absent from `outputs` was never collected - i.e. a
            // privileged check on a target that isn't opted in -> Skipped.
            let (status, detail) = match effective {
                Some(output) => {
                    let o = check.evaluate(output);
                    (o.status, o.detail)
                }
                None => match outputs.get(check.command()) {
                    Some(Ok(output)) => {
                        let o = check.evaluate(output);
                        (o.status, o.detail)
                    }
                    // A missing package-manager tool (apt on RHEL, dnf on Debian)
                    // is "not applicable" for that check, not a failure -> Skipped.
                    Some(Err(err)) if err.not_found && check.skip_if_tool_missing() => (
                        Status::Skipped,
                        format!(
                            "{} is not installed on this host; check not applicable.",
                            check.command().split_whitespace().next().unwrap_or("tool"),
                        ),
                    ),
                    Some(Err(err)) => (Status::Error, err.message.clone()),
                    None => (
                        Status::Skipped,
                        "privileged check not enabled for this target".to_string(),
                    ),
                },
            };
            Finding {
                id: check.id(),
                domain: check.domain(),
                title: check.title(),
                severity: check.severity(),
                status,
                detail,
                recommendation: check.recommendation(),
            }
        })
        .collect()
}

/// Run every check against `ssh` and collect findings. `privileged` gates the
/// `sudo -n ...` checks: when `false` their commands are never sent and they are
/// reported as [`Status::Skipped`].
///
/// Host-level failures (auth, connection, timeout) abort the whole audit.
/// A per-command remote failure (ssh connected but the command errored) is
/// recorded as an `Error` finding for the checks that needed it; the rest run.
pub async fn run_audit(
    ssh: &SshConfig,
    privileged: bool,
    filter: &CheckFilter,
) -> Result<Vec<Finding>, SshError> {
    let checks = selected_checks(filter);
    // Snap each distinct command exactly once, only for the selected checks.
    let mut outputs: Outputs = HashMap::new();
    for check in &checks {
        // Never send a privileged command to a target that didn't opt in.
        if !(check.privileged() && !privileged) {
            snap(
                ssh,
                &mut outputs,
                check.command(),
                check.tolerate_nonzero_exit(),
            )
            .await?;
        }
        // The effective (privileged) source is only sent to opted-in targets; if
        // its sudo grant is missing the command errors and the check falls back.
        if privileged {
            if let Some(cmd) = check.effective_command() {
                snap(ssh, &mut outputs, cmd, false).await?;
            }
        }
    }

    Ok(evaluate_with(&checks, &outputs, privileged))
}

/// Run `cmd` once (dedup by command) and record its output: `Ok` stdout, or an
/// `Err` message when it connected but the command failed. Host-level failures
/// (auth, connection, timeout) abort the whole audit. When `tolerate_nonzero` is
/// set, a non-zero exit still records the command's (partial) stdout as `Ok` -
/// for whole-filesystem scans whose exit reflects a transient per-path error.
async fn snap(
    ssh: &SshConfig,
    outputs: &mut Outputs,
    cmd: &'static str,
    tolerate_nonzero: bool,
) -> Result<(), SshError> {
    if outputs.contains_key(cmd) {
        return Ok(());
    }
    match ssh.run(cmd).await {
        Ok(out) => {
            outputs.insert(cmd, Ok(out.stdout));
        }
        // A check that opts into tolerating a non-zero exit keeps the partial
        // stdout (e.g. `find /` that raced a transient per-path error).
        Err(SshError::RemoteCommand { stdout, .. }) if tolerate_nonzero => {
            outputs.insert(cmd, Ok(stdout));
        }
        // A command that connected but failed becomes an Error finding; reuse the
        // error's own Display so the message never drifts from `SshError`. Exit
        // 127 ("command not found") means the tool isn't installed, which a
        // package-manager check turns into a Skipped (not-applicable) result.
        Err(e @ SshError::RemoteCommand { .. }) => {
            let not_found = matches!(
                e,
                SshError::RemoteCommand {
                    code: Some(127),
                    ..
                }
            );
            outputs.insert(
                cmd,
                Err(CmdError {
                    message: e.to_string(),
                    not_found,
                }),
            );
        }
        Err(host_level) => return Err(host_level),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Status;

    const SSHD_CMD: &str = "cat /etc/ssh/sshd_config";
    const SSHD_EFFECTIVE: &str = "sudo -n sshd -T";

    fn status_of<'a>(findings: &'a [Finding], id: &str) -> &'a Status {
        &findings.iter().find(|f| f.id == id).unwrap().status
    }

    // A weak file config that ssh-weak-crypto flags, and an effective config
    // (as `sshd -T` would print) with no weak algorithms.
    const WEAK_FILE: &str = "Ciphers aes128-cbc,3des-cbc\n";
    const STRONG_EFFECTIVE: &str =
        "ciphers aes256-gcm@openssh.com\nmacs hmac-sha2-256-etm@openssh.com\n";

    #[test]
    fn effective_source_supersedes_file_when_privileged() {
        let mut outputs: Outputs = HashMap::new();
        outputs.insert(SSHD_CMD, Ok(WEAK_FILE.to_string()));
        outputs.insert(SSHD_EFFECTIVE, Ok(STRONG_EFFECTIVE.to_string()));

        // Privileged: the effective (strong) config wins -> pass.
        let priv_findings = evaluate(&outputs, true);
        assert_eq!(status_of(&priv_findings, "ssh-weak-crypto"), &Status::Pass);

        // Unprivileged: the file (weak) is judged -> fail.
        let unpriv_findings = evaluate(&outputs, false);
        assert_eq!(
            status_of(&unpriv_findings, "ssh-weak-crypto"),
            &Status::Fail
        );
    }

    #[test]
    fn falls_back_to_file_when_effective_command_failed() {
        // Opted in, but `sshd -T` errored (no sudo grant): fall back to the file.
        let mut outputs: Outputs = HashMap::new();
        outputs.insert(SSHD_CMD, Ok(WEAK_FILE.to_string()));
        outputs.insert(SSHD_EFFECTIVE, Err(CmdError::other("no sudo")));

        let findings = evaluate(&outputs, true);
        assert_eq!(status_of(&findings, "ssh-weak-crypto"), &Status::Fail);
    }

    #[test]
    fn missing_tool_skips_package_manager_check() {
        // apt-get absent (exit 127) -> the apt check is Skipped, not Error.
        let mut outputs: Outputs = HashMap::new();
        outputs.insert(
            "apt-get -s upgrade",
            Err(CmdError {
                message: "remote command failed (code Some(127)): apt-get: not found".to_string(),
                not_found: true,
            }),
        );
        let findings = evaluate(&outputs, false);
        assert_eq!(
            status_of(&findings, "updates-security-pending"),
            &Status::Skipped
        );
    }

    #[test]
    fn present_tool_that_fails_still_errors() {
        // apt-get present but failed (e.g. dpkg lock) -> genuine Error, not skip.
        let mut outputs: Outputs = HashMap::new();
        outputs.insert("apt-get -s upgrade", Err(CmdError::other("dpkg is locked")));
        let findings = evaluate(&outputs, false);
        assert_eq!(
            status_of(&findings, "updates-security-pending"),
            &Status::Error
        );
    }

    #[test]
    fn privileged_check_absent_is_skipped() {
        // No shadow output collected -> the privileged check is Skipped, not Error.
        let outputs: Outputs = HashMap::new();
        let findings = evaluate(&outputs, false);
        assert_eq!(
            status_of(&findings, "accounts-shadow-empty-password"),
            &Status::Skipped
        );
    }
}
