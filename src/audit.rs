//! Audit engine: run each check's command once (cached), then evaluate.

use std::collections::HashMap;

use crate::checks::{all_checks, Finding, Status};
use crate::ssh::{SshConfig, SshError};

/// Command output collected once per distinct command: `Ok` stdout, or `Err`
/// with a message when the command ran but failed on the host.
pub type Outputs = HashMap<&'static str, Result<String, String>>;

/// Build findings by evaluating every check against pre-collected command
/// outputs. Pure (no I/O): shared by [`run_audit`] and the evals. An `Err`
/// output becomes an `Error` finding for every check that needs it.
///
/// `privileged` mirrors the target's opt-in: when set, a check's
/// [`effective_command`](crate::checks::Check::effective_command) output (e.g.
/// `sshd -T`) supersedes its normal command if it was collected successfully;
/// otherwise the check falls back to its normal command, so the audit is robust
/// when the sudo grant is missing.
pub fn evaluate(outputs: &Outputs, privileged: bool) -> Vec<Finding> {
    all_checks()
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
                    Some(Err(err)) => (Status::Error, err.clone()),
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
pub async fn run_audit(ssh: &SshConfig, privileged: bool) -> Result<Vec<Finding>, SshError> {
    // Snap each distinct command exactly once.
    let mut outputs: Outputs = HashMap::new();
    for check in &all_checks() {
        // Never send a privileged command to a target that didn't opt in.
        if !(check.privileged() && !privileged) {
            snap(ssh, &mut outputs, check.command()).await?;
        }
        // The effective (privileged) source is only sent to opted-in targets; if
        // its sudo grant is missing the command errors and the check falls back.
        if privileged {
            if let Some(cmd) = check.effective_command() {
                snap(ssh, &mut outputs, cmd).await?;
            }
        }
    }

    Ok(evaluate(&outputs, privileged))
}

/// Run `cmd` once (dedup by command) and record its output: `Ok` stdout, or an
/// `Err` message when it connected but the command failed. Host-level failures
/// (auth, connection, timeout) abort the whole audit.
async fn snap(ssh: &SshConfig, outputs: &mut Outputs, cmd: &'static str) -> Result<(), SshError> {
    if outputs.contains_key(cmd) {
        return Ok(());
    }
    match ssh.run(cmd).await {
        Ok(out) => {
            outputs.insert(cmd, Ok(out.stdout));
        }
        // A command that connected but failed becomes an Error finding; reuse the
        // error's own Display so the message never drifts from `SshError`.
        Err(e @ SshError::RemoteCommand { .. }) => {
            outputs.insert(cmd, Err(e.to_string()));
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
        outputs.insert(SSHD_EFFECTIVE, Err("no sudo".to_string()));

        let findings = evaluate(&outputs, true);
        assert_eq!(status_of(&findings, "ssh-weak-crypto"), &Status::Fail);
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
