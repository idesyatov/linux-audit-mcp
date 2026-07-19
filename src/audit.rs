//! Audit engine: run each check's command once (cached), then evaluate.

use std::collections::HashMap;

use crate::checks::{all_checks, Finding, Status};
use crate::ssh::{SshConfig, SshError};

/// Command output collected once per distinct command: `Ok` stdout, or `Err`
/// with a message when the command ran but failed on the host.
pub type Outputs = HashMap<&'static str, Result<String, String>>;

/// Build findings by evaluating every check against pre-collected command
/// outputs. Pure (no I/O): shared by [`run_audit`] and later-stage evals. An
/// `Err` output becomes an `Error` finding for every check that needs it.
pub fn evaluate(outputs: &Outputs) -> Vec<Finding> {
    all_checks()
        .iter()
        .map(|check| {
            // A command absent from `outputs` was never collected - i.e. a
            // privileged check on a target that isn't opted in -> Skipped.
            let (status, detail) = match outputs.get(check.command()) {
                Some(Ok(output)) => {
                    let o = check.evaluate(output);
                    (o.status, o.detail)
                }
                Some(Err(err)) => (Status::Error, err.clone()),
                None => (
                    Status::Skipped,
                    "privileged check not enabled for this target".to_string(),
                ),
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
        if check.privileged() && !privileged {
            continue;
        }
        let cmd = check.command();
        if outputs.contains_key(cmd) {
            continue;
        }
        match ssh.run(cmd).await {
            Ok(out) => {
                outputs.insert(cmd, Ok(out.stdout));
            }
            Err(SshError::RemoteCommand { code, stderr }) => {
                outputs.insert(
                    cmd,
                    Err(format!("remote command failed (code {code:?}): {stderr}")),
                );
            }
            Err(host_level) => return Err(host_level),
        }
    }

    Ok(evaluate(&outputs))
}
