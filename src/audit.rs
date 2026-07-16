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
        .map(|check| match &outputs[check.command()] {
            Ok(output) => {
                let outcome = check.evaluate(output);
                Finding {
                    id: check.id(),
                    domain: check.domain(),
                    title: check.title(),
                    severity: check.severity(),
                    status: outcome.status,
                    detail: outcome.detail,
                    recommendation: check.recommendation(),
                }
            }
            Err(err) => Finding {
                id: check.id(),
                domain: check.domain(),
                title: check.title(),
                severity: check.severity(),
                status: Status::Error,
                detail: err.clone(),
                recommendation: check.recommendation(),
            },
        })
        .collect()
}

/// Run every check against `ssh` and collect findings.
///
/// Host-level failures (auth, connection, timeout) abort the whole audit.
/// A per-command remote failure (ssh connected but the command errored) is
/// recorded as an `Error` finding for the checks that needed it; the rest run.
pub async fn run_audit(ssh: &SshConfig) -> Result<Vec<Finding>, SshError> {
    // Snap each distinct command exactly once.
    let mut outputs: Outputs = HashMap::new();
    for check in &all_checks() {
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
