//! SSH-domain checks (parsing `/etc/ssh/sshd_config`).
//!
//! Each check applies the OpenSSH built-in default when a directive is absent,
//! so a stock config is judged the way sshd would actually behave. Match blocks
//! are not considered (see [`super::parse::parse_sshd_config`]).

use super::parse::parse_sshd_config;
use super::{Check, Domain, Outcome, Severity};

const SSHD_CMD: &str = "cat /etc/ssh/sshd_config";

/// Value of `key` from sshd_config, falling back to sshd's built-in `default`.
/// Returned lowercased for case-insensitive comparison.
fn directive(output: &str, key: &str, default: &str) -> String {
    parse_sshd_config(output)
        .get(key)
        .map(String::as_str)
        .unwrap_or(default)
        .to_ascii_lowercase()
}

/// Root can authenticate over SSH (`PermitRootLogin` is not `no`).
pub struct PermitRootLogin;

impl Check for PermitRootLogin {
    fn id(&self) -> &'static str {
        "ssh-permit-root-login"
    }
    fn domain(&self) -> Domain {
        Domain::Ssh
    }
    fn title(&self) -> &'static str {
        "Root login over SSH"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn recommendation(&self) -> &'static str {
        "Set PermitRootLogin no; administer via an unprivileged account and sudo."
    }
    fn command(&self) -> &'static str {
        SSHD_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        // OpenSSH default is prohibit-password; we require an explicit `no`.
        let v = directive(output, "permitrootlogin", "prohibit-password");
        if v == "no" {
            Outcome::pass("PermitRootLogin is no.")
        } else {
            Outcome::fail(format!(
                "PermitRootLogin is '{v}' (root can log in over SSH)."
            ))
        }
    }
}

/// Password authentication is enabled (`PasswordAuthentication` is not `no`).
pub struct PasswordAuthentication;

impl Check for PasswordAuthentication {
    fn id(&self) -> &'static str {
        "ssh-password-authentication"
    }
    fn domain(&self) -> Domain {
        Domain::Ssh
    }
    fn title(&self) -> &'static str {
        "Password authentication over SSH"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn recommendation(&self) -> &'static str {
        "Set PasswordAuthentication no and authenticate with SSH keys only."
    }
    fn command(&self) -> &'static str {
        SSHD_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        // OpenSSH default is yes.
        let v = directive(output, "passwordauthentication", "yes");
        if v == "no" {
            Outcome::pass("PasswordAuthentication is no.")
        } else {
            Outcome::fail(format!(
                "PasswordAuthentication is '{v}' (brute-forceable credentials)."
            ))
        }
    }
}

/// Empty passwords are accepted (`PermitEmptyPasswords yes`).
pub struct PermitEmptyPasswords;

impl Check for PermitEmptyPasswords {
    fn id(&self) -> &'static str {
        "ssh-permit-empty-passwords"
    }
    fn domain(&self) -> Domain {
        Domain::Ssh
    }
    fn title(&self) -> &'static str {
        "Empty passwords permitted over SSH"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn recommendation(&self) -> &'static str {
        "Set PermitEmptyPasswords no."
    }
    fn command(&self) -> &'static str {
        SSHD_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        // OpenSSH default is no.
        let v = directive(output, "permitemptypasswords", "no");
        if v == "yes" {
            Outcome::fail("PermitEmptyPasswords is yes (accounts without a password can log in).")
        } else {
            Outcome::pass("PermitEmptyPasswords is no.")
        }
    }
}

/// X11 forwarding is enabled (`X11Forwarding yes`).
pub struct X11Forwarding;

impl Check for X11Forwarding {
    fn id(&self) -> &'static str {
        "ssh-x11-forwarding"
    }
    fn domain(&self) -> Domain {
        Domain::Ssh
    }
    fn title(&self) -> &'static str {
        "X11 forwarding enabled"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn recommendation(&self) -> &'static str {
        "Disable it unless required: X11Forwarding no."
    }
    fn command(&self) -> &'static str {
        SSHD_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        // OpenSSH default is no.
        let v = directive(output, "x11forwarding", "no");
        if v == "yes" {
            Outcome::fail("X11Forwarding is yes (enlarges the attack surface).")
        } else {
            Outcome::pass("X11Forwarding is no.")
        }
    }
}

/// `MaxAuthTries` allows too many authentication attempts per connection.
pub struct MaxAuthTries;

impl Check for MaxAuthTries {
    fn id(&self) -> &'static str {
        "ssh-max-auth-tries"
    }
    fn domain(&self) -> Domain {
        Domain::Ssh
    }
    fn title(&self) -> &'static str {
        "SSH MaxAuthTries too high"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn recommendation(&self) -> &'static str {
        "Lower it to slow brute-force attempts: MaxAuthTries 4 (or less)."
    }
    fn command(&self) -> &'static str {
        SSHD_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        // OpenSSH default is 6.
        let v = directive(output, "maxauthtries", "6");
        match v.parse::<u32>() {
            Ok(n) if n <= 4 => Outcome::pass(format!("MaxAuthTries is {n}.")),
            Ok(n) => Outcome::fail(format!("MaxAuthTries is {n} (recommended 4 or less).")),
            Err(_) => Outcome::fail(format!("MaxAuthTries is not a number: {v:?}.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Status;
    use super::*;

    const HARDENED: &str = "PermitRootLogin no\n\
        PasswordAuthentication no\n\
        PermitEmptyPasswords no\n\
        X11Forwarding no\n\
        MaxAuthTries 3\n";

    const OPEN: &str = "PermitRootLogin yes\n\
        PasswordAuthentication yes\n\
        PermitEmptyPasswords yes\n\
        X11Forwarding yes\n\
        MaxAuthTries 10\n";

    // Only comments: every directive falls back to its OpenSSH default.
    const DEFAULTS: &str = "# stock config\n";

    #[test]
    fn permit_root_login() {
        assert_eq!(PermitRootLogin.evaluate(HARDENED).status, Status::Pass);
        assert_eq!(PermitRootLogin.evaluate(OPEN).status, Status::Fail);
        // Default prohibit-password is not an explicit `no`.
        assert_eq!(PermitRootLogin.evaluate(DEFAULTS).status, Status::Fail);
    }

    #[test]
    fn password_authentication() {
        assert_eq!(
            PasswordAuthentication.evaluate(HARDENED).status,
            Status::Pass
        );
        assert_eq!(PasswordAuthentication.evaluate(OPEN).status, Status::Fail);
        // Default is yes.
        assert_eq!(
            PasswordAuthentication.evaluate(DEFAULTS).status,
            Status::Fail
        );
    }

    #[test]
    fn permit_empty_passwords() {
        assert_eq!(PermitEmptyPasswords.evaluate(HARDENED).status, Status::Pass);
        assert_eq!(PermitEmptyPasswords.evaluate(OPEN).status, Status::Fail);
        // Default is no.
        assert_eq!(PermitEmptyPasswords.evaluate(DEFAULTS).status, Status::Pass);
    }

    #[test]
    fn x11_forwarding() {
        assert_eq!(X11Forwarding.evaluate(HARDENED).status, Status::Pass);
        assert_eq!(X11Forwarding.evaluate(OPEN).status, Status::Fail);
        // Default is no.
        assert_eq!(X11Forwarding.evaluate(DEFAULTS).status, Status::Pass);
    }

    #[test]
    fn max_auth_tries() {
        assert_eq!(MaxAuthTries.evaluate(HARDENED).status, Status::Pass);
        assert_eq!(MaxAuthTries.evaluate(OPEN).status, Status::Fail);
        // Default is 6 (> 4).
        assert_eq!(MaxAuthTries.evaluate(DEFAULTS).status, Status::Fail);
    }
}
