//! SSH-domain checks (parsing `/etc/ssh/sshd_config`).
//!
//! Each check applies the OpenSSH built-in default when a directive is absent,
//! so a stock config is judged the way sshd would actually behave. Match blocks
//! are not considered when reading the file (see [`super::parse::parse_sshd_config`]).
//!
//! On a target opted in with `privileged = true`, every check upgrades to the
//! *effective* config from `sudo -n sshd -T` (compiled defaults + Match blocks
//! resolved), which supersedes the file read - see
//! [`Check::effective_command`](super::Check::effective_command). The same
//! keyword parser handles both, since `sshd -T` emits `key value` lines.

use super::parse::parse_sshd_config;
use super::{Check, Domain, Outcome, Severity};

const SSHD_CMD: &str = "cat /etc/ssh/sshd_config";
/// Effective config on privileged targets; supersedes [`SSHD_CMD`].
const SSHD_EFFECTIVE_CMD: &str = "sudo -n sshd -T";

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
    fn effective_command(&self) -> Option<&'static str> {
        Some(SSHD_EFFECTIVE_CMD)
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
    fn effective_command(&self) -> Option<&'static str> {
        Some(SSHD_EFFECTIVE_CMD)
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
    fn effective_command(&self) -> Option<&'static str> {
        Some(SSHD_EFFECTIVE_CMD)
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
    fn effective_command(&self) -> Option<&'static str> {
        Some(SSHD_EFFECTIVE_CMD)
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
    fn effective_command(&self) -> Option<&'static str> {
        Some(SSHD_EFFECTIVE_CMD)
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

/// Substrings marking a weak SSH algorithm across ciphers, MACs and key
/// exchange. Case-insensitive; matched against each comma-separated token of
/// `Ciphers`, `MACs` and `KexAlgorithms`. Because cipher/MAC/kex names don't
/// share these fragments, one combined set is safe (a cipher never contains
/// `sha1`, a MAC never contains `-cbc`, etc.).
const WEAK_ALGO_MARKERS: &[&str] = &[
    // ciphers
    "-cbc",
    "arcfour",
    "3des",
    "rc4",
    "blowfish",
    "cast128",
    // MACs
    "md5",
    "sha1",
    "-96",
    "umac-64",
    // key exchange
    "group1-sha1",
    "group-exchange-sha1",
    "gss-",
    "rsa1024",
];

/// Weak SSH ciphers/MACs/key-exchange algorithms are configured. On an
/// unprivileged target only what's *explicitly* set in sshd_config is judged, so
/// an absent directive passes (the effective set - compiled defaults + `Match`
/// blocks - isn't visible without root). On a `privileged` target the check reads
/// `sshd -T`, so the effective algorithm list is judged directly.
pub struct WeakCrypto;

impl WeakCrypto {
    /// Weak tokens across the three algorithm directives. A leading `-` value
    /// (`Ciphers -*-cbc`) *removes* algorithms from the defaults, which is
    /// hardening, so it is never flagged; `+`/`^` (add/prepend) are still judged.
    fn weak_tokens(output: &str) -> Vec<String> {
        let cfg = parse_sshd_config(output);
        let mut weak = Vec::new();
        for key in ["ciphers", "macs", "kexalgorithms"] {
            let Some(val) = cfg.get(key) else { continue };
            let val = val.trim();
            if val.starts_with('-') {
                continue; // removing algorithms from the default set
            }
            let val = val.strip_prefix(['+', '^']).unwrap_or(val);
            for tok in val.split(',').map(|t| t.trim().to_ascii_lowercase()) {
                if !tok.is_empty() && WEAK_ALGO_MARKERS.iter().any(|m| tok.contains(m)) {
                    weak.push(tok);
                }
            }
        }
        weak
    }
}

impl Check for WeakCrypto {
    fn id(&self) -> &'static str {
        "ssh-weak-crypto"
    }
    fn domain(&self) -> Domain {
        Domain::Ssh
    }
    fn title(&self) -> &'static str {
        "Weak SSH ciphers/MACs/key exchange"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn recommendation(&self) -> &'static str {
        "Remove legacy algorithms (CBC ciphers, arcfour/3DES, HMAC-MD5/SHA1, \
         DH-group1/14-SHA1) from Ciphers/MACs/KexAlgorithms."
    }
    fn command(&self) -> &'static str {
        SSHD_CMD
    }
    fn effective_command(&self) -> Option<&'static str> {
        Some(SSHD_EFFECTIVE_CMD)
    }
    fn evaluate(&self, output: &str) -> Outcome {
        let weak = Self::weak_tokens(output);
        if weak.is_empty() {
            Outcome::pass("No weak SSH algorithms configured.")
        } else {
            Outcome::fail(format!(
                "Weak SSH algorithms configured: {}.",
                weak.join(", ")
            ))
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
        MaxAuthTries 3\n\
        Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com\n\
        MACs hmac-sha2-512-etm@openssh.com\n\
        KexAlgorithms curve25519-sha256\n";

    const OPEN: &str = "PermitRootLogin yes\n\
        PasswordAuthentication yes\n\
        PermitEmptyPasswords yes\n\
        X11Forwarding yes\n\
        MaxAuthTries 10\n\
        Ciphers aes256-ctr,aes128-cbc,3des-cbc\n\
        MACs hmac-sha2-256,hmac-md5\n\
        KexAlgorithms curve25519-sha256,diffie-hellman-group1-sha1\n";

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

    #[test]
    fn weak_crypto() {
        assert_eq!(WeakCrypto.evaluate(HARDENED).status, Status::Pass);
        assert_eq!(WeakCrypto.evaluate(OPEN).status, Status::Fail);
        // Unset directives -> pass (effective set needs root/sshd -T).
        assert_eq!(WeakCrypto.evaluate(DEFAULTS).status, Status::Pass);
        // A leading `-` value removes weak algos from the defaults -> not flagged.
        assert_eq!(
            WeakCrypto.evaluate("Ciphers -aes128-cbc,3des-cbc\n").status,
            Status::Pass
        );
        // The detail names the offending algorithms.
        let d = WeakCrypto.evaluate(OPEN).detail;
        assert!(d.contains("aes128-cbc") && d.contains("hmac-md5"), "{d}");
    }
}
