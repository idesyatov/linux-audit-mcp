//! Accounts-domain checks (`getent passwd`, `/etc/login.defs`).

use super::parse::{parse_keyword_map, parse_passwd, shadow_empty_password_accounts};
use super::{Check, Domain, Outcome, Severity};

const PASSWD_CMD: &str = "getent passwd";
const LOGIN_DEFS_CMD: &str = "cat /etc/login.defs";
/// Root-only: `/etc/shadow` is unreadable to unprivileged users.
const SHADOW_CMD: &str = "sudo -n cat /etc/shadow";

/// An account other than `root` has UID 0 (a hidden superuser).
pub struct NonRootUid0;

impl Check for NonRootUid0 {
    fn id(&self) -> &'static str {
        "accounts-nonroot-uid0"
    }
    fn domain(&self) -> Domain {
        Domain::Accounts
    }
    fn title(&self) -> &'static str {
        "Non-root account with UID 0"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn recommendation(&self) -> &'static str {
        "Only `root` should have UID 0. Investigate and remove or re-number any other UID-0 account."
    }
    fn command(&self) -> &'static str {
        PASSWD_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        let extra: Vec<String> = parse_passwd(output)
            .into_iter()
            .filter(|e| e.uid == 0 && e.name != "root")
            .map(|e| e.name)
            .collect();
        if extra.is_empty() {
            Outcome::pass("Only root has UID 0.")
        } else {
            Outcome::fail(format!(
                "Accounts with UID 0 besides root: {}.",
                extra.join(", ")
            ))
        }
    }
}

/// Password expiry policy is missing or too long (`PASS_MAX_DAYS`).
pub struct PassMaxDays;

impl Check for PassMaxDays {
    fn id(&self) -> &'static str {
        "accounts-pass-max-days"
    }
    fn domain(&self) -> Domain {
        Domain::Accounts
    }
    fn title(&self) -> &'static str {
        "Password expiry policy too weak"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn recommendation(&self) -> &'static str {
        "Set PASS_MAX_DAYS to 365 or less in /etc/login.defs."
    }
    fn command(&self) -> &'static str {
        LOGIN_DEFS_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        match parse_keyword_map(output)
            .get("pass_max_days")
            .and_then(|v| v.parse::<u32>().ok())
        {
            Some(days) if days <= 365 => Outcome::pass(format!("PASS_MAX_DAYS is {days}.")),
            Some(days) => Outcome::fail(format!(
                "PASS_MAX_DAYS is {days} (recommended 365 or less)."
            )),
            None => Outcome::fail("PASS_MAX_DAYS is not set (passwords never expire)."),
        }
    }
}

/// The default `UMASK` leaves files readable by group/other.
pub struct DefaultUmask;

impl Check for DefaultUmask {
    fn id(&self) -> &'static str {
        "accounts-umask"
    }
    fn domain(&self) -> Domain {
        Domain::Accounts
    }
    fn title(&self) -> &'static str {
        "Weak default UMASK"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn recommendation(&self) -> &'static str {
        "Set UMASK 027 (or 077) in /etc/login.defs so new files aren't world/group-readable."
    }
    fn command(&self) -> &'static str {
        LOGIN_DEFS_CMD
    }
    fn evaluate(&self, output: &str) -> Outcome {
        // Default UMASK if unset is the permissive 022.
        let raw = parse_keyword_map(output)
            .get("umask")
            .cloned()
            .unwrap_or_else(|| "022".to_string());
        match u32::from_str_radix(raw.trim(), 8) {
            // Group and other must have no access -> those bits set in the mask.
            Ok(mask) if mask & 0o027 == 0o027 => Outcome::pass(format!("UMASK is {raw}.")),
            Ok(_) => Outcome::fail(format!("UMASK is {raw} (too permissive; use 027 or 077).")),
            Err(_) => Outcome::fail(format!("UMASK is not octal: {raw:?}.")),
        }
    }
}

/// An account has an empty password field in `/etc/shadow` - it can log in with
/// no password at all. Privileged: `/etc/shadow` is root-only, read via `sudo`.
pub struct ShadowEmptyPassword;

impl Check for ShadowEmptyPassword {
    fn id(&self) -> &'static str {
        "accounts-shadow-empty-password"
    }
    fn domain(&self) -> Domain {
        Domain::Accounts
    }
    fn title(&self) -> &'static str {
        "Account with an empty password"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn recommendation(&self) -> &'static str {
        "Lock or set a password for any account with an empty /etc/shadow field: passwd -l <user>."
    }
    fn command(&self) -> &'static str {
        SHADOW_CMD
    }
    fn privileged(&self) -> bool {
        true
    }
    fn evaluate(&self, output: &str) -> Outcome {
        let empty = shadow_empty_password_accounts(output);
        if empty.is_empty() {
            Outcome::pass("No accounts have an empty password.")
        } else {
            Outcome::fail(format!(
                "Accounts with an empty password: {}.",
                empty.join(", ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Status;
    use super::*;

    #[test]
    fn nonroot_uid0() {
        let clean = "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n";
        let bad = "root:x:0:0::/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/bash\n";
        assert_eq!(NonRootUid0.evaluate(clean).status, Status::Pass);
        assert_eq!(NonRootUid0.evaluate(bad).status, Status::Fail);
    }

    #[test]
    fn pass_max_days() {
        assert_eq!(
            PassMaxDays.evaluate("PASS_MAX_DAYS 90\n").status,
            Status::Pass
        );
        assert_eq!(
            PassMaxDays.evaluate("PASS_MAX_DAYS 99999\n").status,
            Status::Fail
        );
        assert_eq!(PassMaxDays.evaluate("# nothing\n").status, Status::Fail);
    }

    #[test]
    fn default_umask() {
        assert_eq!(DefaultUmask.evaluate("UMASK 027\n").status, Status::Pass);
        assert_eq!(DefaultUmask.evaluate("UMASK 077\n").status, Status::Pass);
        assert_eq!(DefaultUmask.evaluate("UMASK 022\n").status, Status::Fail);
        // Unset -> default 022 -> fail.
        assert_eq!(DefaultUmask.evaluate("# nothing\n").status, Status::Fail);
    }

    #[test]
    fn shadow_empty_password() {
        // Privileged check reading root-only /etc/shadow.
        assert!(ShadowEmptyPassword.privileged());
        let clean = "root:$6$x$hash:19000::::::\nbin:*:19000::::::\n";
        assert_eq!(ShadowEmptyPassword.evaluate(clean).status, Status::Pass);
        let bad = "root:$6$x$hash:19000::::::\nguest::19000::::::\n";
        let out = ShadowEmptyPassword.evaluate(bad);
        assert_eq!(out.status, Status::Fail);
        assert!(out.detail.contains("guest"));
    }
}
