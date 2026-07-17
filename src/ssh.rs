//! SSH transport to an audited Linux host via the system `ssh` (subprocess).
//!
//! No C bindings: we invoke the platform `ssh` binary with `tokio::process`.
//! Arguments are passed as an argv vector (never through a local shell), so
//! nothing in the destination or command can inject into the `ssh` invocation
//! itself. Every command is validated against the read-only catalog before it
//! is sent (the remote sshd runs it through the login shell, so the catalog's
//! charset rules matter there too).
//!
//! Wired into an MCP tool in Stage 3.
#![allow(dead_code)]

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

use crate::catalog::{self, CatalogError};

/// Prepended to the remote command's `PATH`. A non-interactive SSH session's
/// PATH usually omits `/sbin` and `/usr/sbin`, where some read-only tools live
/// (`sysctl` everywhere; `ss` on RHEL-family). This is a fixed, trusted literal
/// that never carries user input, so it can't widen the read-only guarantee
/// (still enforced on the bare command by [`catalog`]).
const REMOTE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin";

/// `ssh -o StrictHostKeyChecking=<mode>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictHostKey {
    /// Refuse to connect to unknown/changed hosts (strictest).
    Yes,
    /// Trust on first use, refuse if a known key changed (default).
    AcceptNew,
    /// Do not check host keys (insecure; discouraged).
    No,
}

impl StrictHostKey {
    fn as_opt(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::AcceptNew => "accept-new",
            Self::No => "no",
        }
    }
}

/// Connection parameters for one Linux host.
#[derive(Debug, Clone)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Private key file (`ssh -i`). Key-based auth only; passwords are refused.
    pub identity_file: Option<PathBuf>,
    /// TCP connect timeout (`ssh -o ConnectTimeout`).
    pub connect_timeout: Duration,
    /// Wall-clock limit for the whole command; the child is killed on timeout.
    pub command_timeout: Duration,
    pub strict_host_key: StrictHostKey,
    /// Custom known_hosts file (`ssh -o UserKnownHostsFile`).
    pub known_hosts: Option<PathBuf>,
    /// Escape hatch for extra `ssh` options, e.g. `-o` `ProxyJump=...`.
    pub extra_opts: Vec<String>,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 22,
            // Unprivileged by default; the audit stays within non-root reach.
            user: "auditor".to_string(),
            identity_file: None,
            connect_timeout: Duration::from_secs(10),
            command_timeout: Duration::from_secs(30),
            strict_host_key: StrictHostKey::AcceptNew,
            known_hosts: None,
            extra_opts: Vec::new(),
        }
    }
}

/// Result of a successful (spawned and completed) SSH command.
#[derive(Debug, Clone)]
pub struct SshOutput {
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug)]
pub enum SshError {
    /// `host` is empty or contains characters not valid in a hostname/IP.
    InvalidHost(String),
    /// `user` is empty or contains characters not valid in a username.
    InvalidUser(String),
    /// The command was rejected by the read-only catalog.
    CommandRejected(CatalogError),
    /// The `ssh` binary could not be spawned (e.g. not installed).
    Spawn(std::io::Error),
    /// I/O error while waiting for the child.
    Io(std::io::Error),
    /// The command exceeded `command_timeout` and was killed.
    Timeout,
    /// Authentication was refused by the host.
    Auth(String),
    /// The host was unreachable (DNS/connect/transport failure).
    Connection(String),
    /// `ssh` connected but the remote command returned a non-zero status.
    RemoteCommand { code: Option<i32>, stderr: String },
}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHost(h) => write!(f, "invalid host: {h:?}"),
            Self::InvalidUser(u) => write!(f, "invalid user: {u:?}"),
            Self::CommandRejected(e) => write!(f, "command rejected by catalog: {e}"),
            Self::Spawn(e) => write!(f, "failed to spawn ssh: {e}"),
            Self::Io(e) => write!(f, "ssh i/o error: {e}"),
            Self::Timeout => write!(f, "ssh command timed out"),
            Self::Auth(s) => write!(f, "authentication failed: {s}"),
            Self::Connection(s) => write!(f, "connection failed: {s}"),
            Self::RemoteCommand { code, stderr } => {
                write!(f, "remote command failed (code {code:?}): {stderr}")
            }
        }
    }
}

impl Error for SshError {}

/// A hostname or IP literal contains only these characters and never starts
/// with `-` (which `ssh` would otherwise parse as an option).
fn is_valid_host(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with('-')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

fn is_valid_user(user: &str) -> bool {
    !user.is_empty()
        && !user.starts_with('-')
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// A private 0600 copy of an identity file that removes itself on drop.
struct SecuredIdentity {
    path: PathBuf,
}

impl SecuredIdentity {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SecuredIdentity {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn temp_key_path() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("linux-audit-mcp-key-{pid}-{n}"))
}

/// ssh refuses a private key that group/other can access — exactly how a key
/// bind-mounted into a container looks (0777 on Docker Desktop). If `path` is
/// too open, return a private 0600 copy to use instead; otherwise `None` (use
/// the original). Windows governs key access by ACLs, so there it's a no-op.
#[cfg(unix)]
fn secure_identity(path: &Path) -> std::io::Result<Option<SecuredIdentity>> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        // Missing/unreadable: let ssh report it rather than second-guess here.
        Err(_) => return Ok(None),
    };
    if meta.mode() & 0o077 == 0 {
        return Ok(None);
    }

    let data = std::fs::read(path)?;
    let dst = temp_key_path();
    // O_CREAT | O_EXCL with mode 0600: nobody can pre-create or read the copy.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&dst)?;
    f.write_all(&data)?;

    Ok(Some(SecuredIdentity { path: dst }))
}

#[cfg(not(unix))]
fn secure_identity(_path: &Path) -> std::io::Result<Option<SecuredIdentity>> {
    Ok(None)
}

impl SshConfig {
    /// Build the `ssh` argv (without the leading `ssh`). Pure and testable.
    /// `identity` is the key to pass to `-i` (may be a secured copy of
    /// `self.identity_file`; see [`secure_identity`]).
    pub fn build_args(&self, identity: Option<&Path>, command: &str) -> Vec<String> {
        let mut args: Vec<String> = Vec::new();

        args.push("-p".to_string());
        args.push(self.port.to_string());

        if let Some(key) = identity {
            args.push("-i".to_string());
            args.push(key.display().to_string());
            // With an explicit key, don't fall back to other identities.
            args.push("-o".to_string());
            args.push("IdentitiesOnly=yes".to_string());
        }

        // Non-interactive, key-only, bounded connect time.
        args.push("-o".to_string());
        args.push("BatchMode=yes".to_string());
        args.push("-o".to_string());
        args.push("PasswordAuthentication=no".to_string());
        args.push("-o".to_string());
        args.push(format!("ConnectTimeout={}", self.connect_timeout.as_secs()));
        args.push("-o".to_string());
        args.push(format!(
            "StrictHostKeyChecking={}",
            self.strict_host_key.as_opt()
        ));

        if let Some(kh) = &self.known_hosts {
            args.push("-o".to_string());
            args.push(format!("UserKnownHostsFile={}", kh.display()));
        }

        args.extend(self.extra_opts.iter().cloned());

        // Destination carries `user@`, so a `-`-leading host can't be parsed as
        // an option; both fields are also charset-validated in `run`.
        args.push(format!("{}@{}", self.user, self.host));

        // The command is a single argv element handed to the remote shell, with
        // a sane PATH prepended so sbin tools resolve under non-interactive SSH.
        args.push(format!("PATH={REMOTE_PATH} {command}"));

        args
    }

    /// Run a read-only command on the host.
    ///
    /// Order matters for safety: the config and the catalog are checked
    /// *before* any process is spawned.
    pub async fn run(&self, command: &str) -> Result<SshOutput, SshError> {
        if !is_valid_host(&self.host) {
            return Err(SshError::InvalidHost(self.host.clone()));
        }
        if !is_valid_user(&self.user) {
            return Err(SshError::InvalidUser(self.user.clone()));
        }
        catalog::validate(command).map_err(SshError::CommandRejected)?;

        // If the key's permissions are too open (e.g. a 0777 bind-mount inside a
        // container), use a private 0600 copy so ssh accepts it. `secured` lives
        // until the command finishes, then deletes the copy on drop.
        let secured = match &self.identity_file {
            Some(path) => secure_identity(path).map_err(SshError::Io)?,
            None => None,
        };
        let identity = secured
            .as_ref()
            .map(SecuredIdentity::path)
            .or(self.identity_file.as_deref());

        let mut cmd = Command::new("ssh");
        cmd.args(self.build_args(identity, command))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let child = cmd.spawn().map_err(SshError::Spawn)?;

        // On timeout the future is dropped, which kills the child (kill_on_drop).
        let output = timeout(self.command_timeout, child.wait_with_output())
            .await
            .map_err(|_| SshError::Timeout)?
            .map_err(SshError::Io)?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        if output.status.success() {
            return Ok(SshOutput { stdout, stderr });
        }

        // ssh itself exits 255 on transport/auth failures; classify by stderr.
        if output.status.code() == Some(255) {
            let lower = stderr.to_lowercase();
            if lower.contains("permission denied") || lower.contains("authentication") {
                return Err(SshError::Auth(stderr.trim().to_string()));
            }
            return Err(SshError::Connection(stderr.trim().to_string()));
        }

        Err(SshError::RemoteCommand {
            code: output.status.code(),
            stderr: stderr.trim().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SshConfig {
        SshConfig {
            host: "192.168.1.10".to_string(),
            user: "auditor".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn build_args_sets_safe_defaults() {
        let args = cfg().build_args(None, "uname -a");
        let joined = args.join(" ");

        assert!(joined.contains("-p 22"));
        assert!(joined.contains("BatchMode=yes"));
        assert!(joined.contains("PasswordAuthentication=no"));
        assert!(joined.contains("ConnectTimeout=10"));
        assert!(joined.contains("StrictHostKeyChecking=accept-new"));
        // Destination and command are the last two argv elements; the command
        // carries a prepended PATH so sbin tools resolve over SSH.
        assert_eq!(args[args.len() - 2], "auditor@192.168.1.10");
        let cmd = &args[args.len() - 1];
        assert!(cmd.starts_with("PATH=/usr/local/sbin:"));
        assert!(cmd.ends_with(" uname -a"));
    }

    #[test]
    fn build_args_includes_identity_when_set() {
        let mut c = cfg();
        c.identity_file = Some(PathBuf::from("/keys/id_ed25519"));
        let args = c.build_args(c.identity_file.as_deref(), "sysctl -a");
        let joined = args.join(" ");
        assert!(joined.contains("-i /keys/id_ed25519"));
        assert!(joined.contains("IdentitiesOnly=yes"));
    }

    #[cfg(unix)]
    #[test]
    fn secures_a_too_open_identity() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let src = std::env::temp_dir().join(format!("laudit-keytest-{}", std::process::id()));
        std::fs::write(&src, b"KEYDATA").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o777)).unwrap();

        // Too open -> a private 0600 copy with the same content.
        let secured = secure_identity(&src)
            .unwrap()
            .expect("an open key should be copied");
        let copy = secured.path().to_path_buf();
        assert_eq!(std::fs::metadata(&copy).unwrap().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&copy).unwrap(), b"KEYDATA");

        // Already private -> used as-is (no copy).
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(secure_identity(&src).unwrap().is_none());

        // The copy is removed on drop.
        drop(secured);
        assert!(!copy.exists());
        std::fs::remove_file(&src).ok();
    }

    #[test]
    fn host_and_user_validation() {
        assert!(is_valid_host("192.168.1.10"));
        assert!(is_valid_host("server.local"));
        assert!(is_valid_host("fe80::1"));
        assert!(!is_valid_host(""));
        assert!(!is_valid_host("-oProxyCommand=evil"));
        assert!(!is_valid_host("a b"));

        assert!(is_valid_user("auditor"));
        assert!(!is_valid_user("-x"));
        assert!(!is_valid_user("a;b"));
    }

    #[tokio::test]
    async fn run_rejects_non_catalog_command_without_spawning() {
        // A write command must be refused by the catalog, not sent to ssh.
        let err = cfg().run("systemctl restart sshd").await.unwrap_err();
        assert!(matches!(err, SshError::CommandRejected(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn run_rejects_invalid_host() {
        let mut c = cfg();
        c.host = "-oProxyCommand=evil".to_string();
        let err = c.run("uname -a").await.unwrap_err();
        assert!(matches!(err, SshError::InvalidHost(_)), "got {err:?}");
    }
}
