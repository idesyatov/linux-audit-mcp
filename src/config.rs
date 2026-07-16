//! Operator-owned registry of audit targets.
//!
//! Sensitive connection details (host, user, key) live here — in a file the
//! operator controls — never in MCP tool arguments. The `run_audit` tool only
//! accepts a target *alias*, so a (possibly prompt-injected) model can neither
//! choose an arbitrary host (SSRF) nor point at an arbitrary key file.
//!
//! Path: `$LINUX_AUDIT_CONFIG`, else `~/.config/linux-audit-mcp/targets.toml`.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::scoring::Profile;
use crate::ssh::{SshConfig, StrictHostKey};

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub targets: HashMap<String, Target>,
}

#[derive(Debug, Deserialize)]
pub struct Target {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_user")]
    pub user: String,
    #[serde(default)]
    pub identity_file: Option<PathBuf>,
    #[serde(default)]
    pub strict_host_key: StrictHostKeyMode,
    #[serde(default = "default_connect_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_command_secs")]
    pub command_timeout_secs: u64,
    /// Default audit profile for this target; overridable per `run_audit` call.
    #[serde(default)]
    pub profile: Option<Profile>,
}

fn default_port() -> u16 {
    22
}
fn default_user() -> String {
    "auditor".to_string()
}
fn default_connect_secs() -> u64 {
    10
}
fn default_command_secs() -> u64 {
    30
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StrictHostKeyMode {
    Yes,
    #[default]
    AcceptNew,
    No,
}

impl From<StrictHostKeyMode> for StrictHostKey {
    fn from(m: StrictHostKeyMode) -> Self {
        match m {
            StrictHostKeyMode::Yes => StrictHostKey::Yes,
            StrictHostKeyMode::AcceptNew => StrictHostKey::AcceptNew,
            StrictHostKeyMode::No => StrictHostKey::No,
        }
    }
}

impl Target {
    pub fn to_ssh_config(&self) -> SshConfig {
        SshConfig {
            host: self.host.clone(),
            port: self.port,
            user: self.user.clone(),
            identity_file: self.identity_file.as_deref().map(expand_tilde),
            connect_timeout: Duration::from_secs(self.connect_timeout_secs),
            command_timeout: Duration::from_secs(self.command_timeout_secs),
            strict_host_key: self.strict_host_key.into(),
            known_hosts: None,
            extra_opts: Vec::new(),
        }
    }
}

impl Config {
    pub fn target(&self, alias: &str) -> Result<&Target, ConfigError> {
        self.targets
            .get(alias)
            .ok_or_else(|| ConfigError::UnknownTarget(alias.to_string()))
    }
}

/// Load the config from the default/env path.
pub fn load() -> Result<Config, ConfigError> {
    load_from(&config_path())
}

/// Load the config from an explicit path.
pub fn load_from(path: &Path) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    toml::from_str(&text).map_err(ConfigError::Parse)
}

pub fn config_path() -> PathBuf {
    if let Some(p) = std::env::var_os("LINUX_AUDIT_CONFIG") {
        return PathBuf::from(p);
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .unwrap_or_default();
    PathBuf::from(home)
        .join(".config")
        .join("linux-audit-mcp")
        .join("targets.toml")
}

/// Expand a leading `~` to the user's home directory.
fn expand_tilde(path: &Path) -> PathBuf {
    if let Ok(rest) = path.strip_prefix("~") {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

#[derive(Debug)]
pub enum ConfigError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse(toml::de::Error),
    UnknownTarget(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(f, "cannot read config {}: {source}", path.display())
            }
            Self::Parse(e) => write!(f, "invalid config: {e}"),
            Self::UnknownTarget(t) => write!(f, "unknown target {t:?}"),
        }
    }
}

impl Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_targets_with_defaults() {
        let cfg: Config = toml::from_str(
            r#"
            [targets.web]
            host = "192.168.1.10"

            [targets.db]
            host = "10.0.0.5"
            port = 2222
            user = "audit"
            strict_host_key = "yes"
            profile = "hardened"
            "#,
        )
        .unwrap();

        let web = cfg.target("web").unwrap();
        assert_eq!(web.port, 22);
        assert_eq!(web.user, "auditor");
        assert_eq!(web.profile, None);

        let db = cfg.target("db").unwrap();
        assert_eq!(db.port, 2222);
        assert_eq!(db.profile, Some(Profile::Hardened));
        let ssh = db.to_ssh_config();
        assert_eq!(ssh.host, "10.0.0.5");
        assert_eq!(ssh.user, "audit");
        assert_eq!(ssh.strict_host_key, StrictHostKey::Yes);
    }

    #[test]
    fn unknown_target_is_an_error() {
        let cfg: Config = toml::from_str("[targets.web]\nhost = \"1.1.1.1\"").unwrap();
        assert!(matches!(
            cfg.target("nope"),
            Err(ConfigError::UnknownTarget(_))
        ));
    }
}
