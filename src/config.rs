//! Operator-owned inventory of audit targets and host groups.
//!
//! Sensitive connection details (host, user, key) live here - in a file the
//! operator controls - never in MCP tool arguments. The tools accept only a
//! target *alias* or a *group* name, so a (possibly prompt-injected) model can
//! neither choose an arbitrary host (SSRF) nor point at an arbitrary key file.
//!
//! Inventory model (Ansible-inspired): a `[groups.<name>]` lists `members`
//! (target aliases) and may carry shared vars that its members inherit. Per
//! field, precedence is host value -> group value -> built-in default; a host
//! inheriting the same field from two groups with different values is an error.
//!
//! Path: `$LINUX_AUDIT_CONFIG`, else `~/.config/linux-audit-mcp/targets.toml`.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::anomaly::AnomalyConfig;
use crate::health::Thresholds;
use crate::scoring::Profile;
use crate::ssh::{SshConfig, StrictHostKey};

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub targets: HashMap<String, Target>,
    #[serde(default)]
    pub groups: HashMap<String, Group>,
}

/// Connection/audit settings shared by targets and groups. Every field is
/// optional so "unset" is distinct from "default", which is what lets a group
/// value fill in for a host that didn't set it.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HostVars {
    pub port: Option<u16>,
    pub user: Option<String>,
    pub identity_file: Option<PathBuf>,
    pub strict_host_key: Option<StrictHostKeyMode>,
    pub connect_timeout_secs: Option<u64>,
    pub command_timeout_secs: Option<u64>,
    pub profile: Option<Profile>,
    pub health: Option<Thresholds>,
    pub anomaly: Option<AnomalyConfig>,
    /// Opt in to privileged (`sudo -n ...`) checks for this target. Requires the
    /// operator to grant NOPASSWD sudo for exactly those commands (see README).
    pub privileged: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct Target {
    pub host: String,
    #[serde(flatten)]
    pub vars: HostVars,
}

#[derive(Debug, Deserialize)]
pub struct Group {
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(flatten)]
    pub vars: HostVars,
}

/// A target with every field resolved (host + inherited group vars + defaults).
#[derive(Debug)]
pub struct ResolvedTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub identity_file: Option<PathBuf>,
    pub strict_host_key: StrictHostKeyMode,
    pub connect_timeout_secs: u64,
    pub command_timeout_secs: u64,
    pub profile: Option<Profile>,
    pub health: Thresholds,
    pub anomaly: AnomalyConfig,
    pub privileged: bool,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
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

impl ResolvedTarget {
    pub fn to_ssh_config(&self) -> SshConfig {
        // `$LINUX_AUDIT_IDENTITY_FILE` overrides the key path for every target so
        // the config file stays host-portable: the Docker recipe points the tool
        // at the in-container mount via this env var, without editing targets.toml.
        let identity_file = match std::env::var_os("LINUX_AUDIT_IDENTITY_FILE") {
            Some(p) => Some(PathBuf::from(p)),
            None => self.identity_file.as_deref().map(expand_tilde),
        };
        SshConfig {
            host: self.host.clone(),
            port: self.port,
            user: self.user.clone(),
            identity_file,
            connect_timeout: Duration::from_secs(self.connect_timeout_secs),
            command_timeout: Duration::from_secs(self.command_timeout_secs),
            strict_host_key: self.strict_host_key.into(),
            known_hosts: None,
            extra_opts: Vec::new(),
        }
    }
}

/// Resolve one field: the host's own value, else the single group value among
/// the target's groups, else `None`. Two groups disagreeing is an error.
fn inherit<T: PartialEq + Clone>(
    own: Option<T>,
    groups: &[(&String, &Group)],
    pick: impl Fn(&HostVars) -> Option<T>,
    field: &str,
    alias: &str,
) -> Result<Option<T>, ConfigError> {
    if own.is_some() {
        return Ok(own);
    }
    let mut found: Option<T> = None;
    for (_, g) in groups {
        if let Some(v) = pick(&g.vars) {
            match &found {
                None => found = Some(v),
                Some(existing) if *existing != v => {
                    return Err(ConfigError::ConflictingGroupVar {
                        target: alias.to_string(),
                        field: field.to_string(),
                    });
                }
                _ => {}
            }
        }
    }
    Ok(found)
}

impl Config {
    /// Resolve a target alias into effective settings (host + group vars + defaults).
    pub fn resolve(&self, alias: &str) -> Result<ResolvedTarget, ConfigError> {
        let target = self
            .targets
            .get(alias)
            .ok_or_else(|| ConfigError::UnknownTarget(alias.to_string()))?;

        // Groups this alias belongs to (stable order by group name for messages).
        let mut groups: Vec<(&String, &Group)> = self
            .groups
            .iter()
            .filter(|(_, g)| g.members.iter().any(|m| m == alias))
            .collect();
        groups.sort_by(|a, b| a.0.cmp(b.0));

        let v = &target.vars;
        Ok(ResolvedTarget {
            host: target.host.clone(),
            port: inherit(v.port, &groups, |h| h.port, "port", alias)?.unwrap_or(22),
            user: inherit(v.user.clone(), &groups, |h| h.user.clone(), "user", alias)?
                .unwrap_or_else(|| "auditor".to_string()),
            identity_file: inherit(
                v.identity_file.clone(),
                &groups,
                |h| h.identity_file.clone(),
                "identity_file",
                alias,
            )?,
            strict_host_key: inherit(
                v.strict_host_key,
                &groups,
                |h| h.strict_host_key,
                "strict_host_key",
                alias,
            )?
            .unwrap_or_default(),
            connect_timeout_secs: inherit(
                v.connect_timeout_secs,
                &groups,
                |h| h.connect_timeout_secs,
                "connect_timeout_secs",
                alias,
            )?
            .unwrap_or(10),
            command_timeout_secs: inherit(
                v.command_timeout_secs,
                &groups,
                |h| h.command_timeout_secs,
                "command_timeout_secs",
                alias,
            )?
            .unwrap_or(30),
            profile: inherit(v.profile, &groups, |h| h.profile, "profile", alias)?,
            health: inherit(v.health, &groups, |h| h.health, "health", alias)?.unwrap_or_default(),
            anomaly: inherit(v.anomaly, &groups, |h| h.anomaly, "anomaly", alias)?
                .unwrap_or_default(),
            privileged: inherit(v.privileged, &groups, |h| h.privileged, "privileged", alias)?
                .unwrap_or(false),
        })
    }

    /// The target aliases in a group, validated. The implicit `all` group (unless
    /// defined) is every target. Member order is preserved as declared.
    pub fn group_members(&self, name: &str) -> Result<Vec<String>, ConfigError> {
        if name == "all" && !self.groups.contains_key("all") {
            let mut all: Vec<String> = self.targets.keys().cloned().collect();
            all.sort();
            return Ok(all);
        }
        let group = self
            .groups
            .get(name)
            .ok_or_else(|| ConfigError::UnknownGroup(name.to_string()))?;
        for m in &group.members {
            if !self.targets.contains_key(m) {
                return Err(ConfigError::UnknownMember {
                    group: name.to_string(),
                    member: m.clone(),
                });
            }
        }
        if group.members.is_empty() {
            return Err(ConfigError::EmptyGroup(name.to_string()));
        }
        Ok(group.members.clone())
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
    UnknownGroup(String),
    EmptyGroup(String),
    UnknownMember {
        group: String,
        member: String,
    },
    ConflictingGroupVar {
        target: String,
        field: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(f, "cannot read config {}: {source}", path.display())
            }
            Self::Parse(e) => write!(f, "invalid config: {e}"),
            Self::UnknownTarget(t) => write!(f, "unknown target {t:?}"),
            Self::UnknownGroup(g) => write!(f, "unknown group {g:?}"),
            Self::EmptyGroup(g) => write!(f, "group {g:?} has no members"),
            Self::UnknownMember { group, member } => {
                write!(f, "group {group:?} lists unknown target {member:?}")
            }
            Self::ConflictingGroupVar { target, field } => write!(
                f,
                "target {target:?} inherits conflicting {field:?} from two groups; \
                 set it on the target to disambiguate"
            ),
        }
    }
}

impl Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_targets_with_defaults() {
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

        let web = cfg.resolve("web").unwrap();
        assert_eq!(web.port, 22);
        assert_eq!(web.user, "auditor");
        assert_eq!(web.profile, None);

        let db = cfg.resolve("db").unwrap();
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
            cfg.resolve("nope"),
            Err(ConfigError::UnknownTarget(_))
        ));
    }

    #[test]
    fn group_vars_are_inherited_and_host_overrides() {
        let cfg: Config = toml::from_str(
            r#"
            [groups.mtproto]
            user = "root"
            profile = "hardened"
            members = ["web", "mt2"]

            [targets.web]
            host = "1.1.1.1"

            [targets.mt2]
            host = "2.2.2.2"
            user = "audit"
            "#,
        )
        .unwrap();

        // web inherits user + profile from the group.
        let web = cfg.resolve("web").unwrap();
        assert_eq!(web.user, "root");
        assert_eq!(web.profile, Some(Profile::Hardened));

        // mt2 overrides user, still inherits profile.
        let mt2 = cfg.resolve("mt2").unwrap();
        assert_eq!(mt2.user, "audit");
        assert_eq!(mt2.profile, Some(Profile::Hardened));
    }

    #[test]
    fn conflicting_group_vars_error() {
        let cfg: Config = toml::from_str(
            r#"
            [groups.a]
            user = "root"
            members = ["web"]
            [groups.b]
            user = "audit"
            members = ["web"]
            [targets.web]
            host = "1.1.1.1"
            "#,
        )
        .unwrap();
        assert!(matches!(
            cfg.resolve("web"),
            Err(ConfigError::ConflictingGroupVar { .. })
        ));

        // Setting it on the target disambiguates.
        let cfg2: Config = toml::from_str(
            r#"
            [groups.a]
            user = "root"
            members = ["web"]
            [groups.b]
            user = "audit"
            members = ["web"]
            [targets.web]
            host = "1.1.1.1"
            user = "ops"
            "#,
        )
        .unwrap();
        assert_eq!(cfg2.resolve("web").unwrap().user, "ops");
    }

    #[test]
    fn group_membership_and_validation() {
        let cfg: Config = toml::from_str(
            r#"
            [groups.mtproto]
            members = ["web", "mt2"]
            [targets.web]
            host = "1.1.1.1"
            [targets.mt2]
            host = "2.2.2.2"
            [targets.other]
            host = "3.3.3.3"
            "#,
        )
        .unwrap();

        assert_eq!(cfg.group_members("mtproto").unwrap(), vec!["web", "mt2"]);
        // implicit `all` = every target, sorted.
        assert_eq!(
            cfg.group_members("all").unwrap(),
            vec!["mt2", "other", "web"]
        );
        assert!(matches!(
            cfg.group_members("nope"),
            Err(ConfigError::UnknownGroup(_))
        ));
    }

    #[test]
    fn group_with_unknown_member_errors() {
        let cfg: Config = toml::from_str(
            r#"
            [groups.g]
            members = ["web", "ghost"]
            [targets.web]
            host = "1.1.1.1"
            "#,
        )
        .unwrap();
        assert!(matches!(
            cfg.group_members("g"),
            Err(ConfigError::UnknownMember { .. })
        ));
    }

    #[test]
    fn health_thresholds_parse_and_inherit() {
        // `[targets.x.health]` and `[groups.x.health]` are nested tables inside a
        // flattened HostVars - guard that serde still routes them correctly.
        let cfg: Config = toml::from_str(
            r#"
            [groups.mtproto]
            members = ["web", "mt2"]
            [groups.mtproto.health]
            disk_warn_pct = 70

            [targets.web]
            host = "1.1.1.1"

            [targets.mt2]
            host = "2.2.2.2"
            [targets.mt2.health]
            disk_warn_pct = 60
            "#,
        )
        .unwrap();

        // web inherits the group's health thresholds.
        assert_eq!(cfg.resolve("web").unwrap().health.disk_warn_pct, 70);
        // mt2 overrides with its own.
        assert_eq!(cfg.resolve("mt2").unwrap().health.disk_warn_pct, 60);
    }

    #[test]
    fn anomaly_config_parses_and_inherits() {
        let cfg: Config = toml::from_str(
            r#"
            [groups.prod]
            members = ["web", "db"]
            [groups.prod.anomaly]
            k = 4.0

            [targets.web]
            host = "1.1.1.1"

            [targets.db]
            host = "2.2.2.2"
            [targets.db.anomaly]
            k = 5.0
            min_samples = 20
            "#,
        )
        .unwrap();

        // web inherits the group's anomaly settings; unset fields keep defaults.
        let web = cfg.resolve("web").unwrap();
        assert_eq!(web.anomaly.k, 4.0);
        // unset fields keep their defaults
        assert_eq!(web.anomaly.min_samples, 8);

        // db overrides with its own values.
        let db = cfg.resolve("db").unwrap();
        assert_eq!(db.anomaly.k, 5.0);
        assert_eq!(db.anomaly.min_samples, 20);
        // A target with no anomaly table gets the full default (enabled).
        assert!(cfg.resolve("web").unwrap().anomaly.enabled);
    }

    #[test]
    fn privileged_flag_parses_and_inherits() {
        let cfg: Config = toml::from_str(
            r#"
            [groups.secure]
            members = ["a", "b"]
            privileged = true
            [targets.a]
            host = "1.1.1.1"
            [targets.b]
            host = "2.2.2.2"
            privileged = false
            "#,
        )
        .unwrap();
        assert!(cfg.resolve("a").unwrap().privileged); // inherited from group
        assert!(!cfg.resolve("b").unwrap().privileged); // host overrides to false

        // Default is false (opt-in).
        let plain: Config = toml::from_str("[targets.c]\nhost = \"3.3.3.3\"").unwrap();
        assert!(!plain.resolve("c").unwrap().privileged);
    }

    #[test]
    fn identity_file_env_override() {
        let cfg: Config = toml::from_str(
            "[targets.web]\nhost = \"1.1.1.1\"\nidentity_file = \"~/.ssh/audit_ed25519\"",
        )
        .unwrap();
        let web = cfg.resolve("web").unwrap();

        // No env: the config's own (tilde-expanded) path is used.
        std::env::remove_var("LINUX_AUDIT_IDENTITY_FILE");
        assert!(web.to_ssh_config().identity_file.is_some());

        // Env set: it overrides, so the config stays host-portable.
        std::env::set_var("LINUX_AUDIT_IDENTITY_FILE", "/keys/id_ed25519");
        assert_eq!(
            web.to_ssh_config().identity_file,
            Some(PathBuf::from("/keys/id_ed25519"))
        );
        std::env::remove_var("LINUX_AUDIT_IDENTITY_FILE");
    }
}
