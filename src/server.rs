//! MCP server handler and the stdio serve loop.
//!
//! Tools:
//!   - `ping` - liveness stub.
//!   - `run_audit` - runs the read-only audit against a target *alias* defined
//!     in the operator config. Connection details never come from tool
//!     arguments, so a prompt-injected model cannot choose an arbitrary host or
//!     key (see [`crate::config`]).

use rmcp::{
    handler::server::router::tool::ToolRouter, handler::server::wrapper::Parameters, model::*,
    schemars, tool, tool_handler, tool_router, transport::stdio, ErrorData as McpError,
    ServerHandler, ServiceExt,
};

use crate::scoring::Profile;
use crate::{config, health, history, report, run};

#[derive(Clone)]
pub(crate) struct AuditServer {
    // Read by the `#[tool_handler]`-generated dispatch; the binary's dead-code
    // pass doesn't see that macro-generated read, hence the allow.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub(crate) struct RunAuditParams {
    #[serde(default)]
    #[schemars(description = "Alias of a single target; provide this or `group`")]
    target: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Group name to audit every member of (or `all`); provide this or `target`"
    )]
    group: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Audit profile: \"baseline\" (default) or \"hardened\"; \
                              overrides the target's configured profile"
    )]
    profile: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub(crate) struct InspectLoadParams {
    #[serde(default)]
    #[schemars(description = "Alias of a single target; provide this or `group`")]
    target: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "Group name to snapshot every member of (or `all`); provide this or `target`"
    )]
    group: Option<String>,
}

/// Expand a `target`/`group` selection into aliases plus the group name (if any).
fn select(
    cfg: &config::Config,
    target: Option<String>,
    group: Option<String>,
) -> Result<(Vec<String>, Option<String>), McpError> {
    match (target, group) {
        (Some(t), None) => Ok((vec![t], None)),
        (None, Some(g)) => cfg
            .group_members(&g)
            .map(|m| (m, Some(g)))
            .map_err(|e| McpError::invalid_params(e.to_string(), None)),
        (None, None) => Err(McpError::invalid_params(
            "provide `target` or `group`".to_string(),
            None,
        )),
        (Some(_), Some(_)) => Err(McpError::invalid_params(
            "provide only one of `target` or `group`".to_string(),
            None,
        )),
    }
}

#[tool_router]
impl AuditServer {
    pub(crate) fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Liveness stub: returns "pong".
    #[tool(description = "Health check - returns \"pong\"")]
    async fn ping(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text("pong")]))
    }

    #[tool(
        description = "Run the read-only security audit against a configured target (`target`) \
                       or every member of a group (`group`, or \"all\"). Returns text + JSON."
    )]
    async fn run_audit(
        &self,
        Parameters(params): Parameters<RunAuditParams>,
    ) -> Result<CallToolResult, McpError> {
        let cfg = config::load()
            .map_err(|e| McpError::internal_error(format!("config error: {e}"), None))?;
        let profile_override = match params.profile.as_deref() {
            Some(name) => Some(Profile::parse(name).ok_or_else(|| {
                McpError::invalid_params(format!("unknown profile {name:?}"), None)
            })?),
            None => None,
        };
        let (aliases, group) = select(&cfg, params.target, params.group)?;
        let outcomes = run::audit_targets(&cfg, &aliases, profile_override)
            .await
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let (text, json) = match &group {
            None => {
                let o = &outcomes[0];
                match &o.result {
                    Ok((score, findings)) => (
                        report::text(&o.alias, score, findings),
                        report::json(&o.alias, score, findings)
                            .map_err(|e| McpError::internal_error(e.to_string(), None))?,
                    ),
                    Err(e) => {
                        return Err(McpError::internal_error(
                            format!("audit of '{}' failed: {e}", o.alias),
                            None,
                        ))
                    }
                }
            }
            Some(g) => (
                run::audit_group_text(g, &outcomes),
                run::audit_group_json(g, &outcomes)
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?,
            ),
        };

        Ok(CallToolResult::success(vec![
            ContentBlock::text(text),
            ContentBlock::text(json),
        ]))
    }

    #[tool(
        description = "Take a read-only operational-health snapshot (load, memory, disk, hot \
                       processes, connections, network throughput) of a target (`target`) or \
                       every member of a group (`group`, or \"all\"). Reported separately from \
                       the security audit; it never affects the security score."
    )]
    async fn inspect_load(
        &self,
        Parameters(params): Parameters<InspectLoadParams>,
    ) -> Result<CallToolResult, McpError> {
        let cfg = config::load()
            .map_err(|e| McpError::internal_error(format!("config error: {e}"), None))?;
        let (aliases, group) = select(&cfg, params.target, params.group)?;
        let outcomes = run::health_targets(&cfg, &aliases)
            .await
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        // Persist each successful snapshot so the recurring "pulse" builds up
        // per-host history for later baselining. Best-effort (errors are logged).
        history::record_outcomes(&outcomes, true);

        let (text, json) = match &group {
            None => {
                let o = &outcomes[0];
                match &o.result {
                    Ok(report) => (
                        health::report::text(&o.alias, report),
                        health::report::json(&o.alias, report)
                            .map_err(|e| McpError::internal_error(e.to_string(), None))?,
                    ),
                    Err(e) => {
                        return Err(McpError::internal_error(
                            format!("health snapshot of '{}' failed: {e}", o.alias),
                            None,
                        ))
                    }
                }
            }
            Some(g) => (
                run::health_group_text(g, &outcomes),
                run::health_group_json(g, &outcomes)
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?,
            ),
        };

        Ok(CallToolResult::success(vec![
            ContentBlock::text(text),
            ContentBlock::text(json),
        ]))
    }
}

#[tool_handler]
impl ServerHandler for AuditServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_protocol_version(ProtocolVersion::V_2024_11_05)
            .with_instructions(
                "Read-only tools for Linux servers, addressed by a target alias or a group name \
                 defined in the operator config (never a raw host/key). `run_audit` scores a \
                 host's security posture; `inspect_load` takes an operational-health snapshot \
                 (load/memory/disk/processes/network) kept separate from the security score. Both \
                 accept either `target` (one host) or `group` (all members, or \"all\"). `ping` \
                 is a liveness check."
                    .to_string(),
            )
    }
}

/// Start the MCP server over stdio and run until the client disconnects.
pub(crate) async fn serve() -> anyhow::Result<()> {
    tracing::info!("starting linux-audit-mcp MCP server (stdio)");

    let service = AuditServer::new().serve(stdio()).await.map_err(|e| {
        tracing::error!("failed to start MCP server: {e:?}");
        e
    })?;

    service.waiting().await?;
    Ok(())
}
