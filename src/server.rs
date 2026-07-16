//! MCP server handler and the stdio serve loop.
//!
//! Tools:
//!   - `ping` — liveness stub.
//!   - `run_audit` — runs the read-only audit against a target *alias* defined
//!     in the operator config. Connection details never come from tool
//!     arguments, so a prompt-injected model cannot choose an arbitrary host or
//!     key (see [`crate::config`]).

use rmcp::{
    handler::server::router::tool::ToolRouter, handler::server::wrapper::Parameters, model::*,
    schemars, tool, tool_handler, tool_router, transport::stdio, ErrorData as McpError,
    ServerHandler, ServiceExt,
};

use crate::{audit, config, report};

#[derive(Clone)]
pub(crate) struct AuditServer {
    // Read by the `#[tool_handler]`-generated dispatch; the binary's dead-code
    // pass doesn't see that macro-generated read, hence the allow.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub(crate) struct RunAuditParams {
    #[schemars(description = "Alias of a target defined in the operator config")]
    target: String,
}

#[tool_router]
impl AuditServer {
    pub(crate) fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Liveness stub: returns "pong".
    #[tool(description = "Health check — returns \"pong\"")]
    async fn ping(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text("pong")]))
    }

    #[tool(description = "Run the read-only security audit against a configured target (by alias)")]
    async fn run_audit(
        &self,
        Parameters(params): Parameters<RunAuditParams>,
    ) -> Result<CallToolResult, McpError> {
        let cfg = config::load()
            .map_err(|e| McpError::internal_error(format!("config error: {e}"), None))?;
        let target = cfg
            .target(&params.target)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let findings = audit::run_audit(&target.to_ssh_config())
            .await
            .map_err(|e| McpError::internal_error(format!("audit failed: {e}"), None))?;

        let text = report::text(&params.target, &findings);
        let json = report::json(&params.target, &findings)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

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
                "Read-only security audit for Linux servers. Use `run_audit` with a target \
                 alias (defined in the operator config) to audit a host; `ping` is a liveness \
                 check."
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
