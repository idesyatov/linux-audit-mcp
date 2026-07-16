//! MCP server handler and the stdio serve loop.
//!
//! Tools:
//!   - `ping` — liveness stub.
//!
//! The read-only audit tool (`run_audit`, over a target *alias* from the
//! operator config) arrives in Stage 3.

use rmcp::{
    handler::server::router::tool::ToolRouter, model::*, tool, tool_handler, tool_router,
    transport::stdio, ErrorData as McpError, ServerHandler, ServiceExt,
};

#[derive(Clone)]
pub(crate) struct AuditServer {
    // Read by the `#[tool_handler]`-generated dispatch; the binary's dead-code
    // pass doesn't see that macro-generated read, hence the allow.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
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
}

#[tool_handler]
impl ServerHandler for AuditServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_protocol_version(ProtocolVersion::V_2024_11_05)
            .with_instructions(
                "Read-only security audit for Linux servers. `ping` is a liveness check; \
                 the audit tool arrives in a later stage."
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
