//! linux-audit-mcp — read-only security audit of Linux servers over MCP.
//!
//! `main` starts the MCP stdio server ([`server`]). The read-only SSH transport
//! lives in [`ssh`] and the catalog of permitted read-only commands in
//! [`catalog`]. Audit checks, scoring and the CLI arrive in later stages.

mod catalog;
mod server;
mod ssh;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // stdout carries the MCP stdio transport, so logs go to stderr only.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    server::serve().await
}
