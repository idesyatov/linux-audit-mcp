//! linux-audit-mcp — read-only security audit of Linux servers over MCP.
//!
//! `main` starts the MCP stdio server ([`server`]). Audit logic lives in
//! [`audit`]/[`checks`], the read-only SSH transport in [`ssh`], the catalog of
//! permitted read-only commands in [`catalog`], the target registry in
//! [`config`], and output rendering in [`report`].

mod audit;
mod catalog;
mod checks;
mod config;
mod report;
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
