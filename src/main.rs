//! linux-audit-mcp - read-only security audit of Linux servers over MCP.
//!
//! `main` wires the pieces and routes the CLI: the default (no subcommand) is
//! the MCP stdio server ([`server`]); the `audit` subcommand ([`cli`]) runs a
//! one-shot audit for cron/CI. Audit logic lives in [`audit`]/[`checks`], the
//! read-only SSH transport in [`ssh`], the command catalog in [`catalog`].

mod audit;
mod catalog;
mod checks;
mod cli;
mod config;
mod health;
mod report;
mod run;
mod scoring;
mod server;
mod ssh;

// Stage 8 evals: regression tests over captured per-distro output (tests/fixtures).
#[cfg(test)]
mod evals;

use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // stdout carries the MCP stdio transport (and CLI json output), so logs go
    // to stderr only.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let cli = cli::Cli::parse();
    let code = match cli.command.unwrap_or(cli::Command::Serve) {
        cli::Command::Serve => {
            server::serve().await?;
            0
        }
        cli::Command::Audit(args) => cli::run_audit(args).await?,
        cli::Command::Health(args) => cli::run_health(args).await?,
    };

    std::process::exit(code);
}
