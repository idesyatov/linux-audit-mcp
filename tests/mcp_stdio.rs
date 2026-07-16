//! Integration tests over the stdio MCP transport.
//!
//! Spawns the built server as a child process and speaks MCP to it: the `ping`
//! liveness tool, and the `run_audit` target-registry security boundary.

use rmcp::{model::CallToolRequestParams, service::ServiceExt, transport::TokioChildProcess};
use tokio::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_linux-audit-mcp");

#[tokio::test]
async fn ping_tool_is_advertised_and_returns_pong() -> anyhow::Result<()> {
    let client = ().serve(TokioChildProcess::new(Command::new(BIN))?).await?;

    // tools/list must advertise `ping` and `run_audit`.
    let tools = client.list_tools(Default::default()).await?;
    let names: Vec<&str> = tools.tools.iter().map(|t| t.name.as_ref()).collect();
    assert!(names.contains(&"ping"), "ping not advertised: {names:?}");
    assert!(
        names.contains(&"run_audit"),
        "run_audit not advertised: {names:?}"
    );

    // tools/call ping → "pong".
    let result = client.call_tool(CallToolRequestParams::new("ping")).await?;
    let json = serde_json::to_string(&result)?;
    assert!(json.contains("pong"), "unexpected ping result: {json}");

    client.cancel().await?;
    Ok(())
}

/// The security boundary of the target registry: a target not in the operator
/// config is refused. No host is contacted (lookup fails before any SSH).
#[tokio::test]
async fn run_audit_rejects_unknown_target() -> anyhow::Result<()> {
    // Minimal config with exactly one target.
    let dir = std::env::temp_dir().join(format!("linux-audit-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let cfg = dir.join("targets.toml");
    std::fs::write(&cfg, "[targets.web]\nhost = \"192.0.2.1\"\n")?;

    let mut cmd = Command::new(BIN);
    cmd.env("LINUX_AUDIT_CONFIG", &cfg);
    let client = ().serve(TokioChildProcess::new(cmd)?).await?;

    let args = serde_json::json!({ "target": "does-not-exist" })
        .as_object()
        .unwrap()
        .clone();
    let result = client
        .call_tool(CallToolRequestParams::new("run_audit").with_arguments(args))
        .await;

    assert!(
        result.is_err(),
        "unknown target must be rejected, got: {result:?}"
    );

    client.cancel().await?;
    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}
