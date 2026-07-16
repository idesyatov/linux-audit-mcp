//! Integration test for the Stage 1 MCP skeleton.
//!
//! Spawns the built server as a child process, performs the MCP handshake over
//! stdio, and checks that the `ping` tool is advertised and returns "pong".

use rmcp::{model::CallToolRequestParams, service::ServiceExt, transport::TokioChildProcess};
use tokio::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_linux-audit-mcp");

#[tokio::test]
async fn ping_tool_is_advertised_and_returns_pong() -> anyhow::Result<()> {
    let client = ().serve(TokioChildProcess::new(Command::new(BIN))?).await?;

    // tools/list must advertise `ping`.
    let tools = client.list_tools(Default::default()).await?;
    assert!(
        tools.tools.iter().any(|t| t.name.as_ref() == "ping"),
        "ping tool not found in tools/list: {tools:#?}"
    );

    // tools/call ping → "pong".
    let result = client.call_tool(CallToolRequestParams::new("ping")).await?;
    let json = serde_json::to_string(&result)?;
    assert!(json.contains("pong"), "unexpected ping result: {json}");

    client.cancel().await?;
    Ok(())
}
