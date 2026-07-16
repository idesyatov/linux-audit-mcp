# linux-audit-mcp

Read-only security audit of Linux servers over the **Model Context Protocol
(MCP)**. The server connects to a host over SSH, snapshots configuration with a
tightly restricted set of read-only commands, and reports structured findings
(a scoring engine and per-profile summaries land in later stages).

> **Status:** early development. The MCP skeleton and the read-only SSH transport
> are in place; audit checks are being added stage by stage.

## Read-only by design 🔒

Auditing must never change the host. Every command sent over SSH must be an
**exact member of a curated read-only catalog** (`src/catalog.rs`) — anything
else is refused before it leaves the process. Because the remote sshd runs
commands through a shell, the catalog also rejects shell metacharacters that
could chain or inject a second command. The auditor connects as an
**unprivileged user**; anything requiring root is intentionally out of scope
for now.

The design favors dumb readers (`cat <fixed file>`, `sysctl -a`, `ss -tuln`)
with all parsing done in Rust — keeping the remote command surface tiny and
auditable.

## Develop

No Rust needed on the host — everything runs in Docker:

```bash
docker compose run --rm test    # tests
docker compose run --rm lint    # fmt --check + clippy (-D warnings)
docker compose up dev           # interactive watch
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Use with an MCP client

Build the binary (`docker compose run --rm build-release` → `target/release/`),
then point your MCP client at it over stdio. Example for Claude Desktop
(`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "linux-audit": {
      "command": "/path/to/linux-audit-mcp"
    }
  }
}
```

Currently exposes a `ping` liveness tool; the audit tool arrives in a later
stage.

## License

[MIT](LICENSE)
