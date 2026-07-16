# Security Policy

## Responsible disclosure

If you find a vulnerability in `linux-audit-mcp`, please report it privately
via the repository's **GitHub Security Advisories** ("Security" tab →
"Report a vulnerability") and **do not open a public issue**.

Where possible, please include:

- the project version/commit and the target distribution (if relevant);
- a description of the problem and its potential impact;
- reproduction steps or a PoC;
- a proposed fix, if any.

## Response timeline

- Acknowledgement of receipt — within 72 hours.
- Initial assessment and plan — within 7 days.
- Fix and disclosure coordination — by agreement, usually up to 90 days.

Please allow reasonable time to ship a fix before public disclosure. Thank you
for the responsible approach.

## Project security model

Key invariants; violating them is considered a vulnerability:

- 🔒 **Read-only.** The server must not be able to change the audited host. Every
  command sent over SSH must be an exact member of the read-only command catalog
  (`src/catalog.rs`); sending anything that writes or modifies state is a
  security defect.
- **No shell injection.** The remote sshd runs commands through a shell, so the
  catalog also forbids shell metacharacters that could chain or inject a second
  command. Connection parameters must not allow injecting options into the local
  `ssh` invocation.
- **Least privilege.** The auditor connects as an unprivileged user; commands
  requiring root are intentionally out of scope until explicitly designed for.
- **Transport isolation.** Secrets (keys, credentials, captured file contents)
  must not leak into the MCP transport's stdout or into build artifacts.

## Supported versions

The project is in early development. Until the first stable release, only the
default branch (latest commit) is supported.
