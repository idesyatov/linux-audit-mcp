# 🔒 linux-audit-mcp

![CI](https://github.com/idesyatov/linux-audit-mcp/actions/workflows/ci.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/idesyatov/linux-audit-mcp?sort=semver)
![License](https://img.shields.io/badge/license-MIT-blue)
![Rust](https://img.shields.io/badge/rust-stable-orange)

A **read-only security audit for Linux servers over the Model Context Protocol
(MCP)** — a single static binary that connects over SSH, snapshots the host's
configuration with a tightly restricted set of read-only commands, and reports
structured findings plus a weighted 0–100 security score. Use it from an MCP
client (ask the model to audit a host) or straight from `cron`/CI.

```text
Audit of 'web' [baseline]: score 53/100 (10 passed, 10 failed, 0 errored)
  domains: ssh 30, firewall 70, accounts 90, kernel 85, services 100, updates 100, logging 90
  [FAIL] high     ssh-permit-root-login — PermitRootLogin is 'yes' (root can log in over SSH).
           ↳ Set PermitRootLogin no; administer via an unprivileged account and sudo.
  [FAIL] high     ssh-password-authentication — PasswordAuthentication is 'yes' (brute-forceable credentials).
           ↳ Set PasswordAuthentication no and authenticate with SSH keys only.
  [FAIL] medium   kernel-ip-forward — net.ipv4.ip_forward = 1 (a non-router should not forward packets).
  ...
```

## Why linux-audit-mcp?

- **Read-only by construction.** 🔒 Every command sent over SSH must be an exact
  member of a curated catalog — the tool *cannot* change the host. See
  [Read-only guarantee](#read-only-guarantee).
- **No agent on the target.** Just SSH and standard tools already present on any
  server (`sshd_config`, `sysctl`, `ss`, `systemctl`, …). Nothing to install.
- **Least privilege.** Connects as an unprivileged user; nothing that needs root.
- **Two ways to run.** An MCP server for conversational use, and a plain CLI with
  exit-code gates for `cron`/CI.
- **Actionable.** Every finding carries a severity and a concrete remediation.
- **A single static binary.** No runtime, no dependencies on the box you run it from.

## Features

- 20 checks across 7 domains: **ssh, accounts, kernel, firewall, updates,
  services, logging** ([full list](#checks)).
- Weighted 0–100 scoring with `baseline` / `hardened` [profiles](#scoring--profiles).
- Operator-owned target registry — tool arguments take a target **alias**, never
  a host or key (prevents SSRF / prompt-injection into the connection).
- Text and JSON output; JSON is machine-readable for dashboards/CI.
- Key-only SSH (`PasswordAuthentication=no`, `BatchMode=yes`), bounded timeouts.

## Quick Start

```bash
# 1. Build the binary (Docker; no Rust needed on the host)
make build-release            # -> target/release/linux-audit-mcp

# 2. Point it at a host you control (see Configuration)
mkdir -p ~/.config/linux-audit-mcp
cat > ~/.config/linux-audit-mcp/targets.toml <<'EOF'
[targets.web]
host = "203.0.113.10"
user = "auditor"
identity_file = "~/.ssh/id_ed25519"
EOF

# 3. Audit it
linux-audit-mcp audit --target web
```

<details>
<summary><b>Installation</b></summary>

### From a release (recommended)

Prebuilt archives are on the [Releases](https://github.com/idesyatov/linux-audit-mcp/releases)
page. Pick the one for the machine you'll **run the auditor from** (not the
target):

| Platform            | Archive                                       |
| ------------------- | --------------------------------------------- |
| Linux x86_64        | `linux-audit-mcp-vX.Y.Z-linux-amd64.tar.gz`   |
| Linux aarch64 (ARM) | `linux-audit-mcp-vX.Y.Z-linux-arm64.tar.gz`   |
| macOS x86_64        | `linux-audit-mcp-vX.Y.Z-macos-amd64.tar.gz`   |
| macOS arm64 (Apple) | `linux-audit-mcp-vX.Y.Z-macos-arm64.tar.gz`   |

```bash
tar xzf linux-audit-mcp-vX.Y.Z-linux-amd64.tar.gz
sudo install linux-audit-mcp-vX.Y.Z-linux-amd64/linux-audit-mcp /usr/local/bin/
linux-audit-mcp --version
```

### From source (Docker — no Rust on the host)

```bash
make build-release            # binary at target/release/linux-audit-mcp
```

### From source (with a Rust toolchain)

```bash
cargo build --release         # binary at target/release/linux-audit-mcp
```

> The auditor runs `ssh` as a subprocess, so the machine you run it from needs an
> OpenSSH client on its `PATH`.

</details>

<details>
<summary><b>Configuration</b></summary>

Connection details live in an operator-owned config file — **never** in tool
arguments. Path resolution: `$LINUX_AUDIT_CONFIG`, else
`~/.config/linux-audit-mcp/targets.toml`.

```toml
# One [targets.<alias>] block per host. `run_audit` / `--target` take the alias.
[targets.web]
host = "203.0.113.10"          # required — hostname or IP
port = 22                       # default 22
user = "auditor"                # default "auditor" (unprivileged)
identity_file = "~/.ssh/id_ed25519"   # SSH private key; ~ is expanded
strict_host_key = "accept-new"  # yes | accept-new (default) | no
connect_timeout_secs = 10       # default 10
command_timeout_secs = 30       # default 30
profile = "hardened"            # optional: baseline (default) | hardened

[targets.db]
host = "203.0.113.20"
user = "auditor"
identity_file = "~/.ssh/id_ed25519"
```

### Preparing a target host

The audit is read-only and unprivileged. On the host you want to audit:

```bash
# 1. Create an unprivileged auditor user
sudo useradd -m -s /bin/bash auditor

# 2. Authorize your public key for it
sudo -u auditor mkdir -p /home/auditor/.ssh
echo "ssh-ed25519 AAAA... you@laptop" | sudo tee -a /home/auditor/.ssh/authorized_keys
sudo chmod 700 /home/auditor/.ssh && sudo chmod 600 /home/auditor/.ssh/authorized_keys
sudo chown -R auditor:auditor /home/auditor/.ssh
```

No `sudoers` entry is needed — every check reads world-readable config or runs a
non-privileged query. Standard tools are expected on the target: `sshd_config`,
`getent`, `sysctl`, `ss`, `systemctl`, and (Debian/Ubuntu) `apt-get`.

</details>

<details>
<summary><b>Usage — CLI (cron / CI)</b></summary>

```bash
linux-audit-mcp audit --target web [OPTIONS]
```

| Option           | Description                                                        |
| ---------------- | ----------------------------------------------------------------- |
| `--target`       | Target alias from the config (required).                          |
| `--profile`      | `baseline` \| `hardened` — overrides the target's profile.        |
| `--format`       | `text` (default) \| `json`.                                       |
| `--config`       | Path to `targets.toml` (else `$LINUX_AUDIT_CONFIG` / default).    |
| `--fail-on`      | Exit 2 if any failed check is ≥ this severity. `off` disables. Default `high`. |
| `--fail-under`   | Exit 2 if the total score is below this value (0–100).            |

**Exit codes:** `0` clean · `1` error (config/connection/audit) · `2` a gate tripped.

```bash
# Machine-readable, gate a pipeline on High findings or a score below 70
linux-audit-mcp audit --target web --format json --fail-on high --fail-under 70
```

</details>

<details>
<summary><b>Usage — MCP server (Claude Desktop / Code)</b></summary>

With no subcommand the binary is an MCP stdio server exposing two tools:
`ping` (liveness) and `run_audit`. Register it with your MCP client — for
Claude Desktop, in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "linux-audit": {
      "command": "/usr/local/bin/linux-audit-mcp",
      "env": {
        "LINUX_AUDIT_CONFIG": "/home/you/.config/linux-audit-mcp/targets.toml"
      }
    }
  }
}
```

Then ask the model, e.g. *"Run a hardened audit of the `web` target and summarise
the High findings."* The model calls `run_audit` with `{ "target": "web",
"profile": "hardened" }` and receives the text + JSON report.

`run_audit` only accepts a target **alias** — a prompt-injected model can neither
choose an arbitrary host nor point at an arbitrary key.

</details>

<details>
<summary><b>Checks</b></summary>

20 checks; each reads one read-only command and applies the tool/OpenSSH default
when a setting is absent.

| Domain    | Check id                       | Sev.     | Flags when…                                   |
| --------- | ------------------------------ | -------- | --------------------------------------------- |
| ssh       | `ssh-permit-root-login`        | High     | `PermitRootLogin` is not `no`                 |
| ssh       | `ssh-password-authentication`  | High     | `PasswordAuthentication` is not `no`          |
| ssh       | `ssh-permit-empty-passwords`   | High     | `PermitEmptyPasswords yes`                    |
| ssh       | `ssh-x11-forwarding`           | Low      | `X11Forwarding yes`                           |
| ssh       | `ssh-max-auth-tries`           | Low      | `MaxAuthTries` > 4                            |
| accounts  | `accounts-nonroot-uid0`        | Critical | a non-`root` account has UID 0                |
| accounts  | `accounts-pass-max-days`       | Low      | `PASS_MAX_DAYS` > 365 or unset                |
| accounts  | `accounts-umask`               | Low      | default `UMASK` allows group/other access     |
| kernel    | `kernel-aslr`                  | Medium   | `randomize_va_space` ≠ 2                       |
| kernel    | `kernel-tcp-syncookies`        | Low      | `tcp_syncookies` ≠ 1                           |
| kernel    | `kernel-rp-filter`             | Low      | `rp_filter` not 1/2                            |
| kernel    | `kernel-ip-forward`            | Medium   | `ip_forward` = 1 on a non-router               |
| kernel    | `kernel-accept-redirects`      | Low      | `accept_redirects` = 1                         |
| kernel    | `kernel-source-route`          | Low      | `accept_source_route` = 1                      |
| firewall  | `firewall-enabled`             | High     | no firewalld/ufw/nftables enabled             |
| updates   | `updates-security-pending`     | Medium   | pending security updates (apt)                |
| services  | `services-cleartext-ports`     | Medium   | telnet/ftp/r-services listening               |
| services  | `services-rpcbind`             | Low      | `rpcbind` enabled                              |
| logging   | `logging-auditd`               | Low      | `auditd` not enabled                          |
| logging   | `logging-syslog`               | Low      | no `rsyslog`/`syslog-ng` enabled              |

A check whose command isn't available on the host (e.g. `apt-get` on RHEL) is
reported as `error`, not a pass/fail, and is excluded from the score.

</details>

<details>
<summary><b>Scoring &amp; profiles</b></summary>

```text
S = clamp( Σ(weight_i × domain_score_i) − penalties, 0, 100 )
```

Each failed check deducts from its domain's score by severity (Low 5 · Medium 15
· High 30 · Critical 50). High/Critical failures also add a global penalty
(8/20) so a single severe issue moves the total. Errored checks are excluded.

| Domain   | `baseline` weight | `hardened` weight |
| -------- | ----------------- | ----------------- |
| ssh      | 0.20              | 0.22              |
| firewall | 0.15              | 0.15              |
| accounts | 0.15              | 0.20              |
| kernel   | 0.15              | 0.18              |
| services | 0.15              | 0.13              |
| updates  | 0.10              | 0.06              |
| logging  | 0.10              | 0.06              |

`hardened` also multiplies penalties by ×1.5. Profile precedence: `--profile` /
tool argument → the target's configured `profile` → `baseline`.

</details>

<details>
<summary><b>Read-only guarantee</b></summary>

Auditing must never change the host. Two layers, deny by default:

1. **Exact catalog.** Every command a check issues must be a byte-for-byte member
   of a curated read-only catalog (`src/catalog.rs`). Anything else is refused
   before it leaves the process.
2. **No shell injection.** The remote `sshd` runs commands through a shell, so the
   catalog also rejects shell metacharacters (`; & | \` $ < > ( ) * ? ' "` …). SSH
   connection parameters are charset-validated so nothing can inject options into
   the local `ssh` invocation.

The design favors dumb readers (`cat <fixed file>`, `sysctl -a`, `ss -tuln`) with
all parsing done in Rust — keeping the remote surface tiny and auditable.
Commands requiring root are intentionally absent.

</details>

## Develop

No Rust needed on the host — everything runs in Docker:

```bash
docker compose run --rm test    # tests (unit + integration + per-distro evals)
docker compose run --rm lint    # cargo fmt --check + clippy -D warnings
docker compose up dev           # interactive watch
```

See [CONTRIBUTING.md](CONTRIBUTING.md). CI runs the same services in the same
image. For how the pieces fit together (component and request-flow diagrams, the
read-only trust boundary, and how to add a check) see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Tech stack

Rust (stable) · [`rmcp`](https://crates.io/crates/rmcp) (MCP stdio) · `tokio` ·
`clap` · `serde`. SSH via the system `ssh` subprocess (no C bindings). Docker for
dev/CI/release.

## License

[MIT](LICENSE)
