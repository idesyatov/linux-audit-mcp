# 🔒 linux-audit-mcp

![CI](https://github.com/idesyatov/linux-audit-mcp/actions/workflows/ci.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/idesyatov/linux-audit-mcp?sort=semver)
![License](https://img.shields.io/badge/license-MIT-blue)
![Rust](https://img.shields.io/badge/rust-stable-orange)

**An MCP server that audits Linux servers over SSH** — so an AI assistant like
Claude can check a host on request. The *same* read-only audit also runs as a
plain **CLI**, for a quick terminal report or a cron/CI gate.

It connects with a key you provide, snapshots the host's configuration using only
a curated set of read-only commands, and reports findings with a weighted 0–100
score.

> **New to MCP?** The Model Context Protocol is the open standard AI apps use to
> call external tools. Running this as an MCP server lets Claude Desktop/Code
> invoke the audit itself — you ask in chat, it audits and explains. Prefer a
> plain command and a printed report? The CLI does the same audit, no AI involved.
> Same tool, two front-ends; Docker is just a way to package either one.

```text
Audit of 'web' [baseline]: score 53/100 (10 passed, 10 failed, 0 errored)
  domains: ssh 30, firewall 70, accounts 90, kernel 85, services 100, updates 100, logging 90
  [FAIL] high     ssh-permit-root-login — PermitRootLogin is 'yes' (root can log in over SSH).
           ↳ Set PermitRootLogin no; administer via an unprivileged account and sudo.
  [FAIL] medium   kernel-ip-forward — net.ipv4.ip_forward = 1 (a non-router should not forward packets).
  ...
```

## Features

- **Read-only by construction** 🔒 — every command is a byte-for-byte member of a
  curated catalog; the tool *cannot* change the host.
- **No agent, least privilege** — just SSH as an unprivileged user, using tools
  already on the box (`sshd_config`, `sysctl`, `ss`, `systemctl`, …).
- **20 checks across 7 domains** — ssh, accounts, kernel, firewall, updates,
  services, logging — each with a severity and a concrete fix.
- **Weighted 0–100 score** with `baseline` / `hardened` profiles.
- **Two ways to run** — a CLI with exit-code gates for cron/CI, or an MCP server
  for Claude Desktop/Code. Text and JSON output.
- **Safe by design** — arguments take a target *alias*, never a host or key, so a
  prompt-injected model can't redirect the connection.

## Quick Start

Most people want the same thing first: **a one-off security report for a host
(say, a VPS), from the terminal.** That's the path below — auditing from Claude or
gating CI reuse the very same config (see the table after).

**1. Get the tool** — either is fine:

```bash
docker run --rm ghcr.io/idesyatov/linux-audit-mcp:latest --version   # needs only Docker
# ...or download a native binary for your OS — see Installation.
```

**2. Describe the target** in `~/.config/linux-audit-mcp/targets.toml`:

```toml
[targets.web]
host = "203.0.113.10"
user = "auditor"                        # unprivileged account on the target
identity_file = "~/.ssh/audit_ed25519"  # your SSH private key (same for native & Docker)
```

The target just needs an unprivileged `auditor` user reachable by your key — see
**Configuration** to set that up.

**3. Run the audit** by alias:

```bash
# native binary
linux-audit-mcp audit --target web

# ...or Docker (mount the config + key, read-only)
docker run -i --rm \
  -v ~/.config/linux-audit-mcp/targets.toml:/config/targets.toml:ro \
  -v ~/.ssh/audit_ed25519:/keys/id_ed25519:ro \
  ghcr.io/idesyatov/linux-audit-mcp:latest audit --target web
```

### Which way is for me?

First pick the **front-end** (what you want), then the **packaging** (binary or
Docker — same result):

| I want to…                                | Front-end → section                                       |
| ----------------------------------------- | --------------------------------------------------------- |
| Check a host now, or on a schedule (cron) | CLI → **Use it as a CLI**                                 |
| Audit hosts by chatting with **Claude**   | MCP server → **Use it as an MCP server**                  |
| **Gate CI/CD** on findings                | CLI with `--fail-on` / `--fail-under` → **Use it as a CLI** |

**Binary or Docker?** If you already run Docker, `docker run` installs nothing;
otherwise grab the binary. For Claude, Docker is the most portable. Container
details (mounts, hardening, verifying the signature) are under **Docker image**.

<details>
<summary><b>Installation</b></summary>

Install on the machine you'll **run the auditor from** (not the target). Prebuilt,
signed archives are on the [Releases](https://github.com/idesyatov/linux-audit-mcp/releases)
page — or use the Docker image (see **Run via Docker**), or build from source.

| Platform                | Archive                    |
| ----------------------- | -------------------------- |
| Linux, Intel/AMD 64-bit | `...-linux-amd64.tar.gz`   |
| Linux, ARM 64-bit       | `...-linux-arm64.tar.gz`   |
| macOS, Intel            | `...-macos-amd64.tar.gz`   |
| macOS, Apple Silicon    | `...-macos-arm64.tar.gz`   |
| Windows, 64-bit         | `...-windows-amd64.zip`    |

**Linux / macOS** (`uname -sm` tells you OS/arch):

```bash
ARCH=linux-amd64        # or linux-arm64 / macos-amd64 / macos-arm64
BASE="https://github.com/idesyatov/linux-audit-mcp/releases/latest/download"

curl -LO "$BASE/linux-audit-mcp-$ARCH.tar.gz"
curl -LO "$BASE/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
tar xzf "linux-audit-mcp-$ARCH.tar.gz"
sudo install "linux-audit-mcp-$ARCH/linux-audit-mcp" /usr/local/bin/
linux-audit-mcp --version
```

**Windows** (PowerShell):

```powershell
$Base = "https://github.com/idesyatov/linux-audit-mcp/releases/latest/download"
Invoke-WebRequest "$Base/linux-audit-mcp-windows-amd64.zip" -OutFile audit.zip
Invoke-WebRequest "$Base/SHA256SUMS" -OutFile SHA256SUMS
Get-FileHash audit.zip -Algorithm SHA256   # compare with the windows line in SHA256SUMS
Expand-Archive audit.zip -DestinationPath .
.\linux-audit-mcp-windows-amd64\linux-audit-mcp.exe --version
```

**From source** (no Rust needed — builds in Docker):

```bash
make build-release      # binary at target/release/linux-audit-mcp
# or, with a Rust toolchain: cargo build --release
```

> The auditor runs `ssh` as a subprocess, so an OpenSSH client must be on `PATH`
> — preinstalled on most Linux/macOS, and built into Windows 10/11.

</details>

<details>
<summary><b>Configuration</b></summary>

Connection details live in an operator-owned config — **never** in tool
arguments. Path: `$LINUX_AUDIT_CONFIG`, else `~/.config/linux-audit-mcp/targets.toml`.

```toml
[targets.web]
host = "203.0.113.10"           # required — hostname or IP
port = 22                        # default 22
user = "auditor"                 # default "auditor" (unprivileged)
identity_file = "~/.ssh/id_ed25519"   # SSH private key; ~ is expanded
strict_host_key = "accept-new"   # yes | accept-new (default) | no
connect_timeout_secs = 10        # default 10
command_timeout_secs = 30        # default 30
profile = "hardened"             # optional: baseline (default) | hardened
```

`$LINUX_AUDIT_IDENTITY_FILE`, if set, overrides `identity_file` for every target
— the Docker recipe uses it so `targets.toml` needs no in-container paths.

### Preparing a target host

The audit is read-only and unprivileged — no `sudoers` entry needed. On the host
you want to audit:

```bash
sudo useradd -m -s /bin/bash auditor
sudo -u auditor mkdir -p /home/auditor/.ssh
echo "ssh-ed25519 AAAA... you@laptop" | sudo tee -a /home/auditor/.ssh/authorized_keys
sudo chmod 700 /home/auditor/.ssh && sudo chmod 600 /home/auditor/.ssh/authorized_keys
sudo chown -R auditor:auditor /home/auditor/.ssh
```

Standard tools are expected on the target: `sshd_config`, `getent`, `sysctl`,
`ss`, `systemctl`, and (Debian/Ubuntu) `apt-get`.

</details>

<details>
<summary><b>Use it as a CLI</b></summary>

A one-off report in your terminal (also for cron / CI). Run the native binary — or
the exact same command inside the container:

```bash
# native binary
linux-audit-mcp audit --target web [OPTIONS]

# ...or via Docker (mounts + hardened flags: see "Docker image")
docker run -i --rm \
  -v ~/.config/linux-audit-mcp/targets.toml:/config/targets.toml:ro \
  -v ~/.ssh/audit_ed25519:/keys/id_ed25519:ro \
  ghcr.io/idesyatov/linux-audit-mcp:latest audit --target web [OPTIONS]
```

| Option         | Description                                                          |
| -------------- | ------------------------------------------------------------------- |
| `--target`     | Target alias from the config (required).                            |
| `--profile`    | `baseline` \| `hardened` — overrides the target's profile.          |
| `--format`     | `text` (default) \| `json`.                                         |
| `--config`     | Path to `targets.toml` (else `$LINUX_AUDIT_CONFIG` / default).      |
| `--fail-on`    | Exit 2 if any failed check is ≥ this severity. `off` disables. Default `high`. |
| `--fail-under` | Exit 2 if the total score is below this value (0–100).              |

Exit codes: `0` clean · `1` error · `2` a gate tripped. Example CI gate:

```bash
linux-audit-mcp audit --target web --format json --fail-on high --fail-under 70
```

</details>

<details>
<summary><b>Use it as an MCP server (Claude Desktop / Code)</b></summary>

Run with **no subcommand** and the binary becomes an MCP stdio server exposing the
tools `ping` and `run_audit`. Claude then invokes the audit itself — you ask in
chat, it audits and explains. Register it in `claude_desktop_config.json`, as a
native binary **or** via Docker (same result):

Native binary:

```json
{
  "mcpServers": {
    "linux-audit": {
      "command": "/usr/local/bin/linux-audit-mcp",
      "env": { "LINUX_AUDIT_CONFIG": "/home/you/.config/linux-audit-mcp/targets.toml" }
    }
  }
}
```

Docker (portable; mounts + hardened flags explained under **Docker image**):

```json
{
  "mcpServers": {
    "linux-audit": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/home/you/.config/linux-audit-mcp/targets.toml:/config/targets.toml:ro",
        "-v", "/home/you/.ssh/audit_ed25519:/keys/id_ed25519:ro",
        "ghcr.io/idesyatov/linux-audit-mcp:latest"
      ]
    }
  }
}
```

Just the two mounts — the image sets `LINUX_AUDIT_CONFIG`, `LINUX_AUDIT_IDENTITY_FILE`
and `HOME` by convention (see **Docker image**), so `targets.toml` stays
host-portable. To harden, insert `"--cap-drop=ALL", "--security-opt=no-new-privileges",
"--read-only", "--tmpfs", "/tmp",` after `"--rm",`, and pin `@sha256:<digest>`
instead of `:latest`.

Then ask, e.g. *"Run a hardened audit of `web` and summarise the High findings."*
The model calls `run_audit { "target": "web" }` and gets the text + JSON report.
`run_audit` only accepts a target **alias** — a prompt-injected model can't point
it at another host or key.

</details>

<details>
<summary><b>Docker image</b></summary>

`ghcr.io/idesyatov/linux-audit-mcp` (`linux/amd64`; tags `:X.Y.Z` and `:latest`,
Docker-style without the `v`). This is **the same binary in a container** — it runs
either front-end (CLI or MCP) shown above; Docker is packaging, not a separate
mode. It's a static binary on a minimal Alpine base with only an SSH client, runs
**non-root**, and contains **no keys**. (Apple Silicon / arm64 run it under
emulation for now.)

Just mount two things read-only — the image sets the rest by convention, so
`targets.toml` stays **host-portable** (no in-container paths in it):

- **config** → `-v ...targets.toml:/config/targets.toml:ro` (the image's
  `LINUX_AUDIT_CONFIG` points here).
- **your SSH key** → `-v ...audit_ed25519:/keys/id_ed25519:ro` (the image's
  `LINUX_AUDIT_IDENTITY_FILE` overrides the config's `identity_file` with this
  path, so you keep a normal `~/.ssh/...` value in `targets.toml`). Mount only the
  one audit key, never your whole `~/.ssh`.

A key bind-mounted from Windows/macOS shows up world-readable (0777), which ssh
would normally reject. The tool copies it to a private `0600` file inside the
container before use, so the plain `:ro` mount **just works** — you don't manage
key permissions. `HOME=/tmp` (also set in the image) gives that copy and
`known_hosts` a writable home.

Optional hardening flags — add to `docker run` (or the args list):

```text
--cap-drop=ALL --security-opt=no-new-privileges --read-only --tmpfs /tmp
```

Runs **non-root** (uid `10001`). Under `--read-only`, the `--tmpfs /tmp` keeps the
secured key copy and `known_hosts` writable.

Pin by digest (`@sha256:...`) instead of `:latest`, and verify the cosign (keyless)
signature CI attaches:

```bash
cosign verify ghcr.io/idesyatov/linux-audit-mcp:latest \
  --certificate-identity-regexp '^https://github.com/idesyatov/linux-audit-mcp' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

</details>

<details>
<summary><b>Checks</b></summary>

20 checks; each reads one read-only command and applies the tool/OpenSSH default
when a setting is absent. A command unavailable on the host (e.g. `apt-get` on
RHEL) is reported as `error` and excluded from the score.

| Domain    | Check id                       | Sev.     | Flags when…                                |
| --------- | ------------------------------ | -------- | ------------------------------------------ |
| ssh       | `ssh-permit-root-login`        | High     | `PermitRootLogin` is not `no`              |
| ssh       | `ssh-password-authentication`  | High     | `PasswordAuthentication` is not `no`       |
| ssh       | `ssh-permit-empty-passwords`   | High     | `PermitEmptyPasswords yes`                 |
| ssh       | `ssh-x11-forwarding`           | Low      | `X11Forwarding yes`                        |
| ssh       | `ssh-max-auth-tries`           | Low      | `MaxAuthTries` > 4                         |
| accounts  | `accounts-nonroot-uid0`        | Critical | a non-`root` account has UID 0             |
| accounts  | `accounts-pass-max-days`       | Low      | `PASS_MAX_DAYS` > 365 or unset             |
| accounts  | `accounts-umask`               | Low      | default `UMASK` allows group/other access  |
| kernel    | `kernel-aslr`                  | Medium   | `randomize_va_space` ≠ 2                    |
| kernel    | `kernel-tcp-syncookies`        | Low      | `tcp_syncookies` ≠ 1                        |
| kernel    | `kernel-rp-filter`             | Low      | `rp_filter` not 1/2                         |
| kernel    | `kernel-ip-forward`            | Medium   | `ip_forward` = 1 on a non-router           |
| kernel    | `kernel-accept-redirects`      | Low      | `accept_redirects` = 1                     |
| kernel    | `kernel-source-route`          | Low      | `accept_source_route` = 1                  |
| firewall  | `firewall-enabled`             | High     | no firewalld/ufw/nftables enabled          |
| updates   | `updates-security-pending`     | Medium   | pending security updates (apt)             |
| services  | `services-cleartext-ports`     | Medium   | telnet/ftp/r-services listening            |
| services  | `services-rpcbind`             | Low      | `rpcbind` enabled                          |
| logging   | `logging-auditd`               | Low      | `auditd` not enabled                       |
| logging   | `logging-syslog`               | Low      | no `rsyslog`/`syslog-ng` enabled           |

</details>

<details>
<summary><b>Scoring &amp; profiles</b></summary>

```text
S = clamp( Σ(weight_i × domain_score_i) − penalties, 0, 100 )
```

Each failed check deducts from its domain's score by severity (Low 5 · Medium 15
· High 30 · Critical 50); High/Critical also add a global penalty (8/20). Errored
checks are excluded. `hardened` shifts weight onto accounts/kernel/ssh and
multiplies penalties by ×1.5. Profile precedence: `--profile` / tool argument →
the target's `profile` → `baseline`.

| Domain   | `baseline` | `hardened` |
| -------- | ---------- | ---------- |
| ssh      | 0.20       | 0.22       |
| firewall | 0.15       | 0.15       |
| accounts | 0.15       | 0.20       |
| kernel   | 0.15       | 0.18       |
| services | 0.15       | 0.13       |
| updates  | 0.10       | 0.06       |
| logging  | 0.10       | 0.06       |

</details>

<details>
<summary><b>Read-only guarantee</b></summary>

Auditing must never change the host. Two layers, deny by default:

1. **Exact catalog** — every command a check issues must be a byte-for-byte member
   of a curated read-only catalog (`src/catalog.rs`); anything else is refused
   before it leaves the process.
2. **No shell injection** — the catalog also rejects shell metacharacters (the
   remote `sshd` runs commands through a shell), and SSH connection parameters are
   charset-validated so nothing can inject `ssh` options.

The design favors dumb readers (`cat <file>`, `sysctl -a`, `ss -tuln`) with all
parsing done in Rust. Commands requiring root are intentionally absent.

</details>

## Develop

No Rust needed — everything runs in Docker:

```bash
docker compose run --rm test    # unit + integration + per-distro evals
docker compose run --rm lint    # cargo fmt --check + clippy -D warnings
```

Architecture, diagrams and how to add a check: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).

## Tech stack

Rust (stable) · [`rmcp`](https://crates.io/crates/rmcp) (MCP stdio) · `tokio` ·
`clap` · `serde`. SSH via the system `ssh` subprocess (no C bindings).

## License

[MIT](LICENSE)
