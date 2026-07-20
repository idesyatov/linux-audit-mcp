# 🔒 linux-audit-mcp

![CI](https://github.com/idesyatov/linux-audit-mcp/actions/workflows/ci.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/idesyatov/linux-audit-mcp?sort=semver)
![License](https://img.shields.io/badge/license-MIT-blue)
![Rust](https://img.shields.io/badge/rust-stable-orange)

**Read-only checks for Linux servers, over SSH — in two modes:**

- 🛡️ **Security audit** — a weighted **0–100 hardening score** with concrete fixes.
  Run it when you set up or change a host.
- 📈 **Operational health** — a live **load / memory / disk / network** snapshot of
  one host or your **whole fleet** (host groups), flagged `OK`/`WARN`/`CRIT`. Run it
  on a schedule to keep a pulse on every server — each run is recorded and checked
  against the host's own baseline to surface **anomalies**.

Run either from your terminal, in cron/CI, or let **Claude** run it for you (it's an
MCP server). It connects with an SSH key you provide and issues only a curated set of
read-only commands, so it **cannot change the host**.

> **New to MCP?** The Model Context Protocol lets AI apps call external tools — as
> an MCP server, Claude Desktop/Code runs the checks itself and explains the result
> ("audit web", "is anything under load?"). Prefer a plain command? The CLI does the
> same, no AI involved. Same tool, two front-ends; Docker just packages either one.

**Audit** — one host's security posture:

```text
Audit of 'web' [baseline]: score 53/100 (10 passed, 10 failed, 0 errored)
  domains: ssh 30, firewall 70, accounts 90, kernel 85, services 100, updates 100, logging 90
  [FAIL] high     ssh-permit-root-login — PermitRootLogin is 'yes' (root can log in over SSH).
           ↳ Set PermitRootLogin no; administer via an unprivileged account and sudo.
  [FAIL] medium   kernel-ip-forward — net.ipv4.ip_forward = 1 (a non-router should not forward packets).
  ...
```

**Health** — a live pulse across a whole group (`--group prod`):

```text
Health group 'prod' (3 hosts): 2 OK, 1 WARN, 0 CRIT, 0 error
=== db [WARN] ===
Health of 'db': WARN (operational, not a security score)
  [OK  ] health-load          0.30 per core (1m 0.30, 5m 0.28, 15m 0.25 over 4 core(s))
  [WARN] health-disk          88% on / (/ 88%, /data 55%)
  [OK  ] health-net-throughput ens3 rx 1.20 / tx 0.40 MiB/s
  ...
```

## Features

- **Read-only by construction** 🔒 — every command is a byte-for-byte member of a
  curated catalog and runs as an unprivileged user; the tool *cannot* change the host.
- **Security audit** — 24 checks across 7 domains (ssh, accounts, kernel, firewall,
  updates, services, logging), each with a severity and a concrete fix, rolled up
  into a weighted **0–100 score** with `baseline` / `hardened` profiles.
- **Operational health** — a separate snapshot of load, memory, disk, hot processes,
  connections and per-interface **network throughput** as `OK`/`WARN`/`CRIT`. Kept
  **out** of the security score (workload isn't a vulnerability).
- **Host groups** — Ansible-style inventory with shared vars; audit or snapshot a
  whole group concurrently.
- **Safe by design** — tools take a target *alias* or *group*, never a raw host or
  key, so a prompt-injected model can't redirect the connection.

## Quick start

The fastest path — **Docker, nothing to install** — in three steps. *(Prefer a
native binary? See **Installation** below. Want **Claude** to run it? See **Use it
as an MCP server**.)*

Check it runs:

```bash
docker run --pull always --rm ghcr.io/idesyatov/linux-audit-mcp:latest --version
```

### 1 · Prepare the target host

Once, on the server you want to audit — create an unprivileged user reachable by
your SSH key. The audit is read-only, so **no `sudo`/root is needed**:

```bash
sudo useradd -m -s /bin/bash auditor
sudo -u auditor mkdir -p /home/auditor/.ssh
echo "ssh-ed25519 AAAA... you@laptop" | sudo tee -a /home/auditor/.ssh/authorized_keys
sudo chmod 700 /home/auditor/.ssh && sudo chmod 600 /home/auditor/.ssh/authorized_keys
sudo chown -R auditor:auditor /home/auditor/.ssh
```

### 2 · Configure the target

In `~/.config/linux-audit-mcp/targets.toml` — one block per host:

```toml
[targets.web]
host = "203.0.113.10"                     # your server's IP or hostname
user = "auditor"                          # the unprivileged account from step 1
identity_file = "~/.ssh/audit_ed25519"    # your SSH private key
```

That's the whole minimum. Timeouts, profiles, health thresholds and **host
groups** are all optional — see **Configuration**.

### 3 · Run it

Mount the config and key read-only, then run either mode by alias. **Audit** a
host's security posture:

```bash
docker run --pull always --rm \
  -v ~/.config/linux-audit-mcp/targets.toml:/config/targets.toml:ro \
  -v ~/.ssh/audit_ed25519:/keys/id_ed25519:ro \
  ghcr.io/idesyatov/linux-audit-mcp:latest audit --target web
```

...or take a live **health** snapshot — of one host, or your **whole fleet** with
`--group` (same two mounts):

```bash
docker run --pull always --rm \
  -v ~/.config/linux-audit-mcp/targets.toml:/config/targets.toml:ro \
  -v ~/.ssh/audit_ed25519:/keys/id_ed25519:ro \
  ghcr.io/idesyatov/linux-audit-mcp:latest health --group all
```

**That's it.** From here:

- **Keep a pulse on the fleet** — run the health command from cron with
  `--fail-on-status warn`; it exits non-zero (alert-friendly) the moment any host
  crosses a threshold.
- **CI / JSON** — `--format json` plus gates (`--fail-on` / `--fail-under` for
  audit) → see **Use it as a CLI**.
- **Chat with Claude** — run either mode as an **MCP server** (see below).

<details>
<summary><b>Installation</b></summary>

Install on the machine you'll **run the auditor from** (not the target). Prebuilt,
signed archives are on the [Releases](https://github.com/idesyatov/linux-audit-mcp/releases)
page — or use the Docker image (see **Docker image**), or build from source.

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

### Groups (Ansible-style inventory)

Group hosts to audit or snapshot them all at once. A `[groups.<name>]` lists
`members` (target aliases) and may carry **shared vars** its members inherit, so
common settings live in one place:

```toml
[groups.mtproto]
user = "root"                         # inherited by every member
identity_file = "~/.ssh/audit_ed25519"
profile = "hardened"
members = ["web", "mt2", "mt3"]

[groups.mtproto.health]               # optional group-wide thresholds
la_per_core_warn = 2.0

[targets.web]
host = "203.0.113.10"                 # only what's unique per host

[targets.mt2]
host = "203.0.113.11"

[targets.mt3]
host = "203.0.113.12"
user = "audit"                        # override just for this host
```

Precedence per field: **host value → group value → built-in default**. A host
inheriting the same field from two groups with different values is a config error
(set it on the host to disambiguate). Run against a group with `--group mtproto`
(CLI) or `{ "group": "mtproto" }` (MCP); the implicit **`all`** group is every
target. Hosts in a group run **concurrently**, and one unreachable host doesn't
sink the rest — it's reported as an error line in the group report.

Optional per-target thresholds for the `health` / `inspect_load` snapshot (any
subset; omitted keys use the defaults shown):

```toml
[targets.web.health]
la_per_core_warn = 1.0    # 1-min load average per core
la_per_core_crit = 2.0
mem_used_warn_pct = 85    # memory in use (%)
mem_used_crit_pct = 95
swap_used_warn_pct = 50   # swap in use (%)
swap_used_crit_pct = 90
disk_warn_pct = 85        # filesystem capacity (%)
disk_crit_pct = 95
iowait_warn_pct = 20.0    # CPU time waiting on I/O (%) — host is disk-bound
iowait_crit_pct = 50.0
net_rx_warn_mibps = 0.0   # per-interface throughput (MiB/s); 0 disables (informational)
net_rx_crit_mibps = 0.0
net_tx_warn_mibps = 0.0
net_tx_crit_mibps = 0.0
net_sample_secs = 1       # gap between the two /proc/net/dev samples
top_n = 5                 # hot processes listed per resource
```

Optional per-target **anomaly detection** settings (compared against the host's
own recorded history; any subset, omitted keys use the defaults shown):

```toml
[targets.web.anomaly]
enabled = true      # master switch for this target
k = 3.5             # flag when the modified z-score (deviation in scaled-MAD units) >= k
rel_floor = 0.15    # ...and the change is at least this fraction of the baseline
min_samples = 8     # snapshots required before a metric is judged (else "warming up")
window = 100        # most-recent snapshots forming the baseline
```

### Preparing a target host

Create the unprivileged `auditor` user reachable by your key — see **Quick start ›
step 1**. No `sudoers` entry is needed (the audit is read-only). Standard tools are
expected on the target: `sshd_config`, `getent`, `sysctl`, `ss`, `systemctl`,
`uptime`, `free`, `df`, `ps`, `vmstat`, and (Debian/Ubuntu) `apt-get`.

</details>

<details>
<summary><b>Use it as a CLI</b></summary>

A one-off report in your terminal (also for cron / CI) — native binary:

```bash
linux-audit-mcp audit --target web [OPTIONS]
```

...or the same via Docker (mounts explained under **Docker image**):

```bash
docker run --rm \
  -v ~/.config/linux-audit-mcp/targets.toml:/config/targets.toml:ro \
  -v ~/.ssh/audit_ed25519:/keys/id_ed25519:ro \
  ghcr.io/idesyatov/linux-audit-mcp:latest audit --target web [OPTIONS]
```

| Option         | Description                                                          |
| -------------- | ------------------------------------------------------------------- |
| `--target`     | Single target alias (this **or** `--group`).                        |
| `--group`      | Group name — audits every member concurrently (or `all`).           |
| `--profile`    | `baseline` \| `hardened` — overrides the target's profile.          |
| `--format`     | `text` (default) \| `json`.                                         |
| `--config`     | Path to `targets.toml` (else `$LINUX_AUDIT_CONFIG` / default).      |
| `--fail-on`    | Exit 2 if any failed check is ≥ this severity. `off` disables. Default `high`. |
| `--fail-under` | Exit 2 if the total score is below this value (0–100).              |

For a group, exit code is the strongest signal across hosts: a tripped gate (2)
dominates, else an unreachable host (1), else clean (0).

Exit codes: `0` clean · `1` error · `2` a gate tripped. Example CI gate:

```bash
linux-audit-mcp audit --target web --format json --fail-on high --fail-under 70
```

### Operational-health snapshot

`health` takes a point-in-time snapshot (load, memory, disk, hot processes,
connections) — reported **separately** from the security audit, with no 0–100
score:

```bash
linux-audit-mcp health --target web            # text (default) or --format json
```

| Option            | Description                                                     |
| ----------------- | -------------------------------------------------------------- |
| `--target`        | Single target alias (this **or** `--group`).                   |
| `--group`         | Group name — snapshots every member concurrently (or `all`).   |
| `--format`        | `text` (default) \| `json`.                                    |
| `--config`        | Path to `targets.toml` (else `$LINUX_AUDIT_CONFIG` / default). |
| `--fail-on-status`| Exit 2 when overall status is at least `warn` / `crit`. `off` (default) never gates. |
| `--no-store`      | Do not append this snapshot to the on-disk history.            |

Thresholds are per-target (see **Configuration**). Each snapshot is also
**recorded** to a per-target history file (see **Health history**), and compared
against this host's own recent norm — see **Anomaly detection** below.

</details>

<details>
<summary><b>Health history</b></summary>

Every `health` run (and every `inspect_load` MCP call) appends its snapshot to an
append-only JSONL file per target — one line per run — so you can inspect trends.
`history` prints the recent readings:

```bash
linux-audit-mcp history --target web              # text table (or --format json)
linux-audit-mcp history --target web --limit 50
```

| Option     | Description                                                          |
| ---------- | ------------------------------------------------------------------- |
| `--target` | Target alias whose recorded history to show (required).             |
| `--limit`  | Most-recent snapshots to show (default `20`; `0` for all).          |
| `--format` | `text` (default) \| `json`.                                         |
| `--config` | Path to `targets.toml` (else `$LINUX_AUDIT_CONFIG` / default).      |

Storage location: `$LINUX_AUDIT_DATA_DIR`, else
`~/.local/share/linux-audit-mcp/history/<alias>.jsonl`. Retention is automatic —
only the newest `$LINUX_AUDIT_HISTORY_MAX` snapshots per target are kept
(default `1000`; `0` keeps all), so the files never grow unbounded.

The image already sets `LINUX_AUDIT_DATA_DIR=/data` and pre-owns `/data` as the
non-root user, so to persist history across runs just mount **any** volume there
— one extra `-v`, no `-e`, named or bind:

```bash
docker run --rm \
  -v ~/.config/linux-audit-mcp/targets.toml:/config/targets.toml:ro \
  -v ~/.ssh/audit_ed25519:/keys/id_ed25519:ro \
  -v linux-audit-history:/data \
  ghcr.io/idesyatov/linux-audit-mcp:latest health --group all
```

</details>

<details>
<summary><b>Anomaly detection</b></summary>

Once enough history has accumulated, every `health` run compares the fresh
reading against **this host's own recent norm** and flags metrics that deviate —
a real anomaly is a departure from the host's baseline, not the crossing of a
global threshold. The baseline is **robust**: the median and median absolute
deviation (MAD) over the recent window, so a single transient spike does not
poison the norm. A metric is flagged only when it is both statistically far from
the median (modified z-score ≥ `k`) **and** materially large (≥ `rel_floor` of
the baseline), which keeps stable metrics quiet.

Anomalies show up as an `ANOMALY` block in the health report (and an `anomalies`
array in the JSON). They are **informational only** — an anomaly is an unusual
workload, not a hardening regression, so it never changes the health `overall`
status, the exit code, or the security score. Until a target has at least
`min_samples` snapshots you'll see a `baseline warming up (n/min)` note instead.

```text
Health of 'db': WARN (operational, not a security score)
  [WARN] health-disk           88% on / (/ 88%)
  ...
  ANOMALY vs baseline (1), informational:
    health-load          3.90 vs median 0.35 (+1014%, z=11.2)
```

Tunable per target (see **Configuration**): `enabled`, `k` (default `3.5`),
`rel_floor` (`0.15`), `min_samples` (`8`), `window` (`100`).

</details>

<details>
<summary><b>Use it as an MCP server (Claude Desktop / Code)</b></summary>

Run with **no subcommand** and the binary becomes an MCP stdio server exposing the
tools `ping`, `run_audit` and `inspect_load` (the operational-health snapshot,
reported separately from the security score). Claude then invokes them itself —
you ask in chat, it audits and explains. Register it in
`claude_desktop_config.json`, as a native binary **or** via Docker (same result):

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
Or *"Is `web` under load right now?"* → `inspect_load { "target": "web" }`, or for
a whole group *"Check load on all mtproto hosts"* → `inspect_load { "group":
"mtproto" }`. Both tools accept only a target **alias** or a **group** name from
the config — a prompt-injected model can't point them at another host or key.

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

24 checks; each reads one read-only command and applies the tool/OpenSSH default
when a setting is absent. A command unavailable on the host (e.g. `apt-get` on
RHEL) is reported as `error` and excluded from the score. Checks marked 🔑 are
**privileged** (need `sudo`) and run only on targets opted in with
`privileged = true` — otherwise they are `skipped` (see **Privileged checks**).

| Domain    | Check id                       | Sev.     | Flags when…                                |
| --------- | ------------------------------ | -------- | ------------------------------------------ |
| ssh       | `ssh-permit-root-login`        | High     | `PermitRootLogin` is not `no`              |
| ssh       | `ssh-password-authentication`  | High     | `PasswordAuthentication` is not `no`       |
| ssh       | `ssh-permit-empty-passwords`   | High     | `PermitEmptyPasswords yes`                 |
| ssh       | `ssh-x11-forwarding`           | Low      | `X11Forwarding yes`                        |
| ssh       | `ssh-max-auth-tries`           | Low      | `MaxAuthTries` > 4                         |
| ssh       | `ssh-weak-crypto`              | Medium   | weak `Ciphers`/`MACs`/`KexAlgorithms` set (effective set on 🔑 privileged targets) |
| accounts  | `accounts-nonroot-uid0`        | Critical | a non-`root` account has UID 0             |
| accounts  | `accounts-pass-max-days`       | Low      | `PASS_MAX_DAYS` > 365 or unset             |
| accounts  | `accounts-umask`               | Low      | default `UMASK` allows group/other access  |
| accounts  | `accounts-shadow-empty-password` 🔑 | Critical | an account has an empty `/etc/shadow` password |
| kernel    | `kernel-aslr`                  | Medium   | `randomize_va_space` ≠ 2                    |
| kernel    | `kernel-tcp-syncookies`        | Low      | `tcp_syncookies` ≠ 1                        |
| kernel    | `kernel-rp-filter`             | Low      | `rp_filter` not 1/2                         |
| kernel    | `kernel-ip-forward`            | Medium   | `ip_forward` = 1 on a non-router (Docker/container hosts are auto-detected and excused) |
| kernel    | `kernel-accept-redirects`      | Low      | `accept_redirects` = 1                     |
| kernel    | `kernel-source-route`          | Low      | `accept_source_route` = 1                  |
| firewall  | `firewall-enabled`             | High     | no firewalld/ufw/nftables enabled          |
| updates   | `updates-security-pending`     | Medium   | pending security updates (apt)             |
| updates   | `updates-auto-updates`         | Low      | no automatic security-update service on    |
| services  | `services-cleartext-ports`     | Medium   | telnet/ftp/r-services listening            |
| services  | `services-rpcbind`             | Low      | `rpcbind` enabled                          |
| services  | `services-fail2ban`            | Low      | `fail2ban` not enabled                     |
| logging   | `logging-auditd`               | Low      | `auditd` not enabled                       |
| logging   | `logging-syslog`               | Low      | no `rsyslog`/`syslog-ng` enabled           |

</details>

<details>
<summary><b>Privileged checks (🔑, opt-in)</b></summary>

A few checks need root to read (`/etc/shadow`, …). They are **off by default** and
run only on targets you explicitly opt in:

```toml
[targets.web]
host = "203.0.113.10"
privileged = true          # enable sudo-based checks for this host
```

They run as `sudo -n <read-only command>` — **`-n` never prompts**. A host that
isn't opted in never receives the command and the check is `skipped` (never a
hang). Nothing else changes: the commands are still exact members of the
read-only catalog, and the model still only ever picks a target *alias*.

Opting in also **upgrades the SSH domain**: every ssh-domain check reads the
*effective* config from `sudo -n sshd -T` (compiled defaults **and** `Match`
blocks resolved) instead of parsing `/etc/ssh/sshd_config`, so `ssh-weak-crypto`
and friends become authoritative. If that command isn't granted, the ssh checks
fall back to the file — the audit never breaks.

Grant the auditor **passwordless sudo for exactly these commands** — never `ALL`.
On the target (`visudo -f /etc/sudoers.d/linux-audit`):

```
auditor ALL=(root) NOPASSWD: /usr/bin/cat /etc/shadow, /usr/sbin/sshd -T
```

Skipped checks are excluded from the score (like `error`); the report shows them
as `[SKIP]` with an `N skipped` note. Opt in per host or per group (the flag is
inherited like other group vars).

</details>

<details>
<summary><b>Operational health</b></summary>

A separate, read-only snapshot (`health` CLI / `inspect_load` MCP tool) using the
same target aliases and command catalog. It reports metrics as `OK`/`WARN`/`CRIT`
against per-target thresholds (see **Configuration**) plus the top processes by
CPU and memory — and deliberately produces **no** 0–100 score, so momentary
workload never colours the security posture. A missing/unparseable input is
reported `UNKNOWN` and never gates.

| Metric id             | Reads (unprivileged)                       | Warn/Crit when…                          |
| --------------------- | ------------------------------------------ | ---------------------------------------- |
| `health-load`         | `uptime`, `nproc`                          | 1-min load per core ≥ threshold          |
| `health-memory`       | `free -b`                                  | memory in use % ≥ threshold              |
| `health-swap`         | `free -b`                                  | swap in use % ≥ threshold                |
| `health-disk`         | `df -P`                                    | worst real filesystem % ≥ threshold      |
| `health-iowait`       | `vmstat 1 2`                               | CPU I/O-wait % ≥ threshold (disk-bound host) |
| `health-connections`  | `ss -s`                                    | informational (established/total count)  |
| `health-net-throughput` | `cat /proc/net/dev` (×2, ~1s apart)      | per-interface rx/tx MiB/s; informational unless net thresholds set |

Hot processes come from `ps -eo pid,comm,pcpu,pmem`. Two metrics need a timed
sample: `vmstat 1 2` takes a one-second CPU sample for I/O-wait, and network
throughput samples the interface counters **twice** (`net_sample_secs` apart, ~1s)
for the delta — so the snapshot takes a second or two longer. Each
reading is also compared against the host's recorded baseline (median + MAD) — see
**Anomaly detection**.

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
