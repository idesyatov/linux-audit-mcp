//! Tolerant parsers for the operational-health probes.
//!
//! Same discipline as [`crate::checks::parse`]: dumb readers on the host, all
//! structure recovered here in Rust so every probe is unit-tested against
//! captured output without a live host.

/// The three load averages (1/5/15 min) from `uptime`.
///
/// Tolerant of both `.` and `,` decimals: after `load average:` each of the
/// first three whitespace tokens is stripped of separator commas and parsed.
pub fn parse_load_average(output: &str) -> Option<[f64; 3]> {
    let tail = output.split("load average:").nth(1)?;
    let mut vals = tail.split_whitespace().filter_map(|tok| {
        let t = tok.trim_matches(',');
        // A decimal-comma locale leaves an inner comma (e.g. "0,15"); a
        // dot-decimal token has none. Normalize either to a dot.
        let t = if t.contains(',') {
            t.replacen(',', ".", 1)
        } else {
            t.to_string()
        };
        t.parse::<f64>().ok()
    });
    Some([vals.next()?, vals.next()?, vals.next()?])
}

/// CPU count from `nproc`.
pub fn parse_nproc(output: &str) -> Option<u32> {
    output.trim().lines().next()?.trim().parse().ok()
}

/// Names of failed systemd units from `systemctl list-units --state=failed
/// --no-legend`. Each line is `UNIT LOAD ACTIVE SUB DESCRIPTION`, optionally
/// prefixed with a status bullet (`●`/`*`); the unit name is the first token and
/// always contains a `.` (e.g. `nginx.service`). Blank lines and any stray
/// non-unit line are skipped, so empty output (no failed units) yields `[]`.
pub fn parse_failed_units(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let unit = line
                .trim()
                .trim_start_matches(['●', '*', ' '])
                .split_whitespace()
                .next()?;
            unit.contains('.').then(|| unit.to_string())
        })
        .collect()
}

/// Containers in a broken state from `docker ps -a` / `podman ps -a` table
/// output. Returns `(name, state)` where state is `"restarting"` (crash loop) or
/// `"unhealthy"` (failing healthcheck). The container name is the last column;
/// the STATUS keywords are matched anywhere on the line, so exact column
/// alignment doesn't matter (STATUS/PORTS contain spaces and resist splitting).
/// The header and healthy/stopped (`Up`/`Exited`) containers are skipped.
pub fn parse_container_problems(output: &str) -> Vec<(String, &'static str)> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with("CONTAINER ID") {
                return None;
            }
            let name = line.split_whitespace().last()?;
            if line.contains("Restarting") {
                Some((name.to_string(), "restarting"))
            } else if line.contains("(unhealthy)") {
                Some((name.to_string(), "unhealthy"))
            } else {
                None
            }
        })
        .collect()
}

/// Uptime in whole seconds for the running containers in `docker ps -a` /
/// `podman ps -a` output: `(name, uptime_secs)` for every `Up` container. The
/// value is coarse - docker humanizes the STATUS (`Up 2 days`, `Up About an
/// hour`, `Up 40 seconds`) - but a restart resets it to a small value, so a drop
/// versus the previous snapshot reveals a restart (see
/// [`crate::run::annotate_changes`]). Non-running containers (Exited/Restarting/
/// Created) have no stable uptime and are skipped.
pub fn parse_container_uptimes(output: &str) -> Vec<(String, u64)> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with("CONTAINER ID") {
                return None;
            }
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let up_idx = tokens.iter().position(|t| *t == "Up")?;
            let secs = parse_up_duration(&tokens[up_idx + 1..])?;
            let name = tokens.last()?;
            Some((name.to_string(), secs))
        })
        .collect()
}

/// Parse the humanized duration that follows `Up` in a container STATUS into
/// seconds. Handles `2 days`, `a/an <unit>`, `About a/an <unit>`, and `Less than
/// a second`. Units are approximate (month = 30d, year = 365d) - only the trend
/// between snapshots matters. Unknown shapes yield `None`.
fn parse_up_duration(rest: &[&str]) -> Option<u64> {
    // "Less than a second"
    if rest.first() == Some(&"Less") {
        return Some(0);
    }
    // "About an hour" / "About a minute" -> the quantity is one.
    let (qty, unit) = if rest.first() == Some(&"About") {
        (1u64, *rest.get(2)?)
    } else {
        let qty = match *rest.first()? {
            "a" | "an" => 1,
            n => n.parse().ok()?,
        };
        (qty, *rest.get(1)?)
    };
    let per = match unit.trim_end_matches('s') {
        "second" => 1,
        "minute" => 60,
        "hour" => 3_600,
        "day" => 86_400,
        "week" => 604_800,
        "month" => 2_592_000,
        "year" => 31_536_000,
        _ => return None,
    };
    Some(qty * per)
}

/// Memory and swap totals in bytes, from `free -b`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemInfo {
    pub mem_total: u64,
    pub mem_used: u64,
    /// `available` column (modern procps); 0 if the column is absent.
    pub mem_available: u64,
    pub swap_total: u64,
    pub swap_used: u64,
}

/// Parse `free -b` (`Mem:`/`Swap:` rows). Columns:
/// `total used free shared buff/cache available`.
pub fn parse_free(output: &str) -> Option<MemInfo> {
    let num = |line: &str, idx: usize| -> Option<u64> {
        line.split_whitespace()
            .nth(idx)
            .and_then(|s| s.parse().ok())
    };
    let mut mem_total = None;
    let mut mem_used = None;
    let mut mem_available = 0u64;
    let mut swap_total = 0u64;
    let mut swap_used = 0u64;
    for line in output.lines() {
        let head = line.split_whitespace().next().unwrap_or("");
        match head {
            "Mem:" => {
                mem_total = num(line, 1);
                mem_used = num(line, 2);
                mem_available = num(line, 6).unwrap_or(0);
            }
            "Swap:" => {
                swap_total = num(line, 1).unwrap_or(0);
                swap_used = num(line, 2).unwrap_or(0);
            }
            _ => {}
        }
    }
    Some(MemInfo {
        mem_total: mem_total?,
        mem_used: mem_used?,
        mem_available,
        swap_total,
        swap_used,
    })
}

/// One filesystem row from `df -P`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub source: String,
    pub use_pct: u8,
    pub mount: String,
}

/// Parse `df -P` and drop pseudo-filesystems (tmpfs/overlay/`/dev`, `/run`,
/// `/sys`, `/proc` mounts) so disk pressure reflects real storage.
pub fn parse_df(output: &str) -> Vec<Mount> {
    output
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            // Filesystem 1024-blocks Used Available Capacity Mounted-on
            if f.len() < 6 || f[0] == "Filesystem" {
                return None;
            }
            let source = f[0].to_string();
            let use_pct: u8 = f[4].trim_end_matches('%').parse().ok()?;
            let mount = f[5..].join(" ");
            if matches!(source.as_str(), "tmpfs" | "devtmpfs" | "overlay" | "none")
                || ["/dev", "/run", "/sys", "/proc"]
                    .iter()
                    .any(|p| mount == *p || mount.starts_with(&format!("{p}/")))
            {
                return None;
            }
            Some(Mount {
                source,
                use_pct,
                mount,
            })
        })
        .collect()
}

/// Parse `/proc/sys/fs/file-nr` (`allocated  unused  max`) into
/// `(allocated, max)` open file descriptors. `unused` is ignored (it is 0 on
/// modern kernels). `None` if the two numbers can't be read.
pub fn parse_file_nr(output: &str) -> Option<(u64, u64)> {
    let f: Vec<&str> = output.split_whitespace().collect();
    let allocated = f.first()?.parse().ok()?;
    let max = f.get(2)?.parse().ok()?;
    Some((allocated, max))
}

/// Parse the two-line `cat nf_conntrack_count nf_conntrack_max` output into
/// `(count, max)` tracked connections. `None` if either number is missing (e.g.
/// the conntrack module isn't loaded, so the files don't exist).
pub fn parse_conntrack(output: &str) -> Option<(u64, u64)> {
    let mut nums = output.lines().filter_map(|l| l.trim().parse::<u64>().ok());
    Some((nums.next()?, nums.next()?))
}

/// Parse the `cat /proc/loadavg /proc/sys/kernel/pid_max` output into
/// `(tasks, pid_max)`. `tasks` is the total of loadavg's `running/total` field
/// (kernel scheduling entities: processes + threads), which consume PIDs;
/// `pid_max` is the ceiling they approach. `None` if either can't be read.
pub fn parse_pid_usage(output: &str) -> Option<(u64, u64)> {
    let mut lines = output.lines();
    let loadavg = lines.next()?;
    // "0.15 0.10 0.05 1/234 5678" -> field 3 is running/total.
    let tasks = loadavg
        .split_whitespace()
        .nth(3)?
        .split('/')
        .nth(1)?
        .parse()
        .ok()?;
    let pid_max = lines.next()?.trim().parse().ok()?;
    Some((tasks, pid_max))
}

/// Current TCP socket/memory usage and its ceilings, from `/proc/net/sockstat`
/// concatenated with `tcp_mem`, `tcp_max_orphans`, `tcp_max_tw_buckets`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockStat {
    /// TCP memory in pages (from `sockstat` `TCP: … mem N`).
    pub tcp_mem: u64,
    /// Max TCP memory in pages (3rd value of `tcp_mem`: min/pressure/max).
    pub tcp_mem_max: u64,
    pub orphan: u64,
    pub max_orphans: u64,
    pub tw: u64,
    pub max_tw: u64,
}

/// Parse the combined `cat /proc/net/sockstat <tcp_mem> <tcp_max_orphans>
/// <tcp_max_tw_buckets>` output. The `sockstat` lines are `Label: k v …`; the
/// three ceilings follow as bare number lines (no `:`), in that order. `None` if
/// the `TCP:` line or any ceiling is missing.
pub fn parse_sockstat(output: &str) -> Option<SockStat> {
    let (mut mem, mut orphan, mut tw) = (None, None, None);
    let mut ceilings: Vec<Vec<u64>> = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("TCP:") {
            let toks: Vec<&str> = rest.split_whitespace().collect();
            for pair in toks.chunks(2) {
                if let [k, v] = pair {
                    if let Ok(n) = v.parse::<u64>() {
                        match *k {
                            "mem" => mem = Some(n),
                            "orphan" => orphan = Some(n),
                            "tw" => tw = Some(n),
                            _ => {}
                        }
                    }
                }
            }
        } else if !line.contains(':') {
            let nums: Vec<u64> = line
                .split_whitespace()
                .filter_map(|t| t.parse().ok())
                .collect();
            if !nums.is_empty() {
                ceilings.push(nums);
            }
        }
    }
    Some(SockStat {
        tcp_mem: mem?,
        tcp_mem_max: *ceilings.first()?.get(2)?, // tcp_mem: min pressure max
        orphan: orphan?,
        max_orphans: *ceilings.get(1)?.first()?,
        tw: tw?,
        max_tw: *ceilings.get(2)?.first()?,
    })
}

/// Parse `ListenOverflows` and `ListenDrops` from `/proc/net/netstat` into
/// `(overflows, drops)` cumulative counts. The file has header/value line pairs
/// per section (`TcpExt:` names, then `TcpExt:` values); we find the columns by
/// name so kernel-version column shifts don't matter. `None` if the `TcpExt`
/// pair or either column is absent.
pub fn parse_netstat_listen(output: &str) -> Option<(u64, u64)> {
    let mut names: Option<Vec<&str>> = None;
    for line in output.lines() {
        let Some(rest) = line.strip_prefix("TcpExt:") else {
            continue;
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        match &names {
            None => names = Some(fields), // first TcpExt line = column names
            Some(cols) => {
                // second TcpExt line = values, in the same column order
                let ovf = fields.get(cols.iter().position(|c| *c == "ListenOverflows")?)?;
                let drops = fields.get(cols.iter().position(|c| *c == "ListenDrops")?)?;
                return Some((ovf.parse().ok()?, drops.parse().ok()?));
            }
        }
    }
    None
}

/// Parse `/proc/net/stat/nf_conntrack` into cumulative `(drop, early_drop,
/// insert_failed)` summed across CPUs. The first line is the column names, then
/// one hex-value line per CPU in the same order; columns are found by name (like
/// [`parse_netstat_listen`]) so kernel-version shifts don't matter, and values
/// are hex. `None` if none of the three drop-related columns exist or there are
/// no data rows. A missing column contributes 0 (older kernels lack some).
pub fn parse_conntrack_drops(output: &str) -> Option<(u64, u64, u64)> {
    let mut lines = output.lines();
    let header: Vec<&str> = lines.next()?.split_whitespace().collect();
    let idx = |name: &str| header.iter().position(|c| *c == name);
    let (di, ei, ii) = (idx("drop"), idx("early_drop"), idx("insert_failed"));
    if di.is_none() && ei.is_none() && ii.is_none() {
        return None;
    }
    let (mut drop, mut early, mut insf) = (0u64, 0u64, 0u64);
    let mut rows = 0usize;
    for line in lines {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        rows += 1;
        let get = |i: Option<usize>| {
            i.and_then(|i| f.get(i))
                .and_then(|v| u64::from_str_radix(v, 16).ok())
                .unwrap_or(0)
        };
        drop += get(di);
        early += get(ei);
        insf += get(ii);
    }
    (rows > 0).then_some((drop, early, insf))
}

/// Parse TCP stack-pressure counters from `/proc/net/netstat` into cumulative
/// `(abort_on_memory, prune_called, rcvq_drop)`. Same `TcpExt:` header/value pair
/// shape as [`parse_netstat_listen`], columns found by name. Tolerant: a column an
/// older kernel lacks contributes 0, so `None` means only that the `TcpExt` value
/// line is absent entirely.
pub fn parse_netstat_tcp_errors(output: &str) -> Option<(u64, u64, u64)> {
    let mut names: Option<Vec<&str>> = None;
    for line in output.lines() {
        let Some(rest) = line.strip_prefix("TcpExt:") else {
            continue;
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        match &names {
            None => names = Some(fields), // first TcpExt line = column names
            Some(cols) => {
                // second TcpExt line = values, in the same column order
                let val = |name: &str| {
                    cols.iter()
                        .position(|c| *c == name)
                        .and_then(|i| fields.get(i))
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(0)
                };
                return Some((
                    val("TCPAbortOnMemory"),
                    val("PruneCalled"),
                    val("TCPRcvQDrop"),
                ));
            }
        }
    }
    None
}

/// Parse `Tcp: RetransSegs` (cumulative TCP retransmitted segments) from
/// `/proc/net/snmp`. The file has a `Tcp:` name line then a `Tcp:` value line;
/// the `RetransSegs` column is found by name. `None` if the pair or column is
/// absent. Some `Tcp:` fields (e.g. `MaxConn`) are signed, but `RetransSegs` is a
/// counter, so `u64` is correct.
pub fn parse_snmp_tcp(output: &str) -> Option<u64> {
    let mut names: Option<Vec<&str>> = None;
    for line in output.lines() {
        let Some(rest) = line.strip_prefix("Tcp:") else {
            continue;
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        match &names {
            None => names = Some(fields),
            Some(cols) => {
                let i = cols.iter().position(|c| *c == "RetransSegs")?;
                return fields.get(i)?.parse().ok();
            }
        }
    }
    None
}

/// One kernel-log category with its hit count and most-recent matching line.
#[derive(Debug, Clone, PartialEq)]
pub struct KernelEventCategory {
    pub label: &'static str,
    pub count: usize,
    pub last_line: String,
    pub critical: bool,
}

/// Result of scanning the kernel ring buffer for curated failure signatures.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct KernelEvents {
    /// Matched categories, in signature order (only non-empty ones appear).
    pub categories: Vec<KernelEventCategory>,
}

impl KernelEvents {
    /// Total matched lines across all categories.
    pub fn total(&self) -> usize {
        self.categories.iter().map(|c| c.count).sum()
    }

    /// Whether any matched category is a critical (Crit-worthy) fault.
    pub fn any_critical(&self) -> bool {
        self.categories.iter().any(|c| c.critical)
    }
}

/// Curated kernel-log signatures: `(substring, category label, critical)`.
/// Deliberately conservative - kernel wording drifts across versions, so each
/// needle is chosen to avoid benign lines (e.g. the boot-time `Machine check
/// events logged` note is *not* matched; only an actual `Machine Check Exception`
/// / `Hardware Error` is). OOM kills are covered by `health-oom`, not here.
const KERNEL_SIGNATURES: &[(&str, &str, bool)] = &[
    ("soft lockup", "soft lockup", true),
    ("blocked for more than", "hung task", true),
    ("Kernel panic", "kernel panic", true),
    ("Hardware Error", "hardware error (MCE)", true),
    ("Machine Check Exception", "machine check exception", true),
    ("Oops", "kernel oops", true),
    ("BUG:", "kernel BUG", true),
    ("nf_conntrack: table full", "conntrack table full", false),
    (
        "neighbour table overflow",
        "neighbour table overflow",
        false,
    ),
    ("EXT4-fs error", "ext4 filesystem error", false),
    ("blk_update_request", "block I/O error", false),
];

/// Scan `dmesg` output for the curated [`KERNEL_SIGNATURES`]. Each line is counted
/// under the first signature it matches (specific patterns are ordered first), so
/// a `BUG: soft lockup` line lands in `soft lockup`, not `kernel BUG`. The most
/// recent matching line per category is kept for the report detail.
pub fn parse_kernel_events(output: &str) -> KernelEvents {
    let mut categories: Vec<KernelEventCategory> = Vec::new();
    for line in output.lines() {
        for (needle, label, critical) in KERNEL_SIGNATURES {
            if line.contains(needle) {
                match categories.iter_mut().find(|c| c.label == *label) {
                    Some(c) => {
                        c.count += 1;
                        c.last_line = line.trim().to_string();
                    }
                    None => categories.push(KernelEventCategory {
                        label,
                        count: 1,
                        last_line: line.trim().to_string(),
                        critical: *critical,
                    }),
                }
                break;
            }
        }
    }
    KernelEvents { categories }
}

/// One process row from `ps -eo pid,comm,pcpu,pmem`.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ProcInfo {
    pub pid: u32,
    pub comm: String,
    pub cpu: f64,
    pub mem: f64,
}

/// Parse `ps -eo pid,comm,pcpu,pmem --sort=-pcpu`.
pub fn parse_ps(output: &str) -> Vec<ProcInfo> {
    output
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 || f[0] == "PID" {
                return None;
            }
            Some(ProcInfo {
                pid: f[0].parse().ok()?,
                comm: f[1].to_string(),
                cpu: f[2].parse().ok()?,
                mem: f[3].parse().ok()?,
            })
        })
        .collect()
}

/// Count OOM-killer kills in `dmesg` output. The kernel logs one
/// `Out of memory: Kill process ...` / `Out of memory: Killed process ...` line
/// per victim (wording varies by kernel version), so counting that prefix counts
/// the kills. Matching `Out of memory: Kill` covers both spellings.
pub fn parse_oom_kills(output: &str) -> usize {
    output
        .lines()
        .filter(|l| l.contains("Out of memory: Kill"))
        .count()
}

/// Count zombie (defunct) processes in `ps -eo stat --no-headers` output. Each
/// line is a process's STAT field; the state is the leading letter, so `Z`
/// (optionally with modifiers like `Z+`, `Zl`) marks a zombie. Blank lines are
/// skipped.
pub fn parse_zombie_count(output: &str) -> usize {
    output
        .lines()
        .filter(|l| l.trim_start().starts_with('Z'))
        .count()
}

/// Cumulative RX/TX counters for one interface, from `/proc/net/dev`: bytes,
/// packets, errors and drops per direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetCounters {
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errs: u64,
    pub rx_drop: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errs: u64,
    pub tx_drop: u64,
}

/// Parse `cat /proc/net/dev` into `iface -> counters`. The two header lines and
/// the loopback interface are skipped. Columns after the `iface:` are receive
/// (`bytes` 0, `packets` 1, `errs` 2, `drop` 3, ...) then transmit (`bytes` 8,
/// `packets` 9, `errs` 10, `drop` 11, ...).
pub fn parse_net_dev(output: &str) -> std::collections::HashMap<String, NetCounters> {
    let mut map = std::collections::HashMap::new();
    for line in output.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue; // header lines have no colon
        };
        let iface = name.trim();
        if iface.is_empty() || iface == "lo" {
            continue;
        }
        let nums: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect();
        // Need through the transmit drop column (index 11).
        if nums.len() < 12 {
            continue;
        }
        map.insert(
            iface.to_string(),
            NetCounters {
                rx_bytes: nums[0],
                rx_packets: nums[1],
                rx_errs: nums[2],
                rx_drop: nums[3],
                tx_bytes: nums[8],
                tx_packets: nums[9],
                tx_errs: nums[10],
                tx_drop: nums[11],
            },
        );
    }
    map
}

/// Socket totals from `ss -s`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketSummary {
    pub total: u64,
    pub tcp_estab: u64,
}

/// Parse `ss -s` (`Total: N` and the `TCP:` line's `estab N`).
pub fn parse_ss_summary(output: &str) -> Option<SocketSummary> {
    let after = |hay: &str, needle: &str| -> Option<u64> {
        let rest = hay.split(needle).nth(1)?;
        let digits: String = rest
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        digits.parse().ok()
    };
    let mut total = None;
    let mut tcp_estab = 0u64;
    for line in output.lines() {
        if total.is_none() {
            if let Some(n) = after(line, "Total:") {
                total = Some(n);
            }
        }
        if line.trim_start().starts_with("TCP:") {
            if let Some(n) = after(line, "estab ") {
                tcp_estab = n;
            }
        }
    }
    Some(SocketSummary {
        total: total?,
        tcp_estab,
    })
}

/// CPU-pressure figures from the current (second) sample of `vmstat 1 2`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VmStat {
    /// `wa`: percent of CPU time waiting on I/O.
    pub iowait: f64,
    /// `st`: percent of CPU time stolen by the hypervisor (0 if absent).
    pub steal: f64,
    /// `b`: processes blocked on I/O.
    pub blocked: u64,
}

/// Parse `vmstat 1 2`. The column header (`... us sy id wa st`) is located by
/// name, so field order variations are tolerated, and the *last* all-numeric row
/// is used - i.e. the one-second delta, not the since-boot average in row one.
pub fn parse_vmstat(output: &str) -> Option<VmStat> {
    // Column indices for wa/st/b, taken from the name header.
    let mut cols: Option<(usize, Option<usize>, Option<usize>)> = None;
    let mut last_data: Option<Vec<f64>> = None;
    for line in output.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.is_empty() {
            continue;
        }
        // The name header is the row that labels the `wa` column.
        if toks.contains(&"wa") {
            let idx = |name: &str| toks.iter().position(|t| *t == name);
            if let Some(wa) = idx("wa") {
                cols = Some((wa, idx("st"), idx("b")));
            }
            continue;
        }
        // A data row is all-numeric; keep the last one seen.
        if toks.iter().all(|t| t.parse::<f64>().is_ok()) {
            last_data = Some(toks.iter().filter_map(|t| t.parse().ok()).collect());
        }
    }
    let (wa_i, st_i, b_i) = cols?;
    let data = last_data?;
    Some(VmStat {
        iowait: *data.get(wa_i)?,
        steal: st_i.and_then(|i| data.get(i)).copied().unwrap_or(0.0),
        blocked: b_i
            .and_then(|i| data.get(i))
            .map(|v| *v as u64)
            .unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_average_dot_and_comma() {
        let out = " 14:23:05 up 10 days,  3:45,  2 users,  load average: 0.15, 1.10, 2.05\n";
        assert_eq!(parse_load_average(out), Some([0.15, 1.10, 2.05]));
        let comma = "load average: 0,15, 1,10, 2,05";
        assert_eq!(parse_load_average(comma), Some([0.15, 1.10, 2.05]));
        assert_eq!(parse_load_average("no averages here"), None);
    }

    #[test]
    fn nproc() {
        assert_eq!(parse_nproc("4\n"), Some(4));
        assert_eq!(parse_nproc("  8 "), Some(8));
        assert_eq!(parse_nproc("x"), None);
    }

    #[test]
    fn failed_units() {
        // Empty output = no failed units.
        assert!(parse_failed_units("").is_empty());
        assert!(parse_failed_units("\n  \n").is_empty());
        // Plain lines and a leading status bullet are both handled.
        let out = "nginx.service    loaded failed failed A high performance web server\n\
                   ● docker.service loaded failed failed Docker Application Container Engine\n";
        assert_eq!(
            parse_failed_units(out),
            vec!["nginx.service".to_string(), "docker.service".to_string()]
        );
        // A stray non-unit line (no dot) is skipped.
        assert!(parse_failed_units("garbage line here\n").is_empty());
    }

    #[test]
    fn container_problems() {
        let out = "CONTAINER ID   IMAGE          COMMAND   CREATED       STATUS                       PORTS   NAMES\n\
                   a1b2c3d4e5f6   nginx:latest   \"...\"     2 days ago    Up 2 days                    80/tcp  web\n\
                   b2c3d4e5f6a7   redis:7        \"...\"     2 days ago    Up 2 days (healthy)          6379/tcp cache\n\
                   c3d4e5f6a7b8   postgres:16    \"...\"     3 days ago    Up 3 days (unhealthy)        5432/tcp db\n\
                   d4e5f6a7b8c9   proxy:latest   \"...\"     3 months ago  Restarting (2) 5 seconds ago 443/tcp mtproxy\n\
                   e5f6a7b8c9d0   old:latest     \"...\"     1 week ago    Exited (0) 3 days ago                stopped\n";
        let p = parse_container_problems(out);
        assert_eq!(
            p,
            vec![
                ("db".to_string(), "unhealthy"),
                ("mtproxy".to_string(), "restarting"),
            ]
        );
        // Header-only / empty output -> nothing.
        assert!(parse_container_problems(
            "CONTAINER ID   IMAGE   COMMAND   CREATED   STATUS   PORTS   NAMES\n"
        )
        .is_empty());
        assert!(parse_container_problems("").is_empty());
    }

    #[test]
    fn container_uptimes() {
        let out = "CONTAINER ID   IMAGE          COMMAND   CREATED       STATUS                       PORTS   NAMES\n\
                   a1b2c3d4e5f6   nginx:latest   \"...\"     2 days ago    Up 2 days                    80/tcp  web\n\
                   b2c3d4e5f6a7   redis:7        \"...\"     2 hours ago   Up About an hour (healthy)   6379/tcp cache\n\
                   c3d4e5f6a7b8   busy:16        \"...\"     1 min ago     Up 40 seconds                5432/tcp fresh\n\
                   d4e5f6a7b8c9   proxy:latest   \"...\"     3 months ago  Restarting (2) 5 seconds ago 443/tcp mtproxy\n\
                   e5f6a7b8c9d0   old:latest     \"...\"     1 week ago    Exited (0) 3 days ago                stopped\n";
        let up = parse_container_uptimes(out);
        assert_eq!(
            up,
            vec![
                ("web".to_string(), 172_800), // 2 days
                ("cache".to_string(), 3_600), // About an hour
                ("fresh".to_string(), 40),    // 40 seconds
            ]
        );
        // Restarting/Exited/Created have no stable uptime and are skipped.
        assert!(!up.iter().any(|(n, _)| n == "mtproxy" || n == "stopped"));
        // "Less than a second" -> 0, still tracked so a later restart is a drop.
        let sub = "CONTAINER ID x\nx img c cr Up Less than a second p tiny\n";
        assert_eq!(parse_container_uptimes(sub), vec![("tiny".to_string(), 0)]);
    }

    #[test]
    fn free_mem_and_swap() {
        let out = "              total        used        free      shared  buff/cache   available\n\
                   Mem:     8000000000  2000000000  1000000000    50000000  5000000000  5500000000\n\
                   Swap:    2000000000   500000000  1500000000\n";
        let m = parse_free(out).unwrap();
        assert_eq!(m.mem_total, 8_000_000_000);
        assert_eq!(m.mem_available, 5_500_000_000);
        assert_eq!(m.swap_total, 2_000_000_000);
        assert_eq!(m.swap_used, 500_000_000);
    }

    #[test]
    fn free_without_swap() {
        let out = "              total        used        free      shared  buff/cache   available\n\
                   Mem:     1000000000   400000000   200000000    10000000   400000000   500000000\n\
                   Swap:             0           0           0\n";
        let m = parse_free(out).unwrap();
        assert_eq!(m.swap_total, 0);
    }

    #[test]
    fn df_drops_pseudo_and_reads_capacity() {
        let out = "Filesystem     1024-blocks     Used Available Capacity Mounted on\n\
                   /dev/sda1         41251136 32000000   9251136      78% /\n\
                   tmpfs              4061728        0   4061728       0% /dev/shm\n\
                   devtmpfs           4000000        0   4000000       0% /dev\n\
                   /dev/sdb1        100000000 95000000   5000000      95% /data\n";
        let mounts = parse_df(out);
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].mount, "/");
        assert_eq!(mounts[0].use_pct, 78);
        assert_eq!(mounts[1].mount, "/data");
        assert_eq!(mounts[1].use_pct, 95);
    }

    #[test]
    fn file_nr_reads_allocated_and_max() {
        assert_eq!(
            parse_file_nr("8064\t0\t9223372036854775807\n"),
            Some((8064, 9_223_372_036_854_775_807))
        );
        assert_eq!(parse_file_nr("170000 0 200000"), Some((170_000, 200_000)));
        assert_eq!(parse_file_nr("garbage"), None);
    }

    #[test]
    fn conntrack_reads_count_and_max() {
        assert_eq!(parse_conntrack("12345\n262144\n"), Some((12345, 262_144)));
        assert_eq!(parse_conntrack("5"), None); // max line missing (module absent)
    }

    #[test]
    fn sockstat_reads_usage_and_ceilings() {
        let out = "sockets: used 431\n\
                   TCP: inuse 20 orphan 5 tw 34 alloc 25 mem 9000\n\
                   UDP: inuse 8 mem 1\n\
                   FRAG: inuse 0 memory 0\n\
                   4096 6144 9216\n\
                   65536\n\
                   16384\n";
        let s = parse_sockstat(out).unwrap();
        assert_eq!(s.tcp_mem, 9000);
        assert_eq!(s.tcp_mem_max, 9216); // 3rd tcp_mem value
        assert_eq!((s.orphan, s.max_orphans), (5, 65536));
        assert_eq!((s.tw, s.max_tw), (34, 16384));
        // Missing ceilings -> None.
        assert!(parse_sockstat("TCP: inuse 1 orphan 0 tw 0 mem 1\n").is_none());
    }

    #[test]
    fn netstat_listen_finds_columns_by_name() {
        let out = "TcpExt: SyncookiesSent ListenOverflows ListenDrops TCPHPHits\n\
                   TcpExt: 3 12 34 999\n\
                   IpExt: InNoRoutes InTruncatedPkts\n\
                   IpExt: 0 0\n";
        assert_eq!(parse_netstat_listen(out), Some((12, 34)));
        // No TcpExt value line -> None.
        assert_eq!(parse_netstat_listen("IpExt: A B\nIpExt: 1 2\n"), None);
    }

    #[test]
    fn conntrack_drops_sums_hex_across_cpus() {
        // Header + two CPU rows; values are hex. drop=0x0a+0x00=10,
        // early_drop=0x02+0x03=5, insert_failed=0x01+0x00=1.
        let out = "entries searched found new invalid ignore delete delete_list insert insert_failed drop early_drop\n\
                   0000004a 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001 0000000a 00000002\n\
                   0000004a 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000003\n";
        assert_eq!(parse_conntrack_drops(out), Some((10, 5, 1)));
        // No drop-related columns -> None.
        assert_eq!(
            parse_conntrack_drops("entries found\n00000001 00000002\n"),
            None
        );
        // Header only, no data rows -> None.
        assert_eq!(parse_conntrack_drops("entries drop early_drop\n"), None);
    }

    #[test]
    fn netstat_tcp_errors_finds_columns_by_name() {
        let out = "TcpExt: SyncookiesSent TCPAbortOnMemory PruneCalled TCPRcvQDrop TCPHPHits\n\
                   TcpExt: 3 7 12 4 999\n\
                   IpExt: InNoRoutes InTruncatedPkts\n\
                   IpExt: 0 0\n";
        assert_eq!(parse_netstat_tcp_errors(out), Some((7, 12, 4)));
        // Older kernel missing a column -> that column contributes 0.
        let old = "TcpExt: SyncookiesSent PruneCalled\n\
                   TcpExt: 3 12\n";
        assert_eq!(parse_netstat_tcp_errors(old), Some((0, 12, 0)));
        // No TcpExt value line -> None.
        assert_eq!(parse_netstat_tcp_errors("IpExt: A B\nIpExt: 1 2\n"), None);
    }

    #[test]
    fn snmp_tcp_reads_retrans_segs() {
        let out = "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens RetransSegs InErrs\n\
                   Tcp: 1 200 120000 -1 5 42 0\n\
                   Udp: InDatagrams NoPorts\n\
                   Udp: 100 2\n";
        assert_eq!(parse_snmp_tcp(out), Some(42));
        // No RetransSegs column -> None.
        assert_eq!(parse_snmp_tcp("Tcp: RtoMin\nTcp: 200\n"), None);
        // No Tcp value line -> None.
        assert_eq!(parse_snmp_tcp("Udp: InDatagrams\nUdp: 1\n"), None);
    }

    #[test]
    fn pid_usage_reads_tasks_and_max() {
        assert_eq!(
            parse_pid_usage("0.15 0.10 0.05 1/234 5678\n32768\n"),
            Some((234, 32768))
        );
        assert_eq!(parse_pid_usage("bad\n32768\n"), None);
    }

    #[test]
    fn ps_skips_header() {
        let out = "    PID COMMAND         %CPU %MEM\n\
                   \x20     1 systemd          0.0  0.1\n\
                   \x20   823 mysqld          12.3  8.4\n";
        let p = parse_ps(out);
        assert_eq!(p.len(), 2);
        assert_eq!(p[1].comm, "mysqld");
        assert_eq!(p[1].cpu, 12.3);
        assert_eq!(p[1].mem, 8.4);
    }

    #[test]
    fn zombie_count() {
        let out = "Ss\nR\nS\nZ\nS+\nZ+\nSl\n";
        assert_eq!(parse_zombie_count(out), 2);
        // No zombies.
        assert_eq!(parse_zombie_count("Ss\nR\nS+\n"), 0);
        assert_eq!(parse_zombie_count(""), 0);
    }

    #[test]
    fn oom_kills() {
        let out = "[12345.6] some driver message\n\
                   [12346.0] Out of memory: Killed process 4242 (mysqld) total-vm:...\n\
                   [12347.1] oom-killer: gfp_mask=0x...\n\
                   [20000.0] Out of memory: Kill process 999 (java) score 500\n";
        // Two victim lines (both spellings), not the oom-killer invocation line.
        assert_eq!(parse_oom_kills(out), 2);
        assert_eq!(parse_oom_kills("clean boot\n"), 0);
        assert_eq!(parse_oom_kills(""), 0);
    }

    #[test]
    fn kernel_events_categorize_and_rank() {
        let out = "[0.0] Linux version 6.1.0\n\
                   [1.2] EXT4-fs (vda1): mounted filesystem\n\
                   [3.4] EXT4-fs error (device vda1): ext4_find_entry: reading directory\n\
                   [5.6] nf_conntrack: table full, dropping packet\n\
                   [7.8] watchdog: BUG: soft lockup - CPU#0 stuck for 22s\n\
                   [9.0] mce: [Hardware Error]: CPU 0: Machine Check: 0 Bank 4\n";
        let ev = parse_kernel_events(out);
        assert_eq!(ev.total(), 4); // ext4-error, conntrack-full, soft-lockup, hardware-error
        assert!(ev.any_critical()); // soft lockup + hardware error are critical
                                    // The benign `EXT4-fs (vda1): mounted` line is NOT matched.
        let ext4 = ev
            .categories
            .iter()
            .find(|c| c.label == "ext4 filesystem error")
            .unwrap();
        assert_eq!(ext4.count, 1);
        assert!(!ext4.critical);
        // `BUG: soft lockup` lands in soft-lockup (ordered first), not kernel BUG.
        assert!(ev.categories.iter().any(|c| c.label == "soft lockup"));
        assert!(!ev.categories.iter().any(|c| c.label == "kernel BUG"));
        // A clean log -> nothing, not critical.
        let clean = parse_kernel_events("[0.0] booting\n[1.0] all good\n");
        assert_eq!(clean.total(), 0);
        assert!(!clean.any_critical());
    }

    #[test]
    fn ss_summary() {
        let out = "Total: 230\n\
                   TCP:   15 (estab 8, closed 2, orphaned 0, timewait 1)\n";
        let s = parse_ss_summary(out).unwrap();
        assert_eq!(s.total, 230);
        assert_eq!(s.tcp_estab, 8);
    }

    #[test]
    fn vmstat_uses_last_sample_by_column_name() {
        let out = "procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----\n\
                   \x20r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st\n\
                   \x201  0      0 600000 200000 150000    0    0     5    12   90  180  3  1 95  1  0\n\
                   \x204  2      0 590000 200000 150000    0    0   200   500  450  900 12  6 57 25  0\n";
        let v = parse_vmstat(out).unwrap();
        assert_eq!(v.iowait, 25.0); // second (delta) row, not the boot average
        assert_eq!(v.blocked, 2);
        assert_eq!(v.steal, 0.0);
    }

    #[test]
    fn vmstat_without_steal_column() {
        // Older/no-virt vmstat may omit `st`; steal defaults to 0.
        let out = " r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa\n\
                   \x203  1      0 800000 100000 300000    0    0   120   340  400  800 10  5 60 25\n";
        let v = parse_vmstat(out).unwrap();
        assert_eq!(v.iowait, 25.0);
        assert_eq!(v.steal, 0.0);
    }

    #[test]
    fn vmstat_garbage_is_none() {
        assert_eq!(parse_vmstat("no header here\n1 2 3\n"), None);
    }

    #[test]
    fn net_dev_skips_headers_and_lo() {
        let out = "Inter-|   Receive                                                |  Transmit\n\
                   \x20face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
                   \x20   lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n\
                   \x20 eth0: 500000 500 0 0 0 0 0 0 200000 400 0 0 0 0 0 0\n";
        let m = parse_net_dev(out);
        assert_eq!(m.len(), 1); // lo dropped
        let eth0 = m.get("eth0").unwrap();
        assert_eq!(eth0.rx_bytes, 500_000);
        assert_eq!(eth0.tx_bytes, 200_000);
    }
}
