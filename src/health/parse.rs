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

/// Cumulative RX/TX byte counters for one interface, from `/proc/net/dev`.
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
