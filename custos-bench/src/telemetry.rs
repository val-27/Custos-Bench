//! Network goodput, sysfs wire counters, and `/proc` resource samples.
//!
//! Sysfs and procfs paths only exist on Linux. On other hosts the samplers
//! return an empty snapshot instead of failing the run, so the harness can
//! still be compiled and unit-tested on the development machine.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct NicCounters {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WireThroughput {
    pub iface: String,
    pub elapsed_secs: f64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_mbps: f64,
    pub rx_mbps: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Goodput {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub elapsed_secs: f64,
    pub tx_mbps: f64,
    pub rx_mbps: f64,
    pub tx_gbps: f64,
    pub rx_gbps: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessSample {
    pub label: String,
    pub pid: u32,
    pub samples: u64,
    pub avg_cpu_percent: f64,
    pub peak_cpu_percent: f64,
    pub avg_rss_kb: u64,
    pub peak_rss_kb: u64,
    pub rss_per_1000_requests_kb: f64,
    pub cpu_per_1000_requests_percent: f64,
}

#[derive(Debug, Clone)]
pub struct WatchedProcess {
    pub label: String,
    pub pid: u32,
}

#[derive(Debug, Clone, Copy, Default)]
struct ProcTick {
    utime: u64,
    stime: u64,
    rss_kb: u64,
}

#[derive(Debug)]
struct ProcAccum {
    label: String,
    pid: u32,
    last: Option<ProcTick>,
    cpu_sum: f64,
    cpu_samples: u64,
    peak_cpu: f64,
    rss_sum: u128,
    rss_samples: u64,
    peak_rss: u64,
}

pub fn read_nic(iface: &str) -> std::io::Result<NicCounters> {
    let base = PathBuf::from("/sys/class/net").join(iface).join("statistics");
    Ok(NicCounters {
        tx_bytes: read_u64(&base.join("tx_bytes"))?,
        rx_bytes: read_u64(&base.join("rx_bytes"))?,
        tx_packets: read_u64(&base.join("tx_packets"))?,
        rx_packets: read_u64(&base.join("rx_packets"))?,
    })
}

fn read_u64(path: &Path) -> std::io::Result<u64> {
    let text = fs::read_to_string(path)?;
    text.trim()
        .parse::<u64>()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

pub fn wire_throughput(iface: &str, before: NicCounters, after: NicCounters, elapsed: Duration) -> WireThroughput {
    let secs = elapsed.as_secs_f64().max(1e-9);
    let tx = after.tx_bytes.saturating_sub(before.tx_bytes);
    let rx = after.rx_bytes.saturating_sub(before.rx_bytes);
    WireThroughput {
        iface: iface.to_string(),
        elapsed_secs: secs,
        tx_bytes: tx,
        rx_bytes: rx,
        tx_packets: after.tx_packets.saturating_sub(before.tx_packets),
        rx_packets: after.rx_packets.saturating_sub(before.rx_packets),
        tx_mbps: bytes_to_mbps(tx, secs),
        rx_mbps: bytes_to_mbps(rx, secs),
    }
}

pub fn goodput(tx_bytes: u64, rx_bytes: u64, elapsed: Duration) -> Goodput {
    let secs = elapsed.as_secs_f64().max(1e-9);
    let tx_mbps = bytes_to_mbps(tx_bytes, secs);
    let rx_mbps = bytes_to_mbps(rx_bytes, secs);
    Goodput {
        tx_bytes,
        rx_bytes,
        elapsed_secs: secs,
        tx_mbps,
        rx_mbps,
        tx_gbps: tx_mbps / 1000.0,
        rx_gbps: rx_mbps / 1000.0,
    }
}

fn bytes_to_mbps(bytes: u64, secs: f64) -> f64 {
    (bytes as f64) * 8.0 / secs / 1_000_000.0
}

/// Parse `--watch-pids` tokens. Accepted forms: `1234` and `triton:1234`.
pub fn parse_watch_tokens(tokens: &[String]) -> Vec<WatchedProcess> {
    let mut out = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let (label, pid_str) = if let Some((name, pid)) = token.split_once(':') {
            (name.to_string(), pid)
        } else {
            (format!("pid{index}"), token)
        };
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            out.push(WatchedProcess { label, pid });
        }
    }
    out
}

/// Resolve process names to PIDs by scanning `/proc/<pid>/comm`. Linux only.
pub fn resolve_names(names: &[String]) -> Vec<WatchedProcess> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return out;
    };
    let wanted: Vec<&str> = names.iter().map(|s| s.as_str().trim()).filter(|s| !s.is_empty()).collect();
    if wanted.is_empty() {
        return out;
    }
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        let comm_path = entry.path().join("comm");
        let Ok(comm) = fs::read_to_string(&comm_path) else {
            continue;
        };
        let comm = comm.trim();
        if wanted.contains(&comm) {
            out.push(WatchedProcess {
                label: comm.to_string(),
                pid,
            });
        }
    }
    out
}

fn read_proc_tick(pid: u32) -> std::io::Result<ProcTick> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let utime_stime = parse_utime_stime(&stat).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "unparseable /proc/pid/stat")
    })?;
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let rss_kb = parse_vm_rss_kb(&status).unwrap_or(0);
    Ok(ProcTick {
        utime: utime_stime.0,
        stime: utime_stime.1,
        rss_kb,
    })
}

/// `utime` is field 14 and `stime` is field 15 (1-based) of `/proc/pid/stat`.
/// The command field is wrapped in parentheses and may contain spaces.
pub fn parse_utime_stime(stat: &str) -> Option<(u64, u64)> {
    let end = stat.rfind(')')?;
    let rest = stat.get(end + 1..)?.trim();
    let mut fields = rest.split_whitespace();
    // After `)` the next field is state (field 3). utime is field 14, so skip 11.
    for _ in 0..11 {
        fields.next()?;
    }
    let utime = fields.next()?.parse().ok()?;
    let stime = fields.next()?.parse().ok()?;
    Some((utime, stime))
}

pub fn parse_vm_rss_kb(status: &str) -> Option<u64> {
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            let kb = value.split_whitespace().next()?;
            return kb.parse().ok();
        }
    }
    None
}

fn clock_ticks_per_sec() -> f64 {
    // POSIX CLK_TCK is 100 on Linux. libc::sysconf would be nicer but keeps
    // the dependency set smaller; 100 is the kernel default and the value
    // reported by `getconf CLK_TCK` on every supported testbed.
    100.0
}

pub struct ProcSampler {
    accums: Vec<ProcAccum>,
    interval: Duration,
}

impl ProcSampler {
    pub fn new(processes: Vec<WatchedProcess>, interval: Duration) -> Self {
        let accums = processes
            .into_iter()
            .map(|proc| ProcAccum {
                label: proc.label,
                pid: proc.pid,
                last: read_proc_tick(proc.pid).ok(),
                cpu_sum: 0.0,
                cpu_samples: 0,
                peak_cpu: 0.0,
                rss_sum: 0,
                rss_samples: 0,
                peak_rss: 0,
            })
            .collect();
        Self { accums, interval }
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn is_empty(&self) -> bool {
        self.accums.is_empty()
    }

    pub fn poll(&mut self) {
        let ticks = clock_ticks_per_sec();
        let window = self.interval.as_secs_f64().max(1e-6);
        for accum in &mut self.accums {
            let Ok(tick) = read_proc_tick(accum.pid) else {
                continue;
            };
            if let Some(prev) = accum.last {
                let cpu_ticks = tick.utime.saturating_sub(prev.utime) + tick.stime.saturating_sub(prev.stime);
                let cpu_pct = (cpu_ticks as f64 / ticks) / window * 100.0;
                accum.cpu_sum += cpu_pct;
                accum.cpu_samples += 1;
                if cpu_pct > accum.peak_cpu {
                    accum.peak_cpu = cpu_pct;
                }
            }
            accum.rss_sum += tick.rss_kb as u128;
            accum.rss_samples += 1;
            if tick.rss_kb > accum.peak_rss {
                accum.peak_rss = tick.rss_kb;
            }
            accum.last = Some(tick);
        }
    }

    pub fn finish(self, completed_requests: u64) -> Vec<ProcessSample> {
        let per_thousand = if completed_requests == 0 {
            0.0
        } else {
            1000.0 / completed_requests as f64
        };
        self.accums
            .into_iter()
            .map(|accum| {
                let avg_cpu = if accum.cpu_samples == 0 {
                    0.0
                } else {
                    accum.cpu_sum / accum.cpu_samples as f64
                };
                let avg_rss = if accum.rss_samples == 0 {
                    0
                } else {
                    (accum.rss_sum / accum.rss_samples as u128) as u64
                };
                ProcessSample {
                    label: accum.label,
                    pid: accum.pid,
                    samples: accum.rss_samples,
                    avg_cpu_percent: avg_cpu,
                    peak_cpu_percent: accum.peak_cpu,
                    avg_rss_kb: avg_rss,
                    peak_rss_kb: accum.peak_rss,
                    rss_per_1000_requests_kb: avg_rss as f64 * per_thousand,
                    cpu_per_1000_requests_percent: avg_cpu * per_thousand,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stat_with_spaces_in_comm() {
        let stat = "42 (my proc) R 1 1 1 0 -1 0 0 0 0 0 10 20 0 0 20 0 1 0 0 0 0 0 0 0 0";
        assert_eq!(parse_utime_stime(stat), Some((10, 20)));
    }

    #[test]
    fn parses_vmrss() {
        let status = "Name:\ttriton\nVmRSS:\t  204800 kB\nVmSize:\t 400000 kB\n";
        assert_eq!(parse_vm_rss_kb(status), Some(204800));
    }

    #[test]
    fn goodput_uses_decimal_megabits() {
        let g = goodput(1_000_000, 0, Duration::from_secs(1));
        assert!((g.tx_mbps - 8.0).abs() < 1e-9);
        assert!((g.tx_gbps - 0.008).abs() < 1e-9);
    }

    #[test]
    fn watch_tokens_accept_bare_and_named_pids() {
        let parsed = parse_watch_tokens(&[
            "11".into(),
            "envoy:22".into(),
            "custos:33".into(),
        ]);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[1].label, "envoy");
        assert_eq!(parsed[1].pid, 22);
    }

    #[test]
    fn wire_delta_ignores_counter_wrap_via_saturating_sub() {
        let before = NicCounters {
            tx_bytes: 100,
            rx_bytes: 50,
            tx_packets: 1,
            rx_packets: 1,
        };
        let after = NicCounters {
            tx_bytes: 100 + 125_000,
            rx_bytes: 50,
            tx_packets: 3,
            rx_packets: 1,
        };
        let wire = wire_throughput("lo", before, after, Duration::from_secs(1));
        assert!((wire.tx_mbps - 1.0).abs() < 1e-9);
        assert_eq!(wire.tx_packets, 2);
    }
}
