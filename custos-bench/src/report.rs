//! Terminal summary plus JSON and CSV percentile exports.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use hdrhistogram::Histogram;
use serde::Serialize;

use crate::telemetry::{Goodput, ProcessSample, WireThroughput};

pub const PERCENTILES: &[(&str, f64)] = &[
    ("p0", 0.0),
    ("p50", 50.0),
    ("p90", 90.0),
    ("p95", 95.0),
    ("p99", 99.0),
    ("p99.9", 99.9),
    ("p99.99", 99.99),
];

#[derive(Debug, Clone, Serialize)]
pub struct LatencySummary {
    pub name: String,
    pub count: u64,
    pub min_ns: u64,
    pub mean_ns: f64,
    pub max_ns: u64,
    pub stdev_ns: f64,
    pub percentiles_ns: Vec<Percentile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Percentile {
    pub label: String,
    pub percentile: f64,
    pub ns: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct StatusCounts {
    pub ok: u64,
    pub invalid_argument: u64,
    pub unavailable: u64,
    pub internal: u64,
    pub http_400: u64,
    pub deadline_exceeded: u64,
    pub other: u64,
    pub transport: u64,
}

impl StatusCounts {
    #[allow(dead_code)]
    pub fn total(&self) -> u64 {
        self.ok
            + self.invalid_argument
            + self.unavailable
            + self.internal
            + self.http_400
            + self.deadline_exceeded
            + self.other
            + self.transport
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Accuracy {
    pub benign_sent: u64,
    pub benign_rejected: u64,
    pub malicious_sent: u64,
    pub malicious_rejected: u64,
    pub false_positive_rate: f64,
    pub true_positive_drop_rate: f64,
}

impl Accuracy {
    pub fn from_counts(
        benign_sent: u64,
        benign_rejected: u64,
        malicious_sent: u64,
        malicious_rejected: u64,
    ) -> Self {
        let false_positive_rate = ratio(benign_rejected, benign_sent);
        let true_positive_drop_rate = ratio(malicious_rejected, malicious_sent);
        Self {
            benign_sent,
            benign_rejected,
            malicious_sent,
            malicious_rejected,
            false_positive_rate,
            true_positive_drop_rate,
        }
    }
}

fn ratio(numer: u64, denom: u64) -> f64 {
    if denom == 0 {
        0.0
    } else {
        numer as f64 / denom as f64
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TrialReport {
    pub label: String,
    pub regime: String,
    pub target: String,
    pub rps: u64,
    pub requests_requested: u64,
    pub requests_completed: u64,
    pub elapsed_secs: f64,
    pub offered_rps: f64,
    pub achieved_rps: f64,
    pub latency: LatencySummary,
    pub service_time: LatencySummary,
    pub benign_latency: Option<LatencySummary>,
    pub malicious_latency: Option<LatencySummary>,
    pub status: StatusCounts,
    pub accuracy: Accuracy,
    pub goodput: Goodput,
    pub wire: Option<WireThroughput>,
    pub processes: Vec<ProcessSample>,
}

pub fn summarize(name: &str, hist: &Histogram<u64>) -> LatencySummary {
    let percentiles_ns = if hist.is_empty() {
        PERCENTILES
            .iter()
            .map(|(label, percentile)| Percentile {
                label: (*label).to_string(),
                percentile: *percentile,
                ns: 0,
            })
            .collect()
    } else {
        PERCENTILES
            .iter()
            .map(|(label, percentile)| Percentile {
                label: (*label).to_string(),
                percentile: *percentile,
                ns: hist.value_at_percentile(*percentile),
            })
            .collect()
    };
    let max_ns = if hist.is_empty() { 0 } else { hist.max() };
    LatencySummary {
        name: name.to_string(),
        count: hist.len(),
        min_ns: hist.min(),
        mean_ns: if hist.is_empty() { 0.0 } else { hist.mean() },
        max_ns,
        stdev_ns: if hist.is_empty() { 0.0 } else { hist.stdev() },
        percentiles_ns,
    }
}

pub fn new_histogram() -> Histogram<u64> {
    Histogram::<u64>::new_with_bounds(1, 60_000_000_000, 3)
        .expect("1 ns .. 60 s with 3 significant figures is a valid histogram")
}

pub fn print_summary(report: &TrialReport, mut out: impl Write) -> io::Result<()> {
    writeln!(out, "custos-bench  {}", report.label)?;
    writeln!(
        out,
        "regime={}  target={}  offered={:.1} rps  achieved={:.1} rps  elapsed={:.3} s",
        report.regime, report.target, report.offered_rps, report.achieved_rps, report.elapsed_secs
    )?;
    writeln!(
        out,
        "completed={} / {}    goodput tx={:.3} Mbps ({:.6} Gbps)  rx={:.3} Mbps",
        report.requests_completed,
        report.requests_requested,
        report.goodput.tx_mbps,
        report.goodput.tx_gbps,
        report.goodput.rx_mbps
    )?;
    if let Some(wire) = &report.wire {
        writeln!(
            out,
            "wire iface={}  tx={:.3} Mbps  rx={:.3} Mbps  tx_pkts={}  rx_pkts={}",
            wire.iface, wire.tx_mbps, wire.rx_mbps, wire.tx_packets, wire.rx_packets
        )?;
    }
    write_latency_row(&mut out, &report.latency)?;
    write_latency_row(&mut out, &report.service_time)?;
    if let Some(benign) = &report.benign_latency {
        write_latency_row(&mut out, benign)?;
    }
    if let Some(malicious) = &report.malicious_latency {
        write_latency_row(&mut out, malicious)?;
    }
    let status = &report.status;
    writeln!(
        out,
        "status  ok={}  invalid_argument={}  http_400={}  unavailable={}  internal={}  deadline={}  other={}  transport={}",
        status.ok,
        status.invalid_argument,
        status.http_400,
        status.unavailable,
        status.internal,
        status.deadline_exceeded,
        status.other,
        status.transport
    )?;
    writeln!(
        out,
        "accuracy  FPR={:.6} ({}/{})  TP-drop={:.6} ({}/{})",
        report.accuracy.false_positive_rate,
        report.accuracy.benign_rejected,
        report.accuracy.benign_sent,
        report.accuracy.true_positive_drop_rate,
        report.accuracy.malicious_rejected,
        report.accuracy.malicious_sent
    )?;
    for proc in &report.processes {
        writeln!(
            out,
            "proc {:<12} pid={}  cpu avg={:.2}% peak={:.2}%  rss avg={} KiB peak={} KiB  per_1k_req cpu={:.4}% rss={:.1} KiB",
            proc.label,
            proc.pid,
            proc.avg_cpu_percent,
            proc.peak_cpu_percent,
            proc.avg_rss_kb,
            proc.peak_rss_kb,
            proc.cpu_per_1000_requests_percent,
            proc.rss_per_1000_requests_kb
        )?;
    }
    Ok(())
}

fn write_latency_row(out: &mut impl Write, summary: &LatencySummary) -> io::Result<()> {
    write!(
        out,
        "{:<18} n={:<8} min={:<12} mean={:<14.1} ",
        summary.name, summary.count, summary.min_ns, summary.mean_ns
    )?;
    for point in &summary.percentiles_ns {
        if point.label == "p0" {
            continue;
        }
        write!(out, "{}={:<12} ", point.label, point.ns)?;
    }
    writeln!(out, "max={}", summary.max_ns)
}

pub fn export(report: &TrialReport, dir: &Path) -> io::Result<(PathBuf, PathBuf)> {
    fs::create_dir_all(dir)?;
    let stem = sanitize(&report.label);
    let json_path = dir.join(format!("{stem}.json"));
    let csv_path = dir.join(format!("{stem}.csv"));
    let json = serde_json::to_string_pretty(report)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    fs::write(&json_path, json + "\n")?;
    fs::write(&csv_path, latency_csv(report))?;
    Ok((json_path, csv_path))
}

fn latency_csv(report: &TrialReport) -> String {
    let mut lines = Vec::new();
    lines.push(
        "series,count,min_ns,mean_ns,p0_ns,p50_ns,p90_ns,p95_ns,p99_ns,p99.9_ns,p99.99_ns,max_ns"
            .to_string(),
    );
    lines.push(csv_row(&report.latency));
    lines.push(csv_row(&report.service_time));
    if let Some(benign) = &report.benign_latency {
        lines.push(csv_row(benign));
    }
    if let Some(malicious) = &report.malicious_latency {
        lines.push(csv_row(malicious));
    }
    lines.join("\n") + "\n"
}

fn csv_row(summary: &LatencySummary) -> String {
    let mut cols = vec![
        summary.name.clone(),
        summary.count.to_string(),
        summary.min_ns.to_string(),
        format!("{:.3}", summary.mean_ns),
    ];
    for point in &summary.percentiles_ns {
        cols.push(point.ns.to_string());
    }
    cols.push(summary.max_ns.to_string());
    cols.join(",")
}

fn sanitize(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "trial".to_string()
    } else {
        out
    }
}

/// Classify a tonic status into the admission counters.
///
/// A malicious rejection is `INVALID_ARGUMENT` or an HTTP 400 mapped by the
/// proxy. Benign traffic that lands in either bucket is a false positive.
pub fn is_admission_reject(code: &str) -> bool {
    matches!(code, "INVALID_ARGUMENT" | "HTTP_400")
}

pub fn classify_status(code: &str, counts: &mut StatusCounts) {
    match code {
        "OK" => counts.ok += 1,
        "INVALID_ARGUMENT" => counts.invalid_argument += 1,
        "UNAVAILABLE" => counts.unavailable += 1,
        "INTERNAL" => counts.internal += 1,
        "HTTP_400" => counts.http_400 += 1,
        "DEADLINE_EXCEEDED" => counts.deadline_exceeded += 1,
        "TRANSPORT" => counts.transport += 1,
        _ => counts.other += 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_export_covers_the_scientific_set() {
        let mut hist = new_histogram();
        for value in [1_000u64, 2_000, 3_000, 10_000, 1_000_000] {
            hist.record(value).unwrap();
        }
        let summary = summarize("latency", &hist);
        let labels: Vec<_> = summary.percentiles_ns.iter().map(|p| p.label.as_str()).collect();
        assert_eq!(
            labels,
            ["p0", "p50", "p90", "p95", "p99", "p99.9", "p99.99"]
        );
        assert_eq!(summary.max_ns, hist.max());
        assert!(summary.min_ns <= 1_000);
    }

    #[test]
    fn accuracy_rates_are_ratios_of_rejected_to_sent() {
        let accuracy = Accuracy::from_counts(99, 1, 1, 1);
        assert!((accuracy.false_positive_rate - 1.0 / 99.0).abs() < 1e-12);
        assert!((accuracy.true_positive_drop_rate - 1.0).abs() < 1e-12);
    }

    #[test]
    fn admission_reject_is_invalid_argument_or_http_400() {
        assert!(is_admission_reject("INVALID_ARGUMENT"));
        assert!(is_admission_reject("HTTP_400"));
        assert!(!is_admission_reject("OK"));
        assert!(!is_admission_reject("UNAVAILABLE"));
    }
}
