//! Open-loop scheduler with coordinated-omission accounting.
//!
//! Request `k` is due at `T_scheduled = T0 + k * Δt`. The histogram records
//! `L_k = T_completed - T_scheduled`, which includes queueing behind a stalled
//! server. Service time `S_k = T_completed - T_actual_send` is kept separately
//! so a closed-loop tool's optimistic latency can be compared after the fact.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use hdrhistogram::Histogram;
use http::uri::PathAndQuery;
use quanta::Clock;
use tokio::sync::Semaphore;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;

use crate::cli::{Cli, Regime};
use crate::raw_codec::RawCodec;
use crate::report::{
    classify_status, is_admission_reject, new_histogram, Accuracy, StatusCounts, TrialReport,
};
use crate::telemetry::{self, Goodput, ProcessSample, WireThroughput};

const MODEL_INFER: &str = "/inference.GRPCInferenceService/ModelInfer";

#[derive(Debug, Clone)]
pub struct Payload {
    pub name: String,
    pub bytes: Bytes,
    pub malicious: bool,
}

#[derive(Debug, Clone)]
pub struct Corpus {
    pub benign: Vec<Payload>,
    pub malicious: Vec<Payload>,
}

impl Corpus {
    pub fn load(dir: &Path, benign_stem: &str) -> Result<Self> {
        let benign_dir = dir.join("benign");
        let malicious_dir = dir.join("malicious");
        let mut benign = load_dir(&benign_dir, false)?;
        if benign.is_empty() {
            return Err(anyhow!("no .pb payloads in {}", benign_dir.display()));
        }
        if let Some(index) = benign.iter().position(|p| p.name == benign_stem) {
            let chosen = benign.remove(index);
            benign.insert(0, chosen);
        } else if benign_stem != "all" {
            return Err(anyhow!(
                "benign payload `{benign_stem}` not found in {}",
                benign_dir.display()
            ));
        }
        let malicious = if malicious_dir.is_dir() {
            load_dir(&malicious_dir, true)?
        } else {
            Vec::new()
        };
        Ok(Self { benign, malicious })
    }

    pub fn select(&self, regime: Regime, index: u64, malicious_percent: u64) -> &Payload {
        match regime {
            Regime::SteadyBenign => &self.benign[0],
            Regime::Interleaved => {
                let period = (100 / malicious_percent.max(1)).max(1);
                if !self.malicious.is_empty() && index % period == period - 1 {
                    &self.malicious[(index / period) as usize % self.malicious.len()]
                } else {
                    &self.benign[0]
                }
            }
            Regime::SaturatingBurst => {
                if self.malicious.is_empty() {
                    &self.benign[0]
                } else {
                    &self.malicious[index as usize % self.malicious.len()]
                }
            }
        }
    }
}

fn load_dir(dir: &Path, malicious: bool) -> Result<Vec<Payload>> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("pb"))
        .collect();
    paths.sort();
    let mut payloads = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("payload")
            .to_string();
        payloads.push(Payload {
            name,
            bytes: Bytes::from(bytes),
            malicious,
        });
    }
    Ok(payloads)
}

#[derive(Debug)]
struct Observation {
    latency_ns: u64,
    service_ns: u64,
    malicious: bool,
    status: &'static str,
    tx_bytes: u64,
    rx_bytes: u64,
}

struct SharedHistograms {
    latency: Histogram<u64>,
    service: Histogram<u64>,
    benign: Histogram<u64>,
    malicious: Histogram<u64>,
    status: StatusCounts,
    benign_sent: u64,
    benign_rejected: u64,
    malicious_sent: u64,
    malicious_rejected: u64,
    tx_bytes: u64,
    rx_bytes: u64,
}

impl SharedHistograms {
    fn new() -> Self {
        Self {
            latency: new_histogram(),
            service: new_histogram(),
            benign: new_histogram(),
            malicious: new_histogram(),
            status: StatusCounts::default(),
            benign_sent: 0,
            benign_rejected: 0,
            malicious_sent: 0,
            malicious_rejected: 0,
            tx_bytes: 0,
            rx_bytes: 0,
        }
    }

    fn record(&mut self, obs: Observation) {
        self.latency.saturating_record(obs.latency_ns.max(1));
        self.service.saturating_record(obs.service_ns.max(1));
        classify_status(obs.status, &mut self.status);
        let rejected = is_admission_reject(obs.status);
        if obs.malicious {
            self.malicious.saturating_record(obs.latency_ns.max(1));
            self.malicious_sent += 1;
            if rejected {
                self.malicious_rejected += 1;
            }
        } else {
            self.benign.saturating_record(obs.latency_ns.max(1));
            self.benign_sent += 1;
            if rejected {
                self.benign_rejected += 1;
            }
        }
        self.tx_bytes += obs.tx_bytes;
        self.rx_bytes += obs.rx_bytes;
    }
}

pub async fn execute(cli: &Cli, clock: &Clock) -> Result<TrialReport> {
    let corpus = Corpus::load(&cli.corpus, &cli.batch)?;
    if cli.dry_run {
        return Ok(dry_report(cli, &corpus));
    }
    let path: PathAndQuery = cli
        .method
        .parse()
        .with_context(|| format!("invalid method path {}", cli.method))?;
    let endpoint = endpoint(&cli.target, cli.timeout_ms, cli.max_message_bytes)?;
    let channel = endpoint.connect().await.context("connecting to target")?;

    let stop = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicU64::new(0));
    let mut processes = telemetry::parse_watch_tokens(&cli.watch_pids);
    processes.extend(telemetry::resolve_names(&cli.watch_names));
    let sampler = telemetry::ProcSampler::new(processes, Duration::from_millis(cli.sample_ms.max(1)));
    let sampler_stop = Arc::clone(&stop);
    let sample_handle = if sampler.is_empty() {
        None
    } else {
        Some(tokio::task::spawn_blocking(move || sample_loop(sampler, sampler_stop)))
    };

    let nic_before = cli.net_iface.as_deref().and_then(|iface| telemetry::read_nic(iface).ok());
    let t0 = clock.raw();
    let started = std::time::Instant::now();

    let observations = match cli.regime {
        Regime::SaturatingBurst => {
            run_burst(cli, clock, &corpus, channel, path, t0, &stop, &completed).await?
        }
        Regime::SteadyBenign | Regime::Interleaved => {
            run_open_loop(cli, clock, &corpus, channel, path, t0, &stop, &completed).await?
        }
    };
    stop.store(true, Ordering::Relaxed);
    let elapsed = started.elapsed();
    let process_samples = match sample_handle {
        Some(handle) => handle.await.unwrap_or_default(),
        None => Vec::new(),
    };
    let wire = match (&cli.net_iface, nic_before) {
        (Some(iface), Some(before)) => telemetry::read_nic(iface)
            .ok()
            .map(|after| telemetry::wire_throughput(iface, before, after, elapsed)),
        _ => None,
    };

    Ok(assemble(cli, observations, elapsed, process_samples, wire))
}

fn sample_loop(mut sampler: telemetry::ProcSampler, stop: Arc<AtomicBool>) -> Vec<ProcessSample> {
    let interval = sampler.interval();
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(interval);
        sampler.poll();
    }
    sampler.poll();
    sampler.finish(0)
}

fn endpoint(target: &str, timeout_ms: u64, _max_message: usize) -> Result<Endpoint> {
    let mut endpoint = Endpoint::from_shared(target.to_string()).context("parsing target URI")?;
    endpoint = endpoint
        .timeout(Duration::from_millis(timeout_ms))
        .connect_timeout(Duration::from_secs(5))
        .http2_keep_alive_interval(Duration::from_secs(10))
        .tcp_nodelay(true)
        .concurrency_limit(65_536);
    Ok(endpoint)
}

#[allow(clippy::too_many_arguments)]
async fn run_open_loop(
    cli: &Cli,
    clock: &Clock,
    corpus: &Corpus,
    channel: Channel,
    path: PathAndQuery,
    t0: u64,
    stop: &AtomicBool,
    completed: &AtomicU64,
) -> Result<Vec<Observation>> {
    let rps = cli.rps.max(1);
    let interval_ns = 1_000_000_000u64 / rps;
    let limit = Arc::new(Semaphore::new(cli.concurrency.max(1)));
    let duration_ns = cli.duration_ns();
    let mut tasks = Vec::new();
    let mut index = 0u64;

    loop {
        if index >= cli.requests {
            break;
        }
        if let Some(bound) = duration_ns {
            let elapsed = clock.delta(t0, clock.raw()).as_nanos() as u64;
            if elapsed >= bound {
                break;
            }
        }
        let scheduled_ns = t0_offset(index, interval_ns);
        wait_until(clock, t0, scheduled_ns).await;

        let payload = corpus.select(cli.regime, index, cli.malicious_percent).clone();
        let permit = Arc::clone(&limit)
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("concurrency semaphore closed"))?;
        let mut grpc = tonic::client::Grpc::new(channel.clone())
            .max_decoding_message_size(cli.max_message_bytes)
            .max_encoding_message_size(cli.max_message_bytes);
        let path = path.clone();
        let clock = clock.clone();
        let timeout = Duration::from_millis(cli.timeout_ms);
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            let actual_send = clock.raw();
            let status = unary(&mut grpc, path, payload.bytes.clone(), timeout).await;
            let completed_at = clock.raw();
            let latency_ns = clock
                .delta(t0, completed_at)
                .as_nanos()
                .saturating_sub(scheduled_ns as u128) as u64;
            let service_ns = clock.delta(actual_send, completed_at).as_nanos() as u64;
            Observation {
                latency_ns,
                service_ns,
                malicious: payload.malicious,
                status: status.0,
                tx_bytes: payload.bytes.len() as u64,
                rx_bytes: status.1,
            }
        }));
        index += 1;
    }
    stop.store(true, Ordering::Relaxed);
    let mut observations = Vec::with_capacity(tasks.len());
    for task in tasks {
        if let Ok(obs) = task.await {
            completed.fetch_add(1, Ordering::Relaxed);
            observations.push(obs);
        }
    }
    Ok(observations)
}

#[allow(clippy::too_many_arguments)]
async fn run_burst(
    cli: &Cli,
    clock: &Clock,
    corpus: &Corpus,
    channel: Channel,
    path: PathAndQuery,
    t0: u64,
    stop: &AtomicBool,
    completed: &AtomicU64,
) -> Result<Vec<Observation>> {
    let n = cli.concurrency.max(1).min(cli.requests as usize);
    let mut tasks = Vec::with_capacity(n);
    for index in 0..n as u64 {
        let payload = corpus.select(Regime::SaturatingBurst, index, cli.malicious_percent).clone();
        let mut grpc = tonic::client::Grpc::new(channel.clone())
            .max_decoding_message_size(cli.max_message_bytes)
            .max_encoding_message_size(cli.max_message_bytes);
        let path = path.clone();
        let clock = clock.clone();
        let timeout = Duration::from_millis(cli.timeout_ms);
        tasks.push(tokio::spawn(async move {
            let actual_send = clock.raw();
            let status = unary(&mut grpc, path, payload.bytes.clone(), timeout).await;
            let completed_at = clock.raw();
            Observation {
                latency_ns: clock.delta(t0, completed_at).as_nanos() as u64,
                service_ns: clock.delta(actual_send, completed_at).as_nanos() as u64,
                malicious: payload.malicious,
                status: status.0,
                tx_bytes: payload.bytes.len() as u64,
                rx_bytes: status.1,
            }
        }));
    }
    let mut observations = Vec::with_capacity(tasks.len());
    for task in tasks {
        if let Ok(obs) = task.await {
            completed.fetch_add(1, Ordering::Relaxed);
            observations.push(obs);
        }
    }
    stop.store(true, Ordering::Relaxed);
    Ok(observations)
}

async fn unary(
    grpc: &mut tonic::client::Grpc<Channel>,
    path: PathAndQuery,
    payload: Bytes,
    timeout: Duration,
) -> (&'static str, u64) {
    let ready = tokio::time::timeout(timeout, grpc.ready()).await;
    if ready.is_err() {
        return ("DEADLINE_EXCEEDED", 0);
    }
    if let Err(_err) = ready.unwrap() {
        return ("TRANSPORT", 0);
    }
    let request = Request::new(payload);
    match tokio::time::timeout(timeout, grpc.unary(request, path, RawCodec)).await {
        Ok(Ok(response)) => ("OK", response.into_inner().len() as u64),
        Ok(Err(status)) => (status_label(&status), 0),
        Err(_) => ("DEADLINE_EXCEEDED", 0),
    }
}

fn status_label(status: &tonic::Status) -> &'static str {
    let message = status.message();
    if message.contains("400") {
        return "HTTP_400";
    }
    match status.code() {
        tonic::Code::Ok => "OK",
        tonic::Code::InvalidArgument => "INVALID_ARGUMENT",
        tonic::Code::Unavailable => "UNAVAILABLE",
        tonic::Code::Internal => "INTERNAL",
        tonic::Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
        _ => "OTHER",
    }
}

fn t0_offset(index: u64, interval_ns: u64) -> u64 {
    index.saturating_mul(interval_ns)
}

async fn wait_until(clock: &Clock, t0: u64, offset_ns: u64) {
    loop {
        let elapsed = clock.delta(t0, clock.raw()).as_nanos() as u64;
        if elapsed >= offset_ns {
            return;
        }
        let remain = offset_ns - elapsed;
        if remain > 1_500_000 {
            tokio::time::sleep(Duration::from_nanos(remain - 500_000)).await;
        } else if remain > 50_000 {
            tokio::task::yield_now().await;
        } else {
            std::hint::spin_loop();
        }
    }
}

fn assemble(
    cli: &Cli,
    observations: Vec<Observation>,
    elapsed: Duration,
    mut processes: Vec<ProcessSample>,
    wire: Option<WireThroughput>,
) -> TrialReport {
    let mut histograms = SharedHistograms::new();
    for obs in observations {
        histograms.record(obs);
    }
    let completed = histograms.latency.len();
    for proc in &mut processes {
        let per_thousand = if completed == 0 {
            0.0
        } else {
            1000.0 / completed as f64
        };
        proc.rss_per_1000_requests_kb = proc.avg_rss_kb as f64 * per_thousand;
        proc.cpu_per_1000_requests_percent = proc.avg_cpu_percent * per_thousand;
    }
    let secs = elapsed.as_secs_f64().max(1e-9);
    let goodput: Goodput = telemetry::goodput(histograms.tx_bytes, histograms.rx_bytes, elapsed);
    let separate = cli.regime == Regime::Interleaved;
    TrialReport {
        label: cli.label.clone(),
        regime: regime_name(cli.regime).to_string(),
        target: cli.target.clone(),
        rps: cli.rps,
        requests_requested: cli.requests,
        requests_completed: completed,
        elapsed_secs: secs,
        offered_rps: cli.rps as f64,
        achieved_rps: completed as f64 / secs,
        latency: crate::report::summarize("latency_co", &histograms.latency),
        service_time: crate::report::summarize("service_time", &histograms.service),
        benign_latency: separate.then(|| crate::report::summarize("benign", &histograms.benign)),
        malicious_latency: separate.then(|| crate::report::summarize("malicious", &histograms.malicious)),
        status: histograms.status,
        accuracy: Accuracy::from_counts(
            histograms.benign_sent,
            histograms.benign_rejected,
            histograms.malicious_sent,
            histograms.malicious_rejected,
        ),
        goodput,
        wire,
        processes,
    }
}

fn dry_report(cli: &Cli, corpus: &Corpus) -> TrialReport {
    let mut latency = new_histogram();
    let payload = corpus.select(cli.regime, 0, cli.malicious_percent);
    latency.saturating_record(payload.bytes.len() as u64);
    TrialReport {
        label: cli.label.clone(),
        regime: regime_name(cli.regime).to_string(),
        target: cli.target.clone(),
        rps: cli.rps,
        requests_requested: cli.requests,
        requests_completed: 0,
        elapsed_secs: 0.0,
        offered_rps: cli.rps as f64,
        achieved_rps: 0.0,
        latency: crate::report::summarize("latency_co", &latency),
        service_time: crate::report::summarize("service_time", &new_histogram()),
        benign_latency: None,
        malicious_latency: None,
        status: StatusCounts::default(),
        accuracy: Accuracy::default(),
        goodput: Goodput::default(),
        wire: None,
        processes: Vec::new(),
    }
}

pub fn regime_name(regime: Regime) -> &'static str {
    match regime {
        Regime::SteadyBenign => "steady-benign",
        Regime::Interleaved => "interleaved",
        Regime::SaturatingBurst => "saturating-burst",
    }
}

#[cfg(test)]
pub fn scheduled_offset_ns(index: u64, rps: u64) -> u64 {
    t0_offset(index, 1_000_000_000 / rps.max(1))
}

#[cfg(test)]
pub fn co_latency_ns(t0_ns: u64, scheduled_offset: u64, completed_ns: u64) -> u64 {
    completed_ns.saturating_sub(t0_ns.saturating_add(scheduled_offset))
}

#[allow(dead_code)]
pub fn default_method() -> &'static str {
    MODEL_INFER
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_corpus() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("custos-bench-corpus-{nanos}"));
        std::fs::create_dir_all(dir.join("benign")).unwrap();
        std::fs::create_dir_all(dir.join("malicious")).unwrap();
        std::fs::write(dir.join("benign/benign_b1.pb"), b"\x0a\x08resnet50").unwrap();
        std::fs::write(dir.join("benign/benign_b2.pb"), vec![0u8; 32]).unwrap();
        std::fs::write(dir.join("malicious/nesting_depth_17.pb"), b"\x2a\x02\x08\x01").unwrap();
        std::fs::write(dir.join("malicious/varint_truncated_eof.pb"), b"\x08\xff\xff\xff").unwrap();
        dir
    }

    #[test]
    fn loads_pb_files_and_prefers_the_requested_batch() {
        let dir = temp_corpus();
        let corpus = Corpus::load(&dir, "benign_b2").unwrap();
        assert_eq!(corpus.benign[0].name, "benign_b2");
        assert_eq!(corpus.malicious.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn interleaved_selection_is_one_percent_and_cycles() {
        let dir = temp_corpus();
        let corpus = Corpus::load(&dir, "benign_b1").unwrap();
        let mut malicious = 0;
        let mut names = Vec::new();
        for index in 0..200 {
            let payload = corpus.select(Regime::Interleaved, index, 1);
            if payload.malicious {
                malicious += 1;
                names.push(payload.name.clone());
            }
        }
        assert_eq!(malicious, 2);
        assert_eq!(names[0], "nesting_depth_17");
        assert_eq!(names[1], "varint_truncated_eof");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coordinated_omission_includes_scheduling_lag() {
        let t0 = 1_000_000u64;
        let scheduled = scheduled_offset_ns(10, 1000);
        assert_eq!(scheduled, 10_000_000);
        let completed = t0 + scheduled + 5_000_000;
        assert_eq!(co_latency_ns(t0, scheduled, completed), 5_000_000);
        let late_send_completed = t0 + scheduled + 50_000_000;
        assert_eq!(co_latency_ns(t0, scheduled, late_send_completed), 50_000_000);
    }

    #[test]
    fn burst_selects_only_malicious_payloads() {
        let dir = temp_corpus();
        let corpus = Corpus::load(&dir, "benign_b1").unwrap();
        let first = corpus.select(Regime::SaturatingBurst, 0, 1);
        let second = corpus.select(Regime::SaturatingBurst, 1, 1);
        assert!(first.malicious && second.malicious);
        assert_ne!(first.name, second.name);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
