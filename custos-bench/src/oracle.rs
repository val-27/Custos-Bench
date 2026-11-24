//! One-shot sweep of every manifest entry.
//!
//! Protobuf rows go through the tonic `RawCodec`, which adds the 5-byte gRPC
//! frame. `http-body` rows are the exact HTTP/2 DATA payload and are sent
//! with prior-knowledge h2c so a second frame is not wrapped around them.
//! Header-only RPC probes live in the manifest and are not `.pb` files under
//! `benign/` or `malicious/`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http::header::{CONTENT_TYPE, HOST};
use http::uri::PathAndQuery;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use quanta::Clock;
use serde::Deserialize;
use tokio::net::TcpStream;
use tonic::transport::Channel;

use crate::cli::{BackendKind, Cli, ProbeCell};
use crate::report::{oracle_matches, OracleRow, ProbeObservation, StudyMeta, TrialReport};
use crate::scheduler::{self, Corpus, Observation};

#[derive(Debug, Clone)]
pub(crate) struct OracleCase {
    pub name: String,
    pub expected: String,
    pub body: Bytes,
    #[allow(dead_code)]
    pub path: PathBuf,
    pub method: String,
    pub framing: String,
    pub role: String,
    pub pair_id: Option<String>,
    pub family: Option<String>,
    pub twin: Option<String>,
    pub mutation: Option<String>,
    pub eligible: bool,
    pub ineligible_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct EligiblePair {
    pub pair_id: String,
    pub family: String,
    pub mutation: String,
    pub attack: OracleCase,
    pub twin: OracleCase,
}

#[derive(Debug, Deserialize)]
struct ManifestFile {
    artifacts: Vec<ManifestArtifact>,
}

#[derive(Debug, Deserialize)]
struct ManifestArtifact {
    name: String,
    expected: String,
    pb_path: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default = "default_framing")]
    framing: String,
    #[serde(default = "default_role")]
    role: String,
    #[serde(default)]
    pair_id: Option<String>,
    #[serde(default)]
    family: Option<String>,
    #[serde(default)]
    twin: Option<String>,
    #[serde(default)]
    mutation: Option<String>,
    #[serde(default)]
    eligible: bool,
    #[serde(default)]
    ineligible_reason: Option<String>,
}

fn default_method() -> String {
    crate::cli::MODEL_INFER_PATH.to_string()
}

fn default_framing() -> String {
    "protobuf".to_string()
}

fn default_role() -> String {
    "background".to_string()
}

pub(crate) fn load_cases(corpus: &Path) -> Result<Vec<OracleCase>> {
    let manifest_path = corpus.join("manifest.json");
    let text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest: ManifestFile = serde_json::from_str(&text)
        .with_context(|| format!("parsing {}", manifest_path.display()))?;
    let mut cases = Vec::with_capacity(manifest.artifacts.len());
    for artifact in manifest.artifacts {
        if artifact.expected != "allow" && artifact.expected != "reject" {
            return Err(anyhow!(
                "{} has expected `{}`; the sweep accepts allow or reject",
                artifact.name,
                artifact.expected
            ));
        }
        if artifact.framing != "protobuf" && artifact.framing != "http-body" {
            return Err(anyhow!(
                "{} has framing `{}`; the sweep accepts protobuf or http-body",
                artifact.name,
                artifact.framing
            ));
        }
        let _: PathAndQuery = artifact
            .method
            .parse()
            .with_context(|| format!("invalid method path on {}", artifact.name))?;
        let path = resolve_payload(corpus, &artifact.pb_path)?;
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        cases.push(OracleCase {
            name: artifact.name,
            expected: artifact.expected,
            body: Bytes::from(bytes),
            path,
            method: artifact.method,
            framing: artifact.framing,
            role: artifact.role,
            pair_id: artifact.pair_id,
            family: artifact.family,
            twin: artifact.twin,
            mutation: artifact.mutation,
            eligible: artifact.eligible,
            ineligible_reason: artifact.ineligible_reason,
        });
    }
    if cases.is_empty() {
        return Err(anyhow!("manifest {} has no artifacts", manifest_path.display()));
    }
    Ok(cases)
}

/// Loads and validates all eligible `(attack, twin)` pairs from `corpus/manifest.json`.
/// Fails closed if any reject row is missing an eligibility classification or if an eligible
/// attack references a missing or non-allow twin.
pub(crate) fn load_eligible_pairs(corpus: &Path) -> Result<Vec<EligiblePair>> {
    let cases = load_cases(corpus)?;
    let by_name: HashMap<String, OracleCase> =
        cases.iter().map(|c| (c.name.clone(), c.clone())).collect();
    let mut seen_pair_ids = HashMap::new();
    let mut pairs = Vec::new();

    for case in &cases {
        if case.eligible {
            if case.role != "attack" || case.expected != "reject" {
                return Err(anyhow!(
                    "{} has eligible=true but role={} expected={}",
                    case.name,
                    case.role,
                    case.expected
                ));
            }
            let pair_id = case
                .pair_id
                .clone()
                .ok_or_else(|| anyhow!("eligible attack {} is missing pair_id", case.name))?;
            if let Some(prev) = seen_pair_ids.insert(pair_id.clone(), case.name.clone()) {
                return Err(anyhow!(
                    "duplicate pair_id `{pair_id}` on {} and {prev}",
                    case.name
                ));
            }
            let mutation = case
                .mutation
                .clone()
                .ok_or_else(|| anyhow!("eligible attack {} is missing mutation", case.name))?;
            let twin_name = case
                .twin
                .clone()
                .ok_or_else(|| anyhow!("eligible attack {} is missing twin", case.name))?;
            let twin = by_name
                .get(&twin_name)
                .ok_or_else(|| anyhow!("{} references missing twin `{twin_name}`", case.name))?
                .clone();
            if twin.expected != "allow" {
                return Err(anyhow!(
                    "twin `{twin_name}` for {} must have expected=allow, got {}",
                    case.name,
                    twin.expected
                ));
            }
            pairs.push(EligiblePair {
                pair_id,
                family: case.family.clone().unwrap_or_else(|| "general".to_string()),
                mutation,
                attack: case.clone(),
                twin,
            });
        } else if case.expected == "reject"
            && case.ineligible_reason.as_deref().unwrap_or("").is_empty()
        {
            return Err(anyhow!(
                "ineligible reject {} is missing ineligible_reason",
                case.name
            ));
        }
    }

    if pairs.is_empty() {
        return Err(anyhow!(
            "manifest in {} has zero eligible pairs for paired-probe",
            corpus.display()
        ));
    }
    Ok(pairs)
}

/// Deterministic SplitMix64 Fisher-Yates shuffle of eligible pairs using `(trial_seed, trial_index)`.
pub(crate) fn shuffle_pairs(pairs: &mut [EligiblePair], trial_seed: u64, trial_index: u32) {
    let mut state = trial_seed ^ ((trial_index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let mut next_u64 = || -> u64 {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    for i in (1..pairs.len()).rev() {
        let j = (next_u64() as usize) % (i + 1);
        pairs.swap(i, j);
    }
}

pub(crate) fn format_probe_request_id(
    trial_index: u32,
    cell_label: &str,
    pair_id: &str,
    role: &str,
    topology: &str,
    seq: usize,
) -> String {
    format!("t{trial_index}-{cell_label}-{pair_id}-{role}-{topology}-{seq:03}")
}

fn resolve_payload(corpus: &Path, rel: &str) -> Result<PathBuf> {
    let rel_path = Path::new(rel);
    if rel_path.is_absolute() {
        if rel_path.is_file() {
            return Ok(rel_path.to_path_buf());
        }
        return Err(anyhow!("payload not found: {}", rel_path.display()));
    }
    let mut tried = Vec::new();
    if let Some(parent) = corpus.parent() {
        let candidate = parent.join(rel_path);
        if candidate.is_file() {
            return Ok(candidate);
        }
        tried.push(candidate);
    }
    let direct = corpus.join(rel_path);
    if direct.is_file() {
        return Ok(direct);
    }
    tried.push(direct);
    if let Ok(stripped) = rel_path.strip_prefix("corpus") {
        let nested = corpus.join(stripped);
        if nested.is_file() {
            return Ok(nested);
        }
        tried.push(nested);
    }
    Err(anyhow!(
        "payload `{rel}` not found (looked in {})",
        tried
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// Map an h2c response onto the same status labels the tonic path uses.
/// HTTP 403 and 400 win over a missing or contradictory `grpc-status`.
pub(crate) fn classify_http_response(http_status: u16, grpc_status: Option<&str>) -> &'static str {
    if http_status == 403 {
        return "PERMISSION_DENIED";
    }
    if http_status == 400 {
        return "HTTP_400";
    }
    if let Some(code) = grpc_status {
        return classify_grpc_status_code(code);
    }
    if http_status == 200 {
        "OK"
    } else {
        "OTHER"
    }
}

pub(crate) fn classify_grpc_status_code(code: &str) -> &'static str {
    match code.trim() {
        "0" => "OK",
        "3" => "INVALID_ARGUMENT",
        "4" => "DEADLINE_EXCEEDED",
        "7" => "PERMISSION_DENIED",
        "13" => "INTERNAL",
        "14" => "UNAVAILABLE",
        _ => "OTHER",
    }
}

pub(crate) async fn execute_sweep(cli: &Cli, clock: &Clock) -> Result<TrialReport> {
    let cases = load_cases(&cli.corpus)?;
    if cli.dry_run {
        let rows = cases
            .iter()
            .map(|case| OracleRow {
                name: case.name.clone(),
                expected: case.expected.clone(),
                status: "DRY_RUN".to_string(),
                matched: false,
                tx_bytes: case.body.len() as u64,
                rx_bytes: 0,
                latency_ns: 0,
                method: case.method.clone(),
                framing: case.framing.clone(),
            })
            .collect();
        return Ok(scheduler::assemble(
            cli,
            Vec::new(),
            Duration::ZERO,
            Vec::new(),
            None,
            rows,
        ));
    }

    let started = std::time::Instant::now();
    let mut channel = connect(cli).await?;
    let mut observations = Vec::with_capacity(cases.len());
    let mut rows = Vec::with_capacity(cases.len());
    for case in &cases {
        let send_at = clock.raw();
        let (status, rx_bytes) = if case.framing == "http-body" {
            send_h2c(cli, case, None).await
        } else {
            let outcome = send_protobuf(&mut channel, cli, case, None).await;
            if outcome.0 == "TRANSPORT" || outcome.0 == "UNAVAILABLE" {
                if let Ok(fresh) = connect(cli).await {
                    channel = fresh;
                }
            }
            outcome
        };
        let completed = clock.raw();
        let latency_ns = clock.delta(send_at, completed).as_nanos() as u64;
        rows.push(OracleRow {
            name: case.name.clone(),
            expected: case.expected.clone(),
            status: status.to_string(),
            matched: oracle_matches(&case.expected, status),
            tx_bytes: case.body.len() as u64,
            rx_bytes,
            latency_ns,
            method: case.method.clone(),
            framing: case.framing.clone(),
        });
        observations.push(Observation {
            name: case.name.clone(),
            latency_ns,
            service_ns: latency_ns,
            malicious: case.expected == "reject",
            status,
            tx_bytes: case.body.len() as u64,
            rx_bytes,
        });
    }
    Ok(scheduler::assemble(
        cli,
        observations,
        started.elapsed(),
        Vec::new(),
        None,
        rows,
    ))
}

pub(crate) fn cell_label(cell: ProbeCell, rps: u64) -> String {
    match cell {
        ProbeCell::L0 => "l0".to_string(),
        ProbeCell::L1 => format!("l1_rps{rps}"),
    }
}

/// Executes `--regime paired-probe`:
/// 1. Refuses `--backend sim`.
/// 2. Loads and lints all eligible `(attack, twin)` pairs from `corpus/manifest.json` and shuffles
///    their order deterministically using `(trial_seed, trial_index)`.
/// 3. If `--cell l1`, starts an open-loop benign background stream at `--rps` using the widened
///    `--batch all` allow-twin rotation on a dedicated tonic channel, warms up for
///    `--probe-warmup-secs`, and keeps background running until the last probe completes.
/// 4. Sends each eligible pair's `attack` followed by its `twin` on a separate probe channel,
///    spaced by `--probe-interval-ms` (`200 ms` default), stamping `x-request-id` as
///    `t{trial}-{cell}-{pair}-{role}-{topo}-{seq}`.
/// 5. Records background observations in the trial histogram (excluding all probe sends) and
///    records probe observations in `TrialReport.probes` (and `<label>.probes.jsonl`).
pub(crate) async fn execute_paired_probe(cli: &Cli, clock: &Clock) -> Result<TrialReport> {
    if cli.backend == BackendKind::Sim {
        return Err(anyhow!(
            "--regime paired-probe refuses --backend sim; use --backend triton against official tritonserver"
        ));
    }
    let mut pairs = load_eligible_pairs(&cli.corpus)?;
    shuffle_pairs(&mut pairs, cli.trial_seed, cli.trial_index);
    let cell_str = cell_label(cli.cell, cli.rps);
    let study_meta = StudyMeta {
        study_id: cli.study_id.clone(),
        backend: "triton".to_string(),
        cell: cell_str.clone(),
        topology_tag: cli.topology_tag.clone(),
        trial_index: cli.trial_index,
        trial_seed: cli.trial_seed,
        probe_interval_ms: cli.probe_interval_ms,
        probe_warmup_secs: cli.probe_warmup_secs,
        eligible_pairs: pairs.len(),
    };

    if cli.dry_run {
        let mut probes = Vec::with_capacity(pairs.len() * 2);
        let mut seq = 0usize;
        for pair in &pairs {
            for (role, case) in [("attack", &pair.attack), ("twin", &pair.twin)] {
                seq += 1;
                let req_id = format_probe_request_id(
                    cli.trial_index,
                    &cell_str,
                    &pair.pair_id,
                    role,
                    &cli.topology_tag,
                    seq,
                );
                probes.push(ProbeObservation {
                    request_id: req_id,
                    pair_id: pair.pair_id.clone(),
                    family: pair.family.clone(),
                    mutation: pair.mutation.clone(),
                    role: role.to_string(),
                    payload_name: case.name.clone(),
                    expected: case.expected.clone(),
                    status: "DRY_RUN".to_string(),
                    topology: cli.topology_tag.clone(),
                    cell: cell_str.clone(),
                    trial: cli.trial_index,
                    seq,
                    tx_bytes: case.body.len() as u64,
                    rx_bytes: 0,
                    latency_ns: 0,
                    method: case.method.clone(),
                    framing: case.framing.clone(),
                });
            }
        }
        let mut report = scheduler::assemble(
            cli,
            Vec::new(),
            Duration::ZERO,
            Vec::new(),
            None,
            Vec::new(),
        );
        report.study_meta = Some(study_meta);
        report.probes = probes;
        return Ok(report);
    }

    let started = std::time::Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicU64::new(0));

    // Optional background load task on a dedicated tonic channel for `--cell l1`.
    let bg_handle = if cli.cell == ProbeCell::L1 {
        let corpus = Corpus::load(&cli.corpus, &cli.batch)?;
        let bg_path: PathAndQuery = cli
            .method
            .parse()
            .with_context(|| format!("invalid background method path {}", cli.method))?;
        let bg_channel = connect(cli).await.context("connecting background channel")?;
        let cli_bg = cli.clone();
        let clock_bg = clock.clone();
        let stop_bg = Arc::clone(&stop);
        let completed_bg = Arc::clone(&completed);
        let t0 = clock.raw();
        Some(tokio::spawn(async move {
            scheduler::run_background_until_stopped(
                &cli_bg,
                &clock_bg,
                &corpus,
                bg_channel,
                bg_path,
                t0,
                &stop_bg,
                &completed_bg,
            )
            .await
        }))
    } else {
        None
    };

    if cli.cell == ProbeCell::L1 && cli.probe_warmup_secs > 0 {
        tokio::time::sleep(Duration::from_secs(cli.probe_warmup_secs)).await;
    }

    let mut probe_channel = connect(cli).await.context("connecting probe channel")?;
    let mut probes = Vec::with_capacity(pairs.len() * 2);
    let probe_gap = Duration::from_millis(cli.probe_interval_ms);
    let mut seq = 0usize;

    for pair in &pairs {
        for (role, case) in [("attack", &pair.attack), ("twin", &pair.twin)] {
            if seq > 0 && !probe_gap.is_zero() {
                tokio::time::sleep(probe_gap).await;
            }
            seq += 1;
            let req_id = format_probe_request_id(
                cli.trial_index,
                &cell_str,
                &pair.pair_id,
                role,
                &cli.topology_tag,
                seq,
            );
            let send_at = clock.raw();
            let (status, rx_bytes) = if case.framing == "http-body" {
                send_h2c(cli, case, Some(&req_id)).await
            } else {
                let outcome = send_protobuf(&mut probe_channel, cli, case, Some(&req_id)).await;
                if outcome.0 == "TRANSPORT" || outcome.0 == "UNAVAILABLE" {
                    if let Ok(fresh) = connect(cli).await {
                        probe_channel = fresh;
                    }
                }
                outcome
            };
            let done_at = clock.raw();
            let latency_ns = clock.delta(send_at, done_at).as_nanos() as u64;
            probes.push(ProbeObservation {
                request_id: req_id,
                pair_id: pair.pair_id.clone(),
                family: pair.family.clone(),
                mutation: pair.mutation.clone(),
                role: role.to_string(),
                payload_name: case.name.clone(),
                expected: case.expected.clone(),
                status: status.to_string(),
                topology: cli.topology_tag.clone(),
                cell: cell_str.clone(),
                trial: cli.trial_index,
                seq,
                tx_bytes: case.body.len() as u64,
                rx_bytes,
                latency_ns,
                method: case.method.clone(),
                framing: case.framing.clone(),
            });
        }
    }

    stop.store(true, Ordering::Relaxed);
    let bg_observations = match bg_handle {
        Some(handle) => handle.await.context("joining background task")??,
        None => Vec::new(),
    };
    let elapsed = started.elapsed();

    let mut report = scheduler::assemble(
        cli,
        bg_observations,
        elapsed,
        Vec::new(),
        None,
        Vec::new(),
    );
    report.study_meta = Some(study_meta);
    report.probes = probes;
    Ok(report)
}

async fn connect(cli: &Cli) -> Result<Channel> {
    let endpoint = scheduler::endpoint(&cli.target, cli.timeout_ms, cli.max_message_bytes)?;
    let timeout = Duration::from_millis(cli.timeout_ms.max(1));
    match tokio::time::timeout(timeout, endpoint.connect()).await {
        Ok(Ok(channel)) => Ok(channel),
        Ok(Err(err)) => Err(err).context("connecting to target"),
        Err(_) => Err(anyhow!("timed out connecting to {}", cli.target)),
    }
}

async fn send_protobuf(
    channel: &mut Channel,
    cli: &Cli,
    case: &OracleCase,
    request_id: Option<&str>,
) -> (&'static str, u64) {
    let path = match case.method.parse::<PathAndQuery>() {
        Ok(path) => path,
        Err(_) => return ("TRANSPORT", 0),
    };
    let mut grpc = tonic::client::Grpc::new(channel.clone())
        .max_decoding_message_size(cli.max_message_bytes)
        .max_encoding_message_size(cli.max_message_bytes);
    let compressed = case.name == "grpc_compressed_flag_01";
    scheduler::unary_with_request_id(
        &mut grpc,
        path,
        case.body.clone(),
        compressed,
        request_id,
        Duration::from_millis(cli.timeout_ms.max(1)),
    )
    .await
}

async fn send_h2c(cli: &Cli, case: &OracleCase, request_id: Option<&str>) -> (&'static str, u64) {
    let timeout = Duration::from_millis(cli.timeout_ms.max(1));
    match tokio::time::timeout(timeout, send_h2c_inner(cli, case, request_id)).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(_)) => ("TRANSPORT", 0),
        Err(_) => ("DEADLINE_EXCEEDED", 0),
    }
}

async fn send_h2c_inner(
    cli: &Cli,
    case: &OracleCase,
    request_id: Option<&str>,
) -> Result<(&'static str, u64)> {
    let (host, addr) = resolve_target(&cli.target).await?;
    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting to {addr}"))?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (sender, connection) = http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Full<Bytes>>(io)
        .await
        .context("http2 handshake")?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let outcome = send_on(sender, &host, case, request_id).await;
    connection_task.abort();
    outcome
}

async fn send_on(
    mut sender: hyper::client::conn::http2::SendRequest<Full<Bytes>>,
    host: &str,
    case: &OracleCase,
    request_id: Option<&str>,
) -> Result<(&'static str, u64)> {
    sender.ready().await.context("http2 connection closed")?;
    let mut builder = http::Request::builder()
        .method(http::Method::POST)
        .uri(&case.method)
        .header(HOST, host)
        .header(CONTENT_TYPE, "application/grpc")
        .header("te", "trailers");
    if let Some(req_id) = request_id {
        builder = builder.header("x-request-id", req_id);
    }
    let request = builder
        .body(Full::new(case.body.clone()))
        .context("building the h2 request")?;
    let response = sender.send_request(request).await.context("sending h2 request")?;
    let http_status = response.status().as_u16();
    let header_grpc = header_value(response.headers().get("grpc-status"));
    let collected = response
        .into_body()
        .collect()
        .await
        .context("reading h2 body")?;
    let trailer_grpc = collected
        .trailers()
        .and_then(|trailers| header_value(trailers.get("grpc-status")));
    let grpc_status = trailer_grpc.or(header_grpc);
    let rx_bytes = collected.to_bytes().len() as u64;
    Ok((
        classify_http_response(http_status, grpc_status.as_deref()),
        rx_bytes,
    ))
}

fn header_value(value: Option<&http::HeaderValue>) -> Option<String> {
    value.and_then(|value| value.to_str().ok().map(|text| text.to_string()))
}

async fn resolve_target(target: &str) -> Result<(String, std::net::SocketAddr)> {
    let uri: http::Uri = target.parse().context("parsing target URI")?;
    if uri.scheme_str() == Some("https") {
        return Err(anyhow!(
            "http-body framing uses h2c prior knowledge and does not negotiate TLS"
        ));
    }
    let host = uri.host().context("target URI has no host")?;
    let port = uri.port_u16().unwrap_or(80);
    let host_header = if port == 80 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let addr = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolving {host}:{port}"))?
        .next()
        .with_context(|| format!("no address for {host}:{port}"))?;
    Ok((host_header, addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_403_and_grpc_status_map_onto_sweep_labels() {
        assert_eq!(classify_http_response(403, None), "PERMISSION_DENIED");
        assert_eq!(classify_http_response(403, Some("0")), "PERMISSION_DENIED");
        assert_eq!(classify_http_response(400, None), "HTTP_400");
        assert_eq!(classify_http_response(200, Some("3")), "INVALID_ARGUMENT");
        assert_eq!(classify_http_response(200, Some("7")), "PERMISSION_DENIED");
        assert_eq!(classify_http_response(200, Some("13")), "INTERNAL");
        assert_eq!(classify_http_response(200, Some("0")), "OK");
        assert_eq!(classify_http_response(200, None), "OK");
        assert_eq!(classify_http_response(503, None), "OTHER");
        assert_eq!(classify_grpc_status_code(" 4 "), "DEADLINE_EXCEEDED");
    }

    #[test]
    fn resolves_manifest_paths_and_rejects_a_bad_expected() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("custos-oracle-{nanos}"));
        let corpus = root.join("corpus");
        std::fs::create_dir_all(corpus.join("benign")).unwrap();
        std::fs::create_dir_all(corpus.join("framing")).unwrap();
        std::fs::write(corpus.join("benign/a.pb"), b"abc").unwrap();
        std::fs::write(corpus.join("framing/f.body"), b"\x00\x00\x00\x00\x01x").unwrap();
        let manifest = serde_json::json!({
            "artifacts": [
                {
                    "name": "a",
                    "expected": "allow",
                    "pb_path": "corpus/benign/a.pb",
                    "method": "/inference.GRPCInferenceService/ModelInfer",
                    "framing": "protobuf"
                },
                {
                    "name": "direct",
                    "expected": "allow",
                    "pb_path": "benign/a.pb",
                    "framing": "protobuf"
                },
                {
                    "name": "f",
                    "expected": "reject",
                    "pb_path": "corpus/framing/f.body",
                    "method": "/inference.GRPCInferenceService/ModelInfer",
                    "framing": "http-body"
                }
            ]
        });
        std::fs::write(corpus.join("manifest.json"), manifest.to_string()).unwrap();
        let cases = load_cases(&corpus).unwrap();
        assert_eq!(cases.len(), 3);
        assert_eq!(std::fs::read(&cases[0].path).unwrap(), b"abc");
        assert_eq!(std::fs::read(&cases[1].path).unwrap(), b"abc");
        assert_eq!(cases[1].method, crate::cli::MODEL_INFER_PATH);
        assert_eq!(cases[2].framing, "http-body");
        assert!(cases[2].path.ends_with("f.body"));

        let bad = serde_json::json!({
            "artifacts": [{
                "name": "a",
                "expected": "maybe",
                "pb_path": "corpus/benign/a.pb"
            }]
        });
        std::fs::write(corpus.join("manifest.json"), bad.to_string()).unwrap();
        assert!(load_cases(&corpus).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn repo_manifest_keeps_framing_and_rpc_out_of_the_mix_directories() {
        let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../corpus");
        let cases = load_cases(&corpus).expect("generated corpus manifest");
        assert!(cases.len() >= 59, "manifest has {} entries", cases.len());
        let framing: Vec<_> = cases.iter().filter(|case| case.framing == "http-body").collect();
        assert!(framing.len() >= 3);
        for case in &framing {
            let text = case.path.to_string_lossy();
            assert!(!text.contains("/benign/"), "{}", case.name);
            assert!(!text.contains("/malicious/"), "{}", case.name);
            assert_eq!(case.body[0], 0x00, "{}", case.name);
        }
        let two = cases.iter().find(|case| case.name == "frame_two_concat").unwrap();
        let declared = u32::from_be_bytes(two.body[1..5].try_into().unwrap()) as usize;
        assert_ne!(declared, two.body.len() - 5);
        let single = cases.iter().find(|case| case.name == "frame_single").unwrap();
        let single_len = u32::from_be_bytes(single.body[1..5].try_into().unwrap()) as usize;
        assert_eq!(single_len, single.body.len() - 5);
        assert!(cases.iter().any(|case| {
            case.name == "rpc_system_shared_memory_register"
                && case.expected == "reject"
                && case.framing == "protobuf"
                && !case.path.to_string_lossy().contains("/malicious/")
        }));
        assert!(cases.iter().any(|case| case.name == "benign_b1" && case.expected == "allow"));
        assert!(!cases.iter().any(|case| case.name == "benign_fp32_ceiling"));
        let shm = cases
            .iter()
            .find(|case| case.name == "cve_2024_0088_shm_params_infer")
            .unwrap();
        let needle = b"\x1a\x13triton_shm_internal";
        assert!(shm.body.windows(needle.len()).any(|window| window == needle));
        let wrong = b"\x12\x13triton_shm_internal";
        assert!(!shm.body.windows(wrong.len()).any(|window| window == wrong));
    }

    #[tokio::test]
    async fn paired_probe_refuses_sim_and_dry_run_excludes_probes_from_background_histogram() {
        use clap::Parser;
        let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../corpus");
        let pairs = load_eligible_pairs(&corpus).expect("eligible pairs in repo manifest");
        assert_eq!(pairs.len(), 14);

        // 1. `--backend sim` must fail closed.
        let cli_sim = Cli::parse_from([
            "custos-bench",
            "--regime",
            "paired-probe",
            "--backend",
            "sim",
            "--corpus",
            corpus.to_str().unwrap(),
            "--dry-run",
        ]);
        let clock = Clock::new();
        assert!(execute_paired_probe(&cli_sim, &clock).await.is_err());

        // 2. `--backend triton --dry-run` produces 28 probes (attack before twin per pair),
        //    deterministic Fisher-Yates order per trial index, and zero background histogram entries.
        let cli_t1 = Cli::parse_from([
            "custos-bench",
            "--regime",
            "paired-probe",
            "--backend",
            "triton",
            "--cell",
            "l1",
            "--rps",
            "100",
            "--trial-seed",
            "12345",
            "--trial-index",
            "1",
            "--topology-tag",
            "C",
            "--corpus",
            corpus.to_str().unwrap(),
            "--dry-run",
        ]);
        let rep1 = execute_paired_probe(&cli_t1, &clock).await.unwrap();
        assert_eq!(rep1.latency.count, 0, "probes must not enter background histogram");
        assert_eq!(rep1.probes.len(), 28);
        for chunk in rep1.probes.chunks_exact(2) {
            assert_eq!(chunk[0].role, "attack");
            assert_eq!(chunk[1].role, "twin");
            assert_eq!(chunk[0].pair_id, chunk[1].pair_id);
            assert!(chunk[0].request_id.starts_with("t1-l1_rps100-"));
            assert!(chunk[0].request_id.contains("-attack-C-"));
            assert!(chunk[1].request_id.contains("-twin-C-"));
        }

        // Different trial index produces a different Fisher-Yates shuffle order.
        let cli_t2 = Cli::parse_from([
            "custos-bench",
            "--regime",
            "paired-probe",
            "--backend",
            "triton",
            "--cell",
            "l1",
            "--rps",
            "100",
            "--trial-seed",
            "12345",
            "--trial-index",
            "2",
            "--topology-tag",
            "C",
            "--corpus",
            corpus.to_str().unwrap(),
            "--dry-run",
        ]);
        let rep2 = execute_paired_probe(&cli_t2, &clock).await.unwrap();
        let order1: Vec<_> = rep1.probes.iter().map(|p| &p.pair_id).collect();
        let order2: Vec<_> = rep2.probes.iter().map(|p| &p.pair_id).collect();
        assert_ne!(order1, order2);
    }
}
