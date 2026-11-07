//! One-shot sweep of every manifest entry.
//!
//! Protobuf rows go through the tonic `RawCodec`, which adds the 5-byte gRPC
//! frame. `http-body` rows are the exact HTTP/2 DATA payload and are sent
//! with prior-knowledge h2c so a second frame is not wrapped around them.
//! Header-only RPC probes live in the manifest and are not `.pb` files under
//! `benign/` or `malicious/`.

use std::path::{Path, PathBuf};
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

use crate::cli::Cli;
use crate::report::{oracle_matches, OracleRow, TrialReport};
use crate::scheduler::{self, Observation};

#[derive(Debug, Clone)]
pub(crate) struct OracleCase {
    pub name: String,
    pub expected: String,
    pub body: Bytes,
    #[allow(dead_code)]
    pub path: PathBuf,
    pub method: String,
    pub framing: String,
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
}

fn default_method() -> String {
    crate::cli::MODEL_INFER_PATH.to_string()
}

fn default_framing() -> String {
    "protobuf".to_string()
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
        });
    }
    if cases.is_empty() {
        return Err(anyhow!("manifest {} has no artifacts", manifest_path.display()));
    }
    Ok(cases)
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
            send_h2c(cli, case).await
        } else {
            let outcome = send_protobuf(&mut channel, cli, case).await;
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

async fn connect(cli: &Cli) -> Result<Channel> {
    let endpoint = scheduler::endpoint(&cli.target, cli.timeout_ms, cli.max_message_bytes)?;
    let timeout = Duration::from_millis(cli.timeout_ms.max(1));
    match tokio::time::timeout(timeout, endpoint.connect()).await {
        Ok(Ok(channel)) => Ok(channel),
        Ok(Err(err)) => Err(err).context("connecting to target"),
        Err(_) => Err(anyhow!("timed out connecting to {}", cli.target)),
    }
}

async fn send_protobuf(channel: &mut Channel, cli: &Cli, case: &OracleCase) -> (&'static str, u64) {
    let path = match case.method.parse::<PathAndQuery>() {
        Ok(path) => path,
        Err(_) => return ("TRANSPORT", 0),
    };
    let mut grpc = tonic::client::Grpc::new(channel.clone())
        .max_decoding_message_size(cli.max_message_bytes)
        .max_encoding_message_size(cli.max_message_bytes);
    let compressed = case.name == "grpc_compressed_flag_01";
    scheduler::unary(
        &mut grpc,
        path,
        case.body.clone(),
        compressed,
        Duration::from_millis(cli.timeout_ms.max(1)),
    )
    .await
}

async fn send_h2c(cli: &Cli, case: &OracleCase) -> (&'static str, u64) {
    let timeout = Duration::from_millis(cli.timeout_ms.max(1));
    match tokio::time::timeout(timeout, send_h2c_inner(cli, case)).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(_)) => ("TRANSPORT", 0),
        Err(_) => ("DEADLINE_EXCEEDED", 0),
    }
}

async fn send_h2c_inner(cli: &Cli, case: &OracleCase) -> Result<(&'static str, u64)> {
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
    let outcome = send_on(sender, &host, case).await;
    connection_task.abort();
    outcome
}

async fn send_on(
    mut sender: hyper::client::conn::http2::SendRequest<Full<Bytes>>,
    host: &str,
    case: &OracleCase,
) -> Result<(&'static str, u64)> {
    sender.ready().await.context("http2 connection closed")?;
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(&case.method)
        .header(HOST, host)
        .header(CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
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
}
