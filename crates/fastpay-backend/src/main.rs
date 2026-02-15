use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use fastpay_backend::rest;
use fastpay_backend::service::FastPayBackendService;
use fastpay_backend::state::{BackendLimits, FastPayBackendState};
use fastpay_backend::upstream::{SidecarEndpoint, UpstreamConfig};
use fastpay_proto::v1::fast_pay_aggregator_server::FastPayAggregatorServer;
use tonic::transport::Server;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "fastpay-backend", about = "FastPay backend service")]
struct Cli {
    /// gRPC listen address.
    #[arg(long, default_value = "127.0.0.1:60051")]
    listen: SocketAddr,

    /// HTTP/REST listen address.
    #[arg(long, default_value = "127.0.0.1:8080")]
    http_listen: SocketAddr,

    /// Chain ID for hash computation.
    #[arg(long, default_value = "1337")]
    chain_id: u64,

    /// Sidecar gRPC endpoints (comma-separated URLs).
    #[arg(long, value_delimiter = ',')]
    sidecars: Vec<String>,

    /// Upstream request timeout in milliseconds.
    #[arg(long, default_value = "1500")]
    upstream_timeout_ms: u64,

    /// Upstream max certificates pulled per sidecar request.
    #[arg(long, default_value = "1000")]
    upstream_pull_limit: u32,

    /// QC threshold used by GetTxStatus.
    #[arg(long, default_value = "2")]
    qc_threshold: u32,

    /// Maximum total certificates retained in memory.
    #[arg(long, default_value = "50000")]
    max_total_certs: usize,

    /// Maximum tracked transactions retained in memory.
    #[arg(long, default_value = "10000")]
    max_txs: usize,

    /// Maximum retained certs per (tx_hash, effects_hash).
    #[arg(long, default_value = "32")]
    max_certs_per_tx_effects: usize,

    /// Maximum certificates returned for bulletin board responses.
    #[arg(long, default_value = "2000")]
    max_bulletin_board_response: u32,

    /// Maximum certificates returned for tx status responses.
    #[arg(long, default_value = "256")]
    max_tx_status_certs: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();
    if cli.sidecars.is_empty() {
        return Err("at least one --sidecars endpoint is required".into());
    }

    let limits = BackendLimits {
        max_sidecars: cli.sidecars.len(),
        max_total_certs: cli.max_total_certs,
        max_txs: cli.max_txs,
        max_certs_per_tx_effects: cli.max_certs_per_tx_effects,
        max_bulletin_board_response: cli.max_bulletin_board_response,
        max_tx_status_certs: cli.max_tx_status_certs,
    };
    let state = Arc::new(FastPayBackendState::new(limits));

    let sidecars = cli
        .sidecars
        .iter()
        .enumerate()
        .map(|(idx, url)| SidecarEndpoint {
            name: format!("sidecar-{}", idx + 1),
            url: url.clone(),
        })
        .collect::<Vec<_>>();
    let upstream = UpstreamConfig {
        endpoints: sidecars,
        timeout_ms: cli.upstream_timeout_ms,
        pull_limit: cli.upstream_pull_limit,
    };

    // gRPC service
    let grpc_service = FastPayBackendService {
        state: Arc::clone(&state),
        upstream: upstream.clone(),
        qc_threshold: cli.qc_threshold,
    };

    // REST app state (shares the same backend state)
    let rest_state = Arc::new(rest::AppState {
        state,
        upstream,
        qc_threshold: cli.qc_threshold,
        chain_id: cli.chain_id,
    });

    let rest_router = rest::router(rest_state);

    info!(
        grpc = %cli.listen,
        http = %cli.http_listen,
        sidecars = cli.sidecars.len(),
        qc_threshold = cli.qc_threshold,
        chain_id = cli.chain_id,
        "starting FastPay backend"
    );

    // Spawn REST server on a separate task
    let http_addr = cli.http_listen;
    let http_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(http_addr).await.unwrap();
        info!(addr = %http_addr, "HTTP/REST server listening");
        axum::serve(listener, rest_router).await.unwrap();
    });

    // Run gRPC server on the main task
    let grpc_handle = tokio::spawn(async move {
        Server::builder()
            .add_service(FastPayAggregatorServer::new(grpc_service))
            .serve(cli.listen)
            .await
            .unwrap();
    });

    tokio::select! {
        res = http_handle => { res?; }
        res = grpc_handle => { res?; }
    }

    Ok(())
}
