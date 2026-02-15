//! FastPay validator sidecar binary.
//!
//! Runs a gRPC server implementing the FastPaySidecar service with optional
//! gossip to peer validator sidecars.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use fastpay_crypto::Ed25519Signer;
use fastpay_proto::v1::fast_pay_sidecar_server::FastPaySidecarServer;
use fastpay_types::{Address, AssetId, CertSigningContext, ValidatorId};
use tonic::transport::Server;
use tracing::info;

use fastpay_sidecar::gossip::{run_gossip_loop, GossipConfig};
use fastpay_sidecar::reth::{run_block_subscription, run_tx_submission_loop, RethConfig};
use fastpay_sidecar::service::FastPaySidecarService;
use fastpay_sidecar::state::{SidecarLimits, SidecarState};

/// FastPay validator sidecar.
#[derive(Parser, Debug)]
#[command(name = "fastpay-sidecar", about = "FastPay validator sidecar")]
struct Cli {
    /// gRPC listen address.
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: SocketAddr,

    /// Validator name (e.g., "Dave").
    #[arg(long)]
    name: String,

    /// Validator identity seed (32-byte hex). Deterministic key derivation for demo.
    #[arg(long)]
    seed: String,

    /// Validator ID (32-byte hex).
    #[arg(long)]
    validator_id: String,

    /// Chain ID.
    #[arg(long, default_value = "1337")]
    chain_id: u64,

    /// Epoch number.
    #[arg(long, default_value = "1")]
    epoch: u64,

    /// Initial block height.
    #[arg(long, default_value = "1")]
    block_height: u64,

    /// Peer sidecar gRPC endpoints for gossip (comma-separated).
    #[arg(long, value_delimiter = ',')]
    peers: Vec<String>,

    /// Gossip polling interval in milliseconds.
    #[arg(long, default_value = "1000")]
    gossip_interval_ms: u64,

    /// Max certificates to pull from a peer in one gossip request.
    #[arg(long, default_value = "512")]
    gossip_pull_limit: u32,

    /// Pre-seed demo balances (Alice=15, Bob=5, Carol=5).
    #[arg(long)]
    demo_balances: bool,

    /// Maximum total certificates retained in memory.
    #[arg(long, default_value = "10000")]
    max_total_certs: usize,

    /// Maximum known parent QCs retained in memory.
    #[arg(long, default_value = "4096")]
    max_known_qcs: usize,

    /// Maximum idempotency cache entries retained in memory.
    #[arg(long, default_value = "8192")]
    max_request_cache: usize,

    /// Maximum certificates returned per GetBulletinBoard response.
    #[arg(long, default_value = "1000")]
    max_bulletin_board_response: u32,

    /// RETH node WebSocket URL (e.g., ws://127.0.0.1:8546). Enables RETH integration.
    #[arg(long)]
    reth_ws_url: Option<String>,

    /// Maximum pending EVM transactions tracked for on-chain confirmation.
    #[arg(long, default_value = "4096")]
    max_pending_evm_txs: usize,

    /// Maximum EVM tx receipts to check per block.
    #[arg(long, default_value = "64")]
    max_receipt_batch: usize,
}

fn parse_hex_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "expected 32 bytes (64 hex chars)".to_string())
}

fn demo_balances() -> HashMap<Address, HashMap<AssetId, u64>> {
    use alloy_signer_local::PrivateKeySigner;

    // Derive EVM addresses from the same private keys used by DemoScenario
    // in fastpay-sidecar-mock so the backend and sidecars agree on addresses.
    let alice = Address::from_slice(
        PrivateKeySigner::from_slice(&[0x11; 32])
            .expect("valid key")
            .address()
            .as_slice(),
    )
    .expect("valid address");
    let bob = Address::from_slice(
        PrivateKeySigner::from_slice(&[0x22; 32])
            .expect("valid key")
            .address()
            .as_slice(),
    )
    .expect("valid address");
    let carol = Address::from_slice(
        PrivateKeySigner::from_slice(&[0x33; 32])
            .expect("valid key")
            .address()
            .as_slice(),
    )
    .expect("valid address");
    let asset = AssetId::new([
        0x20, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    ]);
    HashMap::from([
        (alice, HashMap::from([(asset, 15)])),
        (bob, HashMap::from([(asset, 5)])),
        (carol, HashMap::from([(asset, 5)])),
    ])
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

    let seed = parse_hex_32(&cli.seed)?;
    let validator_id_bytes = parse_hex_32(&cli.validator_id)?;
    let validator_id = ValidatorId::new(validator_id_bytes);

    let signer = Ed25519Signer::from_seed(validator_id, seed);
    let signing_ctx = CertSigningContext {
        chain_id: cli.chain_id,
        domain_tag: "tempo.fastpay.cert.v1",
        protocol_version: 1,
        epoch: cli.epoch,
    };

    let balances = if cli.demo_balances {
        info!("using demo balances: Alice=15, Bob=5, Carol=5");
        demo_balances()
    } else {
        HashMap::new()
    };

    let state = Arc::new(SidecarState::new(
        cli.name.clone(),
        signer,
        signing_ctx,
        balances,
    ));
    state.set_chain_head(cli.block_height, 1_700_000_000_000);
    state.set_gossip_peers(cli.peers.clone());
    state.set_limits(SidecarLimits {
        max_total_certs: cli.max_total_certs,
        max_known_qcs: cli.max_known_qcs,
        max_request_cache: cli.max_request_cache,
        max_bulletin_board_response: cli.max_bulletin_board_response,
        max_pending_evm_txs: cli.max_pending_evm_txs,
    });

    // Optionally spawn RETH integration tasks.
    let reth_tx_sender = if let Some(ref ws_url) = cli.reth_ws_url {
        let config = RethConfig::new(
            ws_url.clone(),
            cli.max_pending_evm_txs,
            cli.max_receipt_batch,
        );
        let (tx_sender, tx_receiver) = tokio::sync::mpsc::channel(256);

        tokio::spawn(run_block_subscription(Arc::clone(&state), config.clone()));
        tokio::spawn(run_tx_submission_loop(
            Arc::clone(&state),
            config,
            tx_receiver,
        ));

        info!(reth_ws_url = ws_url.as_str(), "RETH integration enabled");
        Some(tx_sender)
    } else {
        info!("RETH integration disabled (no --reth-ws-url)");
        None
    };

    let service = FastPaySidecarService::new(Arc::clone(&state), reth_tx_sender);

    // Start gossip loop.
    let gossip_config = GossipConfig {
        peers: cli.peers,
        interval: Duration::from_millis(cli.gossip_interval_ms),
        pull_limit: cli.gossip_pull_limit,
    };
    tokio::spawn(run_gossip_loop(Arc::clone(&state), gossip_config));

    info!(
        listen = %cli.listen,
        name = cli.name.as_str(),
        chain_id = cli.chain_id,
        epoch = cli.epoch,
        "starting FastPay sidecar"
    );

    Server::builder()
        .add_service(FastPaySidecarServer::new(service))
        .serve(cli.listen)
        .await?;

    Ok(())
}
