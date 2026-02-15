//! RETH node integration: block subscription, tx submission, overlay clearing.
//!
//! Enabled only when `--reth-ws-url` is provided at startup.

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::keccak256;
use alloy_provider::{Provider, ProviderBuilder, WsConnect};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::state::{PendingEvmTx, SidecarState};
use fastpay_types::{Address, AssetId, NonceKey, TxHash};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RethConfig {
    pub ws_url: String,
    pub max_pending_txs: usize,
    pub reconnect_base_ms: u64,
    pub reconnect_max_ms: u64,
    pub max_receipt_batch: usize,
}

impl RethConfig {
    pub fn new(ws_url: String, max_pending_txs: usize, max_receipt_batch: usize) -> Self {
        Self {
            ws_url,
            max_pending_txs,
            reconnect_base_ms: 500,
            reconnect_max_ms: 30_000,
            max_receipt_batch,
        }
    }
}

// ---------------------------------------------------------------------------
// ForwardingInfo — sent from gRPC handler to tx submission loop
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ForwardingInfo {
    pub raw_evm_tx: Vec<u8>,
    pub fastpay_tx_hash: TxHash,
    pub sender: Address,
    pub recipient: Address,
    pub amount: u64,
    pub asset: AssetId,
    pub nonce_key: NonceKey,
    pub nonce_seq: u64,
}

// ---------------------------------------------------------------------------
// Block subscription loop (reconnects on WS drop)
// ---------------------------------------------------------------------------

/// Subscribes to new block headers via WebSocket. On each block:
/// - Updates chain head in sidecar state
/// - Clears confirmed txs from the overlay
///
/// Reconnects with exponential backoff on WS errors.
pub async fn run_block_subscription(state: Arc<SidecarState>, config: RethConfig) {
    let mut backoff_ms = config.reconnect_base_ms;

    loop {
        info!(
            url = config.ws_url.as_str(),
            "connecting to RETH node via WS (block sub)"
        );

        let ws_connect = WsConnect::new(&config.ws_url);
        let provider = match ProviderBuilder::new().connect_ws(ws_connect).await {
            Ok(p) => {
                backoff_ms = config.reconnect_base_ms;
                p
            }
            Err(e) => {
                error!(error = %e, backoff_ms, "failed to connect to RETH WS");
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(config.reconnect_max_ms);
                continue;
            }
        };

        info!("block subscription connected to RETH node");

        let sub = match provider.subscribe_blocks().await {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "failed to subscribe to blocks");
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(config.reconnect_max_ms);
                continue;
            }
        };

        let mut stream = sub.into_stream();
        use tokio_stream::StreamExt;

        while let Some(header) = stream.next().await {
            let block_num = header.number;
            let block_hash: [u8; 32] = header.hash.0;
            let timestamp_ms = header.timestamp * 1000;

            info!(
                block = block_num,
                hash = hex::encode(block_hash),
                "new block from RETH"
            );

            state.set_chain_head_with_hash(block_num, block_hash, timestamp_ms);

            clear_confirmed_txs(&state, &provider, config.max_receipt_batch).await;
        }

        warn!("block subscription stream ended, reconnecting...");
        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        backoff_ms = (backoff_ms * 2).min(config.reconnect_max_ms);
    }
}

// ---------------------------------------------------------------------------
// Clear confirmed txs
// ---------------------------------------------------------------------------

async fn clear_confirmed_txs(state: &SidecarState, provider: &impl Provider, max_batch: usize) {
    let hashes = state.get_pending_evm_tx_hashes(max_batch);
    if hashes.is_empty() {
        return;
    }

    let mut cleared = 0u32;
    for evm_hash in &hashes {
        let tx_hash = alloy_primitives::B256::from(*evm_hash);
        match provider.get_transaction_receipt(tx_hash).await {
            Ok(Some(_receipt)) => {
                state.clear_confirmed_tx(evm_hash);
                cleared += 1;
                info!(
                    tx = hex::encode(evm_hash),
                    "cleared confirmed EVM tx from overlay"
                );
            }
            Ok(None) => {
                // Not yet mined, retry next block.
            }
            Err(e) => {
                warn!(
                    tx = hex::encode(evm_hash),
                    error = %e,
                    "failed to fetch receipt, will retry"
                );
            }
        }
    }

    if cleared > 0 {
        info!(cleared, "overlay clearing complete");
    }
}

// ---------------------------------------------------------------------------
// TX submission loop
// ---------------------------------------------------------------------------

/// Receives forwarding info from the gRPC handlers and submits raw EVM txs
/// to a separately-connected RETH node. Reconnects independently of the
/// block subscription.
pub async fn run_tx_submission_loop(
    state: Arc<SidecarState>,
    config: RethConfig,
    mut receiver: mpsc::Receiver<ForwardingInfo>,
) {
    let mut backoff_ms = config.reconnect_base_ms;

    // Connect before accepting any txs.
    loop {
        info!(
            url = config.ws_url.as_str(),
            "connecting to RETH node via WS (tx sub)"
        );
        let ws_connect = WsConnect::new(&config.ws_url);
        match ProviderBuilder::new().connect_ws(ws_connect).await {
            Ok(provider) => {
                info!("tx submission connected to RETH node");
                backoff_ms = config.reconnect_base_ms;

                // Process txs until a fatal send error forces reconnect.
                let should_continue =
                    process_txs(&state, &provider, &mut receiver, &config, &mut backoff_ms).await;
                if !should_continue {
                    return; // Channel closed, stop.
                }
                // Otherwise loop to reconnect.
            }
            Err(e) => {
                error!(error = %e, "failed to connect for tx submission");
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(config.reconnect_max_ms);
            }
        }
    }
}

/// Process forwarded txs using the given provider. Returns `false` when the
/// receiver channel is closed (caller should stop), `true` if a reconnect
/// is needed.
async fn process_txs(
    state: &SidecarState,
    provider: &impl Provider,
    receiver: &mut mpsc::Receiver<ForwardingInfo>,
    config: &RethConfig,
    backoff_ms: &mut u64,
) -> bool {
    while let Some(fwd) = receiver.recv().await {
        let evm_tx_hash: [u8; 32] = keccak256(&fwd.raw_evm_tx).0;

        // Register as pending BEFORE submission (race safety).
        let current_block = state.current_block_height();
        state.register_pending_evm_tx(PendingEvmTx {
            evm_tx_hash,
            fastpay_tx_hash: fwd.fastpay_tx_hash,
            sender: fwd.sender,
            recipient: fwd.recipient,
            amount: fwd.amount,
            asset: fwd.asset,
            nonce_key: fwd.nonce_key,
            nonce_seq: fwd.nonce_seq,
            raw_tx: fwd.raw_evm_tx.clone(),
            submitted_at_block: current_block,
        });

        match provider.send_raw_transaction(&fwd.raw_evm_tx).await {
            Ok(pending) => {
                info!(
                    evm_tx = hex::encode(evm_tx_hash),
                    pending_tx = %pending.tx_hash(),
                    "submitted raw EVM tx to RETH"
                );
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("already known") || msg.contains("nonce too low") {
                    warn!(
                        evm_tx = hex::encode(evm_tx_hash),
                        error = %e,
                        "tx already known or nonce consumed"
                    );
                } else {
                    error!(
                        evm_tx = hex::encode(evm_tx_hash),
                        error = %e,
                        "failed to submit raw EVM tx, will reconnect"
                    );
                    tokio::time::sleep(Duration::from_millis(*backoff_ms)).await;
                    *backoff_ms = (*backoff_ms * 2).min(config.reconnect_max_ms);
                    return true; // Signal reconnect needed.
                }
            }
        }
    }

    info!("tx submission channel closed, stopping loop");
    false
}
