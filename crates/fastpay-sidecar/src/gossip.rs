//! Gossip: periodic certificate exchange between validator sidecars.
//!
//! Each sidecar polls its peers' bulletin boards and ingests new certificates.
//! This is the simplest possible gossip: pull-based, periodic, unfiltered.

use std::sync::Arc;
use std::time::Duration;

use fastpay_proto::v1;
use tonic::transport::Channel;
use tracing::{debug, info, warn};

use crate::state::SidecarState;

/// Configuration for the gossip loop.
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// Peer sidecar gRPC endpoints (e.g., "http://127.0.0.1:50052").
    pub peers: Vec<String>,
    /// Polling interval.
    pub interval: Duration,
    /// Max number of certificates pulled per poll request.
    pub pull_limit: u32,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            peers: Vec::new(),
            interval: Duration::from_secs(1),
            pull_limit: 512,
        }
    }
}

/// Run the gossip loop. Spawns as a background task; cancellation via the token
/// returned from the parent scope (or when the runtime shuts down).
pub async fn run_gossip_loop(state: Arc<SidecarState>, config: GossipConfig) {
    if config.peers.is_empty() {
        info!("gossip: no peers configured, gossip disabled");
        return;
    }

    info!(
        peers = ?config.peers,
        interval_ms = config.interval.as_millis(),
        "gossip: starting loop"
    );

    let mut interval = tokio::time::interval(config.interval);
    // Track highest seen timestamp per peer to do incremental syncs.
    let mut since_millis: Vec<u64> = vec![0; config.peers.len()];

    loop {
        interval.tick().await;

        for (i, peer) in config.peers.iter().enumerate() {
            match pull_from_peer(peer, since_millis[i], config.pull_limit).await {
                Ok(certs) => {
                    if !certs.is_empty() {
                        let max_ts = certs
                            .iter()
                            .map(|c| c.created_unix_millis)
                            .max()
                            .unwrap_or(0);
                        let ingested = state.ingest_peer_certs(certs);
                        if ingested > 0 {
                            debug!(peer, ingested, "gossip: ingested certs from peer");
                        }
                        // Advance since_millis to avoid re-fetching.
                        if max_ts >= since_millis[i] {
                            since_millis[i] = max_ts.saturating_add(1);
                        }
                    }
                }
                Err(e) => {
                    warn!(peer, error = %e, "gossip: failed to pull from peer");
                }
            }
        }
    }
}

async fn pull_from_peer(
    peer: &str,
    since_unix_millis: u64,
    pull_limit: u32,
) -> Result<Vec<v1::ValidatorCertificate>, Box<dyn std::error::Error + Send + Sync>> {
    let channel = Channel::from_shared(peer.to_string())?.connect().await?;
    let mut client = v1::fast_pay_sidecar_client::FastPaySidecarClient::new(channel);

    let resp = client
        .get_bulletin_board(v1::GetBulletinBoardRequest {
            filter: None,
            since_unix_millis,
            limit: pull_limit,
        })
        .await?;

    Ok(resp.into_inner().certs)
}
