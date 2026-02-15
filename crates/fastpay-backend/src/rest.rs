use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use alloy_consensus::{transaction::SignableTransaction, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::TxKind;
use axum::extract::{Path, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use fastpay_crypto::{
    compute_effects_hash, compute_tx_hash, Ed25519Certificate, EffectsHashInput, MultiCertQC,
    SimpleAssembler, TxHashInput,
};
use fastpay_proto::v1;
use fastpay_sidecar_mock::DemoScenario;
use fastpay_types::{
    Address, AssetId, EffectsHash, Expiry, NonceKey, QuorumCert, TxHash, ValidatorId,
    VerificationContext,
};
use fastpay_user_client::{parse_ed25519_proto_cert, CertManager, TxBuilder};
use serde::{Deserialize, Serialize};
use tokio_stream::wrappers::ReceiverStream;
use tower_http::cors::CorsLayer;
use tracing::warn;

use crate::state::{compare_chain_head, FastPayBackendState};
use crate::upstream::{
    fanout_get_bulletin_board, fanout_get_chain_head, fanout_submit_fastpay, SidecarEndpoint,
    UpstreamConfig,
};

/// Demo nonce key: 0x5b repeated 32 times.
const DEMO_NONCE_KEY: [u8; 32] = [0x5b; 32];

/// Default expiry: 10 minutes from now (unix millis).
const DEFAULT_EXPIRY_OFFSET_MS: u64 = 10 * 60 * 1000;

/// TIP-20 payment prefix: token addresses starting with 0x20c0...
const TIP20_PAYMENT_PREFIX: [u8; 2] = [0x20, 0xc0];

pub struct AppState {
    pub state: Arc<FastPayBackendState>,
    pub upstream: UpstreamConfig,
    pub qc_threshold: u32,
    pub chain_id: u64,
}

pub fn router(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/submit-raw-tx", post(submit_raw_tx))
        .route("/api/v1/chain/head", get(chain_head))
        .route("/api/v1/tx/{tx_hash}/status", get(tx_status))
        .route("/api/v1/demo/chained-flow", post(demo_chained_flow))
        .layer(CorsLayer::permissive())
        .with_state(app_state)
}

// ---------------------------------------------------------------------------
// EVM transaction decoding (mirrors fastpay-sidecar-mock logic)
// ---------------------------------------------------------------------------

struct DecodedPayment {
    sender: [u8; 20],
    recipient: [u8; 20],
    amount: u64,
    asset: [u8; 20],
    /// The EVM tx nonce, used as nonce_seq in the FastPay 2D nonce.
    nonce_seq: u64,
}

fn decode_signed_tx(bytes: &[u8]) -> Result<DecodedPayment, String> {
    let envelope =
        TxEnvelope::decode_2718_exact(bytes).map_err(|e| format!("invalid EVM tx: {e}"))?;

    // Extract sender via signature recovery
    let sender_alloy = match &envelope {
        TxEnvelope::Legacy(signed) => signed
            .signature()
            .recover_address_from_prehash(&signed.tx().signature_hash()),
        TxEnvelope::Eip2930(signed) => signed
            .signature()
            .recover_address_from_prehash(&signed.tx().signature_hash()),
        TxEnvelope::Eip1559(signed) => signed
            .signature()
            .recover_address_from_prehash(&signed.tx().signature_hash()),
        TxEnvelope::Eip4844(signed) => signed
            .signature()
            .recover_address_from_prehash(&signed.tx().signature_hash()),
        TxEnvelope::Eip7702(signed) => signed
            .signature()
            .recover_address_from_prehash(&signed.tx().signature_hash()),
    }
    .map_err(|_| "unable to recover tx signer".to_string())?;

    let sender: [u8; 20] = sender_alloy.into_array();

    // Extract to, value, input, nonce from the inner transaction
    let (to_kind, value, input, nonce_seq) = match &envelope {
        TxEnvelope::Legacy(signed) => {
            let tx = signed.tx();
            (tx.to, tx.value, tx.input.to_vec(), tx.nonce)
        }
        TxEnvelope::Eip2930(signed) => {
            let tx = signed.tx();
            (tx.to, tx.value, tx.input.to_vec(), tx.nonce)
        }
        TxEnvelope::Eip1559(signed) => {
            let tx = signed.tx();
            (tx.to, tx.value, tx.input.to_vec(), tx.nonce)
        }
        _ => return Err("unsupported EVM tx type for payment".to_string()),
    };

    if !value.is_zero() {
        return Err("native value transfers not supported".to_string());
    }

    let token_addr = match to_kind {
        TxKind::Call(addr) => addr,
        TxKind::Create => return Err("contract creation is not a payment tx".to_string()),
    };

    if !token_addr.as_slice().starts_with(&TIP20_PAYMENT_PREFIX) {
        return Err("token address is not TIP-20 payment-prefixed".to_string());
    }

    // Parse ERC-20 transfer(address,uint256) calldata
    if input.len() != 68 || input[0..4] != [0xa9, 0x05, 0x9c, 0xbb] {
        return Err("unsupported call data (expected ERC-20 transfer)".to_string());
    }

    // Recipient: bytes 4..36, first 12 bytes must be zero (address padding)
    if input[4..16].iter().any(|b| *b != 0) {
        return Err("invalid recipient encoding".to_string());
    }
    let recipient: [u8; 20] = input[16..36].try_into().map_err(|_| "invalid recipient")?;

    // Amount: bytes 36..68, upper 24 bytes must be zero (fits u64)
    if input[36..60].iter().any(|b| *b != 0) {
        return Err("amount does not fit u64".to_string());
    }
    let amount = u64::from_be_bytes(input[60..68].try_into().map_err(|_| "invalid amount")?);

    let asset: [u8; 20] = token_addr
        .as_slice()
        .try_into()
        .map_err(|_| "invalid token address")?;

    Ok(DecodedPayment {
        sender,
        recipient,
        amount,
        asset,
        nonce_seq,
    })
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SubmitRawTxRequest {
    signed_tx: String,
}

#[derive(Serialize)]
struct SubmitRawTxResponse {
    tx_hash: String,
    stage: &'static str,
    cert_count: usize,
    qc_formed: bool,
}

#[derive(Serialize)]
struct ChainHeadResponse {
    block_height: u64,
    block_hash: String,
    unix_millis: u64,
}

#[derive(Serialize)]
struct TxStatusResponse {
    tx_hash: String,
    stage: &'static str,
    cert_count: usize,
    qc_formed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    qc_hash: Option<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn submit_raw_tx(
    State(app): State<Arc<AppState>>,
    Json(req): Json<SubmitRawTxRequest>,
) -> Result<Json<SubmitRawTxResponse>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    let signed_tx_bytes = hex_decode(&req.signed_tx)
        .map_err(|e| bad_request(format!("invalid signed_tx hex: {e}")))?;

    // Decode the signed EVM transaction to extract sender/recipient/amount/asset
    let decoded = decode_signed_tx(&signed_tx_bytes)
        .map_err(|e| bad_request(format!("tx decode failed: {e}")))?;

    let sender = Address::new(decoded.sender);
    let recipient = Address::new(decoded.recipient);
    let asset = AssetId::new(decoded.asset);
    let amount = decoded.amount;
    let nonce_key = NonceKey::new(DEMO_NONCE_KEY);
    let nonce_seq = decoded.nonce_seq;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let expiry = Expiry::UnixMillis(now_ms + DEFAULT_EXPIRY_OFFSET_MS);

    // Compute hashes
    let tx_hash = compute_tx_hash(&TxHashInput {
        chain_id: app.chain_id,
        tempo_tx: signed_tx_bytes.clone(),
        nonce_key,
        nonce_seq,
        expiry,
        parent_qc_hash: None,
    });

    let _effects_hash = compute_effects_hash(&EffectsHashInput {
        sender,
        recipient,
        amount,
        asset,
        nonce_key,
        nonce_seq,
    });

    // Build proto with decoded payment data
    let intent = v1::PaymentIntent {
        sender: Some(v1::Address {
            data: decoded.sender.to_vec(),
        }),
        recipient: Some(v1::Address {
            data: decoded.recipient.to_vec(),
        }),
        amount,
        asset: Some(v1::AssetId {
            data: decoded.asset.to_vec(),
        }),
    };

    let fastpay_tx = v1::FastPayTx {
        chain_id: Some(v1::ChainId {
            value: app.chain_id,
        }),
        tempo_tx: Some(v1::TempoTxBytes {
            data: signed_tx_bytes,
        }),
        intent: Some(intent.clone()),
        nonce: Some(v1::Nonce2D {
            nonce_key_be: DEMO_NONCE_KEY.to_vec(),
            nonce_seq,
        }),
        expiry: Some(match expiry {
            Expiry::UnixMillis(ms) => v1::Expiry {
                kind: Some(v1::expiry::Kind::UnixMillis(ms)),
            },
            Expiry::MaxBlockHeight(h) => v1::Expiry {
                kind: Some(v1::expiry::Kind::MaxBlockHeight(h)),
            },
        }),
        parent_qc_hash: Vec::new(),
        client_request_id: String::new(),
        tempo_tx_format: v1::TempoTxFormat::EvmOpaqueBytesV1 as i32,
        overlay: Some(v1::OverlayMetadata {
            payment: Some(intent),
        }),
    };

    let submit_req = v1::SubmitFastPayRequest {
        tx: Some(fastpay_tx),
        parent_qcs: Vec::new(),
    };
    let upstream_results = fanout_submit_fastpay(&app.upstream, submit_req).await;

    let mut certs = Vec::new();
    for (endpoint, result) in upstream_results {
        match result {
            Ok(response) => {
                if let Some(v1::submit_fast_pay_response::Result::Cert(cert)) = response.result {
                    certs.push(cert);
                }
            }
            Err(err) => {
                warn!(endpoint = endpoint.name.as_str(), error = %err, "REST submit upstream failed");
            }
        }
    }

    app.state.ingest_certs(certs.clone());
    let cert_count = certs.len();
    let qc_formed = cert_count >= app.qc_threshold as usize;

    let stage = if qc_formed {
        "CERTIFIED"
    } else if cert_count > 0 {
        "ACCEPTED"
    } else {
        "STAGE_UNSPECIFIED"
    };

    Ok(Json(SubmitRawTxResponse {
        tx_hash: format!("0x{}", hex::encode(tx_hash.as_bytes())),
        stage,
        cert_count,
        qc_formed,
    }))
}

async fn chain_head(
    State(app): State<Arc<AppState>>,
) -> Result<Json<ChainHeadResponse>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    let upstream_results = fanout_get_chain_head(&app.upstream).await;
    let mut best_head: Option<v1::GetChainHeadResponse> = None;

    for (endpoint, result) in upstream_results {
        match result {
            Ok(head) => {
                best_head = Some(match best_head {
                    Some(current) => {
                        if compare_chain_head(&head, &current).is_gt() {
                            head
                        } else {
                            current
                        }
                    }
                    None => head,
                });
            }
            Err(err) => {
                warn!(endpoint = endpoint.name.as_str(), error = %err, "REST chain head upstream failed");
            }
        }
    }

    if let Some(head) = &best_head {
        app.state.set_chain_head(head.clone());
    }

    let head = best_head
        .or_else(|| app.state.get_chain_head())
        .ok_or_else(|| unavailable("all sidecars unavailable"))?;

    Ok(Json(ChainHeadResponse {
        block_height: head.block_height,
        block_hash: format!("0x{}", hex::encode(&head.block_hash)),
        unix_millis: head.unix_millis,
    }))
}

async fn tx_status(
    State(app): State<Arc<AppState>>,
    Path(tx_hash_hex): Path<String>,
) -> Result<Json<TxStatusResponse>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    let tx_hash_bytes =
        hex_decode(&tx_hash_hex).map_err(|e| bad_request(format!("invalid tx_hash: {e}")))?;
    let tx_hash = TxHash::from_slice(&tx_hash_bytes)
        .map_err(|e| bad_request(format!("invalid tx_hash length: {e}")))?;

    // Refresh certs from sidecars
    let refresh = v1::GetBulletinBoardRequest {
        filter: Some(v1::get_bulletin_board_request::Filter::TxHash(
            tx_hash.as_bytes().to_vec(),
        )),
        since_unix_millis: 0,
        limit: app.upstream.pull_limit,
    };
    let upstream_results = fanout_get_bulletin_board(&app.upstream, refresh).await;
    for (endpoint, result) in upstream_results {
        match result {
            Ok(response) => app.state.ingest_certs(response.certs),
            Err(err) => {
                warn!(endpoint = endpoint.name.as_str(), error = %err, "REST tx-status refresh failed");
            }
        }
    }

    let groups = app.state.get_certs_by_tx_effects(tx_hash);
    let all_certs = app.state.get_tx_certs_deduped(tx_hash);
    let cert_count = all_certs.len();

    let mut qc_formed = false;
    let mut qc_hash_str: Option<String> = None;

    // Check if any effects_hash group meets threshold
    for (effects_hash, effect_certs) in &groups {
        if effect_certs.len() >= app.qc_threshold as usize {
            let selected: Vec<_> = effect_certs
                .iter()
                .take(app.qc_threshold as usize)
                .cloned()
                .collect();
            if let Ok(domain_certs) = to_domain_certs(&selected) {
                let computed = fastpay_crypto::compute_qc_hash(
                    &tx_hash,
                    effects_hash,
                    app.qc_threshold,
                    &domain_certs,
                );
                qc_hash_str = Some(format!("0x{}", hex::encode(computed.as_bytes())));
                qc_formed = true;
                break;
            }
        }
    }

    let stage = if qc_formed {
        "CERTIFIED"
    } else if cert_count > 0 {
        "ACCEPTED"
    } else {
        "STAGE_UNSPECIFIED"
    };

    Ok(Json(TxStatusResponse {
        tx_hash: format!("0x{}", hex::encode(tx_hash.as_bytes())),
        stage,
        cert_count,
        qc_formed,
        qc_hash: qc_hash_str,
    }))
}

// ---------------------------------------------------------------------------
// SSE chained-flow demo
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct DemoStepEvent {
    step: &'static str,
    label: &'static str,
    description: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    qc_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_qc_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_count: Option<u32>,
    timestamp_ms: u64,
}

#[derive(Serialize)]
struct DemoChainHeadEvent {
    block_height: u64,
    block_hash: String,
    unix_millis: u64,
}

#[derive(Serialize)]
struct DemoDoneEvent {
    success: bool,
    total_ms: u64,
    start_block_height: u64,
}

#[derive(Serialize)]
struct DemoErrorEvent {
    message: String,
}

fn elapsed_ms(start: &Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

/// Query validator info from a sidecar via direct tonic call (Send-compatible).
async fn get_validator_info_direct(url: &str) -> Result<v1::GetValidatorInfoResponse, String> {
    let mut client = v1::fast_pay_sidecar_client::FastPaySidecarClient::connect(url.to_string())
        .await
        .map_err(|e| format!("connect to {url}: {e}"))?;
    client
        .get_validator_info(v1::GetValidatorInfoRequest::default())
        .await
        .map(|r| r.into_inner())
        .map_err(|e| format!("get_validator_info from {url}: {e}"))
}

async fn build_demo_verify_ctx(
    endpoints: &[SidecarEndpoint],
    chain_id: u64,
    epoch: u64,
) -> Result<VerificationContext, String> {
    if endpoints.len() < 2 {
        return Err("need at least 2 sidecar endpoints".to_string());
    }
    let mut committee = HashMap::new();
    for ep in endpoints {
        let info = get_validator_info_direct(&ep.url)
            .await?
            .validator
            .ok_or_else(|| format!("missing validator info from {}", ep.url))?;
        committee.insert(
            ValidatorId::from_slice(&info.id).map_err(|e| e.to_string())?,
            <[u8; 32]>::try_from(info.pubkey.as_slice()).map_err(|e| e.to_string())?,
        );
    }
    Ok(VerificationContext {
        chain_id,
        domain_tag: "tempo.fastpay.cert.v1".to_string(),
        protocol_version: 1,
        epoch,
        committee,
    })
}

/// Build a tx, fanout-submit to sidecars, collect certs, assemble QC.
/// Returns (QC, proto QC) on success.
#[allow(clippy::too_many_arguments)]
async fn demo_send_payment(
    upstream: &UpstreamConfig,
    cert_mgr: &mut CertManager<Ed25519Certificate, MultiCertQC, SimpleAssembler>,
    chain_id: u64,
    sender: Address,
    sender_key: [u8; 32],
    recipient: Address,
    amount: u64,
    asset: AssetId,
    nonce_key: NonceKey,
    nonce_seq: u64,
    expiry: Expiry,
    parent_qc: Option<&MultiCertQC>,
    parent_proto_qc: Option<v1::QuorumCertificate>,
) -> Result<(MultiCertQC, v1::QuorumCertificate), String> {
    let mut builder = TxBuilder::new(chain_id)
        .with_payment(sender, recipient, amount, asset)
        .with_sender_private_key(sender_key)
        .with_nonce_seq(nonce_key, nonce_seq)
        .with_expiry(expiry);
    if let Some(pqc) = parent_qc {
        builder = builder.with_parent_qc(pqc);
    }
    let built = builder.build().map_err(|e| format!("build tx: {e}"))?;

    let submit_req = v1::SubmitFastPayRequest {
        tx: Some(built.tx.clone()),
        parent_qcs: parent_proto_qc.into_iter().collect(),
    };
    let upstream_results = fanout_submit_fastpay(upstream, submit_req).await;

    let mut proto_certs = Vec::new();
    for (ep, result) in upstream_results {
        match result {
            Ok(resp) => {
                if let Some(v1::submit_fast_pay_response::Result::Cert(cert)) = resp.result {
                    let domain_cert = parse_ed25519_proto_cert(cert.clone())
                        .map_err(|e| format!("parse cert from {}: {e}", ep.name))?;
                    cert_mgr
                        .collect_certificate(built.tx_hash, built.effects_hash, domain_cert)
                        .map_err(|e| format!("collect cert: {e}"))?;
                    proto_certs.push(cert);
                }
            }
            Err(err) => {
                warn!(endpoint = ep.name.as_str(), error = %err, "demo submit failed");
            }
        }
    }

    if proto_certs.len() < 2 {
        return Err(format!(
            "not enough certs: got {}, need 2",
            proto_certs.len()
        ));
    }

    let qc = cert_mgr
        .assemble_qc(built.tx_hash, built.effects_hash)
        .map_err(|e| format!("assemble QC: {e}"))?;

    let proto_qc = v1::QuorumCertificate {
        tx_hash: built.tx_hash.as_bytes().to_vec(),
        effects_hash: built.effects_hash.as_bytes().to_vec(),
        certs: proto_certs,
        threshold: qc.threshold(),
        qc_hash: qc.qc_hash().as_bytes().to_vec(),
    };

    Ok((qc, proto_qc))
}

async fn demo_chained_flow(State(app): State<Arc<AppState>>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(32);

    let upstream = app.upstream.clone();
    let chain_id = app.chain_id;

    tokio::spawn(async move {
        let start = Instant::now();

        macro_rules! send_event {
            ($event_type:expr, $data:expr) => {
                if tx
                    .send(Ok(Event::default()
                        .event($event_type)
                        .json_data($data)
                        .expect("serialize")))
                    .await
                    .is_err()
                {
                    return;
                }
            };
        }

        macro_rules! send_error {
            ($msg:expr) => {
                let _ = tx
                    .send(Ok(Event::default()
                        .event("error")
                        .json_data(DemoErrorEvent {
                            message: $msg.to_string(),
                        })
                        .expect("serialize")))
                    .await;
                return;
            };
        }

        // Build verification context via direct tonic calls (Send-compatible)
        let verify_ctx = match build_demo_verify_ctx(&upstream.endpoints, chain_id, 1).await {
            Ok(ctx) => ctx,
            Err(e) => {
                send_error!(format!("failed to build verification context: {e}"));
            }
        };

        // Random nonce key per invocation to avoid contention on repeated runs
        let nonce_key = NonceKey::new(rand::random::<[u8; 32]>());

        let scenario = DemoScenario::new(chain_id, 1);
        let accounts = scenario.accounts;
        let keys = scenario.account_keys;

        let mut cert_mgr =
            CertManager::<Ed25519Certificate, MultiCertQC, SimpleAssembler>::new(verify_ctx, 2);

        // Grab initial chain head
        let chain_heads = fanout_get_chain_head(&upstream).await;
        let start_block_height = chain_heads
            .into_iter()
            .filter_map(|(_, r)| r.ok())
            .map(|h| h.block_height)
            .max()
            .unwrap_or(0);

        // Step 1: Alice submit started
        send_event!(
            "step",
            DemoStepEvent {
                step: "alice_submit_started",
                label: "Alice -> Bob",
                description: "Alice sending $10 to Bob",
                tx_hash: None,
                qc_hash: None,
                parent_qc_hash: None,
                cert_count: None,
                timestamp_ms: elapsed_ms(&start),
            }
        );

        // Execute Alice -> Bob
        let (qc1, proto_qc1) = match demo_send_payment(
            &upstream,
            &mut cert_mgr,
            chain_id,
            accounts.alice,
            keys.alice,
            accounts.bob,
            10,
            accounts.asset,
            nonce_key,
            0,
            Expiry::MaxBlockHeight(100),
            None,
            None,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                send_error!(format!("Alice->Bob payment failed: {e}"));
            }
        };

        // Step 2: Alice QC formed
        send_event!(
            "step",
            DemoStepEvent {
                step: "alice_qc_formed",
                label: "QC1 Formed",
                description: "Quorum certificate for Alice->Bob assembled",
                tx_hash: Some(format!("0x{}", hex::encode(qc1.tx_hash().as_bytes()))),
                qc_hash: Some(format!("0x{}", hex::encode(qc1.qc_hash().as_bytes()))),
                parent_qc_hash: None,
                cert_count: Some(qc1.threshold()),
                timestamp_ms: elapsed_ms(&start),
            }
        );

        // Step 3: Bob imports QC1
        send_event!(
            "step",
            DemoStepEvent {
                step: "bob_import_qc",
                label: "Bob Imports QC1",
                description: "Bob imports QC1 as parent for chained spend",
                tx_hash: None,
                qc_hash: None,
                parent_qc_hash: Some(format!("0x{}", hex::encode(qc1.qc_hash().as_bytes()))),
                cert_count: None,
                timestamp_ms: elapsed_ms(&start),
            }
        );

        // Step 4: Bob submit started
        send_event!(
            "step",
            DemoStepEvent {
                step: "bob_submit_started",
                label: "Bob -> Carol",
                description: "Bob sending $10 to Carol with parent QC",
                tx_hash: None,
                qc_hash: None,
                parent_qc_hash: Some(format!("0x{}", hex::encode(qc1.qc_hash().as_bytes()))),
                cert_count: None,
                timestamp_ms: elapsed_ms(&start),
            }
        );

        // Execute Bob -> Carol with parent QC
        let (qc2, _proto_qc2) = match demo_send_payment(
            &upstream,
            &mut cert_mgr,
            chain_id,
            accounts.bob,
            keys.bob,
            accounts.carol,
            10,
            accounts.asset,
            nonce_key,
            0,
            Expiry::MaxBlockHeight(100),
            Some(&qc1),
            Some(proto_qc1),
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                send_error!(format!("Bob->Carol payment failed: {e}"));
            }
        };

        // Step 5: Bob QC formed
        send_event!(
            "step",
            DemoStepEvent {
                step: "bob_qc_formed",
                label: "QC2 Formed",
                description: "Quorum certificate for Bob->Carol assembled",
                tx_hash: Some(format!("0x{}", hex::encode(qc2.tx_hash().as_bytes()))),
                qc_hash: Some(format!("0x{}", hex::encode(qc2.qc_hash().as_bytes()))),
                parent_qc_hash: Some(format!("0x{}", hex::encode(qc1.qc_hash().as_bytes()))),
                cert_count: Some(qc2.threshold()),
                timestamp_ms: elapsed_ms(&start),
            }
        );

        // Step 6: Chain head
        let chain_heads = fanout_get_chain_head(&upstream).await;
        if let Some(head) = chain_heads.into_iter().filter_map(|(_, r)| r.ok()).next() {
            send_event!(
                "chain_head",
                DemoChainHeadEvent {
                    block_height: head.block_height,
                    block_hash: format!("0x{}", hex::encode(&head.block_hash)),
                    unix_millis: head.unix_millis,
                }
            );
        }

        // Step 7: Done
        send_event!(
            "done",
            DemoDoneEvent {
                success: true,
                total_ms: elapsed_ms(&start),
                start_block_height,
            }
        );
    });

    Sse::new(ReceiverStream::new(rx))
        .keep_alive(KeepAlive::default())
        .into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s)
}

fn bad_request(msg: String) -> (axum::http::StatusCode, Json<ErrorResponse>) {
    (
        axum::http::StatusCode::BAD_REQUEST,
        Json(ErrorResponse { error: msg }),
    )
}

fn unavailable(msg: &str) -> (axum::http::StatusCode, Json<ErrorResponse>) {
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse {
            error: msg.to_string(),
        }),
    )
}

// Lightweight domain cert for QC hash computation (mirrors service.rs DomainCert)
#[derive(Clone)]
struct DomainCert {
    tx_hash: TxHash,
    effects_hash: EffectsHash,
    signer: fastpay_types::ValidatorId,
    signature: Vec<u8>,
    created_unix_millis: u64,
}

impl fastpay_types::Certificate for DomainCert {
    fn tx_hash(&self) -> &TxHash {
        &self.tx_hash
    }
    fn effects_hash(&self) -> &EffectsHash {
        &self.effects_hash
    }
    fn signer(&self) -> &fastpay_types::ValidatorId {
        &self.signer
    }
    fn verify(
        &self,
        _ctx: &fastpay_types::VerificationContext,
    ) -> Result<(), fastpay_types::CryptoError> {
        Ok(())
    }
    fn signature_bytes(&self) -> &[u8] {
        &self.signature
    }
    fn created_at(&self) -> u64 {
        self.created_unix_millis
    }
}

fn to_domain_certs(certs: &[v1::ValidatorCertificate]) -> Result<Vec<DomainCert>, String> {
    let mut out = Vec::with_capacity(certs.len());
    for cert in certs {
        let tx_hash = TxHash::from_slice(&cert.tx_hash).map_err(|e| e.to_string())?;
        let effects_hash =
            EffectsHash::from_slice(&cert.effects_hash).map_err(|e| e.to_string())?;
        let signer = crate::state::signer_from_cert(cert).map_err(|e| e.to_string())?;
        out.push(DomainCert {
            tx_hash,
            effects_hash,
            signer,
            signature: cert.signature.clone(),
            created_unix_millis: cert.created_unix_millis,
        });
    }
    Ok(out)
}
