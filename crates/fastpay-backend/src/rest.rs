use std::sync::Arc;

use alloy_consensus::{transaction::SignableTransaction, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::TxKind;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use fastpay_crypto::{compute_effects_hash, compute_tx_hash, EffectsHashInput, TxHashInput};
use fastpay_proto::v1;
use fastpay_types::{Address, AssetId, EffectsHash, Expiry, NonceKey, TxHash};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tracing::warn;

use crate::state::{compare_chain_head, FastPayBackendState};
use crate::upstream::{
    fanout_get_bulletin_board, fanout_get_chain_head, fanout_submit_fastpay, UpstreamConfig,
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
