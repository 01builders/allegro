//! SidecarState: concurrent validator state for FastPay sidecar.
//!
//! Ported from MockSidecar with RwLock for thread-safe gRPC serving.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;

use fastpay_crypto::{
    compute_effects_hash, compute_qc_hash, compute_tx_hash, Ed25519Signer, EffectsHashInput,
    TxHashInput,
};
use fastpay_proto::v1;
use fastpay_types::{
    Address, AssetId, CertSigningContext, Certificate, CryptoError, Expiry, NonceKey, QcHash,
    Signer, TxHash, ValidationError, ValidatorId,
};

// ---------------------------------------------------------------------------
// DecodedPayment
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPayment {
    pub sender: Address,
    pub recipient: Address,
    pub amount: u64,
    pub asset: AssetId,
}

// ---------------------------------------------------------------------------
// Inner (mutable state behind RwLock)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SidecarLimits {
    pub max_total_certs: usize,
    pub max_known_qcs: usize,
    pub max_request_cache: usize,
    pub max_bulletin_board_response: u32,
}

impl Default for SidecarLimits {
    fn default() -> Self {
        Self {
            max_total_certs: 10_000,
            max_known_qcs: 4_096,
            max_request_cache: 8_192,
            max_bulletin_board_response: 1_000,
        }
    }
}

#[derive(Debug, Clone)]
struct CachedSubmit {
    tx_hash: TxHash,
    response: v1::SubmitFastPayResponse,
}

#[derive(Debug)]
struct Inner {
    balances: HashMap<Address, HashMap<AssetId, u64>>,
    overlay: HashMap<Address, HashMap<AssetId, i128>>,
    signed_txs: HashMap<(Address, NonceKey, u64), TxHash>,
    my_certs_by_tx: HashMap<TxHash, v1::ValidatorCertificate>,
    certs: HashMap<TxHash, Vec<v1::ValidatorCertificate>>,
    known_qcs: HashMap<QcHash, v1::QuorumCertificate>,
    known_qc_order: VecDeque<QcHash>,
    request_cache: HashMap<String, CachedSubmit>,
    request_cache_order: VecDeque<String>,
    nonce_sequences: HashMap<(Address, NonceKey), u64>,
    current_block_height: u64,
    current_unix_millis: u64,
    limits: SidecarLimits,
}

// ---------------------------------------------------------------------------
// SidecarState
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SidecarState {
    name: String,
    signer: Ed25519Signer,
    signing_ctx: CertSigningContext,
    inner: RwLock<Inner>,
}

impl SidecarState {
    pub fn new(
        name: impl Into<String>,
        signer: Ed25519Signer,
        signing_ctx: CertSigningContext,
        balances: HashMap<Address, HashMap<AssetId, u64>>,
    ) -> Self {
        Self {
            name: name.into(),
            signer,
            signing_ctx,
            inner: RwLock::new(Inner {
                balances,
                overlay: HashMap::new(),
                signed_txs: HashMap::new(),
                my_certs_by_tx: HashMap::new(),
                certs: HashMap::new(),
                known_qcs: HashMap::new(),
                known_qc_order: VecDeque::new(),
                request_cache: HashMap::new(),
                request_cache_order: VecDeque::new(),
                nonce_sequences: HashMap::new(),
                current_block_height: 0,
                current_unix_millis: 0,
                limits: SidecarLimits::default(),
            }),
        }
    }

    pub fn set_chain_head(&self, block_height: u64, unix_millis: u64) {
        let mut inner = self.inner.write().unwrap();
        inner.current_block_height = block_height;
        inner.current_unix_millis = unix_millis;
    }

    pub fn set_limits(&self, limits: SidecarLimits) {
        let mut inner = self.inner.write().unwrap();
        inner.limits = limits;
    }

    // -----------------------------------------------------------------------
    // RPC: SubmitFastPay
    // -----------------------------------------------------------------------

    pub fn submit_fastpay(&self, req: v1::SubmitFastPayRequest) -> v1::SubmitFastPayResponse {
        let prepared = match prepare_submission(&req, self.signing_ctx.chain_id) {
            Ok(prepared) => prepared,
            Err(reject_reason) => {
                return response_reject(reject_reason);
            }
        };

        let mut inner = self.inner.write().unwrap();

        if let Some(request_id) = prepared.request_id.as_ref() {
            let cache_key = request_cache_key(request_id, prepared.decoded.sender);
            if let Some(cached) = inner.request_cache.get(&cache_key) {
                if cached.tx_hash == prepared.tx_hash {
                    return cached.response.clone();
                }
                return response_reject(reject(
                    v1::RejectCode::InvalidFormat,
                    "client_request_id reused for different tx",
                ));
            }
        }

        let response = match self.validate_and_sign(&mut inner, &prepared, &req.parent_qcs) {
            Ok(cert) => response_cert(cert),
            Err(reject_reason) => response_reject(reject_reason),
        };

        if let Some(request_id) = prepared.request_id {
            let cache_key = request_cache_key(&request_id, prepared.decoded.sender);
            cache_submit_response(&mut inner, cache_key, prepared.tx_hash, response.clone());
        }

        response
    }

    // -----------------------------------------------------------------------
    // RPC: GetBulletinBoard
    // -----------------------------------------------------------------------

    pub fn get_bulletin_board(
        &self,
        req: v1::GetBulletinBoardRequest,
    ) -> v1::GetBulletinBoardResponse {
        let inner = self.inner.read().unwrap();

        let mut certs: Vec<v1::ValidatorCertificate> = inner
            .certs
            .values()
            .flat_map(|v| v.iter().cloned())
            .collect();

        certs.retain(|cert| cert.created_unix_millis >= req.since_unix_millis);
        if let Some(filter) = req.filter {
            certs.retain(|cert| match &filter {
                v1::get_bulletin_board_request::Filter::TxHash(hash) => cert.tx_hash == *hash,
                v1::get_bulletin_board_request::Filter::Address(address) => {
                    cert_involves_address(cert, &address.data)
                }
            });
        }
        certs.sort_by_key(|cert| cert.created_unix_millis);

        let limit = if req.limit > 0 {
            req.limit.min(inner.limits.max_bulletin_board_response)
        } else {
            inner.limits.max_bulletin_board_response
        } as usize;
        if certs.len() > limit {
            certs.truncate(limit);
        }

        v1::GetBulletinBoardResponse {
            certs,
            next_cursor: String::new(),
        }
    }

    // -----------------------------------------------------------------------
    // RPC: GetValidatorInfo
    // -----------------------------------------------------------------------

    pub fn get_validator_info(&self) -> v1::GetValidatorInfoResponse {
        v1::GetValidatorInfoResponse {
            validator: Some(v1::ValidatorId {
                name: self.name.clone(),
                id: self.signer.validator_id().as_bytes().to_vec(),
                pubkey: self.signer.public_key_bytes().to_vec(),
            }),
            gossip_peers: Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // RPC: GetChainHead
    // -----------------------------------------------------------------------

    pub fn get_chain_head(&self) -> v1::GetChainHeadResponse {
        let inner = self.inner.read().unwrap();
        v1::GetChainHeadResponse {
            block_height: inner.current_block_height,
            block_hash: Vec::new(),
            unix_millis: inner.current_unix_millis,
        }
    }

    // -----------------------------------------------------------------------
    // Gossip: ingest certificates from a peer sidecar
    // -----------------------------------------------------------------------

    pub fn ingest_peer_certs(&self, certs: Vec<v1::ValidatorCertificate>) -> u32 {
        let mut inner = self.inner.write().unwrap();
        let mut ingested = 0u32;
        for cert in certs {
            if total_cert_count(&inner.certs) >= inner.limits.max_total_certs {
                break;
            }

            if let Ok(tx_hash) = TxHash::from_slice(&cert.tx_hash) {
                if store_cert_dedup_by_signer(&mut inner, tx_hash, cert) {
                    ingested += 1;
                }
            }
        }
        ingested
    }

    // -----------------------------------------------------------------------
    // Core validation + signing
    // -----------------------------------------------------------------------

    fn validate_and_sign(
        &self,
        inner: &mut Inner,
        prepared: &PreparedSubmit,
        parent_qcs: &[v1::QuorumCertificate],
    ) -> Result<v1::ValidatorCertificate, v1::RejectReason> {
        if is_expired(inner, prepared.expiry) {
            return Err(reject(v1::RejectCode::Expired, "transaction expired"));
        }

        let contention_key = (
            prepared.decoded.sender,
            prepared.nonce_key,
            prepared.nonce_seq,
        );
        if let Some(existing) = inner.signed_txs.get(&contention_key) {
            if existing != &prepared.tx_hash {
                return Err(reject(
                    v1::RejectCode::Equivocation,
                    "equivocation detected",
                ));
            }
            if let Some(cert) = inner.my_certs_by_tx.get(existing) {
                return Ok(cert.clone());
            }
        }

        validate_nonce(
            inner,
            prepared.decoded.sender,
            prepared.nonce_key,
            prepared.nonce_seq,
        )?;

        let available = available_balance(
            inner,
            prepared.decoded.sender,
            prepared.decoded.asset,
            prepared.decoded.amount,
            parent_qcs,
            &prepared.tx,
            prepared.effects_hash,
        )?;
        if available < prepared.decoded.amount as i128 {
            return Err(reject(
                v1::RejectCode::InsufficientFunds,
                "insufficient funds",
            ));
        }

        let cert = self
            .signer
            .sign(&self.signing_ctx, &prepared.tx_hash, &prepared.effects_hash)
            .map_err(to_reject)?;
        let cert_proto = to_proto_cert(
            &self.name,
            self.signer.public_key_bytes(),
            &cert,
            &prepared.decoded,
            prepared.nonce_key,
            prepared.nonce_seq,
        );

        inner.signed_txs.insert(contention_key, prepared.tx_hash);
        inner.nonce_sequences.insert(
            (prepared.decoded.sender, prepared.nonce_key),
            prepared.nonce_seq + 1,
        );
        apply_overlay(inner, &prepared.decoded);
        store_cert_dedup_by_signer(inner, prepared.tx_hash, cert_proto.clone());
        inner
            .my_certs_by_tx
            .insert(prepared.tx_hash, cert_proto.clone());

        Ok(cert_proto)
    }
}

// ===========================================================================
// Free functions (operate on Inner or are pure)
// ===========================================================================

#[derive(Debug, Clone)]
struct PreparedSubmit {
    tx: v1::FastPayTx,
    decoded: DecodedPayment,
    nonce_key: NonceKey,
    nonce_seq: u64,
    expiry: Expiry,
    tx_hash: TxHash,
    effects_hash: fastpay_types::EffectsHash,
    request_id: Option<String>,
}

fn prepare_submission(
    req: &v1::SubmitFastPayRequest,
    expected_chain_id: u64,
) -> Result<PreparedSubmit, v1::RejectReason> {
    let tx = req
        .tx
        .clone()
        .ok_or_else(|| reject(v1::RejectCode::InvalidFormat, "missing tx"))?;

    let chain_id = tx
        .chain_id
        .as_ref()
        .ok_or_else(|| reject(v1::RejectCode::InvalidFormat, "missing chain_id"))?
        .value;
    if chain_id != expected_chain_id {
        return Err(reject(v1::RejectCode::WrongChain, "wrong chain_id"));
    }

    let decoded = decode_payment_from_fastpay_tx(&tx)?;
    validate_intent(&tx, &decoded)?;
    let expiry = parse_expiry(tx.expiry.as_ref())?;

    let nonce = tx
        .nonce
        .as_ref()
        .ok_or_else(|| reject(v1::RejectCode::InvalidFormat, "missing nonce"))?;
    let nonce_key = NonceKey::from_slice(&nonce.nonce_key_be)
        .map_err(|_| reject(v1::RejectCode::InvalidFormat, "nonce_key must be 32 bytes"))?;
    let nonce_seq = nonce.nonce_seq;

    let tx_hash = compute_tx_hash_from_proto(&tx, nonce_key, nonce_seq, expiry)?;
    let effects_hash = compute_effects_hash(&EffectsHashInput {
        sender: decoded.sender,
        recipient: decoded.recipient,
        amount: decoded.amount,
        asset: decoded.asset,
        nonce_key,
        nonce_seq,
    });

    let request_id = tx.client_request_id.trim().to_owned();
    let request_id = if request_id.is_empty() {
        None
    } else {
        Some(request_id)
    };

    Ok(PreparedSubmit {
        tx,
        decoded,
        nonce_key,
        nonce_seq,
        expiry,
        tx_hash,
        effects_hash,
        request_id,
    })
}

fn response_cert(cert: v1::ValidatorCertificate) -> v1::SubmitFastPayResponse {
    v1::SubmitFastPayResponse {
        result: Some(v1::submit_fast_pay_response::Result::Cert(cert)),
    }
}

fn response_reject(reject_reason: v1::RejectReason) -> v1::SubmitFastPayResponse {
    v1::SubmitFastPayResponse {
        result: Some(v1::submit_fast_pay_response::Result::Reject(reject_reason)),
    }
}

fn request_cache_key(request_id: &str, sender: Address) -> String {
    format!("{}:{request_id}", hex::encode(sender.as_bytes()))
}

fn cache_submit_response(
    inner: &mut Inner,
    request_id: String,
    tx_hash: TxHash,
    response: v1::SubmitFastPayResponse,
) {
    if inner.limits.max_request_cache == 0 {
        return;
    }

    inner
        .request_cache
        .insert(request_id.clone(), CachedSubmit { tx_hash, response });
    inner.request_cache_order.push_back(request_id);

    while inner.request_cache_order.len() > inner.limits.max_request_cache {
        if let Some(oldest) = inner.request_cache_order.pop_front() {
            inner.request_cache.remove(&oldest);
        }
    }
}

fn decode_payment_from_fastpay_tx(tx: &v1::FastPayTx) -> Result<DecodedPayment, v1::RejectReason> {
    let tempo_tx = tx
        .tempo_tx
        .as_ref()
        .ok_or_else(|| reject(v1::RejectCode::InvalidFormat, "missing tempo_tx"))?;
    decode_payment_from_tempo_tx(&tempo_tx.data)
}

pub fn decode_payment_from_tempo_tx(bytes: &[u8]) -> Result<DecodedPayment, v1::RejectReason> {
    if bytes.len() != 68 {
        return Err(reject(
            v1::RejectCode::InvalidFormat,
            "tempo_tx must be 68 bytes",
        ));
    }
    let sender = Address::from_slice(&bytes[0..20])
        .map_err(|_| reject(v1::RejectCode::InvalidFormat, "invalid sender"))?;
    let recipient = Address::from_slice(&bytes[20..40])
        .map_err(|_| reject(v1::RejectCode::InvalidFormat, "invalid recipient"))?;
    let amount = u64::from_be_bytes(
        bytes[40..48]
            .try_into()
            .map_err(|_| reject(v1::RejectCode::InvalidFormat, "invalid amount"))?,
    );
    let asset = AssetId::from_slice(&bytes[48..68])
        .map_err(|_| reject(v1::RejectCode::InvalidFormat, "invalid asset"))?;
    Ok(DecodedPayment {
        sender,
        recipient,
        amount,
        asset,
    })
}

fn validate_intent(tx: &v1::FastPayTx, decoded: &DecodedPayment) -> Result<(), v1::RejectReason> {
    if let Some(intent) = &tx.intent {
        let sender = to_address(intent.sender.as_ref())
            .map_err(|_| reject(v1::RejectCode::InvalidFormat, "intent.sender"))?;
        let recipient = to_address(intent.recipient.as_ref())
            .map_err(|_| reject(v1::RejectCode::InvalidFormat, "intent.recipient"))?;
        let asset = to_asset(intent.asset.as_ref())
            .map_err(|_| reject(v1::RejectCode::InvalidFormat, "intent.asset"))?;
        if sender != decoded.sender
            || recipient != decoded.recipient
            || intent.amount != decoded.amount
            || asset != decoded.asset
        {
            return Err(reject(
                v1::RejectCode::InvalidFormat,
                "intent does not match tempo_tx",
            ));
        }
    }
    Ok(())
}

fn compute_tx_hash_from_proto(
    tx: &v1::FastPayTx,
    nonce_key: NonceKey,
    nonce_seq: u64,
    expiry: Expiry,
) -> Result<TxHash, v1::RejectReason> {
    let chain_id = tx
        .chain_id
        .as_ref()
        .ok_or_else(|| reject(v1::RejectCode::InvalidFormat, "missing chain_id"))?
        .value;
    let tempo_tx = tx
        .tempo_tx
        .as_ref()
        .ok_or_else(|| reject(v1::RejectCode::InvalidFormat, "missing tempo_tx"))?
        .data
        .clone();
    let parent_qc_hash = if tx.parent_qc_hash.is_empty() {
        None
    } else {
        Some(QcHash::from_slice(&tx.parent_qc_hash).map_err(|_| {
            reject(
                v1::RejectCode::InvalidFormat,
                "parent_qc_hash must be 32 bytes",
            )
        })?)
    };
    Ok(compute_tx_hash(&TxHashInput {
        chain_id,
        tempo_tx,
        nonce_key,
        nonce_seq,
        expiry,
        parent_qc_hash,
    }))
}

fn validate_nonce(
    inner: &Inner,
    sender: Address,
    nonce_key: NonceKey,
    nonce_seq: u64,
) -> Result<(), v1::RejectReason> {
    let expected = inner
        .nonce_sequences
        .get(&(sender, nonce_key))
        .copied()
        .unwrap_or(0);
    if nonce_seq < expected {
        return Err(reject(
            v1::RejectCode::NonceSeqTooLow,
            "nonce sequence too low",
        ));
    }
    if nonce_seq > expected {
        return Err(reject(
            v1::RejectCode::NonceSeqTooHigh,
            "nonce sequence too high",
        ));
    }
    Ok(())
}

fn available_balance(
    inner: &mut Inner,
    sender: Address,
    asset: AssetId,
    amount: u64,
    parent_qcs: &[v1::QuorumCertificate],
    tx: &v1::FastPayTx,
    _effects_hash: fastpay_types::EffectsHash,
) -> Result<i128, v1::RejectReason> {
    let base = balance_of(&inner.balances, sender, asset) as i128;
    let overlay = overlay_of(&inner.overlay, sender, asset);
    let direct = base + overlay;

    if direct >= amount as i128 {
        cache_known_parent_qcs(inner, parent_qcs)?;
        return Ok(direct);
    }

    if tx.parent_qc_hash.is_empty() {
        return Err(reject(
            v1::RejectCode::MissingParentQc,
            "missing required parent QC",
        ));
    }

    let parent_credits = extract_parent_qc_credits(inner, sender, asset, parent_qcs, tx)?;
    Ok(direct + parent_credits)
}

fn extract_parent_qc_credits(
    inner: &mut Inner,
    sender: Address,
    asset: AssetId,
    parent_qcs: &[v1::QuorumCertificate],
    tx: &v1::FastPayTx,
) -> Result<i128, v1::RejectReason> {
    let expected_parent = QcHash::from_slice(&tx.parent_qc_hash)
        .map_err(|_| reject(v1::RejectCode::InvalidParentQc, "invalid parent_qc_hash"))?;

    let mut matched_qc: Option<&v1::QuorumCertificate> = None;
    let mut seen = HashSet::new();

    for qc in parent_qcs {
        let qc_hash = parse_or_compute_qc_hash(qc)?;
        if !seen.insert(qc_hash) {
            continue;
        }

        insert_known_qc(inner, qc_hash, qc.clone());

        if qc_hash == expected_parent {
            matched_qc = Some(qc);
        }
    }

    let qc = matched_qc.ok_or_else(|| {
        reject(
            v1::RejectCode::MissingParentQc,
            "missing required parent QC",
        )
    })?;

    let parent_tx_hash = TxHash::from_slice(&qc.tx_hash)
        .map_err(|_| reject(v1::RejectCode::InvalidParentQc, "invalid parent tx_hash"))?;

    let local_cert = inner.my_certs_by_tx.get(&parent_tx_hash).ok_or_else(|| {
        reject(
            v1::RejectCode::InvalidParentQc,
            "parent qc is not anchored by local cert",
        )
    })?;

    if local_cert.effects_hash.as_slice() != qc.effects_hash.as_slice() {
        return Err(reject(
            v1::RejectCode::InvalidParentQc,
            "parent qc effects_hash mismatch",
        ));
    }

    let validator_id = local_cert
        .signer
        .as_ref()
        .map(|s| s.id.clone())
        .unwrap_or_default();

    let mut signer_set = HashSet::new();
    let mut validator_effects: Option<&v1::EffectsSummary> = None;

    for cert in &qc.certs {
        if cert.tx_hash != qc.tx_hash || cert.effects_hash != qc.effects_hash {
            return Err(reject(
                v1::RejectCode::InvalidParentQc,
                "qc cert hash mismatch",
            ));
        }

        let signer = cert
            .signer
            .as_ref()
            .ok_or_else(|| reject(v1::RejectCode::InvalidParentQc, "missing qc signer"))?;

        if !signer_set.insert(signer.id.clone()) {
            return Err(reject(
                v1::RejectCode::InvalidParentQc,
                "duplicate signer in parent qc",
            ));
        }

        if signer.id == validator_id {
            validator_effects = cert.effects.as_ref();
        }
    }

    let effects = validator_effects
        .or(local_cert.effects.as_ref())
        .ok_or_else(|| reject(v1::RejectCode::InvalidParentQc, "missing effects summary"))?;

    let recomputed_effects_hash = compute_effects_hash_from_summary(effects)?;
    let qc_effects_hash =
        fastpay_types::EffectsHash::from_slice(&qc.effects_hash).map_err(|_| {
            reject(
                v1::RejectCode::InvalidParentQc,
                "invalid parent effects_hash bytes",
            )
        })?;
    if recomputed_effects_hash != qc_effects_hash {
        return Err(reject(
            v1::RejectCode::InvalidParentQc,
            "parent effects hash mismatch",
        ));
    }

    let recipient = to_address(effects.recipient.as_ref())
        .map_err(|_| reject(v1::RejectCode::InvalidParentQc, "invalid parent recipient"))?;
    let cert_asset = to_asset(effects.asset.as_ref())
        .map_err(|_| reject(v1::RejectCode::InvalidParentQc, "invalid parent asset"))?;

    if recipient == sender && cert_asset == asset {
        Ok(effects.amount as i128)
    } else {
        Ok(0)
    }
}

fn is_expired(inner: &Inner, expiry: Expiry) -> bool {
    match expiry {
        Expiry::MaxBlockHeight(max_height) => inner.current_block_height >= max_height,
        Expiry::UnixMillis(max_ms) => inner.current_unix_millis >= max_ms,
    }
}

fn balance_of(
    balances: &HashMap<Address, HashMap<AssetId, u64>>,
    address: Address,
    asset: AssetId,
) -> u64 {
    balances
        .get(&address)
        .and_then(|m| m.get(&asset))
        .copied()
        .unwrap_or(0)
}

fn overlay_of(
    overlay: &HashMap<Address, HashMap<AssetId, i128>>,
    address: Address,
    asset: AssetId,
) -> i128 {
    overlay
        .get(&address)
        .and_then(|m| m.get(&asset))
        .copied()
        .unwrap_or(0)
}

fn apply_overlay(inner: &mut Inner, decoded: &DecodedPayment) {
    let amount = decoded.amount as i128;
    inner
        .overlay
        .entry(decoded.sender)
        .or_default()
        .entry(decoded.asset)
        .and_modify(|v| *v -= amount)
        .or_insert(-amount);
}

fn store_cert_dedup_by_signer(
    inner: &mut Inner,
    tx_hash: TxHash,
    cert: v1::ValidatorCertificate,
) -> bool {
    if total_cert_count(&inner.certs) >= inner.limits.max_total_certs {
        return false;
    }

    let signer_id = cert
        .signer
        .as_ref()
        .map(|s| s.id.clone())
        .unwrap_or_default();
    let entry = inner.certs.entry(tx_hash).or_default();
    if entry
        .iter()
        .any(|existing| existing.signer.as_ref().map(|s| &s.id) == Some(&signer_id))
    {
        return false;
    }

    entry.push(cert);
    true
}

fn to_proto_cert(
    validator_name: &str,
    validator_pubkey: [u8; 32],
    cert: &fastpay_crypto::Ed25519Certificate,
    payment: &DecodedPayment,
    nonce_key: NonceKey,
    nonce_seq: u64,
) -> v1::ValidatorCertificate {
    v1::ValidatorCertificate {
        signer: Some(v1::ValidatorId {
            name: validator_name.to_string(),
            id: cert.signer().as_bytes().to_vec(),
            pubkey: validator_pubkey.to_vec(),
        }),
        tx_hash: cert.tx_hash().as_bytes().to_vec(),
        effects_hash: cert.effects_hash().as_bytes().to_vec(),
        effects: Some(v1::EffectsSummary {
            sender: Some(v1::Address {
                data: payment.sender.as_bytes().to_vec(),
            }),
            recipient: Some(v1::Address {
                data: payment.recipient.as_bytes().to_vec(),
            }),
            amount: payment.amount,
            asset: Some(v1::AssetId {
                data: payment.asset.as_bytes().to_vec(),
            }),
            nonce: Some(v1::Nonce2D {
                nonce_key_be: nonce_key.as_bytes().to_vec(),
                nonce_seq,
            }),
        }),
        signature: cert.signature_bytes().to_vec(),
        created_unix_millis: cert.created_at(),
    }
}

fn total_cert_count(certs: &HashMap<TxHash, Vec<v1::ValidatorCertificate>>) -> usize {
    certs.values().map(std::vec::Vec::len).sum()
}

fn insert_known_qc(inner: &mut Inner, qc_hash: QcHash, qc: v1::QuorumCertificate) {
    if inner.known_qcs.contains_key(&qc_hash) {
        return;
    }

    inner.known_qcs.insert(qc_hash, qc);
    inner.known_qc_order.push_back(qc_hash);

    while inner.known_qc_order.len() > inner.limits.max_known_qcs {
        if let Some(oldest) = inner.known_qc_order.pop_front() {
            inner.known_qcs.remove(&oldest);
        }
    }
}

fn cache_known_parent_qcs(
    inner: &mut Inner,
    parent_qcs: &[v1::QuorumCertificate],
) -> Result<(), v1::RejectReason> {
    let mut seen = HashSet::new();
    for qc in parent_qcs {
        let qc_hash = parse_or_compute_qc_hash(qc)?;
        if !seen.insert(qc_hash) {
            continue;
        }
        insert_known_qc(inner, qc_hash, qc.clone());
    }
    Ok(())
}

fn compute_effects_hash_from_summary(
    effects: &v1::EffectsSummary,
) -> Result<fastpay_types::EffectsHash, v1::RejectReason> {
    let sender = to_address(effects.sender.as_ref())
        .map_err(|_| reject(v1::RejectCode::InvalidParentQc, "invalid parent sender"))?;
    let recipient = to_address(effects.recipient.as_ref())
        .map_err(|_| reject(v1::RejectCode::InvalidParentQc, "invalid parent recipient"))?;
    let asset = to_asset(effects.asset.as_ref())
        .map_err(|_| reject(v1::RejectCode::InvalidParentQc, "invalid parent asset"))?;
    let nonce = effects
        .nonce
        .as_ref()
        .ok_or_else(|| reject(v1::RejectCode::InvalidParentQc, "missing parent nonce"))?;
    let nonce_key = NonceKey::from_slice(&nonce.nonce_key_be)
        .map_err(|_| reject(v1::RejectCode::InvalidParentQc, "invalid parent nonce_key"))?;

    Ok(compute_effects_hash(&EffectsHashInput {
        sender,
        recipient,
        amount: effects.amount,
        asset,
        nonce_key,
        nonce_seq: nonce.nonce_seq,
    }))
}

fn parse_or_compute_qc_hash(qc: &v1::QuorumCertificate) -> Result<QcHash, v1::RejectReason> {
    let tx_hash = TxHash::from_slice(&qc.tx_hash)
        .map_err(|_| reject(v1::RejectCode::InvalidParentQc, "invalid qc tx_hash"))?;
    let effects_hash = fastpay_types::EffectsHash::from_slice(&qc.effects_hash)
        .map_err(|_| reject(v1::RejectCode::InvalidParentQc, "invalid qc effects_hash"))?;

    let mut certs = Vec::with_capacity(qc.certs.len());
    for cert in &qc.certs {
        let signer = cert
            .signer
            .as_ref()
            .ok_or_else(|| reject(v1::RejectCode::InvalidParentQc, "missing qc signer"))?;
        let signer_id = ValidatorId::from_slice(&signer.id)
            .map_err(|_| reject(v1::RejectCode::InvalidParentQc, "invalid signer id"))?;
        let domain_cert = fastpay_crypto::Ed25519Certificate::new(
            TxHash::from_slice(&cert.tx_hash)
                .map_err(|_| reject(v1::RejectCode::InvalidParentQc, "invalid cert tx_hash"))?,
            fastpay_types::EffectsHash::from_slice(&cert.effects_hash).map_err(|_| {
                reject(v1::RejectCode::InvalidParentQc, "invalid cert effects_hash")
            })?,
            signer_id,
            cert.signature.clone(),
            cert.created_unix_millis,
        )
        .map_err(|_| reject(v1::RejectCode::InvalidParentQc, "invalid cert signature"))?;
        certs.push(domain_cert);
    }

    let computed = compute_qc_hash(&tx_hash, &effects_hash, qc.threshold, certs.as_slice());

    if !qc.qc_hash.is_empty() {
        let provided = QcHash::from_slice(&qc.qc_hash)
            .map_err(|_| reject(v1::RejectCode::InvalidParentQc, "invalid qc_hash"))?;
        if provided != computed {
            return Err(reject(
                v1::RejectCode::InvalidParentQc,
                "provided qc_hash does not match computed hash",
            ));
        }
    }

    Ok(computed)
}

fn parse_expiry(expiry: Option<&v1::Expiry>) -> Result<Expiry, v1::RejectReason> {
    let expiry = expiry.ok_or_else(|| reject(v1::RejectCode::InvalidFormat, "missing expiry"))?;
    match expiry.kind {
        Some(v1::expiry::Kind::MaxBlockHeight(v)) => Ok(Expiry::MaxBlockHeight(v)),
        Some(v1::expiry::Kind::UnixMillis(v)) => Ok(Expiry::UnixMillis(v)),
        None => Err(reject(v1::RejectCode::InvalidFormat, "missing expiry kind")),
    }
}

fn reject(code: v1::RejectCode, message: impl Into<String>) -> v1::RejectReason {
    v1::RejectReason {
        code: code as i32,
        message: message.into(),
    }
}

fn to_reject(err: CryptoError) -> v1::RejectReason {
    reject(v1::RejectCode::TemporaryUnavailable, err.to_string())
}

fn to_address(value: Option<&v1::Address>) -> Result<Address, ValidationError> {
    let value = value.ok_or(ValidationError::MissingField("address"))?;
    Address::from_slice(&value.data)
}

fn to_asset(value: Option<&v1::AssetId>) -> Result<AssetId, ValidationError> {
    let value = value.ok_or(ValidationError::MissingField("asset"))?;
    AssetId::from_slice(&value.data)
}

fn cert_involves_address(cert: &v1::ValidatorCertificate, address: &[u8]) -> bool {
    cert.effects
        .as_ref()
        .map(|effects| {
            effects
                .sender
                .as_ref()
                .map(|v| v.data.as_slice() == address)
                .unwrap_or(false)
                || effects
                    .recipient
                    .as_ref()
                    .map(|v| v.data.as_slice() == address)
                    .unwrap_or(false)
        })
        .unwrap_or(false)
}
