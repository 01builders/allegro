//! MockSidecar: in-memory validator with balance tracking, equivocation guard, and bulletin board.

use std::collections::{HashMap, HashSet};

use alloy_consensus::{transaction::SignableTransaction, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::TxKind;
use fastpay_crypto::{
    compute_effects_hash, compute_qc_hash, compute_tx_hash, Ed25519Signer, EffectsHashInput,
    TxHashInput,
};
use fastpay_proto::v1;
use fastpay_types::{
    Address, AssetId, CertSigningContext, Certificate, CryptoError, Expiry, NonceKey, QcHash,
    Signer, TxHash, ValidationError, ValidatorId,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPayment {
    pub sender: Address,
    pub recipient: Address,
    pub amount: u64,
    pub asset: AssetId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTempoPayload {
    pub recipient: Address,
    pub amount: u64,
    pub asset: AssetId,
}

const MAX_TEMPO_TX_BYTES: usize = 128 * 1024;
const TIP20_PAYMENT_PREFIX: [u8; 12] = [0x20, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

#[derive(Debug, Clone)]
pub struct MockSidecar {
    name: String,
    signer: Ed25519Signer,
    signing_ctx: CertSigningContext,
    pub balances: HashMap<Address, HashMap<AssetId, u64>>,
    pub overlay: HashMap<Address, HashMap<AssetId, i64>>,
    pub signed_txs: HashMap<(Address, NonceKey, u64), TxHash>,
    pub certs: HashMap<TxHash, Vec<v1::ValidatorCertificate>>,
    pub known_qcs: HashMap<QcHash, v1::QuorumCertificate>,
    pub nonce_sequences: HashMap<(Address, NonceKey), u64>,
    pub current_block_height: u64,
    pub current_unix_millis: u64,
}

impl MockSidecar {
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
            balances,
            overlay: HashMap::new(),
            signed_txs: HashMap::new(),
            certs: HashMap::new(),
            known_qcs: HashMap::new(),
            nonce_sequences: HashMap::new(),
            current_block_height: 0,
            current_unix_millis: 0,
        }
    }

    pub fn set_chain_head(&mut self, block_height: u64, unix_millis: u64) {
        self.current_block_height = block_height;
        self.current_unix_millis = unix_millis;
    }

    pub fn submit_fastpay(&mut self, req: v1::SubmitFastPayRequest) -> v1::SubmitFastPayResponse {
        match self.validate_and_sign(req) {
            Ok(cert) => v1::SubmitFastPayResponse {
                result: Some(v1::submit_fast_pay_response::Result::Cert(cert)),
            },
            Err(reject) => v1::SubmitFastPayResponse {
                result: Some(v1::submit_fast_pay_response::Result::Reject(reject)),
            },
        }
    }

    pub fn get_bulletin_board(
        &self,
        req: v1::GetBulletinBoardRequest,
    ) -> v1::GetBulletinBoardResponse {
        let mut certs: Vec<v1::ValidatorCertificate> = self
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
        if req.limit > 0 && certs.len() > req.limit as usize {
            certs.truncate(req.limit as usize);
        }

        v1::GetBulletinBoardResponse {
            certs,
            next_cursor: String::new(),
        }
    }

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

    pub fn get_chain_head(&self) -> v1::GetChainHeadResponse {
        v1::GetChainHeadResponse {
            block_height: self.current_block_height,
            block_hash: Vec::new(),
            unix_millis: self.current_unix_millis,
        }
    }

    fn validate_and_sign(
        &mut self,
        req: v1::SubmitFastPayRequest,
    ) -> Result<v1::ValidatorCertificate, v1::RejectReason> {
        let tx = req
            .tx
            .clone()
            .ok_or_else(|| reject(v1::RejectCode::InvalidFormat, "missing tx"))?;
        let tempo_tx = tx
            .tempo_tx
            .as_ref()
            .ok_or_else(|| reject(v1::RejectCode::InvalidFormat, "missing tempo_tx"))?;
        if tempo_tx.data.is_empty() {
            return Err(reject(v1::RejectCode::InvalidFormat, "empty tempo_tx"));
        }
        if tempo_tx.data.len() > MAX_TEMPO_TX_BYTES {
            return Err(reject(
                v1::RejectCode::InvalidFormat,
                "tempo_tx exceeds maximum size",
            ));
        }
        let tx_format = parse_tempo_tx_format(&tx)?;
        let decoded = overlay_payment_from_fastpay_tx(&tx)?;
        let payload = match tx_format {
            v1::TempoTxFormat::EvmOpaqueBytesV1 => {
                Self::decode_payment_from_tempo_tx(&tempo_tx.data)?
            }
            v1::TempoTxFormat::Unspecified => {
                return Err(reject(
                    v1::RejectCode::InvalidFormat,
                    "tempo_tx_format unspecified",
                ));
            }
        };

        let recovered_sender = recover_sender_from_tempo_tx(&tempo_tx.data)?;
        if recovered_sender != decoded.sender {
            return Err(reject(
                v1::RejectCode::InvalidFormat,
                "overlay sender does not match tx signer",
            ));
        }

        if payload.recipient != decoded.recipient
            || payload.amount != decoded.amount
            || payload.asset != decoded.asset
        {
            return Err(reject(
                v1::RejectCode::InvalidFormat,
                "overlay payment does not match tempo_tx",
            ));
        }

        self.validate_intent(&tx, &decoded)?;
        let expiry = parse_expiry(tx.expiry.as_ref())?;
        if self.is_expired(expiry) {
            return Err(reject(v1::RejectCode::Expired, "transaction expired"));
        }

        let nonce = tx
            .nonce
            .as_ref()
            .ok_or_else(|| reject(v1::RejectCode::InvalidFormat, "missing nonce"))?;
        let nonce_key = NonceKey::from_slice(&nonce.nonce_key_be)
            .map_err(|_| reject(v1::RejectCode::InvalidFormat, "nonce_key must be 32 bytes"))?;
        let nonce_seq = nonce.nonce_seq;

        let tx_hash = self.compute_tx_hash(&tx, nonce_key, nonce_seq, expiry)?;
        let effects_hash = compute_effects_hash(&EffectsHashInput {
            sender: decoded.sender,
            recipient: decoded.recipient,
            amount: decoded.amount,
            asset: decoded.asset,
            nonce_key,
            nonce_seq,
        });

        let contention_key = (decoded.sender, nonce_key, nonce_seq);
        if let Some(existing) = self.signed_txs.get(&contention_key) {
            if existing != &tx_hash {
                return Err(reject(
                    v1::RejectCode::Equivocation,
                    "equivocation detected",
                ));
            }
        }
        self.validate_nonce(decoded.sender, nonce_key, nonce_seq)?;

        let available =
            self.available_balance(decoded.sender, decoded.asset, &req.parent_qcs, &tx)?;
        if available < decoded.amount as i128 {
            return Err(reject(
                v1::RejectCode::InsufficientFunds,
                "insufficient funds",
            ));
        }

        let cert = self
            .signer
            .sign(&self.signing_ctx, &tx_hash, &effects_hash)
            .map_err(to_reject)?;
        let cert_proto = to_proto_cert(
            &self.name,
            self.signer.public_key_bytes(),
            &cert,
            &decoded,
            nonce_key,
            nonce_seq,
        );

        self.signed_txs.insert(contention_key, tx_hash);
        self.nonce_sequences
            .insert((decoded.sender, nonce_key), nonce_seq + 1);
        self.apply_overlay(&decoded);
        self.store_cert_dedup_by_signer(tx_hash, cert_proto.clone());

        Ok(cert_proto)
    }

    pub fn decode_payment_from_tempo_tx(
        bytes: &[u8],
    ) -> Result<DecodedTempoPayload, v1::RejectReason> {
        let envelope = TxEnvelope::decode_2718_exact(bytes).map_err(|_| {
            reject(
                v1::RejectCode::InvalidFormat,
                "invalid ethereum tx encoding",
            )
        })?;

        let (to_kind, value, input) = match envelope {
            TxEnvelope::Legacy(signed) => {
                let tx = signed.tx();
                (tx.to, tx.value, tx.input.to_vec())
            }
            TxEnvelope::Eip2930(signed) => {
                let tx = signed.tx();
                (tx.to, tx.value, tx.input.to_vec())
            }
            TxEnvelope::Eip1559(signed) => {
                let tx = signed.tx();
                (tx.to, tx.value, tx.input.to_vec())
            }
            _ => {
                return Err(reject(
                    v1::RejectCode::NotPaymentTx,
                    "unsupported ethereum tx type",
                ));
            }
        };

        if !value.is_zero() {
            return Err(reject(
                v1::RejectCode::NotPaymentTx,
                "native value transfers are not supported",
            ));
        }

        let token_addr = match to_kind {
            TxKind::Call(addr) => addr,
            TxKind::Create => {
                return Err(reject(
                    v1::RejectCode::NotPaymentTx,
                    "contract creation is not a payment tx",
                ));
            }
        };

        if !token_addr.as_slice().starts_with(&TIP20_PAYMENT_PREFIX) {
            return Err(reject(
                v1::RejectCode::NotPaymentTx,
                "token address is not TIP-20 payment-prefixed",
            ));
        }

        if input.len() != 68 || input[0..4] != [0xa9, 0x05, 0x9c, 0xbb] {
            return Err(reject(
                v1::RejectCode::NotPaymentTx,
                "unsupported call data",
            ));
        }

        if input[4..16].iter().any(|b| *b != 0) {
            return Err(reject(
                v1::RejectCode::InvalidFormat,
                "invalid recipient encoding",
            ));
        }
        if input[36..60].iter().any(|b| *b != 0) {
            return Err(reject(
                v1::RejectCode::InvalidFormat,
                "amount does not fit u64",
            ));
        }

        let recipient = Address::from_slice(&input[16..36])
            .map_err(|_| reject(v1::RejectCode::InvalidFormat, "invalid recipient"))?;
        let amount = u64::from_be_bytes(
            input[60..68]
                .try_into()
                .map_err(|_| reject(v1::RejectCode::InvalidFormat, "invalid amount"))?,
        );

        let asset = AssetId::from_slice(token_addr.as_slice())
            .map_err(|_| reject(v1::RejectCode::InvalidFormat, "invalid token address"))?;

        Ok(DecodedTempoPayload {
            recipient,
            amount,
            asset,
        })
    }

    fn validate_intent(
        &self,
        tx: &v1::FastPayTx,
        decoded: &DecodedPayment,
    ) -> Result<(), v1::RejectReason> {
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

    fn compute_tx_hash(
        &self,
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
        &self,
        sender: Address,
        nonce_key: NonceKey,
        nonce_seq: u64,
    ) -> Result<(), v1::RejectReason> {
        let expected = self
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
        &mut self,
        sender: Address,
        asset: AssetId,
        parent_qcs: &[v1::QuorumCertificate],
        tx: &v1::FastPayTx,
    ) -> Result<i128, v1::RejectReason> {
        let base = self.balance_of(sender, asset) as i128;
        let overlay = self.overlay_of(sender, asset) as i128;
        let parent_credits = self.extract_parent_qc_credits(sender, asset, parent_qcs, tx)?;
        Ok(base + overlay + parent_credits)
    }

    fn extract_parent_qc_credits(
        &mut self,
        sender: Address,
        asset: AssetId,
        parent_qcs: &[v1::QuorumCertificate],
        tx: &v1::FastPayTx,
    ) -> Result<i128, v1::RejectReason> {
        if tx.parent_qc_hash.is_empty() {
            return Ok(0);
        }
        let expected_parent = QcHash::from_slice(&tx.parent_qc_hash)
            .map_err(|_| reject(v1::RejectCode::InvalidParentQc, "invalid parent_qc_hash"))?;

        let mut matched = false;
        let mut seen = HashSet::new();
        let mut credit_total: i128 = 0;

        for qc in parent_qcs {
            let qc_hash = parse_or_compute_qc_hash(qc)?;
            if !seen.insert(qc_hash) {
                continue;
            }
            if qc_hash == expected_parent {
                matched = true;
            }
            self.known_qcs.insert(qc_hash, qc.clone());
            for cert in &qc.certs {
                if let Some(effects) = &cert.effects {
                    let recipient = to_address(effects.recipient.as_ref()).map_err(|_| {
                        reject(v1::RejectCode::InvalidParentQc, "invalid parent recipient")
                    })?;
                    let cert_asset = to_asset(effects.asset.as_ref()).map_err(|_| {
                        reject(v1::RejectCode::InvalidParentQc, "invalid parent asset")
                    })?;
                    if recipient == sender && cert_asset == asset {
                        credit_total += effects.amount as i128;
                        break;
                    }
                }
            }
        }

        if !matched {
            return Err(reject(
                v1::RejectCode::MissingParentQc,
                "missing required parent QC",
            ));
        }
        Ok(credit_total)
    }

    fn is_expired(&self, expiry: Expiry) -> bool {
        match expiry {
            Expiry::MaxBlockHeight(max_height) => self.current_block_height >= max_height,
            Expiry::UnixMillis(max_ms) => self.current_unix_millis >= max_ms,
        }
    }

    fn balance_of(&self, address: Address, asset: AssetId) -> u64 {
        self.balances
            .get(&address)
            .and_then(|m| m.get(&asset))
            .copied()
            .unwrap_or(0)
    }

    fn overlay_of(&self, address: Address, asset: AssetId) -> i64 {
        self.overlay
            .get(&address)
            .and_then(|m| m.get(&asset))
            .copied()
            .unwrap_or(0)
    }

    fn apply_overlay(&mut self, decoded: &DecodedPayment) {
        self.overlay
            .entry(decoded.sender)
            .or_default()
            .entry(decoded.asset)
            .and_modify(|v| *v -= decoded.amount as i64)
            .or_insert(-(decoded.amount as i64));
    }

    fn store_cert_dedup_by_signer(&mut self, tx_hash: TxHash, cert: v1::ValidatorCertificate) {
        let signer_id = cert
            .signer
            .as_ref()
            .map(|s| s.id.clone())
            .unwrap_or_default();
        let entry = self.certs.entry(tx_hash).or_default();
        if entry
            .iter()
            .any(|existing| existing.signer.as_ref().map(|s| &s.id) == Some(&signer_id))
        {
            return;
        }
        entry.push(cert);
    }
}

fn recover_sender_from_tempo_tx(bytes: &[u8]) -> Result<Address, v1::RejectReason> {
    let envelope = TxEnvelope::decode_2718_exact(bytes).map_err(|_| {
        reject(
            v1::RejectCode::InvalidFormat,
            "invalid ethereum tx encoding",
        )
    })?;
    let signer = match envelope {
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
    .map_err(|_| reject(v1::RejectCode::InvalidFormat, "unable to recover tx signer"))?;
    Address::from_slice(signer.as_slice())
        .map_err(|_| reject(v1::RejectCode::InvalidFormat, "invalid signer address"))
}

fn parse_tempo_tx_format(tx: &v1::FastPayTx) -> Result<v1::TempoTxFormat, v1::RejectReason> {
    if tx.tempo_tx_format == v1::TempoTxFormat::Unspecified as i32 {
        return Err(reject(
            v1::RejectCode::InvalidFormat,
            "tempo_tx_format must be specified",
        ));
    }

    v1::TempoTxFormat::try_from(tx.tempo_tx_format).map_err(|_| {
        reject(
            v1::RejectCode::InvalidFormat,
            "unknown tempo_tx_format value",
        )
    })
}

fn overlay_payment_from_fastpay_tx(tx: &v1::FastPayTx) -> Result<DecodedPayment, v1::RejectReason> {
    if let Some(overlay) = tx.overlay.as_ref() {
        if let Some(payment) = overlay.payment.as_ref() {
            return payment_intent_to_decoded(payment, "overlay.payment");
        }
    }

    if let Some(intent) = tx.intent.as_ref() {
        return payment_intent_to_decoded(intent, "intent");
    }

    Err(reject(
        v1::RejectCode::InvalidFormat,
        "missing overlay payment metadata",
    ))
}

fn payment_intent_to_decoded(
    intent: &v1::PaymentIntent,
    field: &'static str,
) -> Result<DecodedPayment, v1::RejectReason> {
    let sender = to_address(intent.sender.as_ref())
        .map_err(|_| reject(v1::RejectCode::InvalidFormat, format!("{field}.sender")))?;
    let recipient = to_address(intent.recipient.as_ref())
        .map_err(|_| reject(v1::RejectCode::InvalidFormat, format!("{field}.recipient")))?;
    let asset = to_asset(intent.asset.as_ref())
        .map_err(|_| reject(v1::RejectCode::InvalidFormat, format!("{field}.asset")))?;
    Ok(DecodedPayment {
        sender,
        recipient,
        amount: intent.amount,
        asset,
    })
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

fn parse_or_compute_qc_hash(qc: &v1::QuorumCertificate) -> Result<QcHash, v1::RejectReason> {
    if !qc.qc_hash.is_empty() {
        return QcHash::from_slice(&qc.qc_hash)
            .map_err(|_| reject(v1::RejectCode::InvalidParentQc, "invalid qc_hash"));
    }
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
    Ok(compute_qc_hash(
        &tx_hash,
        &effects_hash,
        qc.threshold,
        certs.as_slice(),
    ))
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy_consensus::{transaction::SignableTransaction, TxEip1559, TxLegacy};
    use alloy_eips::{eip2718::Encodable2718, eip2930::AccessList};
    use alloy_primitives::{Address as AlloyAddress, Bytes, U256};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use fastpay_crypto::{
        compute_effects_hash, compute_qc_hash, compute_tx_hash, Ed25519Signer, EffectsHashInput,
        TxHashInput,
    };
    use fastpay_proto::v1;
    use fastpay_types::{Address, AssetId, CertSigningContext, NonceKey, Signer, TxHash};

    use crate::mock_sidecar::{DecodedPayment, MockSidecar};

    fn address_from_private_key(private_key: [u8; 32]) -> Address {
        Address::from_slice(
            PrivateKeySigner::from_slice(&private_key)
                .expect("valid private key")
                .address()
                .as_slice(),
        )
        .expect("20-byte address")
    }

    fn private_key_for_sender(sender: Address) -> [u8; 32] {
        for key in [[0x11; 32], [0x22; 32], [0x33; 32]] {
            if address_from_private_key(key) == sender {
                return key;
            }
        }
        panic!("unknown sender address for test signer")
    }

    fn tip20_asset() -> AssetId {
        AssetId::new([
            0x20, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        ])
    }

    fn erc20_transfer_calldata(recipient: Address, amount: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(68);
        data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(recipient.as_bytes());
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&amount.to_be_bytes());
        data
    }

    fn encode_payment(payment: &DecodedPayment) -> Vec<u8> {
        let signer = PrivateKeySigner::from_slice(&private_key_for_sender(payment.sender))
            .expect("valid sender key");
        let tx = TxLegacy {
            chain_id: Some(1337),
            nonce: 0,
            gas_price: 1,
            gas_limit: 80_000,
            to: AlloyAddress::from_slice(payment.asset.as_bytes()).into(),
            value: U256::ZERO,
            input: Bytes::from(erc20_transfer_calldata(payment.recipient, payment.amount)),
        };
        let signature = signer
            .sign_hash_sync(&tx.signature_hash())
            .expect("sign legacy tx");
        tx.into_signed(signature).encoded_2718()
    }

    fn encode_typed_payment(payment: &DecodedPayment) -> Vec<u8> {
        let signer = PrivateKeySigner::from_slice(&private_key_for_sender(payment.sender))
            .expect("valid sender key");
        let tx = TxEip1559 {
            chain_id: 1337,
            nonce: 0,
            gas_limit: 80_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            to: AlloyAddress::from_slice(payment.asset.as_bytes()).into(),
            value: U256::ZERO,
            access_list: AccessList::default(),
            input: Bytes::from(erc20_transfer_calldata(payment.recipient, payment.amount)),
        };
        let signature = signer
            .sign_hash_sync(&tx.signature_hash())
            .expect("sign typed tx");
        tx.into_signed(signature).encoded_2718()
    }

    fn make_sidecar() -> (MockSidecar, DecodedPayment, DecodedPayment) {
        let alice = address_from_private_key([0x11; 32]);
        let bob = address_from_private_key([0x22; 32]);
        let carol = address_from_private_key([0x33; 32]);
        let asset = tip20_asset();
        let payment_ab = DecodedPayment {
            sender: alice,
            recipient: bob,
            amount: 10,
            asset,
        };
        let payment_ac = DecodedPayment {
            sender: alice,
            recipient: carol,
            amount: 10,
            asset,
        };

        let mut balances = HashMap::new();
        balances.insert(alice, HashMap::from([(asset, 15)]));
        balances.insert(bob, HashMap::from([(asset, 5)]));
        balances.insert(carol, HashMap::from([(asset, 5)]));
        let signer =
            Ed25519Signer::from_seed(fastpay_types::ValidatorId::new([0x44; 32]), [7u8; 32]);
        let ctx = CertSigningContext {
            chain_id: 1337,
            domain_tag: "tempo.fastpay.cert.v1",
            protocol_version: 1,
            epoch: 1,
        };
        let mut sidecar = MockSidecar::new("Dave", signer, ctx, balances);
        sidecar.set_chain_head(1, 1_700_000_000_000);
        (sidecar, payment_ab, payment_ac)
    }

    fn submit_request(
        payment: &DecodedPayment,
        seq: u64,
        expiry_height: u64,
    ) -> v1::SubmitFastPayRequest {
        let intent = v1::PaymentIntent {
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
        };

        v1::SubmitFastPayRequest {
            tx: Some(v1::FastPayTx {
                chain_id: Some(v1::ChainId { value: 1337 }),
                tempo_tx: Some(v1::TempoTxBytes {
                    data: encode_payment(payment),
                }),
                intent: Some(intent.clone()),
                nonce: Some(v1::Nonce2D {
                    nonce_key_be: [0x5b; 32].to_vec(),
                    nonce_seq: seq,
                }),
                expiry: Some(v1::Expiry {
                    kind: Some(v1::expiry::Kind::MaxBlockHeight(expiry_height)),
                }),
                parent_qc_hash: Vec::new(),
                client_request_id: String::new(),
                tempo_tx_format: v1::TempoTxFormat::EvmOpaqueBytesV1 as i32,
                overlay: Some(v1::OverlayMetadata {
                    payment: Some(intent),
                }),
            }),
            parent_qcs: Vec::new(),
        }
    }

    #[test]
    fn accepts_valid_transaction() {
        let (mut sidecar, payment, _) = make_sidecar();
        let resp = sidecar.submit_fastpay(submit_request(&payment, 0, 20));
        match resp.result {
            Some(v1::submit_fast_pay_response::Result::Cert(cert)) => {
                assert_eq!(cert.tx_hash.len(), 32);
                assert_eq!(cert.effects_hash.len(), 32);
            }
            _ => panic!("expected cert"),
        }
    }

    #[test]
    fn rejects_insufficient_funds() {
        let (mut sidecar, mut payment, _) = make_sidecar();
        payment.amount = 1_000;
        let resp = sidecar.submit_fastpay(submit_request(&payment, 0, 20));
        match resp.result {
            Some(v1::submit_fast_pay_response::Result::Reject(reject)) => {
                assert_eq!(reject.code, v1::RejectCode::InsufficientFunds as i32);
            }
            _ => panic!("expected reject"),
        }
    }

    #[test]
    fn rejects_equivocation_attempt() {
        let (mut sidecar, payment_ab, payment_ac) = make_sidecar();
        let first = sidecar.submit_fastpay(submit_request(&payment_ab, 0, 20));
        assert!(matches!(
            first.result,
            Some(v1::submit_fast_pay_response::Result::Cert(_))
        ));

        let second = sidecar.submit_fastpay(submit_request(&payment_ac, 0, 20));
        match second.result {
            Some(v1::submit_fast_pay_response::Result::Reject(reject)) => {
                assert_eq!(reject.code, v1::RejectCode::Equivocation as i32);
            }
            _ => panic!("expected equivocation reject"),
        }
    }

    #[test]
    fn rejects_expired_transaction() {
        let (mut sidecar, payment, _) = make_sidecar();
        let resp = sidecar.submit_fastpay(submit_request(&payment, 0, 1));
        match resp.result {
            Some(v1::submit_fast_pay_response::Result::Reject(reject)) => {
                assert_eq!(reject.code, v1::RejectCode::Expired as i32);
            }
            _ => panic!("expected expired reject"),
        }
    }

    #[test]
    fn dedupes_signer_in_cert_store() {
        let (mut sidecar, payment, _) = make_sidecar();
        let first = sidecar.submit_fastpay(submit_request(&payment, 0, 20));
        let cert = match first.result {
            Some(v1::submit_fast_pay_response::Result::Cert(cert)) => cert,
            _ => panic!("expected cert"),
        };
        let tx_hash = TxHash::from_slice(&cert.tx_hash).unwrap();
        let existing_len = sidecar.certs.get(&tx_hash).unwrap().len();
        sidecar.store_cert_dedup_by_signer(tx_hash, cert);
        assert_eq!(sidecar.certs.get(&tx_hash).unwrap().len(), existing_len);
    }

    #[test]
    fn rejects_missing_overlay_and_intent() {
        let (mut sidecar, payment, _) = make_sidecar();
        let mut req = submit_request(&payment, 0, 20);
        let tx = req.tx.as_mut().expect("tx");
        tx.intent = None;
        tx.overlay = None;
        let resp = sidecar.submit_fastpay(req);
        match resp.result {
            Some(v1::submit_fast_pay_response::Result::Reject(reject)) => {
                assert_eq!(reject.code, v1::RejectCode::InvalidFormat as i32);
            }
            _ => panic!("expected missing overlay reject"),
        }
    }

    #[test]
    fn rejects_unknown_tempo_tx_format() {
        let (mut sidecar, payment, _) = make_sidecar();
        let mut req = submit_request(&payment, 0, 20);
        req.tx.as_mut().expect("tx").tempo_tx_format = 999;
        let resp = sidecar.submit_fastpay(req);
        match resp.result {
            Some(v1::submit_fast_pay_response::Result::Reject(reject)) => {
                assert_eq!(reject.code, v1::RejectCode::InvalidFormat as i32);
            }
            _ => panic!("expected invalid format reject"),
        }
    }

    #[test]
    fn decodes_legacy_eth_transaction_payload() {
        let (_, payment, _) = make_sidecar();
        let decoded = MockSidecar::decode_payment_from_tempo_tx(&encode_payment(&payment))
            .expect("legacy tx should decode");
        assert_eq!(decoded.recipient, payment.recipient);
        assert_eq!(decoded.amount, payment.amount);
        assert_eq!(decoded.asset, payment.asset);
    }

    #[test]
    fn decodes_typed_eth_transaction_payload() {
        let (_, payment, _) = make_sidecar();
        let decoded = MockSidecar::decode_payment_from_tempo_tx(&encode_typed_payment(&payment))
            .expect("typed tx should decode");
        assert_eq!(decoded.recipient, payment.recipient);
        assert_eq!(decoded.amount, payment.amount);
        assert_eq!(decoded.asset, payment.asset);
    }

    #[test]
    fn computes_parent_qc_credit() {
        let (mut sidecar, payment, _) = make_sidecar();
        let tx_hash = compute_tx_hash(&TxHashInput {
            chain_id: 1337,
            tempo_tx: encode_payment(&payment),
            nonce_key: NonceKey::new([0x5b; 32]),
            nonce_seq: 0,
            expiry: fastpay_types::Expiry::MaxBlockHeight(20),
            parent_qc_hash: None,
        });
        let effects_hash = compute_effects_hash(&EffectsHashInput {
            sender: payment.sender,
            recipient: payment.recipient,
            amount: payment.amount,
            asset: payment.asset,
            nonce_key: NonceKey::new([0x5b; 32]),
            nonce_seq: 0,
        });
        let cert = sidecar
            .signer
            .sign(&sidecar.signing_ctx, &tx_hash, &effects_hash)
            .unwrap();
        let proto_cert = super::to_proto_cert(
            "Dave",
            sidecar.signer.public_key_bytes(),
            &cert,
            &payment,
            NonceKey::new([0x5b; 32]),
            0,
        );
        let qc_hash = compute_qc_hash(&tx_hash, &effects_hash, 1, &[cert]);

        let qc = v1::QuorumCertificate {
            tx_hash: tx_hash.as_bytes().to_vec(),
            effects_hash: effects_hash.as_bytes().to_vec(),
            certs: vec![proto_cert],
            threshold: 1,
            qc_hash: qc_hash.as_bytes().to_vec(),
        };
        let mut req = submit_request(&payment, 0, 20);
        req.tx.as_mut().unwrap().parent_qc_hash = qc_hash.as_bytes().to_vec();
        req.parent_qcs.push(qc);
        // Bob can spend because parent credit is counted for recipient.
        req.tx.as_mut().unwrap().tempo_tx = Some(v1::TempoTxBytes {
            data: encode_payment(&DecodedPayment {
                sender: payment.recipient,
                recipient: Address::new([0x03; 20]),
                amount: payment.amount,
                asset: payment.asset,
            }),
        });
        let child_intent = v1::PaymentIntent {
            sender: Some(v1::Address {
                data: payment.recipient.as_bytes().to_vec(),
            }),
            recipient: Some(v1::Address {
                data: [0x03; 20].to_vec(),
            }),
            amount: payment.amount,
            asset: Some(v1::AssetId {
                data: payment.asset.as_bytes().to_vec(),
            }),
        };
        req.tx.as_mut().unwrap().intent = Some(child_intent.clone());
        req.tx.as_mut().unwrap().overlay = Some(v1::OverlayMetadata {
            payment: Some(child_intent),
        });

        let resp = sidecar.submit_fastpay(req);
        assert!(matches!(
            resp.result,
            Some(v1::submit_fast_pay_response::Result::Cert(_))
        ));
    }
}
