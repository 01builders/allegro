//! TxBuilder: construct FastPayTx with payment, nonce, expiry, and parent QC.

use std::collections::HashMap;

use alloy_consensus::{transaction::SignableTransaction, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address as AlloyAddress, Bytes, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use fastpay_crypto::{compute_effects_hash, compute_tx_hash, EffectsHashInput, TxHashInput};
use fastpay_proto::v1;
use fastpay_types::{
    Address, AssetId, Expiry, NonceKey, QcHash, QuorumCert, TxHash, ValidationError,
};
use thiserror::Error;

/// Transaction builder validation errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TxBuilderError {
    #[error("missing field `{0}`")]
    MissingField(&'static str),
    #[error("invalid payment: {0}")]
    InvalidPayment(&'static str),
    #[error("signing error: {0}")]
    Signing(String),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

/// Result of a built FastPay transaction including derived hashes.
#[derive(Debug, Clone)]
pub struct BuiltTx {
    pub tx: v1::FastPayTx,
    pub tx_hash: TxHash,
    pub effects_hash: fastpay_types::EffectsHash,
}

/// Fluent transaction builder for `FastPayTx`.
#[derive(Debug, Clone, Default)]
pub struct TxBuilder {
    chain_id: Option<u64>,
    sender: Option<Address>,
    recipient: Option<Address>,
    amount: Option<u64>,
    asset: Option<AssetId>,
    nonce_key: Option<NonceKey>,
    nonce_seq: Option<u64>,
    expiry: Option<Expiry>,
    parent_qc_hash: Option<QcHash>,
    client_request_id: Option<String>,
    tempo_tx_format: Option<i32>,
    tempo_tx_bytes: Option<Vec<u8>>,
    sender_private_key: Option<[u8; 32]>,
    next_nonce_by_key: HashMap<NonceKey, u64>,
}

impl TxBuilder {
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id: Some(chain_id),
            ..Self::default()
        }
    }

    pub fn with_payment(
        mut self,
        sender: Address,
        recipient: Address,
        amount: u64,
        asset: AssetId,
    ) -> Self {
        self.sender = Some(sender);
        self.recipient = Some(recipient);
        self.amount = Some(amount);
        self.asset = Some(asset);
        self
    }

    pub fn with_nonce(mut self, key: NonceKey) -> Self {
        let seq = self.next_nonce_by_key.entry(key).or_insert(0);
        self.nonce_key = Some(key);
        self.nonce_seq = Some(*seq);
        *seq += 1;
        self
    }

    pub fn with_nonce_seq(mut self, key: NonceKey, seq: u64) -> Self {
        self.nonce_key = Some(key);
        self.nonce_seq = Some(seq);
        let next = self.next_nonce_by_key.entry(key).or_insert(0);
        if *next <= seq {
            *next = seq + 1;
        }
        self
    }

    pub fn with_expiry(mut self, expiry: Expiry) -> Self {
        self.expiry = Some(expiry);
        self
    }

    pub fn with_parent_qc<Q: QuorumCert>(mut self, parent_qc: &Q) -> Self {
        self.parent_qc_hash = Some(parent_qc.qc_hash());
        self
    }

    pub fn with_client_request_id(mut self, client_request_id: impl Into<String>) -> Self {
        self.client_request_id = Some(client_request_id.into());
        self
    }

    pub fn with_tempo_tx(mut self, format: v1::TempoTxFormat, tempo_tx_bytes: Vec<u8>) -> Self {
        self.tempo_tx_format = Some(format as i32);
        self.tempo_tx_bytes = Some(tempo_tx_bytes);
        self
    }

    pub fn with_sender_private_key(mut self, private_key: [u8; 32]) -> Self {
        self.sender_private_key = Some(private_key);
        self
    }

    pub fn build(self) -> Result<BuiltTx, TxBuilderError> {
        let chain_id = self
            .chain_id
            .ok_or(TxBuilderError::MissingField("chain_id"))?;
        let sender = self.sender.ok_or(TxBuilderError::MissingField("sender"))?;
        let recipient = self
            .recipient
            .ok_or(TxBuilderError::MissingField("recipient"))?;
        let amount = self.amount.ok_or(TxBuilderError::MissingField("amount"))?;
        let asset = self.asset.ok_or(TxBuilderError::MissingField("asset"))?;
        let nonce_key = self
            .nonce_key
            .ok_or(TxBuilderError::MissingField("nonce.key"))?;
        let nonce_seq = self
            .nonce_seq
            .ok_or(TxBuilderError::MissingField("nonce.seq"))?;
        let expiry = self.expiry.ok_or(TxBuilderError::MissingField("expiry"))?;

        if sender == recipient {
            return Err(TxBuilderError::InvalidPayment(
                "sender and recipient must be different",
            ));
        }
        if amount == 0 {
            return Err(TxBuilderError::InvalidPayment("amount must be > 0"));
        }

        let tempo_tx = if let Some(bytes) = self.tempo_tx_bytes {
            bytes
        } else {
            let sender_private_key = self
                .sender_private_key
                .ok_or(TxBuilderError::MissingField("sender_private_key"))?;
            encode_payment_tempo_tx_signed(
                chain_id,
                sender,
                recipient,
                amount,
                asset,
                sender_private_key,
            )?
        };
        let tempo_tx_format = self
            .tempo_tx_format
            .unwrap_or(v1::TempoTxFormat::EvmOpaqueBytesV1 as i32);
        if tempo_tx_format != v1::TempoTxFormat::EvmOpaqueBytesV1 as i32 {
            return Err(TxBuilderError::InvalidPayment(
                "unsupported tempo_tx_format",
            ));
        }
        let tx_hash_input = TxHashInput {
            chain_id,
            tempo_tx: tempo_tx.clone(),
            nonce_key,
            nonce_seq,
            expiry,
            parent_qc_hash: self.parent_qc_hash,
        };
        let effects_hash_input = EffectsHashInput {
            sender,
            recipient,
            amount,
            asset,
            nonce_key,
            nonce_seq,
        };
        let tx_hash = compute_tx_hash(&tx_hash_input);
        let effects_hash = compute_effects_hash(&effects_hash_input);

        let payment_intent = v1::PaymentIntent {
            sender: Some(v1::Address {
                data: sender.as_bytes().to_vec(),
            }),
            recipient: Some(v1::Address {
                data: recipient.as_bytes().to_vec(),
            }),
            amount,
            asset: Some(v1::AssetId {
                data: asset.as_bytes().to_vec(),
            }),
        };

        let tx = v1::FastPayTx {
            chain_id: Some(v1::ChainId { value: chain_id }),
            tempo_tx: Some(v1::TempoTxBytes { data: tempo_tx }),
            intent: Some(payment_intent.clone()),
            nonce: Some(v1::Nonce2D {
                nonce_key_be: nonce_key.as_bytes().to_vec(),
                nonce_seq,
            }),
            expiry: Some(expiry_to_proto(expiry)),
            parent_qc_hash: self
                .parent_qc_hash
                .map(|h| h.as_bytes().to_vec())
                .unwrap_or_default(),
            client_request_id: self
                .client_request_id
                .unwrap_or_else(|| format!("req-{chain_id}-{nonce_seq}")),
            tempo_tx_format,
            overlay: Some(v1::OverlayMetadata {
                payment: Some(payment_intent),
            }),
        };

        Ok(BuiltTx {
            tx,
            tx_hash,
            effects_hash,
        })
    }
}

pub fn encode_payment_tempo_tx_signed(
    chain_id: u64,
    sender: Address,
    recipient: Address,
    amount: u64,
    asset: AssetId,
    sender_private_key: [u8; 32],
) -> Result<Vec<u8>, TxBuilderError> {
    let signer = PrivateKeySigner::from_slice(&sender_private_key)
        .map_err(|err| TxBuilderError::Signing(err.to_string()))?;

    let sender_addr = AlloyAddress::from_slice(sender.as_bytes());
    if signer.address() != sender_addr {
        return Err(TxBuilderError::Signing(
            "sender private key does not match sender address".to_string(),
        ));
    }

    let token_addr = AlloyAddress::from_slice(asset.as_bytes());

    let mut calldata = Vec::with_capacity(68);
    calldata.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    calldata.extend_from_slice(&[0u8; 12]);
    calldata.extend_from_slice(recipient.as_bytes());
    calldata.extend_from_slice(&[0u8; 24]);
    calldata.extend_from_slice(&amount.to_be_bytes());

    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce: 0,
        gas_price: 1,
        gas_limit: 80_000,
        to: token_addr.into(),
        value: U256::ZERO,
        input: Bytes::from(calldata),
    };

    let signature = signer
        .sign_hash_sync(&tx.signature_hash())
        .map_err(|err| TxBuilderError::Signing(err.to_string()))?;
    let signed = tx.into_signed(signature);
    Ok(signed.encoded_2718())
}

fn expiry_to_proto(expiry: Expiry) -> v1::Expiry {
    let kind = match expiry {
        Expiry::MaxBlockHeight(height) => v1::expiry::Kind::MaxBlockHeight(height),
        Expiry::UnixMillis(ms) => v1::expiry::Kind::UnixMillis(ms),
    };
    v1::Expiry { kind: Some(kind) }
}

#[cfg(test)]
mod tests {
    use alloy_signer_local::PrivateKeySigner;
    use fastpay_crypto::{Ed25519Signer, MultiCertQC, SimpleAssembler};
    use fastpay_types::{
        CertSigningContext, NonceKey, QuorumAssembler, QuorumCert, Signer, ValidatorId,
    };

    use super::{TxBuilder, TxBuilderError};
    use fastpay_proto::v1;
    use fastpay_types::{Address, AssetId, Expiry};

    fn address_from_private_key(private_key: [u8; 32]) -> Address {
        Address::from_slice(
            PrivateKeySigner::from_slice(&private_key)
                .expect("valid private key")
                .address()
                .as_slice(),
        )
        .expect("20-byte address")
    }

    fn tip20_asset() -> AssetId {
        AssetId::new([
            0x20, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        ])
    }

    #[test]
    fn builds_valid_payment_transaction() {
        let sender_private_key = [0x11; 32];
        let sender = address_from_private_key(sender_private_key);
        let recipient = address_from_private_key([0x22; 32]);
        let asset = tip20_asset();
        let built = TxBuilder::new(1337)
            .with_payment(sender, recipient, 10, asset)
            .with_sender_private_key(sender_private_key)
            .with_nonce(NonceKey::new([0x5b; 32]))
            .with_expiry(Expiry::MaxBlockHeight(50))
            .build()
            .expect("build must succeed");

        assert_eq!(built.tx_hash.as_bytes().len(), 32);
        assert_eq!(built.effects_hash.as_bytes().len(), 32);
        assert_eq!(
            built.tx.nonce.expect("nonce").nonce_seq,
            0,
            "first nonce for key should be 0"
        );
        assert!(
            !built.tx.tempo_tx.expect("tempo_tx").data.is_empty(),
            "evm payload should be present"
        );
        assert_eq!(
            built.tx.tempo_tx_format,
            v1::TempoTxFormat::EvmOpaqueBytesV1 as i32
        );
    }

    #[test]
    fn nonce_auto_increments_for_same_key() {
        let sender_private_key = [0x11; 32];
        let sender = address_from_private_key(sender_private_key);
        let recipient = address_from_private_key([0x22; 32]);
        let asset = tip20_asset();
        let key = NonceKey::new([0x5b; 32]);
        let builder = TxBuilder::new(1337)
            .with_payment(sender, recipient, 10, asset)
            .with_sender_private_key(sender_private_key)
            .with_expiry(Expiry::UnixMillis(1_800_000_000_000))
            .with_nonce(key);
        let t1 = builder
            .clone()
            .build()
            .expect("first build should succeed")
            .tx
            .nonce
            .expect("nonce")
            .nonce_seq;
        let t2 = builder
            .with_nonce(key)
            .build()
            .expect("second build should succeed")
            .tx
            .nonce
            .expect("nonce")
            .nonce_seq;
        assert_eq!(t1, 0);
        assert_eq!(t2, 1);
    }

    #[test]
    fn attaches_parent_qc_hash() {
        let sender_private_key = [0x11; 32];
        let sender = address_from_private_key(sender_private_key);
        let recipient_private_key = [0x22; 32];
        let recipient = address_from_private_key(recipient_private_key);
        let asset = tip20_asset();
        let key = NonceKey::new([0x5b; 32]);

        let signer_a = Ed25519Signer::from_seed(ValidatorId::new([0x11; 32]), [0x21; 32]);
        let signer_b = Ed25519Signer::from_seed(ValidatorId::new([0x12; 32]), [0x22; 32]);
        let sign_ctx = CertSigningContext {
            chain_id: 1337,
            domain_tag: "tempo.fastpay.cert.v1",
            protocol_version: 1,
            epoch: 1,
        };

        let built_parent = TxBuilder::new(1337)
            .with_payment(sender, recipient, 10, asset)
            .with_sender_private_key(sender_private_key)
            .with_nonce(key)
            .with_expiry(Expiry::MaxBlockHeight(100))
            .build()
            .expect("parent build succeeds");

        let cert_a = signer_a
            .sign(&sign_ctx, &built_parent.tx_hash, &built_parent.effects_hash)
            .unwrap();
        let cert_b = signer_b
            .sign(&sign_ctx, &built_parent.tx_hash, &built_parent.effects_hash)
            .unwrap();
        let mut assembler =
            SimpleAssembler::new(built_parent.tx_hash, built_parent.effects_hash, 2);
        assembler.add_certificate(cert_a).unwrap();
        assembler.add_certificate(cert_b).unwrap();
        let qc: MultiCertQC = assembler.finalize().unwrap();

        let child = TxBuilder::new(1337)
            .with_payment(recipient, sender, 5, asset)
            .with_sender_private_key(recipient_private_key)
            .with_nonce(NonceKey::new([0x5c; 32]))
            .with_expiry(Expiry::MaxBlockHeight(101))
            .with_parent_qc(&qc)
            .build()
            .unwrap();
        assert_eq!(
            child.tx.parent_qc_hash,
            qc.qc_hash().as_bytes().to_vec(),
            "parent qc hash should be attached"
        );
    }

    #[test]
    fn rejects_invalid_payment_inputs() {
        let sender_private_key = [0x11; 32];
        let sender = address_from_private_key(sender_private_key);
        let asset = tip20_asset();
        let err = TxBuilder::new(1337)
            .with_payment(sender, sender, 0, asset)
            .with_sender_private_key(sender_private_key)
            .with_nonce(NonceKey::new([0x5b; 32]))
            .with_expiry(Expiry::MaxBlockHeight(10))
            .build()
            .expect_err("must reject invalid payment");
        assert!(matches!(err, TxBuilderError::InvalidPayment(_)));
    }
}
