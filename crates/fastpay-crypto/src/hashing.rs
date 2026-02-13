use fastpay_types::{
    Certificate, ChainId, EffectsHash, Expiry, NonceKey, QcHash, TxHash, ValidationError,
};
use sha2::{Digest, Sha256};

use fastpay_types::{Address, AssetId};

const TX_HASH_TAG: &[u8] = b"tempo.fastpay.tx.v1";
const EFFECTS_HASH_TAG: &[u8] = b"tempo.fastpay.effects.v1";
const QC_HASH_TAG: &[u8] = b"tempo.fastpay.qc.v1";
const CERT_PREIMAGE_TAG: &[u8] = b"tempo.fastpay.cert.preimage.v1";

/// Canonical encoding rules used by all hash functions in this module:
/// 1. Big-endian fixed-width integers: u16/u32/u64.
/// 2. Variable-length bytes and strings are length-prefixed with u32.
/// 3. Optional fields are encoded with a one-byte presence tag (0 or 1).
/// 4. `Expiry` is encoded with a one-byte variant tag plus its u64 value.
/// 5. QC certificate entries are sorted by signer bytes before hashing.
/// 6. Hashes are SHA-256 over tagged canonical payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxHashInput {
    pub chain_id: ChainId,
    pub tempo_tx: Vec<u8>,
    pub nonce_key: NonceKey,
    pub nonce_seq: u64,
    pub expiry: Expiry,
    pub parent_qc_hash: Option<QcHash>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectsHashInput {
    pub sender: Address,
    pub recipient: Address,
    pub amount: u64,
    pub asset: AssetId,
    pub nonce_key: NonceKey,
    pub nonce_seq: u64,
}

pub fn compute_tx_hash(input: &TxHashInput) -> TxHash {
    let mut enc = Vec::new();
    enc.extend_from_slice(TX_HASH_TAG);
    put_u64(&mut enc, input.chain_id);
    put_bytes(&mut enc, &input.tempo_tx);
    enc.extend_from_slice(input.nonce_key.as_bytes());
    put_u64(&mut enc, input.nonce_seq);
    put_expiry(&mut enc, input.expiry);
    match input.parent_qc_hash {
        Some(hash) => {
            put_u8(&mut enc, 1);
            enc.extend_from_slice(hash.as_bytes());
        }
        None => put_u8(&mut enc, 0),
    }
    TxHash::new(sha256_32(&enc))
}

pub fn compute_effects_hash(input: &EffectsHashInput) -> EffectsHash {
    let mut enc = Vec::new();
    enc.extend_from_slice(EFFECTS_HASH_TAG);
    enc.extend_from_slice(input.sender.as_bytes());
    enc.extend_from_slice(input.recipient.as_bytes());
    put_u64(&mut enc, input.amount);
    enc.extend_from_slice(input.asset.as_bytes());
    enc.extend_from_slice(input.nonce_key.as_bytes());
    put_u64(&mut enc, input.nonce_seq);
    EffectsHash::new(sha256_32(&enc))
}

pub fn build_cert_signing_preimage(
    chain_id: ChainId,
    domain_tag: &str,
    protocol_version: u16,
    epoch: u64,
    tx_hash: &TxHash,
    effects_hash: &EffectsHash,
) -> Vec<u8> {
    let mut enc = Vec::new();
    enc.extend_from_slice(CERT_PREIMAGE_TAG);
    put_string(&mut enc, domain_tag);
    put_u16(&mut enc, protocol_version);
    put_u64(&mut enc, chain_id);
    put_u64(&mut enc, epoch);
    enc.extend_from_slice(tx_hash.as_bytes());
    enc.extend_from_slice(effects_hash.as_bytes());
    enc
}

pub fn compute_cert_message_digest(
    chain_id: ChainId,
    domain_tag: &str,
    protocol_version: u16,
    epoch: u64,
    tx_hash: &TxHash,
    effects_hash: &EffectsHash,
) -> [u8; 32] {
    let preimage = build_cert_signing_preimage(
        chain_id,
        domain_tag,
        protocol_version,
        epoch,
        tx_hash,
        effects_hash,
    );
    sha256_32(&preimage)
}

pub fn compute_qc_hash<C: Certificate>(
    tx_hash: &TxHash,
    effects_hash: &EffectsHash,
    threshold: u32,
    certs: &[C],
) -> QcHash {
    let mut sorted: Vec<&C> = certs.iter().collect();
    sorted.sort_by_key(|cert| cert.signer().as_bytes().to_vec());

    let mut enc = Vec::new();
    enc.extend_from_slice(QC_HASH_TAG);
    enc.extend_from_slice(tx_hash.as_bytes());
    enc.extend_from_slice(effects_hash.as_bytes());
    put_u32(&mut enc, threshold);
    put_u32(&mut enc, sorted.len() as u32);
    for cert in sorted {
        enc.extend_from_slice(cert.signer().as_bytes());
        put_bytes(&mut enc, cert.signature_bytes());
        put_u64(&mut enc, cert.created_at());
    }
    QcHash::new(sha256_32(&enc))
}

pub fn validate_hash_bytes(kind: &'static str, value: &[u8]) -> Result<[u8; 32], ValidationError> {
    value
        .try_into()
        .map_err(|_| ValidationError::InvalidLength {
            kind,
            expected: 32,
            actual: value.len(),
        })
}

fn sha256_32(input: &[u8]) -> [u8; 32] {
    let digest: [u8; 32] = Sha256::digest(input).into();
    digest
}

fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    put_u32(out, value.len() as u32);
    out.extend_from_slice(value);
}

fn put_string(out: &mut Vec<u8>, value: &str) {
    put_bytes(out, value.as_bytes());
}

fn put_expiry(out: &mut Vec<u8>, expiry: Expiry) {
    match expiry {
        Expiry::MaxBlockHeight(height) => {
            put_u8(out, 0);
            put_u64(out, height);
        }
        Expiry::UnixMillis(ts) => {
            put_u8(out, 1);
            put_u64(out, ts);
        }
    }
}

#[cfg(test)]
mod tests {
    use fastpay_types::{Address, AssetId, Certificate, EffectsHash, Expiry, NonceKey, QcHash, TxHash, ValidatorId};

    use super::{
        EffectsHashInput, TxHashInput, build_cert_signing_preimage, compute_cert_message_digest,
        compute_effects_hash, compute_qc_hash, compute_tx_hash,
    };

    #[derive(Clone)]
    struct DummyCert {
        tx_hash: TxHash,
        effects_hash: EffectsHash,
        signer: ValidatorId,
        signature: Vec<u8>,
        created_at: u64,
    }

    impl Certificate for DummyCert {
        fn tx_hash(&self) -> &TxHash {
            &self.tx_hash
        }

        fn effects_hash(&self) -> &EffectsHash {
            &self.effects_hash
        }

        fn signer(&self) -> &ValidatorId {
            &self.signer
        }

        fn verify(&self, _ctx: &fastpay_types::VerificationContext) -> Result<(), fastpay_types::CryptoError> {
            Ok(())
        }

        fn signature_bytes(&self) -> &[u8] {
            &self.signature
        }

        fn created_at(&self) -> u64 {
            self.created_at
        }
    }

    #[test]
    fn golden_vectors() {
        let tx_input = TxHashInput {
            chain_id: 1337,
            tempo_tx: b"tempo:transfer:alice:bob:10".to_vec(),
            nonce_key: NonceKey::new([0x5b; 32]),
            nonce_seq: 7,
            expiry: Expiry::MaxBlockHeight(99),
            parent_qc_hash: Some(QcHash::new([0x11; 32])),
        };
        let effects_input = EffectsHashInput {
            sender: Address::new([0x01; 20]),
            recipient: Address::new([0x02; 20]),
            amount: 10,
            asset: AssetId::new([0x03; 20]),
            nonce_key: NonceKey::new([0x5b; 32]),
            nonce_seq: 7,
        };

        let tx_hash = compute_tx_hash(&tx_input);
        let effects_hash = compute_effects_hash(&effects_input);
        let preimage = build_cert_signing_preimage(
            1337,
            "tempo.fastpay.cert.v1",
            1,
            42,
            &tx_hash,
            &effects_hash,
        );
        let preimage_digest =
            compute_cert_message_digest(1337, "tempo.fastpay.cert.v1", 1, 42, &tx_hash, &effects_hash);

        let cert_a = DummyCert {
            tx_hash,
            effects_hash,
            signer: ValidatorId::new([0x0a; 32]),
            signature: vec![0xaa; 64],
            created_at: 1000,
        };
        let cert_b = DummyCert {
            tx_hash,
            effects_hash,
            signer: ValidatorId::new([0x0b; 32]),
            signature: vec![0xbb; 64],
            created_at: 1001,
        };
        let qc_hash = compute_qc_hash(&tx_hash, &effects_hash, 2, &[cert_b.clone(), cert_a.clone()]);
        let qc_hash_reordered = compute_qc_hash(&tx_hash, &effects_hash, 2, &[cert_a, cert_b]);

        assert_eq!(hex::encode(tx_hash.as_bytes()), "80f0bddcad91b05df8b0f96fe3b42fea9a5b5d358a61664616ec17289d80d8df");
        assert_eq!(hex::encode(effects_hash.as_bytes()), "7ff26a3ecef7a937adaa2f13bcbb2dc349b1daaa63b5ede4b18f20d130f8859e");
        assert_eq!(hex::encode(preimage), "74656d706f2e666173747061792e636572742e707265696d6167652e76310000001574656d706f2e666173747061792e636572742e763100010000000000000539000000000000002a80f0bddcad91b05df8b0f96fe3b42fea9a5b5d358a61664616ec17289d80d8df7ff26a3ecef7a937adaa2f13bcbb2dc349b1daaa63b5ede4b18f20d130f8859e");
        assert_eq!(hex::encode(preimage_digest), "02bf6c27eb0c808a9fbda3cad277eab0634e6050a068054b878eeccc3e712313");
        assert_eq!(hex::encode(qc_hash.as_bytes()), "fee9c0774bd5e57638e46c265bba36430f22e76ce9fa203a5eba6972a7809737");
        assert_eq!(qc_hash, qc_hash_reordered);
    }
}
