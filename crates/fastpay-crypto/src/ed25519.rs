use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, Verifier as DalekVerifier, VerifyingKey};
use fastpay_types::{
    CertSigningContext, Certificate, CryptoError, EffectsHash, Signer, TxHash, ValidationError,
    ValidatorId, VerificationContext,
};
use serde::{Deserialize, Serialize};

use crate::hashing::compute_cert_message_digest;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Certificate {
    tx_hash: TxHash,
    effects_hash: EffectsHash,
    signer: ValidatorId,
    signature: Vec<u8>,
    created_at: u64,
}

impl Ed25519Certificate {
    pub fn new(
        tx_hash: TxHash,
        effects_hash: EffectsHash,
        signer: ValidatorId,
        signature: Vec<u8>,
        created_at: u64,
    ) -> Result<Self, ValidationError> {
        if signature.len() != 64 {
            return Err(ValidationError::InvalidLength {
                kind: "signature",
                expected: 64,
                actual: signature.len(),
            });
        }
        Ok(Self {
            tx_hash,
            effects_hash,
            signer,
            signature,
            created_at,
        })
    }

    pub fn signature_array(&self) -> Result<[u8; 64], CryptoError> {
        self.signature
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidLength {
                kind: "signature",
                expected: 64,
                actual: self.signature.len(),
            })
    }
}

impl Certificate for Ed25519Certificate {
    fn tx_hash(&self) -> &TxHash {
        &self.tx_hash
    }

    fn effects_hash(&self) -> &EffectsHash {
        &self.effects_hash
    }

    fn signer(&self) -> &ValidatorId {
        &self.signer
    }

    fn verify(&self, ctx: &VerificationContext) -> Result<(), CryptoError> {
        let pubkey = ctx
            .committee
            .get(&self.signer)
            .ok_or(CryptoError::UnknownSigner(self.signer))?;
        let verify_key = VerifyingKey::from_bytes(pubkey)
            .map_err(|err| CryptoError::Message(format!("invalid pubkey: {err}")))?;
        let signature = Signature::from_bytes(&self.signature_array()?);
        let digest = compute_cert_message_digest(
            ctx.chain_id,
            &ctx.domain_tag,
            ctx.protocol_version,
            ctx.epoch,
            &self.tx_hash,
            &self.effects_hash,
        );
        verify_key
            .verify(&digest, &signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    fn signature_bytes(&self) -> &[u8] {
        &self.signature
    }

    fn created_at(&self) -> u64 {
        self.created_at
    }
}

#[derive(Debug, Clone)]
pub struct Ed25519Signer {
    validator_id: ValidatorId,
    signing_key: SigningKey,
}

impl Ed25519Signer {
    pub fn new(validator_id: ValidatorId, signing_key: SigningKey) -> Self {
        Self {
            validator_id,
            signing_key,
        }
    }

    pub fn from_seed(validator_id: ValidatorId, seed: [u8; 32]) -> Self {
        Self::new(validator_id, SigningKey::from_bytes(&seed))
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn sign_with_timestamp(
        &self,
        ctx: &CertSigningContext,
        tx_hash: &TxHash,
        effects_hash: &EffectsHash,
        created_at: u64,
    ) -> Result<Ed25519Certificate, CryptoError> {
        let digest = compute_cert_message_digest(
            ctx.chain_id,
            ctx.domain_tag,
            ctx.protocol_version,
            ctx.epoch,
            tx_hash,
            effects_hash,
        );
        let signature = self.signing_key.sign(&digest).to_bytes().to_vec();
        Ed25519Certificate::new(
            *tx_hash,
            *effects_hash,
            self.validator_id,
            signature,
            created_at,
        )
        .map_err(|err| CryptoError::Message(err.to_string()))
    }
}

impl Signer for Ed25519Signer {
    type Cert = Ed25519Certificate;

    fn sign(
        &self,
        ctx: &CertSigningContext,
        tx_hash: &TxHash,
        effects_hash: &EffectsHash,
    ) -> Result<Self::Cert, CryptoError> {
        self.sign_with_timestamp(ctx, tx_hash, effects_hash, unix_millis_now())
    }

    fn validator_id(&self) -> &ValidatorId {
        &self.validator_id
    }
}

fn unix_millis_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use fastpay_types::{CertSigningContext, Certificate, VerificationContext};

    use super::{Ed25519Signer, Signer};
    use crate::{
        EffectsHashInput, TxHashInput, compute_effects_hash, compute_tx_hash,
        hashing::compute_cert_message_digest,
    };
    use fastpay_types::{Address, AssetId, NonceKey};

    #[test]
    fn sign_and_verify_certificate() {
        let signer_id = fastpay_types::ValidatorId::new([0x44; 32]);
        let signer = Ed25519Signer::from_seed(signer_id, [0x10; 32]);
        let tx_hash = compute_tx_hash(&TxHashInput {
            chain_id: 1,
            tempo_tx: b"tx-bytes".to_vec(),
            nonce_key: NonceKey::new([0x5b; 32]),
            nonce_seq: 1,
            expiry: fastpay_types::Expiry::MaxBlockHeight(10),
            parent_qc_hash: None,
        });
        let effects_hash = compute_effects_hash(&EffectsHashInput {
            sender: Address::new([1; 20]),
            recipient: Address::new([2; 20]),
            amount: 5,
            asset: AssetId::new([3; 20]),
            nonce_key: NonceKey::new([0x5b; 32]),
            nonce_seq: 1,
        });
        let sign_ctx = CertSigningContext {
            chain_id: 1,
            domain_tag: "tempo.fastpay.cert.v1",
            protocol_version: 1,
            epoch: 9,
        };

        let cert = signer
            .sign_with_timestamp(&sign_ctx, &tx_hash, &effects_hash, 1234)
            .expect("sign should succeed");
        let mut committee = HashMap::new();
        committee.insert(signer_id, signer.public_key_bytes());
        let verify_ctx = VerificationContext {
            chain_id: 1,
            domain_tag: "tempo.fastpay.cert.v1".to_string(),
            protocol_version: 1,
            epoch: 9,
            committee,
        };
        cert.verify(&verify_ctx).expect("verify should succeed");

        let digest = compute_cert_message_digest(
            1,
            "tempo.fastpay.cert.v1",
            1,
            9,
            &tx_hash,
            &effects_hash,
        );
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn verify_rejects_unknown_signer() {
        let signer_id = fastpay_types::ValidatorId::new([0x55; 32]);
        let signer = Ed25519Signer::from_seed(signer_id, [0x20; 32]);
        let tx_hash = compute_tx_hash(&TxHashInput {
            chain_id: 1,
            tempo_tx: b"tx".to_vec(),
            nonce_key: NonceKey::new([0x5b; 32]),
            nonce_seq: 2,
            expiry: fastpay_types::Expiry::MaxBlockHeight(11),
            parent_qc_hash: None,
        });
        let effects_hash = compute_effects_hash(&EffectsHashInput {
            sender: Address::new([1; 20]),
            recipient: Address::new([2; 20]),
            amount: 8,
            asset: AssetId::new([4; 20]),
            nonce_key: NonceKey::new([0x5b; 32]),
            nonce_seq: 2,
        });
        let sign_ctx = CertSigningContext {
            chain_id: 1,
            domain_tag: "tempo.fastpay.cert.v1",
            protocol_version: 1,
            epoch: 9,
        };
        let cert = signer.sign(&sign_ctx, &tx_hash, &effects_hash).unwrap();

        let verify_ctx = VerificationContext {
            chain_id: 1,
            domain_tag: "tempo.fastpay.cert.v1".to_string(),
            protocol_version: 1,
            epoch: 9,
            committee: HashMap::new(),
        };
        let err = cert.verify(&verify_ctx).expect_err("must reject unknown signer");
        assert!(matches!(err, fastpay_types::CryptoError::UnknownSigner(_)));
    }
}
