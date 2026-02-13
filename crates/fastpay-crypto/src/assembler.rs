//! SimpleAssembler: collects certificates until quorum threshold is met.

use std::collections::HashSet;

use fastpay_types::{
    AssemblyError, Certificate, EffectsHash, QuorumAssembler, TxHash, ValidatorId,
};

use crate::{Ed25519Certificate, MultiCertQC};

#[derive(Debug, Clone)]
pub struct SimpleAssembler {
    tx_hash: TxHash,
    effects_hash: EffectsHash,
    threshold: u32,
    certs: Vec<Ed25519Certificate>,
    seen_signers: HashSet<ValidatorId>,
}

impl QuorumAssembler for SimpleAssembler {
    type Cert = Ed25519Certificate;
    type QC = MultiCertQC;

    fn new(tx_hash: TxHash, effects_hash: EffectsHash, threshold: u32) -> Self {
        Self {
            tx_hash,
            effects_hash,
            threshold,
            certs: Vec::new(),
            seen_signers: HashSet::new(),
        }
    }

    fn add_certificate(&mut self, cert: Self::Cert) -> Result<(), AssemblyError> {
        if cert.tx_hash() != &self.tx_hash {
            return Err(AssemblyError::TxHashMismatch);
        }
        if cert.effects_hash() != &self.effects_hash {
            return Err(AssemblyError::EffectsHashMismatch);
        }
        if !self.seen_signers.insert(*cert.signer()) {
            return Err(AssemblyError::DuplicateCertificate(*cert.signer()));
        }
        self.certs.push(cert);
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.certs.len() >= self.threshold as usize
    }

    fn finalize(self) -> Result<Self::QC, AssemblyError> {
        if !self.is_complete() {
            return Err(AssemblyError::ThresholdNotMet {
                required: self.threshold,
                have: self.certs.len(),
            });
        }
        Ok(MultiCertQC::new(
            self.tx_hash,
            self.effects_hash,
            self.threshold,
            self.certs,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use fastpay_types::{CertSigningContext, QuorumAssembler, VerificationContext};

    use crate::{
        compute_effects_hash, compute_tx_hash, Ed25519Signer, EffectsHashInput, SimpleAssembler,
        TxHashInput,
    };
    use fastpay_types::{Address, AssetId, NonceKey, QuorumCert, Signer};

    #[test]
    fn assembler_rejects_duplicate_signers() {
        let tx_hash = compute_tx_hash(&TxHashInput {
            chain_id: 1,
            tempo_tx: b"tx".to_vec(),
            nonce_key: NonceKey::new([0x5b; 32]),
            nonce_seq: 1,
            expiry: fastpay_types::Expiry::MaxBlockHeight(100),
            parent_qc_hash: None,
        });
        let effects_hash = compute_effects_hash(&EffectsHashInput {
            sender: Address::new([1; 20]),
            recipient: Address::new([2; 20]),
            amount: 10,
            asset: AssetId::new([3; 20]),
            nonce_key: NonceKey::new([0x5b; 32]),
            nonce_seq: 1,
        });
        let signer_id = fastpay_types::ValidatorId::new([0x10; 32]);
        let signer = Ed25519Signer::from_seed(signer_id, [9; 32]);
        let sign_ctx = CertSigningContext {
            chain_id: 1,
            domain_tag: "tempo.fastpay.cert.v1",
            protocol_version: 1,
            epoch: 7,
        };
        let cert1 = signer.sign(&sign_ctx, &tx_hash, &effects_hash).unwrap();
        let cert2 = signer.sign(&sign_ctx, &tx_hash, &effects_hash).unwrap();

        let mut asm = SimpleAssembler::new(tx_hash, effects_hash, 2);
        asm.add_certificate(cert1).unwrap();
        let err = asm.add_certificate(cert2).expect_err("duplicate must fail");
        assert!(matches!(
            err,
            fastpay_types::AssemblyError::DuplicateCertificate(_)
        ));
    }

    #[test]
    fn assembler_finalize_and_verify() {
        let tx_hash = compute_tx_hash(&TxHashInput {
            chain_id: 1,
            tempo_tx: b"tx2".to_vec(),
            nonce_key: NonceKey::new([0x5b; 32]),
            nonce_seq: 2,
            expiry: fastpay_types::Expiry::MaxBlockHeight(101),
            parent_qc_hash: None,
        });
        let effects_hash = compute_effects_hash(&EffectsHashInput {
            sender: Address::new([4; 20]),
            recipient: Address::new([5; 20]),
            amount: 12,
            asset: AssetId::new([6; 20]),
            nonce_key: NonceKey::new([0x5b; 32]),
            nonce_seq: 2,
        });
        let signer_a_id = fastpay_types::ValidatorId::new([0x21; 32]);
        let signer_b_id = fastpay_types::ValidatorId::new([0x22; 32]);
        let signer_a = Ed25519Signer::from_seed(signer_a_id, [0x31; 32]);
        let signer_b = Ed25519Signer::from_seed(signer_b_id, [0x32; 32]);
        let sign_ctx = CertSigningContext {
            chain_id: 1,
            domain_tag: "tempo.fastpay.cert.v1",
            protocol_version: 1,
            epoch: 7,
        };
        let cert_a = signer_a.sign(&sign_ctx, &tx_hash, &effects_hash).unwrap();
        let cert_b = signer_b.sign(&sign_ctx, &tx_hash, &effects_hash).unwrap();

        let mut asm = SimpleAssembler::new(tx_hash, effects_hash, 2);
        asm.add_certificate(cert_a).unwrap();
        asm.add_certificate(cert_b).unwrap();
        let qc = asm.finalize().expect("threshold met");
        assert!(qc.is_complete());
        assert_eq!(qc.cert_count(), 2);

        let mut committee = HashMap::new();
        committee.insert(signer_a_id, signer_a.public_key_bytes());
        committee.insert(signer_b_id, signer_b.public_key_bytes());
        let ctx = VerificationContext {
            chain_id: 1,
            domain_tag: "tempo.fastpay.cert.v1".to_string(),
            protocol_version: 1,
            epoch: 7,
            committee,
        };
        qc.verify(&ctx).expect("QC must verify");
        assert_eq!(qc.qc_hash().as_bytes().len(), 32);
    }
}
