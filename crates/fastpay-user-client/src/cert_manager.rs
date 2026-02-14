//! CertManager: collect, verify, and assemble certificates into quorum certs.

use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
};

use fastpay_types::{
    AssemblyError, Certificate, CryptoError, EffectsHash, QuorumAssembler, QuorumCert, TxHash,
    ValidationError, VerificationContext,
};
use thiserror::Error;

/// Certificate manager errors for validation and QC assembly.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CertManagerError {
    #[error("certificate tx hash mismatch")]
    TxHashMismatch,
    #[error("certificate effects hash mismatch")]
    EffectsHashMismatch,
    #[error("duplicate certificate from signer {0}")]
    DuplicateSigner(String),
    #[error("missing certificates for tx")]
    MissingCertificates,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Assembly(#[from] AssemblyError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

/// Collects validator certificates and assembles quorum certificates.
#[derive(Debug, Clone)]
pub struct CertManager<C, Q, A>
where
    C: Certificate,
    Q: QuorumCert<Cert = C>,
    A: QuorumAssembler<Cert = C, QC = Q>,
{
    verification_context: VerificationContext,
    threshold: u32,
    certificates: HashMap<TxHash, Vec<C>>,
    qcs: HashMap<TxHash, Q>,
    _marker: PhantomData<A>,
}

impl<C, Q, A> CertManager<C, Q, A>
where
    C: Certificate,
    Q: QuorumCert<Cert = C>,
    A: QuorumAssembler<Cert = C, QC = Q>,
{
    pub fn new(verification_context: VerificationContext, threshold: u32) -> Self {
        Self {
            verification_context,
            threshold,
            certificates: HashMap::new(),
            qcs: HashMap::new(),
            _marker: PhantomData,
        }
    }

    pub fn collect_certificate(
        &mut self,
        expected_tx_hash: TxHash,
        expected_effects_hash: EffectsHash,
        cert: C,
    ) -> Result<(), CertManagerError> {
        if cert.tx_hash() != &expected_tx_hash {
            return Err(CertManagerError::TxHashMismatch);
        }
        if cert.effects_hash() != &expected_effects_hash {
            return Err(CertManagerError::EffectsHashMismatch);
        }
        cert.verify(&self.verification_context)?;

        let signer_hex = cert.signer().to_string();
        let entry = self.certificates.entry(expected_tx_hash).or_default();
        if entry
            .iter()
            .any(|existing| existing.signer() == cert.signer())
        {
            return Err(CertManagerError::DuplicateSigner(signer_hex));
        }
        entry.push(cert);
        Ok(())
    }

    pub fn certificates_for(&self, tx_hash: &TxHash) -> &[C] {
        self.certificates
            .get(tx_hash)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub fn assemble_qc(
        &mut self,
        tx_hash: TxHash,
        effects_hash: EffectsHash,
    ) -> Result<Q, CertManagerError> {
        let certs = self
            .certificates
            .get(&tx_hash)
            .ok_or(CertManagerError::MissingCertificates)?;

        let mut assembler = A::new(tx_hash, effects_hash, self.threshold);
        for cert in certs {
            assembler.add_certificate(cert.clone())?;
        }
        let qc = assembler.finalize()?;
        qc.verify(&self.verification_context)?;
        self.qcs.insert(tx_hash, qc.clone());
        Ok(qc)
    }

    pub fn get_qc(&self, tx_hash: &TxHash) -> Option<&Q> {
        self.qcs.get(tx_hash)
    }

    pub fn prune_cert_cache(&mut self, max_entries: usize) {
        if self.certificates.len() <= max_entries {
            return;
        }
        let mut keys: Vec<TxHash> = self.certificates.keys().copied().collect();
        keys.sort_unstable();
        for key in keys.into_iter().take(self.certificates.len() - max_entries) {
            self.certificates.remove(&key);
        }
    }

    pub fn known_signers(&self, tx_hash: &TxHash) -> HashSet<String> {
        self.certificates_for(tx_hash)
            .iter()
            .map(|c| c.signer().to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy_signer_local::PrivateKeySigner;
    use fastpay_crypto::{Ed25519Signer, SimpleAssembler};
    use fastpay_types::{
        CertSigningContext, CryptoError, Expiry, NonceKey, QuorumCert, Signer, ValidatorId,
        VerificationContext,
    };

    use super::{CertManager, CertManagerError};
    use crate::tx_builder::TxBuilder;
    use fastpay_types::{Address, AssetId};

    fn make_cert_and_ctx(
        epoch: u64,
    ) -> (
        fastpay_crypto::Ed25519Certificate,
        fastpay_crypto::Ed25519Certificate,
        fastpay_types::TxHash,
        fastpay_types::EffectsHash,
        VerificationContext,
    ) {
        let sender_private_key = [0x11; 32];
        let sender = Address::from_slice(
            PrivateKeySigner::from_slice(&sender_private_key)
                .expect("valid key")
                .address()
                .as_slice(),
        )
        .expect("address");
        let recipient = Address::from_slice(
            PrivateKeySigner::from_slice(&[0x22; 32])
                .expect("valid key")
                .address()
                .as_slice(),
        )
        .expect("address");
        let asset = AssetId::new([
            0x20, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        ]);
        let built = TxBuilder::new(1337)
            .with_payment(sender, recipient, 10, asset)
            .with_sender_private_key(sender_private_key)
            .with_nonce(NonceKey::new([0x5b; 32]))
            .with_expiry(Expiry::MaxBlockHeight(100))
            .build()
            .unwrap();
        let signer_a_id = ValidatorId::new([0x11; 32]);
        let signer_b_id = ValidatorId::new([0x12; 32]);
        let signer_a = Ed25519Signer::from_seed(signer_a_id, [0x21; 32]);
        let signer_b = Ed25519Signer::from_seed(signer_b_id, [0x22; 32]);
        let sign_ctx = CertSigningContext {
            chain_id: 1337,
            domain_tag: "tempo.fastpay.cert.v1",
            protocol_version: 1,
            epoch,
        };
        let cert_a = signer_a
            .sign(&sign_ctx, &built.tx_hash, &built.effects_hash)
            .unwrap();
        let cert_b = signer_b
            .sign(&sign_ctx, &built.tx_hash, &built.effects_hash)
            .unwrap();
        let mut committee = HashMap::new();
        committee.insert(signer_a_id, signer_a.public_key_bytes());
        committee.insert(signer_b_id, signer_b.public_key_bytes());
        let verify_ctx = VerificationContext {
            chain_id: 1337,
            domain_tag: "tempo.fastpay.cert.v1".to_string(),
            protocol_version: 1,
            epoch,
            committee,
        };
        (
            cert_a,
            cert_b,
            built.tx_hash,
            built.effects_hash,
            verify_ctx,
        )
    }

    #[test]
    fn assembles_qc_when_threshold_met() {
        let (cert_a, cert_b, tx_hash, effects_hash, verify_ctx) = make_cert_and_ctx(1);
        let mut mgr = CertManager::<_, _, SimpleAssembler>::new(verify_ctx, 2);
        mgr.collect_certificate(tx_hash, effects_hash, cert_a)
            .unwrap();
        mgr.collect_certificate(tx_hash, effects_hash, cert_b)
            .unwrap();
        let qc = mgr.assemble_qc(tx_hash, effects_hash).unwrap();
        assert!(qc.is_complete());
        assert_eq!(qc.cert_count(), 2);
    }

    #[test]
    fn rejects_duplicate_signer() {
        let (cert_a, _, tx_hash, effects_hash, verify_ctx) = make_cert_and_ctx(1);
        let mut mgr = CertManager::<_, _, SimpleAssembler>::new(verify_ctx, 2);
        mgr.collect_certificate(tx_hash, effects_hash, cert_a.clone())
            .unwrap();
        let err = mgr
            .collect_certificate(tx_hash, effects_hash, cert_a)
            .expect_err("duplicate signer should fail");
        assert!(matches!(err, CertManagerError::DuplicateSigner(_)));
    }

    #[test]
    fn rejects_mismatched_hashes() {
        let (cert_a, _, tx_hash, effects_hash, verify_ctx) = make_cert_and_ctx(1);
        let mut mgr = CertManager::<_, _, SimpleAssembler>::new(verify_ctx, 2);
        let err = mgr
            .collect_certificate(
                fastpay_types::TxHash::new([0xff; 32]),
                effects_hash,
                cert_a.clone(),
            )
            .expect_err("must reject tx hash mismatch");
        assert!(matches!(err, CertManagerError::TxHashMismatch));

        let err = mgr
            .collect_certificate(tx_hash, fastpay_types::EffectsHash::new([0xee; 32]), cert_a)
            .expect_err("must reject effects hash mismatch");
        assert!(matches!(err, CertManagerError::EffectsHashMismatch));
    }

    #[test]
    fn rejects_unknown_signer_or_wrong_epoch() {
        let (cert_a, _, tx_hash, effects_hash, mut verify_ctx) = make_cert_and_ctx(1);
        verify_ctx.committee.clear();
        let mut mgr = CertManager::<_, _, SimpleAssembler>::new(verify_ctx, 2);
        let err = mgr
            .collect_certificate(tx_hash, effects_hash, cert_a.clone())
            .expect_err("unknown signer should be rejected");
        assert!(matches!(
            err,
            CertManagerError::Crypto(CryptoError::UnknownSigner(_))
        ));

        let (_, _, tx_hash, effects_hash, mut verify_ctx_epoch_mismatch) = make_cert_and_ctx(1);
        verify_ctx_epoch_mismatch.epoch = 2;
        let mut mgr = CertManager::<_, _, SimpleAssembler>::new(verify_ctx_epoch_mismatch, 2);
        let err = mgr
            .collect_certificate(tx_hash, effects_hash, cert_a)
            .expect_err("wrong epoch context should fail verification");
        assert!(matches!(err, CertManagerError::Crypto(_)));
    }
}
