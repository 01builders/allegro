//! Trait definitions for Certificate, QuorumCert, QuorumAssembler, and Signer.

use std::collections::HashMap;

use crate::{
    error::{AssemblyError, CryptoError},
    ids::{ChainId, EffectsHash, QcHash, TxHash, ValidatorId},
};

#[derive(Debug, Clone)]
pub struct CertSigningContext {
    pub chain_id: ChainId,
    pub domain_tag: &'static str,
    pub protocol_version: u16,
    pub epoch: u64,
}

#[derive(Debug, Clone)]
pub struct VerificationContext {
    pub chain_id: ChainId,
    pub domain_tag: String,
    pub protocol_version: u16,
    pub epoch: u64,
    pub committee: HashMap<ValidatorId, [u8; 32]>,
}

pub trait Certificate: Clone + Send + Sync {
    fn tx_hash(&self) -> &TxHash;

    fn effects_hash(&self) -> &EffectsHash;

    fn signer(&self) -> &ValidatorId;

    fn verify(&self, ctx: &VerificationContext) -> Result<(), CryptoError>;

    fn signature_bytes(&self) -> &[u8];

    fn created_at(&self) -> u64;
}

pub trait QuorumCert: Clone + Send + Sync {
    type Cert: Certificate;

    fn tx_hash(&self) -> &TxHash;

    fn effects_hash(&self) -> &EffectsHash;

    fn threshold(&self) -> u32;

    fn cert_count(&self) -> usize;

    fn is_complete(&self) -> bool {
        self.cert_count() >= self.threshold() as usize
    }

    fn verify(&self, ctx: &VerificationContext) -> Result<(), CryptoError>;

    fn qc_hash(&self) -> QcHash;

    fn certificates(&self) -> &[Self::Cert];
}

pub trait QuorumAssembler {
    type Cert: Certificate;
    type QC: QuorumCert<Cert = Self::Cert>;

    fn new(tx_hash: TxHash, effects_hash: EffectsHash, threshold: u32) -> Self;

    fn add_certificate(&mut self, cert: Self::Cert) -> Result<(), AssemblyError>;

    fn is_complete(&self) -> bool;

    fn finalize(self) -> Result<Self::QC, AssemblyError>;
}

pub trait Signer {
    type Cert: Certificate;

    fn sign(
        &self,
        ctx: &CertSigningContext,
        tx_hash: &TxHash,
        effects_hash: &EffectsHash,
    ) -> Result<Self::Cert, CryptoError>;

    fn validator_id(&self) -> &ValidatorId;
}
