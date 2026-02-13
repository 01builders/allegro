use std::collections::HashSet;

use fastpay_types::{Certificate, CryptoError, EffectsHash, QcHash, QuorumCert, TxHash, VerificationContext};
use serde::{Deserialize, Serialize};

use crate::{Ed25519Certificate, compute_qc_hash};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiCertQC {
    tx_hash: TxHash,
    effects_hash: EffectsHash,
    threshold: u32,
    certs: Vec<Ed25519Certificate>,
}

impl MultiCertQC {
    pub fn new(
        tx_hash: TxHash,
        effects_hash: EffectsHash,
        threshold: u32,
        certs: Vec<Ed25519Certificate>,
    ) -> Self {
        Self {
            tx_hash,
            effects_hash,
            threshold,
            certs,
        }
    }

    pub fn certs_mut(&mut self) -> &mut Vec<Ed25519Certificate> {
        &mut self.certs
    }
}

impl QuorumCert for MultiCertQC {
    type Cert = Ed25519Certificate;

    fn tx_hash(&self) -> &TxHash {
        &self.tx_hash
    }

    fn effects_hash(&self) -> &EffectsHash {
        &self.effects_hash
    }

    fn threshold(&self) -> u32 {
        self.threshold
    }

    fn cert_count(&self) -> usize {
        self.certs.len()
    }

    fn verify(&self, ctx: &VerificationContext) -> Result<(), CryptoError> {
        if !self.is_complete() {
            return Err(CryptoError::Message(format!(
                "threshold not met: required {}, have {}",
                self.threshold,
                self.certs.len()
            )));
        }

        let mut seen = HashSet::with_capacity(self.certs.len());
        for cert in &self.certs {
            if cert.tx_hash() != &self.tx_hash {
                return Err(CryptoError::Message("certificate tx hash mismatch".to_string()));
            }
            if cert.effects_hash() != &self.effects_hash {
                return Err(CryptoError::Message(
                    "certificate effects hash mismatch".to_string(),
                ));
            }
            if !seen.insert(*cert.signer()) {
                return Err(CryptoError::Message(
                    "duplicate signer in quorum certificate".to_string(),
                ));
            }
            cert.verify(ctx)?;
        }
        Ok(())
    }

    fn qc_hash(&self) -> QcHash {
        compute_qc_hash(&self.tx_hash, &self.effects_hash, self.threshold, &self.certs)
    }

    fn certificates(&self) -> &[Self::Cert] {
        &self.certs
    }
}
