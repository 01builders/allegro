//! Error types for crypto, QC assembly, and validation operations.

use thiserror::Error;

use crate::ids::ValidatorId;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid length for {kind}: expected {expected}, got {actual}")]
    InvalidLength {
        kind: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("invalid signature")]
    InvalidSignature,
    #[error("unknown validator signer {0}")]
    UnknownSigner(ValidatorId),
    #[error("wrong chain id")]
    WrongChain,
    #[error("wrong epoch")]
    WrongEpoch,
    #[error("domain mismatch")]
    DomainMismatch,
    #[error("{0}")]
    Message(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AssemblyError {
    #[error("duplicate certificate from signer {0}")]
    DuplicateCertificate(ValidatorId),
    #[error("tx hash mismatch")]
    TxHashMismatch,
    #[error("effects hash mismatch")]
    EffectsHashMismatch,
    #[error("threshold not met: required {required}, have {have}")]
    ThresholdNotMet { required: u32, have: usize },
    #[error(transparent)]
    Verification(#[from] CryptoError),
    #[error("{0}")]
    Message(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("invalid length for {kind}: expected {expected}, got {actual}")]
    InvalidLength {
        kind: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
    #[error("invalid field `{0}`")]
    InvalidField(&'static str),
    #[error("{0}")]
    Message(String),
}
