//! FastPay user client library for Phase 1.
//!
//! This crate exposes:
//! - transport abstractions (`SidecarTransport`, `MockTransport`, multi-validator wrapper),
//! - transaction construction (`TxBuilder`),
//! - certificate collection + QC assembly (`CertManager`),
//! - wallet state (`WalletState`) with nonce reservation and crash-recovery primitives,
//! - high-level client facade (`FastPayClient`) for send/poll/reconcile workflows.

pub mod cert_manager;
pub mod client;
pub mod transport;
pub mod tx_builder;
pub mod wallet;

pub use cert_manager::{CertManager, CertManagerError};
pub use client::{parse_ed25519_proto_cert, FastPayClient, FastPayClientError};
#[cfg(not(target_arch = "wasm32"))]
pub use transport::GrpcTransport;
pub use transport::{
    MockTransport, MultiValidatorTransport, RequestMeta, RetryPolicy, SidecarTransport,
    TransportConfig, TransportError, ValidatorEndpoint,
};
pub use tx_builder::{encode_payment_tempo_tx_signed, BuiltTx, TxBuilder, TxBuilderError};
pub use wallet::{
    CacheLimits, PendingStatus, PendingTx, StateEvent, WalletError, WalletSnapshot, WalletState,
};
