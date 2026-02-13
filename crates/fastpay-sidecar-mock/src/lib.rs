//! Mock validator sidecar for Phase 1 testing without real nodes.

pub mod mock_sidecar;
pub mod scenarios;

pub use mock_sidecar::{DecodedPayment, MockSidecar};
pub use scenarios::{DemoAccounts, DemoScenario};
