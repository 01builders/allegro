//! Pre-built demo scenarios with Alice, Bob, Carol accounts and validator sidecars.

use std::collections::HashMap;

use alloy_signer_local::PrivateKeySigner;
use fastpay_crypto::Ed25519Signer;
use fastpay_types::{Address, AssetId, CertSigningContext, ValidatorId};

use crate::mock_sidecar::MockSidecar;

#[derive(Debug, Clone, Copy)]
pub struct DemoAccounts {
    pub alice: Address,
    pub bob: Address,
    pub carol: Address,
    pub asset: AssetId,
}

#[derive(Debug, Clone, Copy)]
pub struct DemoAccountKeys {
    pub alice: [u8; 32],
    pub bob: [u8; 32],
    pub carol: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct DemoScenario {
    pub accounts: DemoAccounts,
    pub account_keys: DemoAccountKeys,
    pub dave: MockSidecar,
    pub edgar: MockSidecar,
}

impl DemoScenario {
    pub fn new(chain_id: u64, epoch: u64) -> Self {
        let account_keys = DemoAccountKeys {
            alice: [0x11; 32],
            bob: [0x22; 32],
            carol: [0x33; 32],
        };
        let accounts = DemoAccounts {
            alice: Address::from_slice(
                PrivateKeySigner::from_slice(&account_keys.alice)
                    .expect("valid key")
                    .address()
                    .as_slice(),
            )
            .expect("valid address"),
            bob: Address::from_slice(
                PrivateKeySigner::from_slice(&account_keys.bob)
                    .expect("valid key")
                    .address()
                    .as_slice(),
            )
            .expect("valid address"),
            carol: Address::from_slice(
                PrivateKeySigner::from_slice(&account_keys.carol)
                    .expect("valid key")
                    .address()
                    .as_slice(),
            )
            .expect("valid address"),
            asset: AssetId::new([
                0x20, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa,
            ]),
        };

        let balances = demo_balances(accounts);
        let ctx = CertSigningContext {
            chain_id,
            domain_tag: "tempo.fastpay.cert.v1",
            protocol_version: 1,
            epoch,
        };
        let dave = MockSidecar::new(
            "Dave",
            Ed25519Signer::from_seed(ValidatorId::new([0xd1; 32]), [0x41; 32]),
            ctx.clone(),
            balances.clone(),
        );
        let edgar = MockSidecar::new(
            "Edgar",
            Ed25519Signer::from_seed(ValidatorId::new([0xe1; 32]), [0x42; 32]),
            ctx,
            balances,
        );
        Self {
            accounts,
            account_keys,
            dave,
            edgar,
        }
    }
}

fn demo_balances(accounts: DemoAccounts) -> HashMap<Address, HashMap<AssetId, u64>> {
    HashMap::from([
        (accounts.alice, HashMap::from([(accounts.asset, 15)])),
        (accounts.bob, HashMap::from([(accounts.asset, 5)])),
        (accounts.carol, HashMap::from([(accounts.asset, 5)])),
    ])
}
