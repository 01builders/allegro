use std::collections::HashMap;

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

#[derive(Debug, Clone)]
pub struct DemoScenario {
    pub accounts: DemoAccounts,
    pub dave: MockSidecar,
    pub edgar: MockSidecar,
}

impl DemoScenario {
    pub fn new(chain_id: u64, epoch: u64) -> Self {
        let accounts = DemoAccounts {
            alice: Address::new([0x01; 20]),
            bob: Address::new([0x02; 20]),
            carol: Address::new([0x03; 20]),
            asset: AssetId::new([0xaa; 20]),
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
