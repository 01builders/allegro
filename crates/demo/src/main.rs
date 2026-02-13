use std::collections::HashMap;

use fastpay_crypto::{Ed25519Certificate, MultiCertQC, SimpleAssembler};
use fastpay_sidecar_mock::DemoScenario;
use fastpay_types::{Address, Expiry, NonceKey, QuorumCert, ValidatorId, VerificationContext};
use fastpay_user_client::{
    CacheLimits, CertManager, FastPayClient, MockTransport, MultiValidatorTransport, WalletState,
    SidecarTransport, parse_ed25519_proto_cert,
};
use tracing::info;

fn make_client(
    address: Address,
    transport: MultiValidatorTransport<MockTransport>,
    verify_ctx: VerificationContext,
) -> FastPayClient<MockTransport, Ed25519Certificate, MultiCertQC, SimpleAssembler> {
    FastPayClient::new(
        transport,
        WalletState::new(address, CacheLimits::default()),
        CertManager::<_, _, SimpleAssembler>::new(verify_ctx, 2),
        1337,
        2,
        NonceKey::new([0x5b; 32]),
        parse_ed25519_proto_cert,
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .compact()
        .init();

    let scenario = DemoScenario::new(1337, 1);
    let accounts = scenario.accounts;
    let dave_transport = MockTransport::new(scenario.dave);
    let edgar_transport = MockTransport::new(scenario.edgar);

    let dave_info = dave_transport.get_validator_info().await?.validator.unwrap();
    let edgar_info = edgar_transport.get_validator_info().await?.validator.unwrap();
    let mut committee = HashMap::new();
    committee.insert(
        ValidatorId::from_slice(&dave_info.id)?,
        dave_info.pubkey.as_slice().try_into()?,
    );
    committee.insert(
        ValidatorId::from_slice(&edgar_info.id)?,
        edgar_info.pubkey.as_slice().try_into()?,
    );
    let verify_ctx = VerificationContext {
        chain_id: 1337,
        domain_tag: "tempo.fastpay.cert.v1".to_string(),
        protocol_version: 1,
        epoch: 1,
        committee,
    };

    let mut alice = make_client(
        accounts.alice,
        MultiValidatorTransport::new(vec![dave_transport.clone(), edgar_transport.clone()]),
        verify_ctx.clone(),
    );
    let mut bob = make_client(
        accounts.bob,
        MultiValidatorTransport::new(vec![dave_transport.clone(), edgar_transport.clone()]),
        verify_ctx.clone(),
    );
    let mut carol = make_client(
        accounts.carol,
        MultiValidatorTransport::new(vec![dave_transport.clone(), edgar_transport.clone()]),
        verify_ctx,
    );

    info!("Submitting Alice -> Bob for $10");
    let qc1 = alice
        .send_payment(
            accounts.alice,
            accounts.bob,
            10,
            accounts.asset,
            Expiry::MaxBlockHeight(100),
        )
        .await?;
    info!("QC1 formed: {}", qc1.qc_hash());

    let parent_tx = *qc1.tx_hash();
    let parent_proto = alice
        .get_proto_qc(&parent_tx)
        .cloned()
        .ok_or("alice missing proto qc for parent")?;
    bob.import_proto_qc(parent_tx, parent_proto);

    info!("Submitting Bob -> Carol for $10 with parent QC");
    let qc2 = bob
        .send_payment_with_parent(
            accounts.bob,
            accounts.carol,
            10,
            accounts.asset,
            Expiry::MaxBlockHeight(100),
            &qc1,
        )
        .await?;
    info!("QC2 formed: {}", qc2.qc_hash());

    let certs = carol.poll_bulletin_board().await?;
    info!("Carol sees {} certificates on bulletin boards", certs.len());

    Ok(())
}
