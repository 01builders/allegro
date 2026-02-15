//! Demo binary: Alice→Bob→Carol flow against independently running gRPC sidecars.

use std::collections::HashMap;

use clap::Parser;
use fastpay_crypto::{Ed25519Certificate, MultiCertQC, SimpleAssembler};
use fastpay_sidecar_mock::DemoScenario;
use fastpay_types::{Address, Expiry, NonceKey, QuorumCert, ValidatorId, VerificationContext};
use fastpay_user_client::{
    parse_ed25519_proto_cert, CacheLimits, CertManager, FastPayClient, GrpcTransport,
    MultiValidatorTransport, SidecarTransport, WalletState,
};
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "grpc-chained-demo",
    about = "Run chained FastPay flow against running sidecars"
)]
struct Cli {
    /// First sidecar gRPC URL.
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    dave_url: String,

    /// Second sidecar gRPC URL.
    #[arg(long, default_value = "http://127.0.0.1:50052")]
    edgar_url: String,

    /// Chain ID to use for request building and cert verification.
    #[arg(long, default_value = "1337")]
    chain_id: u64,

    /// Epoch to use for cert verification.
    #[arg(long, default_value = "1")]
    epoch: u64,

    /// Expiry block height used in submitted transactions.
    #[arg(long, default_value = "100")]
    expiry_block_height: u64,
}

fn make_client(
    address: Address,
    sender_private_key: [u8; 32],
    dave_url: &str,
    edgar_url: &str,
    chain_id: u64,
    verify_ctx: VerificationContext,
) -> FastPayClient<GrpcTransport, Ed25519Certificate, MultiCertQC, SimpleAssembler> {
    FastPayClient::new(
        MultiValidatorTransport::new(vec![
            GrpcTransport::new(dave_url),
            GrpcTransport::new(edgar_url),
        ]),
        WalletState::new(address, CacheLimits::default()),
        CertManager::<_, _, SimpleAssembler>::new(verify_ctx, 2),
        chain_id,
        2,
        NonceKey::new([0x5b; 32]),
        parse_ed25519_proto_cert,
    )
    .with_sender_private_key(address, sender_private_key)
    .expect("valid sender key")
}

async fn build_verify_ctx(
    dave_url: &str,
    edgar_url: &str,
    chain_id: u64,
    epoch: u64,
) -> Result<VerificationContext, Box<dyn std::error::Error>> {
    let dave_info = GrpcTransport::new(dave_url)
        .get_validator_info()
        .await?
        .validator
        .ok_or("missing validator info for first sidecar")?;
    let edgar_info = GrpcTransport::new(edgar_url)
        .get_validator_info()
        .await?
        .validator
        .ok_or("missing validator info for second sidecar")?;

    let mut committee = HashMap::new();
    committee.insert(
        ValidatorId::from_slice(&dave_info.id)?,
        dave_info.pubkey.as_slice().try_into()?,
    );
    committee.insert(
        ValidatorId::from_slice(&edgar_info.id)?,
        edgar_info.pubkey.as_slice().try_into()?,
    );

    Ok(VerificationContext {
        chain_id,
        domain_tag: "tempo.fastpay.cert.v1".to_string(),
        protocol_version: 1,
        epoch,
        committee,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();
    let scenario = DemoScenario::new(cli.chain_id, cli.epoch);
    let accounts = scenario.accounts;
    let keys = scenario.account_keys;

    info!(
        dave_url = cli.dave_url.as_str(),
        edgar_url = cli.edgar_url.as_str(),
        "building verification context from sidecars"
    );
    let verify_ctx =
        build_verify_ctx(&cli.dave_url, &cli.edgar_url, cli.chain_id, cli.epoch).await?;

    let mut alice = make_client(
        accounts.alice,
        keys.alice,
        &cli.dave_url,
        &cli.edgar_url,
        cli.chain_id,
        verify_ctx.clone(),
    );
    let mut bob = make_client(
        accounts.bob,
        keys.bob,
        &cli.dave_url,
        &cli.edgar_url,
        cli.chain_id,
        verify_ctx.clone(),
    );
    let mut carol = make_client(
        accounts.carol,
        keys.carol,
        &cli.dave_url,
        &cli.edgar_url,
        cli.chain_id,
        verify_ctx,
    );

    info!("Submitting Alice -> Bob for $10");
    let qc1 = alice
        .send_payment(
            accounts.alice,
            accounts.bob,
            10,
            accounts.asset,
            Expiry::MaxBlockHeight(cli.expiry_block_height),
        )
        .await?;
    info!(qc_hash = %qc1.qc_hash(), "QC1 formed");

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
            Expiry::MaxBlockHeight(cli.expiry_block_height),
            &qc1,
        )
        .await?;
    info!(qc_hash = %qc2.qc_hash(), "QC2 formed");

    let certs = carol.poll_bulletin_board().await?;
    info!(
        cert_count = certs.len(),
        "Carol sees certificates on bulletin board"
    );

    Ok(())
}
