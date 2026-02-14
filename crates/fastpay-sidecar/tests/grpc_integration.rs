//! Integration test: spin up two sidecar gRPC servers and run Alice→Bob→Carol flow
//! using real GrpcTransport from the user-client crate.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fastpay_crypto::{Ed25519Certificate, Ed25519Signer, MultiCertQC, SimpleAssembler};
use fastpay_proto::v1;
use fastpay_proto::v1::fast_pay_sidecar_server::FastPaySidecarServer;
use fastpay_sidecar_mock::DemoScenario;
use fastpay_types::{
    Address, AssetId, CertSigningContext, Expiry, NonceKey, QuorumCert, ValidatorId,
    VerificationContext,
};
use fastpay_user_client::{
    parse_ed25519_proto_cert, CacheLimits, CertManager, FastPayClient, GrpcTransport,
    MultiValidatorTransport, RequestMeta, RetryPolicy, SidecarTransport, TxBuilder, WalletState,
};
use tokio::net::TcpListener;
use tonic::transport::Server;

use fastpay_sidecar::gossip::{run_gossip_loop, GossipConfig};
use fastpay_sidecar::service::FastPaySidecarService;
use fastpay_sidecar::state::{SidecarLimits, SidecarState};

const CHAIN_ID: u64 = 1337;
const EPOCH: u64 = 1;

fn demo_balances() -> HashMap<Address, HashMap<AssetId, u64>> {
    let scenario = DemoScenario::new(CHAIN_ID, EPOCH);
    HashMap::from([
        (
            scenario.accounts.alice,
            HashMap::from([(scenario.accounts.asset, 15)]),
        ),
        (
            scenario.accounts.bob,
            HashMap::from([(scenario.accounts.asset, 5)]),
        ),
        (
            scenario.accounts.carol,
            HashMap::from([(scenario.accounts.asset, 5)]),
        ),
    ])
}

struct SidecarHandle {
    addr: SocketAddr,
    state: Arc<SidecarState>,
}

async fn start_sidecar(name: &str, validator_id: ValidatorId, seed: [u8; 32]) -> SidecarHandle {
    let signer = Ed25519Signer::from_seed(validator_id, seed);
    let signing_ctx = CertSigningContext {
        chain_id: CHAIN_ID,
        domain_tag: "tempo.fastpay.cert.v1",
        protocol_version: 1,
        epoch: EPOCH,
    };
    let state = Arc::new(SidecarState::new(
        name,
        signer,
        signing_ctx,
        demo_balances(),
    ));
    state.set_chain_head(1, 1_700_000_000_000);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let service = FastPaySidecarService::new(Arc::clone(&state));
    tokio::spawn(async move {
        Server::builder()
            .add_service(FastPaySidecarServer::new(service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    // Give the server a moment to start.
    tokio::time::sleep(Duration::from_millis(50)).await;

    SidecarHandle { addr, state }
}

fn make_grpc_client(
    address: Address,
    sender_private_key: [u8; 32],
    dave_url: &str,
    edgar_url: &str,
    verify_ctx: VerificationContext,
) -> FastPayClient<GrpcTransport, Ed25519Certificate, MultiCertQC, SimpleAssembler> {
    let dave_transport = GrpcTransport::new(dave_url);
    let edgar_transport = GrpcTransport::new(edgar_url);
    FastPayClient::new(
        MultiValidatorTransport::new(vec![dave_transport, edgar_transport]),
        WalletState::new(address, CacheLimits::default()),
        CertManager::<_, _, SimpleAssembler>::new(verify_ctx, 2),
        CHAIN_ID,
        2,
        NonceKey::new([0x5b; 32]),
        parse_ed25519_proto_cert,
    )
    .with_sender_private_key(address, sender_private_key)
    .expect("valid sender key")
}

async fn build_verify_ctx(dave_url: &str, edgar_url: &str) -> VerificationContext {
    let dave_transport = GrpcTransport::new(dave_url);
    let edgar_transport = GrpcTransport::new(edgar_url);

    let dave_info = dave_transport
        .get_validator_info()
        .await
        .unwrap()
        .validator
        .unwrap();
    let edgar_info = edgar_transport
        .get_validator_info()
        .await
        .unwrap()
        .validator
        .unwrap();

    let mut committee = HashMap::new();
    committee.insert(
        ValidatorId::from_slice(&dave_info.id).unwrap(),
        dave_info.pubkey.as_slice().try_into().unwrap(),
    );
    committee.insert(
        ValidatorId::from_slice(&edgar_info.id).unwrap(),
        edgar_info.pubkey.as_slice().try_into().unwrap(),
    );

    VerificationContext {
        chain_id: CHAIN_ID,
        domain_tag: "tempo.fastpay.cert.v1".to_string(),
        protocol_version: 1,
        epoch: EPOCH,
        committee,
    }
}

fn request_meta(client_request_id: &str) -> RequestMeta {
    RequestMeta {
        client_request_id: client_request_id.to_string(),
        timeout_ms: 3_000,
        retry_policy: RetryPolicy {
            max_retries: 0,
            initial_backoff_ms: 0,
            max_backoff_ms: 0,
            jitter_ms: 0,
        },
    }
}

fn cert_from_response(resp: v1::SubmitFastPayResponse) -> v1::ValidatorCertificate {
    match resp.result {
        Some(v1::submit_fast_pay_response::Result::Cert(cert)) => cert,
        _ => panic!("expected cert response"),
    }
}

fn reject_from_response(resp: v1::SubmitFastPayResponse) -> v1::RejectReason {
    match resp.result {
        Some(v1::submit_fast_pay_response::Result::Reject(reject)) => reject,
        _ => panic!("expected reject response"),
    }
}

#[tokio::test]
async fn grpc_rejects_wrong_chain_id() {
    let dave = start_sidecar("Dave", ValidatorId::new([0xd1; 32]), [0x41; 32]).await;
    let dave_url = format!("http://{}", dave.addr);

    let transport = GrpcTransport::new(&dave_url);
    let scenario = DemoScenario::new(CHAIN_ID, EPOCH);
    let alice = scenario.accounts.alice;
    let bob = scenario.accounts.bob;
    let asset = scenario.accounts.asset;
    let nonce_key = NonceKey::new([0x5b; 32]);

    let built = TxBuilder::new(CHAIN_ID + 1)
        .with_payment(alice, bob, 10, asset)
        .with_sender_private_key(scenario.account_keys.alice)
        .with_nonce_seq(nonce_key, 0)
        .with_expiry(Expiry::MaxBlockHeight(100))
        .with_client_request_id("wrong-chain")
        .build()
        .unwrap();

    let resp = transport
        .submit_fastpay(
            v1::SubmitFastPayRequest {
                tx: Some(built.tx),
                parent_qcs: Vec::new(),
            },
            request_meta("wrong-chain"),
        )
        .await
        .unwrap();

    let reject = reject_from_response(resp);
    assert_eq!(reject.code, v1::RejectCode::WrongChain as i32);
}

#[tokio::test]
async fn grpc_retry_is_idempotent_for_same_request() {
    let dave = start_sidecar("Dave", ValidatorId::new([0xd1; 32]), [0x41; 32]).await;
    let dave_url = format!("http://{}", dave.addr);

    let transport = GrpcTransport::new(&dave_url);
    let scenario = DemoScenario::new(CHAIN_ID, EPOCH);
    let alice = scenario.accounts.alice;
    let bob = scenario.accounts.bob;
    let asset = scenario.accounts.asset;
    let nonce_key = NonceKey::new([0x5b; 32]);

    let built = TxBuilder::new(CHAIN_ID)
        .with_payment(alice, bob, 10, asset)
        .with_sender_private_key(scenario.account_keys.alice)
        .with_nonce_seq(nonce_key, 0)
        .with_expiry(Expiry::MaxBlockHeight(100))
        .with_client_request_id("idem-req")
        .build()
        .unwrap();

    let req = v1::SubmitFastPayRequest {
        tx: Some(built.tx),
        parent_qcs: Vec::new(),
    };

    let first = transport
        .submit_fastpay(req.clone(), request_meta("idem-req"))
        .await
        .unwrap();
    let second = transport
        .submit_fastpay(req, request_meta("idem-req"))
        .await
        .unwrap();

    let first_cert = cert_from_response(first);
    let second_cert = cert_from_response(second);
    assert_eq!(first_cert.signature, second_cert.signature);
    assert_eq!(first_cert.tx_hash, second_cert.tx_hash);

    let follow_up = TxBuilder::new(CHAIN_ID)
        .with_payment(alice, bob, 5, asset)
        .with_sender_private_key(scenario.account_keys.alice)
        .with_nonce_seq(nonce_key, 1)
        .with_expiry(Expiry::MaxBlockHeight(100))
        .with_client_request_id("idem-req-2")
        .build()
        .unwrap();

    let follow_up_resp = transport
        .submit_fastpay(
            v1::SubmitFastPayRequest {
                tx: Some(follow_up.tx),
                parent_qcs: Vec::new(),
            },
            request_meta("idem-req-2"),
        )
        .await
        .unwrap();

    let _ = cert_from_response(follow_up_resp);
}

#[tokio::test]
async fn grpc_single_payment_alice_to_bob() {
    let dave = start_sidecar("Dave", ValidatorId::new([0xd1; 32]), [0x41; 32]).await;
    let edgar = start_sidecar("Edgar", ValidatorId::new([0xe1; 32]), [0x42; 32]).await;

    let dave_url = format!("http://{}", dave.addr);
    let edgar_url = format!("http://{}", edgar.addr);

    let verify_ctx = build_verify_ctx(&dave_url, &edgar_url).await;

    let scenario = DemoScenario::new(CHAIN_ID, EPOCH);
    let alice = scenario.accounts.alice;
    let bob = scenario.accounts.bob;
    let asset = scenario.accounts.asset;

    let mut client = make_grpc_client(
        alice,
        scenario.account_keys.alice,
        &dave_url,
        &edgar_url,
        verify_ctx,
    );
    let qc = client
        .send_payment(alice, bob, 10, asset, Expiry::MaxBlockHeight(100))
        .await
        .expect("single payment must succeed");
    assert!(qc.is_complete());
}

#[tokio::test]
async fn grpc_chained_payment_alice_bob_carol() {
    let dave = start_sidecar("Dave", ValidatorId::new([0xd1; 32]), [0x41; 32]).await;
    let edgar = start_sidecar("Edgar", ValidatorId::new([0xe1; 32]), [0x42; 32]).await;

    let dave_url = format!("http://{}", dave.addr);
    let edgar_url = format!("http://{}", edgar.addr);

    let verify_ctx = build_verify_ctx(&dave_url, &edgar_url).await;

    let scenario = DemoScenario::new(CHAIN_ID, EPOCH);
    let alice = scenario.accounts.alice;
    let bob = scenario.accounts.bob;
    let carol = scenario.accounts.carol;
    let asset = scenario.accounts.asset;

    let mut alice_client = make_grpc_client(
        alice,
        scenario.account_keys.alice,
        &dave_url,
        &edgar_url,
        verify_ctx.clone(),
    );
    let mut bob_client = make_grpc_client(
        bob,
        scenario.account_keys.bob,
        &dave_url,
        &edgar_url,
        verify_ctx.clone(),
    );
    let mut carol_client = make_grpc_client(
        carol,
        scenario.account_keys.carol,
        &dave_url,
        &edgar_url,
        verify_ctx,
    );

    // Alice -> Bob
    let qc1 = alice_client
        .send_payment(alice, bob, 10, asset, Expiry::MaxBlockHeight(100))
        .await
        .expect("alice->bob must succeed");

    let parent_tx = *qc1.tx_hash();
    let parent_proto = alice_client
        .get_proto_qc(&parent_tx)
        .cloned()
        .expect("alice must have proto qc");
    bob_client.import_proto_qc(parent_tx, parent_proto);

    // Bob -> Carol (chained)
    let qc2 = bob_client
        .send_payment_with_parent(bob, carol, 10, asset, Expiry::MaxBlockHeight(100), &qc1)
        .await
        .expect("bob->carol must succeed");
    assert!(qc2.is_complete());

    // Carol polls bulletin board and sees certificates
    let certs = carol_client.poll_bulletin_board().await.unwrap();
    assert!(
        !certs.is_empty(),
        "carol should see certs on bulletin board"
    );
}

#[tokio::test]
async fn grpc_bulletin_board_limit_is_capped_server_side() {
    let dave = start_sidecar("Dave", ValidatorId::new([0xd1; 32]), [0x41; 32]).await;
    dave.state.set_limits(SidecarLimits {
        max_bulletin_board_response: 1,
        ..SidecarLimits::default()
    });

    let dave_url = format!("http://{}", dave.addr);
    let transport = GrpcTransport::new(&dave_url);

    let scenario = DemoScenario::new(CHAIN_ID, EPOCH);
    let alice = scenario.accounts.alice;
    let bob = scenario.accounts.bob;
    let asset = scenario.accounts.asset;
    let nonce_key = NonceKey::new([0x5b; 32]);

    for (seq, amount) in [(0_u64, 5_u64), (1_u64, 4_u64)] {
        let built = TxBuilder::new(CHAIN_ID)
            .with_payment(alice, bob, amount, asset)
            .with_sender_private_key(scenario.account_keys.alice)
            .with_nonce_seq(nonce_key, seq)
            .with_expiry(Expiry::MaxBlockHeight(100))
            .with_client_request_id(format!("bb-cap-{seq}"))
            .build()
            .unwrap();
        let resp = transport
            .submit_fastpay(
                v1::SubmitFastPayRequest {
                    tx: Some(built.tx),
                    parent_qcs: Vec::new(),
                },
                request_meta(&format!("bb-cap-{seq}")),
            )
            .await
            .unwrap();
        let _ = cert_from_response(resp);
    }

    let bb = transport
        .get_bulletin_board(v1::GetBulletinBoardRequest::default())
        .await
        .unwrap();
    assert_eq!(bb.certs.len(), 1);
}

#[tokio::test]
async fn grpc_gossip_syncs_certs_between_sidecars() {
    let dave = start_sidecar("Dave", ValidatorId::new([0xd1; 32]), [0x41; 32]).await;
    let edgar = start_sidecar("Edgar", ValidatorId::new([0xe1; 32]), [0x42; 32]).await;

    let dave_url = format!("http://{}", dave.addr);
    let edgar_url = format!("http://{}", edgar.addr);

    // Start gossip from Dave -> Edgar and Edgar -> Dave.
    let dave_gossip = GossipConfig {
        peers: vec![edgar_url.clone()],
        interval: Duration::from_millis(100),
        pull_limit: 256,
    };
    let edgar_gossip = GossipConfig {
        peers: vec![dave_url.clone()],
        interval: Duration::from_millis(100),
        pull_limit: 256,
    };
    tokio::spawn(run_gossip_loop(Arc::clone(&dave.state), dave_gossip));
    tokio::spawn(run_gossip_loop(Arc::clone(&edgar.state), edgar_gossip));

    let verify_ctx = build_verify_ctx(&dave_url, &edgar_url).await;

    let scenario = DemoScenario::new(CHAIN_ID, EPOCH);
    let alice = scenario.accounts.alice;
    let bob = scenario.accounts.bob;
    let asset = scenario.accounts.asset;

    let mut client = make_grpc_client(
        alice,
        scenario.account_keys.alice,
        &dave_url,
        &edgar_url,
        verify_ctx,
    );
    let _qc = client
        .send_payment(alice, bob, 10, asset, Expiry::MaxBlockHeight(100))
        .await
        .unwrap();

    // Wait for gossip to propagate.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Query Dave's bulletin board — should have both Dave's and Edgar's certs.
    let dave_transport = GrpcTransport::new(&dave_url);
    let bb = dave_transport
        .get_bulletin_board(fastpay_proto::v1::GetBulletinBoardRequest::default())
        .await
        .unwrap();
    assert!(
        bb.certs.len() >= 2,
        "Dave should have certs from both validators after gossip, got {}",
        bb.certs.len()
    );
}
