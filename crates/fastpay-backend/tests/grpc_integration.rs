use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fastpay_backend::service::FastPayBackendService;
use fastpay_backend::state::{BackendLimits, FastPayBackendState};
use fastpay_backend::upstream::{SidecarEndpoint, UpstreamConfig};
use fastpay_crypto::{compute_qc_hash, Ed25519Signer, SimpleAssembler};
use fastpay_proto::v1;
use fastpay_proto::v1::fast_pay_aggregator_client::FastPayAggregatorClient;
use fastpay_proto::v1::fast_pay_aggregator_server::FastPayAggregatorServer;
use fastpay_proto::v1::fast_pay_sidecar_server::FastPaySidecarServer;
use fastpay_sidecar::service::FastPaySidecarService;
use fastpay_sidecar::state::SidecarState;
use fastpay_sidecar_mock::DemoScenario;
use fastpay_types::{
    Address, AssetId, CertSigningContext, Certificate, EffectsHash, Expiry, NonceKey,
    QuorumAssembler, QuorumCert, TxHash, ValidatorId, VerificationContext,
};
use fastpay_user_client::{
    parse_ed25519_proto_cert, GrpcTransport, RequestMeta, RetryPolicy, SidecarTransport, TxBuilder,
};
use tokio::net::TcpListener;
use tonic::transport::Server;

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

async fn start_sidecar(
    name: &str,
    validator_id: ValidatorId,
    seed: [u8; 32],
    block_height: u64,
    block_hash: [u8; 32],
) -> SidecarHandle {
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
    state.set_chain_head_with_hash(block_height, block_hash, 1_700_000_000_000 + block_height);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let service = FastPaySidecarService::new(Arc::clone(&state), None);
    tokio::spawn(async move {
        Server::builder()
            .add_service(FastPaySidecarServer::new(service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    SidecarHandle { addr, state }
}

async fn start_aggregator(sidecars: &[String], qc_threshold: u32) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let state = Arc::new(FastPayBackendState::new(BackendLimits::default()));
    let upstream = UpstreamConfig {
        endpoints: sidecars
            .iter()
            .enumerate()
            .map(|(idx, url)| SidecarEndpoint {
                name: format!("v{}", idx + 1),
                url: url.clone(),
            })
            .collect(),
        timeout_ms: 2_000,
        pull_limit: 1_000,
    };
    let service = FastPayBackendService {
        state,
        upstream,
        qc_threshold,
    };

    tokio::spawn(async move {
        Server::builder()
            .add_service(FastPayAggregatorServer::new(service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    addr
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

fn build_verify_ctx_from_seeds() -> VerificationContext {
    let dave_id = ValidatorId::new([0xd1; 32]);
    let edgar_id = ValidatorId::new([0xe1; 32]);
    let dave_signer = Ed25519Signer::from_seed(dave_id, [0x41; 32]);
    let edgar_signer = Ed25519Signer::from_seed(edgar_id, [0x42; 32]);
    let mut committee = HashMap::new();
    committee.insert(dave_id, dave_signer.public_key_bytes());
    committee.insert(edgar_id, edgar_signer.public_key_bytes());
    VerificationContext {
        chain_id: CHAIN_ID,
        domain_tag: "tempo.fastpay.cert.v1".to_string(),
        protocol_version: 1,
        epoch: EPOCH,
        committee,
    }
}

async fn submit_to_sidecar(
    url: &str,
    request_id: &str,
    recipient: Address,
    nonce_seq: u64,
) -> v1::SubmitFastPayResponse {
    let request = build_submit_request(request_id, recipient, nonce_seq);

    GrpcTransport::new(url)
        .submit_fastpay(request, request_meta(request_id))
        .await
        .unwrap()
}

fn build_submit_request(
    request_id: &str,
    recipient: Address,
    nonce_seq: u64,
) -> v1::SubmitFastPayRequest {
    let scenario = DemoScenario::new(CHAIN_ID, EPOCH);
    let built = TxBuilder::new(CHAIN_ID)
        .with_payment(
            scenario.accounts.alice,
            recipient,
            10,
            scenario.accounts.asset,
        )
        .with_sender_private_key(scenario.account_keys.alice)
        .with_nonce_seq(NonceKey::new([0x5b; 32]), nonce_seq)
        .with_expiry(Expiry::MaxBlockHeight(100))
        .with_client_request_id(request_id)
        .build()
        .unwrap();

    v1::SubmitFastPayRequest {
        tx: Some(built.tx),
        parent_qcs: Vec::new(),
    }
}

#[tokio::test]
async fn aggregator_merges_bulletin_board_without_duplicate_signers() {
    let dave = start_sidecar(
        "Dave",
        ValidatorId::new([0xd1; 32]),
        [0x41; 32],
        1,
        [0x01; 32],
    )
    .await;
    let edgar = start_sidecar(
        "Edgar",
        ValidatorId::new([0xe1; 32]),
        [0x42; 32],
        1,
        [0x02; 32],
    )
    .await;

    let dave_url = format!("http://{}", dave.addr);
    let edgar_url = format!("http://{}", edgar.addr);
    let aggregator_addr = start_aggregator(&[dave_url.clone(), edgar_url.clone()], 2).await;
    let mut client = FastPayAggregatorClient::connect(format!("http://{}", aggregator_addr))
        .await
        .unwrap();

    let scenario = DemoScenario::new(CHAIN_ID, EPOCH);
    submit_to_sidecar(&dave_url, "agg-bb", scenario.accounts.bob, 0).await;
    submit_to_sidecar(&edgar_url, "agg-bb", scenario.accounts.bob, 0).await;

    let response = client
        .get_bulletin_board(v1::GetBulletinBoardRequest::default())
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.certs.len(), 2);
    assert!(
        response.certs[0].created_unix_millis <= response.certs[1].created_unix_millis,
        "expected deterministic ordering"
    );
}

#[tokio::test]
async fn backend_submit_fastpay_fanout_returns_certs() {
    let dave = start_sidecar(
        "Dave",
        ValidatorId::new([0xd1; 32]),
        [0x41; 32],
        1,
        [0x01; 32],
    )
    .await;
    let edgar = start_sidecar(
        "Edgar",
        ValidatorId::new([0xe1; 32]),
        [0x42; 32],
        1,
        [0x02; 32],
    )
    .await;

    let dave_url = format!("http://{}", dave.addr);
    let edgar_url = format!("http://{}", edgar.addr);
    let backend_addr = start_aggregator(&[dave_url, edgar_url], 2).await;
    let mut client = FastPayAggregatorClient::connect(format!("http://{}", backend_addr))
        .await
        .unwrap();

    let scenario = DemoScenario::new(CHAIN_ID, EPOCH);
    let response = client
        .submit_fast_pay(build_submit_request(
            "backend-submit",
            scenario.accounts.bob,
            0,
        ))
        .await
        .unwrap()
        .into_inner();

    assert!(response.threshold_met);
    assert_eq!(response.certs.len(), 2);
    assert!(response.rejects.is_empty());
    assert_eq!(response.tx_hash.len(), 32);
    assert_eq!(response.effects_hash.len(), 32);
}

#[tokio::test]
async fn aggregator_assembles_quorum_certificate() {
    let dave = start_sidecar(
        "Dave",
        ValidatorId::new([0xd1; 32]),
        [0x41; 32],
        1,
        [0x01; 32],
    )
    .await;
    let edgar = start_sidecar(
        "Edgar",
        ValidatorId::new([0xe1; 32]),
        [0x42; 32],
        1,
        [0x02; 32],
    )
    .await;

    let dave_url = format!("http://{}", dave.addr);
    let edgar_url = format!("http://{}", edgar.addr);
    let aggregator_addr = start_aggregator(&[dave_url.clone(), edgar_url.clone()], 2).await;
    let mut client = FastPayAggregatorClient::connect(format!("http://{}", aggregator_addr))
        .await
        .unwrap();

    let scenario = DemoScenario::new(CHAIN_ID, EPOCH);
    let first = submit_to_sidecar(&dave_url, "agg-qc", scenario.accounts.bob, 0).await;
    let second = submit_to_sidecar(&edgar_url, "agg-qc", scenario.accounts.bob, 0).await;

    let first_cert = match first.result.unwrap() {
        v1::submit_fast_pay_response::Result::Cert(cert) => cert,
        _ => panic!("expected cert"),
    };
    let _second_cert = match second.result.unwrap() {
        v1::submit_fast_pay_response::Result::Cert(cert) => cert,
        _ => panic!("expected cert"),
    };

    let response = client
        .get_quorum_certificate(v1::GetQuorumCertificateRequest {
            tx_hash: first_cert.tx_hash.clone(),
            effects_hash: Vec::new(),
            threshold: 2,
        })
        .await
        .unwrap()
        .into_inner();

    let qc = match response.result.unwrap() {
        v1::get_quorum_certificate_response::Result::Qc(qc) => qc,
        _ => panic!("expected QC response"),
    };

    assert_eq!(qc.certs.len(), 2);
    let parsed = qc
        .certs
        .iter()
        .cloned()
        .map(parse_ed25519_proto_cert)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let tx_hash = TxHash::from_slice(&qc.tx_hash).unwrap();
    let effects_hash = fastpay_types::EffectsHash::from_slice(&qc.effects_hash).unwrap();
    let expected = compute_qc_hash(&tx_hash, &effects_hash, 2, &parsed);
    assert_eq!(qc.qc_hash, expected.as_bytes().to_vec());
}

#[tokio::test]
async fn aggregator_selects_highest_chain_head_with_stable_tiebreak() {
    let dave = start_sidecar(
        "Dave",
        ValidatorId::new([0xd1; 32]),
        [0x41; 32],
        10,
        [0x20; 32],
    )
    .await;
    let edgar = start_sidecar(
        "Edgar",
        ValidatorId::new([0xe1; 32]),
        [0x42; 32],
        10,
        [0x10; 32],
    )
    .await;

    // keep handles alive
    let _ = (&dave.state, &edgar.state);

    let dave_url = format!("http://{}", dave.addr);
    let edgar_url = format!("http://{}", edgar.addr);
    let aggregator_addr = start_aggregator(&[dave_url, edgar_url], 2).await;
    let mut client = FastPayAggregatorClient::connect(format!("http://{}", aggregator_addr))
        .await
        .unwrap();

    let head = client
        .get_chain_head(v1::GetChainHeadRequest {})
        .await
        .unwrap()
        .into_inner();

    assert_eq!(head.block_height, 10);
    assert_eq!(head.block_hash, vec![0x10; 32]);
}

#[tokio::test]
async fn aggregator_tx_status_is_conservative_and_reports_qc() {
    let dave = start_sidecar(
        "Dave",
        ValidatorId::new([0xd1; 32]),
        [0x41; 32],
        1,
        [0x01; 32],
    )
    .await;
    let edgar = start_sidecar(
        "Edgar",
        ValidatorId::new([0xe1; 32]),
        [0x42; 32],
        1,
        [0x02; 32],
    )
    .await;

    let dave_url = format!("http://{}", dave.addr);
    let edgar_url = format!("http://{}", edgar.addr);
    let aggregator_addr = start_aggregator(&[dave_url.clone(), edgar_url.clone()], 2).await;
    let mut client = FastPayAggregatorClient::connect(format!("http://{}", aggregator_addr))
        .await
        .unwrap();

    let scenario = DemoScenario::new(CHAIN_ID, EPOCH);
    let built = TxBuilder::new(CHAIN_ID)
        .with_payment(
            scenario.accounts.alice,
            scenario.accounts.bob,
            10,
            scenario.accounts.asset,
        )
        .with_sender_private_key(scenario.account_keys.alice)
        .with_nonce_seq(NonceKey::new([0x5b; 32]), 0)
        .with_expiry(Expiry::MaxBlockHeight(100))
        .with_client_request_id("agg-status")
        .build()
        .unwrap();

    let before = client
        .get_tx_status(v1::GetTxStatusRequest {
            tx_hash: built.tx_hash.as_bytes().to_vec(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        before.stage,
        v1::tx_lifecycle_update::Stage::Unspecified as i32
    );
    assert!(!before.qc_formed);

    submit_to_sidecar(&dave_url, "agg-status", scenario.accounts.bob, 0).await;
    submit_to_sidecar(&edgar_url, "agg-status", scenario.accounts.bob, 0).await;

    let after = client
        .get_tx_status(v1::GetTxStatusRequest {
            tx_hash: built.tx_hash.as_bytes().to_vec(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        after.stage,
        v1::tx_lifecycle_update::Stage::Certified as i32
    );
    assert!(after.qc_formed);
    assert_eq!(after.certs.len(), 2);
}

#[tokio::test]
async fn backend_submit_verifies_signatures_and_assembles_qc() {
    let dave = start_sidecar(
        "Dave",
        ValidatorId::new([0xd1; 32]),
        [0x41; 32],
        1,
        [0x01; 32],
    )
    .await;
    let edgar = start_sidecar(
        "Edgar",
        ValidatorId::new([0xe1; 32]),
        [0x42; 32],
        1,
        [0x02; 32],
    )
    .await;

    let dave_url = format!("http://{}", dave.addr);
    let edgar_url = format!("http://{}", edgar.addr);
    let backend_addr = start_aggregator(&[dave_url, edgar_url], 2).await;
    let mut client = FastPayAggregatorClient::connect(format!("http://{}", backend_addr))
        .await
        .unwrap();

    let scenario = DemoScenario::new(CHAIN_ID, EPOCH);
    let response = client
        .submit_fast_pay(build_submit_request(
            "verify-sigs",
            scenario.accounts.bob,
            0,
        ))
        .await
        .unwrap()
        .into_inner();

    assert!(response.threshold_met);
    assert_eq!(response.certs.len(), 2);

    // Parse proto certs into domain objects.
    let domain_certs: Vec<_> = response
        .certs
        .into_iter()
        .map(parse_ed25519_proto_cert)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // Cryptographically verify each certificate against the committee.
    let verify_ctx = build_verify_ctx_from_seeds();
    let dave_id = ValidatorId::new([0xd1; 32]);
    let edgar_id = ValidatorId::new([0xe1; 32]);
    let mut seen_signers = std::collections::HashSet::new();
    for cert in &domain_certs {
        cert.verify(&verify_ctx).unwrap();
        seen_signers.insert(*cert.signer());
    }
    assert!(seen_signers.contains(&dave_id));
    assert!(seen_signers.contains(&edgar_id));

    // Assemble QC and verify it.
    let tx_hash = TxHash::from_slice(&response.tx_hash).unwrap();
    let effects_hash = EffectsHash::from_slice(&response.effects_hash).unwrap();
    let mut assembler = SimpleAssembler::new(tx_hash, effects_hash, 2);
    for cert in domain_certs {
        assembler.add_certificate(cert).unwrap();
    }
    assert!(assembler.is_complete());
    let qc = assembler.finalize().unwrap();
    qc.verify(&verify_ctx).unwrap();
    assert_eq!(qc.threshold(), 2);
    assert_eq!(qc.cert_count(), 2);
}

#[tokio::test]
async fn backend_chained_payment_with_verified_qc() {
    let dave = start_sidecar(
        "Dave",
        ValidatorId::new([0xd1; 32]),
        [0x41; 32],
        1,
        [0x01; 32],
    )
    .await;
    let edgar = start_sidecar(
        "Edgar",
        ValidatorId::new([0xe1; 32]),
        [0x42; 32],
        1,
        [0x02; 32],
    )
    .await;

    let dave_url = format!("http://{}", dave.addr);
    let edgar_url = format!("http://{}", edgar.addr);
    let backend_addr = start_aggregator(&[dave_url, edgar_url], 2).await;
    let mut client = FastPayAggregatorClient::connect(format!("http://{}", backend_addr))
        .await
        .unwrap();

    let scenario = DemoScenario::new(CHAIN_ID, EPOCH);
    let verify_ctx = build_verify_ctx_from_seeds();

    // Step 1: Alice -> Bob (10 units) via aggregator.
    let resp1 = client
        .submit_fast_pay(build_submit_request(
            "chain-step1",
            scenario.accounts.bob,
            0,
        ))
        .await
        .unwrap()
        .into_inner();

    assert!(resp1.threshold_met);
    assert_eq!(resp1.certs.len(), 2);

    // Parse, verify, and assemble QC1.
    let certs1: Vec<_> = resp1
        .certs
        .iter()
        .cloned()
        .map(parse_ed25519_proto_cert)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    for cert in &certs1 {
        cert.verify(&verify_ctx).unwrap();
    }

    let tx_hash1 = TxHash::from_slice(&resp1.tx_hash).unwrap();
    let effects_hash1 = EffectsHash::from_slice(&resp1.effects_hash).unwrap();
    let mut asm1 = SimpleAssembler::new(tx_hash1, effects_hash1, 2);
    for cert in certs1 {
        asm1.add_certificate(cert).unwrap();
    }
    let qc1 = asm1.finalize().unwrap();
    qc1.verify(&verify_ctx).unwrap();

    // Step 2: Bob -> Carol (10 units) with parent QC from step 1.
    // Bob has 5 initial + 10 from Alice's QC = 15 effective balance.
    let proto_qc1 = fastpay_user_client::client::build_proto_qc_from_domain(&qc1);
    let built_bob = TxBuilder::new(CHAIN_ID)
        .with_payment(
            scenario.accounts.bob,
            scenario.accounts.carol,
            10,
            scenario.accounts.asset,
        )
        .with_sender_private_key(scenario.account_keys.bob)
        .with_nonce_seq(NonceKey::new([0x5c; 32]), 0)
        .with_expiry(Expiry::MaxBlockHeight(100))
        .with_parent_qc(&qc1)
        .with_client_request_id("chain-step2")
        .build()
        .unwrap();

    let resp2 = client
        .submit_fast_pay(v1::SubmitFastPayRequest {
            tx: Some(built_bob.tx),
            parent_qcs: vec![proto_qc1],
        })
        .await
        .unwrap()
        .into_inner();

    assert!(resp2.threshold_met);
    assert_eq!(resp2.certs.len(), 2);

    // Parse, verify, and assemble QC2.
    let certs2: Vec<_> = resp2
        .certs
        .into_iter()
        .map(parse_ed25519_proto_cert)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    for cert in &certs2 {
        cert.verify(&verify_ctx).unwrap();
    }

    let tx_hash2 = TxHash::from_slice(&resp2.tx_hash).unwrap();
    let effects_hash2 = EffectsHash::from_slice(&resp2.effects_hash).unwrap();
    let mut asm2 = SimpleAssembler::new(tx_hash2, effects_hash2, 2);
    for cert in certs2 {
        asm2.add_certificate(cert).unwrap();
    }
    let qc2 = asm2.finalize().unwrap();
    qc2.verify(&verify_ctx).unwrap();

    // QC1 and QC2 must have different hashes (different transactions).
    assert_ne!(qc1.qc_hash(), qc2.qc_hash());
}
