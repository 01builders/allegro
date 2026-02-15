use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fastpay_backend::service::FastPayBackendService;
use fastpay_backend::state::{BackendLimits, FastPayBackendState};
use fastpay_backend::upstream::{SidecarEndpoint, UpstreamConfig};
use fastpay_crypto::{compute_qc_hash, Ed25519Signer};
use fastpay_proto::v1;
use fastpay_proto::v1::fast_pay_aggregator_client::FastPayAggregatorClient;
use fastpay_proto::v1::fast_pay_aggregator_server::FastPayAggregatorServer;
use fastpay_proto::v1::fast_pay_sidecar_server::FastPaySidecarServer;
use fastpay_sidecar::service::FastPaySidecarService;
use fastpay_sidecar::state::SidecarState;
use fastpay_sidecar_mock::DemoScenario;
use fastpay_types::{Address, AssetId, CertSigningContext, Expiry, NonceKey, TxHash, ValidatorId};
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

    let service = FastPaySidecarService::new(Arc::clone(&state));
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
