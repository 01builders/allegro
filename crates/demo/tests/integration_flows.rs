//! Integration tests for payment flows, rejections, and edge cases.

use std::collections::HashMap;

use fastpay_crypto::{Ed25519Certificate, Ed25519Signer, MultiCertQC, SimpleAssembler};
use fastpay_proto::v1;
use fastpay_sidecar_mock::DemoScenario;
use fastpay_types::{
    Address, AssetId, CertSigningContext, Expiry, NonceKey, QuorumCert, Signer, ValidatorId,
    VerificationContext,
};
use fastpay_user_client::{
    encode_payment_tempo_tx, parse_ed25519_proto_cert, CacheLimits, CertManager, CertManagerError,
    FastPayClient, FastPayClientError, MockTransport, MultiValidatorTransport, SidecarTransport,
    WalletState,
};

async fn build_verify_context(
    dave_transport: &MockTransport,
    edgar_transport: &MockTransport,
    epoch: u64,
) -> VerificationContext {
    let dave = dave_transport
        .get_validator_info()
        .await
        .unwrap()
        .validator
        .unwrap();
    let edgar = edgar_transport
        .get_validator_info()
        .await
        .unwrap()
        .validator
        .unwrap();
    let mut committee = HashMap::new();
    committee.insert(
        ValidatorId::from_slice(&dave.id).unwrap(),
        dave.pubkey.as_slice().try_into().unwrap(),
    );
    committee.insert(
        ValidatorId::from_slice(&edgar.id).unwrap(),
        edgar.pubkey.as_slice().try_into().unwrap(),
    );
    VerificationContext {
        chain_id: 1337,
        domain_tag: "tempo.fastpay.cert.v1".to_string(),
        protocol_version: 1,
        epoch,
        committee,
    }
}

fn make_client(
    address: Address,
    dave_transport: MockTransport,
    edgar_transport: MockTransport,
    verify_ctx: VerificationContext,
) -> FastPayClient<MockTransport, Ed25519Certificate, MultiCertQC, SimpleAssembler> {
    FastPayClient::new(
        MultiValidatorTransport::new(vec![dave_transport, edgar_transport]),
        WalletState::new(address, CacheLimits::default()),
        CertManager::<_, _, SimpleAssembler>::new(verify_ctx, 2),
        1337,
        2,
        NonceKey::new([0x5b; 32]),
        parse_ed25519_proto_cert,
    )
}

fn make_submit_request(
    sender: Address,
    recipient: Address,
    amount: u64,
    asset: AssetId,
    seq: u64,
    expiry: Expiry,
) -> v1::SubmitFastPayRequest {
    let expiry = match expiry {
        Expiry::MaxBlockHeight(h) => v1::Expiry {
            kind: Some(v1::expiry::Kind::MaxBlockHeight(h)),
        },
        Expiry::UnixMillis(ms) => v1::Expiry {
            kind: Some(v1::expiry::Kind::UnixMillis(ms)),
        },
    };
    let payment = v1::PaymentIntent {
        sender: Some(v1::Address {
            data: sender.as_bytes().to_vec(),
        }),
        recipient: Some(v1::Address {
            data: recipient.as_bytes().to_vec(),
        }),
        amount,
        asset: Some(v1::AssetId {
            data: asset.as_bytes().to_vec(),
        }),
    };

    v1::SubmitFastPayRequest {
        tx: Some(v1::FastPayTx {
            chain_id: Some(v1::ChainId { value: 1337 }),
            tempo_tx: Some(v1::TempoTxBytes {
                data: encode_payment_tempo_tx(sender, recipient, amount, asset),
            }),
            intent: Some(payment.clone()),
            nonce: Some(v1::Nonce2D {
                nonce_key_be: [0x5b; 32].to_vec(),
                nonce_seq: seq,
            }),
            expiry: Some(expiry),
            parent_qc_hash: Vec::new(),
            client_request_id: format!("req-{seq}"),
            tempo_tx_format: v1::TempoTxFormat::EvmOpaqueBytesV1 as i32,
            overlay: Some(v1::OverlayMetadata {
                payment: Some(payment),
            }),
        }),
        parent_qcs: Vec::new(),
    }
}

#[tokio::test]
async fn integration_single_payment() {
    let scenario = DemoScenario::new(1337, 1);
    let dave_transport = MockTransport::new(scenario.dave);
    let edgar_transport = MockTransport::new(scenario.edgar);
    let verify_ctx = build_verify_context(&dave_transport, &edgar_transport, 1).await;

    let mut alice = make_client(
        scenario.accounts.alice,
        dave_transport,
        edgar_transport,
        verify_ctx,
    );
    let qc = alice
        .send_payment(
            scenario.accounts.alice,
            scenario.accounts.bob,
            10,
            scenario.accounts.asset,
            Expiry::MaxBlockHeight(100),
        )
        .await
        .expect("single payment must succeed");
    assert!(qc.is_complete());
}

#[tokio::test]
async fn integration_chained_payment() {
    let scenario = DemoScenario::new(1337, 1);
    let dave_transport = MockTransport::new(scenario.dave);
    let edgar_transport = MockTransport::new(scenario.edgar);
    let verify_ctx = build_verify_context(&dave_transport, &edgar_transport, 1).await;
    let mut alice = make_client(
        scenario.accounts.alice,
        dave_transport.clone(),
        edgar_transport.clone(),
        verify_ctx.clone(),
    );
    let mut bob = make_client(
        scenario.accounts.bob,
        dave_transport,
        edgar_transport,
        verify_ctx,
    );

    let qc1 = alice
        .send_payment(
            scenario.accounts.alice,
            scenario.accounts.bob,
            10,
            scenario.accounts.asset,
            Expiry::MaxBlockHeight(100),
        )
        .await
        .unwrap();
    let tx_hash = *qc1.tx_hash();
    bob.import_proto_qc(tx_hash, alice.get_proto_qc(&tx_hash).unwrap().clone());

    let qc2 = bob
        .send_payment_with_parent(
            scenario.accounts.bob,
            scenario.accounts.carol,
            10,
            scenario.accounts.asset,
            Expiry::MaxBlockHeight(100),
            &qc1,
        )
        .await
        .expect("chained payment must succeed");
    assert!(qc2.is_complete());
}

#[tokio::test]
async fn integration_reject_insufficient_funds() {
    let scenario = DemoScenario::new(1337, 1);
    let dave_transport = MockTransport::new(scenario.dave);
    let edgar_transport = MockTransport::new(scenario.edgar);
    let verify_ctx = build_verify_context(&dave_transport, &edgar_transport, 1).await;
    let mut alice = make_client(
        scenario.accounts.alice,
        dave_transport,
        edgar_transport,
        verify_ctx,
    );

    let err = alice
        .send_payment(
            scenario.accounts.alice,
            scenario.accounts.bob,
            1_000,
            scenario.accounts.asset,
            Expiry::MaxBlockHeight(100),
        )
        .await
        .expect_err("must reject insufficient funds");
    assert!(matches!(err, FastPayClientError::Rejected { .. }));
}

#[test]
fn integration_reject_equivocation_attempt() {
    let scenario = DemoScenario::new(1337, 1);
    let mut dave = scenario.dave;
    let req1 = make_submit_request(
        scenario.accounts.alice,
        scenario.accounts.bob,
        10,
        scenario.accounts.asset,
        0,
        Expiry::MaxBlockHeight(100),
    );
    let req2 = make_submit_request(
        scenario.accounts.alice,
        scenario.accounts.carol,
        10,
        scenario.accounts.asset,
        0,
        Expiry::MaxBlockHeight(100),
    );
    let r1 = dave.submit_fastpay(req1);
    assert!(matches!(
        r1.result,
        Some(v1::submit_fast_pay_response::Result::Cert(_))
    ));
    let r2 = dave.submit_fastpay(req2);
    match r2.result {
        Some(v1::submit_fast_pay_response::Result::Reject(reject)) => {
            assert_eq!(reject.code, v1::RejectCode::Equivocation as i32)
        }
        _ => panic!("expected equivocation reject"),
    }
}

#[tokio::test]
async fn integration_reject_expired_transaction() {
    let scenario = DemoScenario::new(1337, 1);
    let dave_transport = MockTransport::new(scenario.dave);
    let edgar_transport = MockTransport::new(scenario.edgar);
    let verify_ctx = build_verify_context(&dave_transport, &edgar_transport, 1).await;
    let mut alice = make_client(
        scenario.accounts.alice,
        dave_transport,
        edgar_transport,
        verify_ctx,
    );
    let err = alice
        .send_payment(
            scenario.accounts.alice,
            scenario.accounts.bob,
            10,
            scenario.accounts.asset,
            Expiry::MaxBlockHeight(0),
        )
        .await
        .expect_err("must reject expired tx");
    assert!(matches!(err, FastPayClientError::Rejected { .. }));
}

#[tokio::test]
async fn integration_reject_invalid_parent_qc() {
    let scenario = DemoScenario::new(1337, 1);
    let dave_transport = MockTransport::new(scenario.dave);
    let edgar_transport = MockTransport::new(scenario.edgar);
    let verify_ctx = build_verify_context(&dave_transport, &edgar_transport, 1).await;
    let mut bob = make_client(
        scenario.accounts.bob,
        dave_transport,
        edgar_transport,
        verify_ctx,
    );

    let fake_qc = MultiCertQC::new(
        fastpay_types::TxHash::new([9; 32]),
        fastpay_types::EffectsHash::new([8; 32]),
        2,
        Vec::new(),
    );
    let err = bob
        .send_payment_with_parent(
            scenario.accounts.bob,
            scenario.accounts.carol,
            10,
            scenario.accounts.asset,
            Expiry::MaxBlockHeight(100),
            &fake_qc,
        )
        .await
        .expect_err("must reject missing parent proto qc");
    assert!(matches!(err, FastPayClientError::MissingParentProtoQc(_)));
}

#[test]
fn integration_reject_intent_mismatch() {
    let scenario = DemoScenario::new(1337, 1);
    let mut dave = scenario.dave;
    let mut req = make_submit_request(
        scenario.accounts.alice,
        scenario.accounts.bob,
        10,
        scenario.accounts.asset,
        0,
        Expiry::MaxBlockHeight(100),
    );
    if let Some(tx) = req.tx.as_mut() {
        if let Some(intent) = tx.intent.as_mut() {
            intent.amount = 99;
        }
    }
    let res = dave.submit_fastpay(req);
    match res.result {
        Some(v1::submit_fast_pay_response::Result::Reject(reject)) => {
            assert_eq!(reject.code, v1::RejectCode::InvalidFormat as i32);
        }
        _ => panic!("expected intent mismatch reject"),
    }
}

#[test]
fn integration_cert_dedupe_by_signer() {
    let scenario = DemoScenario::new(1337, 1);
    let mut dave = scenario.dave;
    let req = make_submit_request(
        scenario.accounts.alice,
        scenario.accounts.bob,
        10,
        scenario.accounts.asset,
        0,
        Expiry::MaxBlockHeight(100),
    );
    let first = dave.submit_fastpay(req.clone());
    assert!(matches!(
        first.result,
        Some(v1::submit_fast_pay_response::Result::Cert(_))
    ));
    let second = dave.submit_fastpay(req);
    assert!(matches!(
        second.result,
        Some(v1::submit_fast_pay_response::Result::Cert(_))
            | Some(v1::submit_fast_pay_response::Result::Reject(_))
    ));
    let bb = dave.get_bulletin_board(v1::GetBulletinBoardRequest::default());
    // Regardless of retries/re-submits, cert store should contain one cert from this signer.
    assert_eq!(bb.certs.len(), 1);
}

#[test]
fn integration_reject_unknown_validator_signer() {
    let signer = Ed25519Signer::from_seed(ValidatorId::new([0x11; 32]), [0x21; 32]);
    let sign_ctx = CertSigningContext {
        chain_id: 1337,
        domain_tag: "tempo.fastpay.cert.v1",
        protocol_version: 1,
        epoch: 1,
    };
    let tx_hash = fastpay_types::TxHash::new([1; 32]);
    let effects_hash = fastpay_types::EffectsHash::new([2; 32]);
    let cert = signer.sign(&sign_ctx, &tx_hash, &effects_hash).unwrap();
    let verify_ctx = VerificationContext {
        chain_id: 1337,
        domain_tag: "tempo.fastpay.cert.v1".to_string(),
        protocol_version: 1,
        epoch: 1,
        committee: HashMap::new(),
    };
    let mut mgr = CertManager::<_, _, SimpleAssembler>::new(verify_ctx, 2);
    let err = mgr
        .collect_certificate(tx_hash, effects_hash, cert)
        .expect_err("unknown signer must be rejected");
    assert!(matches!(err, CertManagerError::Crypto(_)));
}

#[test]
fn integration_reject_mixed_epoch_certs() {
    let signer = Ed25519Signer::from_seed(ValidatorId::new([0x11; 32]), [0x21; 32]);
    let tx_hash = fastpay_types::TxHash::new([1; 32]);
    let effects_hash = fastpay_types::EffectsHash::new([2; 32]);
    let cert = signer
        .sign(
            &CertSigningContext {
                chain_id: 1337,
                domain_tag: "tempo.fastpay.cert.v1",
                protocol_version: 1,
                epoch: 1,
            },
            &tx_hash,
            &effects_hash,
        )
        .unwrap();
    let mut committee = HashMap::new();
    committee.insert(ValidatorId::new([0x11; 32]), signer.public_key_bytes());
    let verify_ctx = VerificationContext {
        chain_id: 1337,
        domain_tag: "tempo.fastpay.cert.v1".to_string(),
        protocol_version: 1,
        epoch: 2,
        committee,
    };
    let mut mgr = CertManager::<_, _, SimpleAssembler>::new(verify_ctx, 2);
    let err = mgr
        .collect_certificate(tx_hash, effects_hash, cert)
        .expect_err("epoch mismatch must be rejected");
    assert!(matches!(err, CertManagerError::Crypto(_)));
}

#[test]
fn integration_conflicting_contention_domain() {
    let scenario = DemoScenario::new(1337, 1);
    let mut dave = scenario.dave;
    let req1 = make_submit_request(
        scenario.accounts.alice,
        scenario.accounts.bob,
        10,
        scenario.accounts.asset,
        0,
        Expiry::MaxBlockHeight(100),
    );
    let req2 = make_submit_request(
        scenario.accounts.alice,
        scenario.accounts.carol,
        10,
        scenario.accounts.asset,
        0,
        Expiry::MaxBlockHeight(100),
    );
    let _ = dave.submit_fastpay(req1);
    let second = dave.submit_fastpay(req2);
    match second.result {
        Some(v1::submit_fast_pay_response::Result::Reject(reject)) => {
            assert_eq!(reject.code, v1::RejectCode::Equivocation as i32)
        }
        _ => panic!("expected conflicting contention reject"),
    }
}

#[test]
fn integration_expiry_boundary_race() {
    let scenario = DemoScenario::new(1337, 1);
    let mut dave = scenario.dave;
    dave.set_chain_head(5, 0);
    let req = make_submit_request(
        scenario.accounts.alice,
        scenario.accounts.bob,
        10,
        scenario.accounts.asset,
        0,
        Expiry::MaxBlockHeight(5),
    );
    let res = dave.submit_fastpay(req);
    match res.result {
        Some(v1::submit_fast_pay_response::Result::Reject(reject)) => {
            assert_eq!(reject.code, v1::RejectCode::Expired as i32);
        }
        _ => panic!("expected expiry boundary reject"),
    }
}

#[test]
fn integration_bulletin_board_partial_sync_consistency() {
    let scenario = DemoScenario::new(1337, 1);
    let mut dave = scenario.dave;
    let req1 = make_submit_request(
        scenario.accounts.alice,
        scenario.accounts.bob,
        5,
        scenario.accounts.asset,
        0,
        Expiry::MaxBlockHeight(100),
    );
    let req2 = make_submit_request(
        scenario.accounts.alice,
        scenario.accounts.bob,
        4,
        scenario.accounts.asset,
        1,
        Expiry::MaxBlockHeight(100),
    );
    let _ = dave.submit_fastpay(req1);
    let _ = dave.submit_fastpay(req2);

    let full = dave.get_bulletin_board(v1::GetBulletinBoardRequest::default());
    let limited = dave.get_bulletin_board(v1::GetBulletinBoardRequest {
        limit: 1,
        ..Default::default()
    });
    assert!(!full.certs.is_empty());
    assert_eq!(limited.certs.len(), 1);
    assert_eq!(limited.certs[0], full.certs[0]);
}

#[test]
fn integration_crash_restart_preserves_nonce_reservation() {
    let mut wallet =
        WalletState::<MultiCertQC>::new(Address::new([0x01; 20]), CacheLimits::default());
    let key = NonceKey::new([0x5b; 32]);
    let seq = wallet.reserve_next_nonce(key);
    assert_eq!(seq, 0);

    let snapshot = wallet.snapshot();
    let journal = wallet.journal.clone();
    let mut recovered =
        WalletState::<MultiCertQC>::new(Address::new([0x01; 20]), CacheLimits::default());
    recovered.recover_from_snapshot_and_journal(snapshot, &journal);
    assert!(recovered.reserved_nonces.contains(&(key, 0)));
}

#[tokio::test]
async fn integration_full_demo_end_to_end() {
    let scenario = DemoScenario::new(1337, 1);
    let dave_transport = MockTransport::new(scenario.dave);
    let edgar_transport = MockTransport::new(scenario.edgar);
    let verify_ctx = build_verify_context(&dave_transport, &edgar_transport, 1).await;
    let mut alice = make_client(
        scenario.accounts.alice,
        dave_transport.clone(),
        edgar_transport.clone(),
        verify_ctx.clone(),
    );
    let mut bob = make_client(
        scenario.accounts.bob,
        dave_transport.clone(),
        edgar_transport.clone(),
        verify_ctx.clone(),
    );
    let mut carol = make_client(
        scenario.accounts.carol,
        dave_transport,
        edgar_transport,
        verify_ctx,
    );

    let qc1 = alice
        .send_payment(
            scenario.accounts.alice,
            scenario.accounts.bob,
            10,
            scenario.accounts.asset,
            Expiry::MaxBlockHeight(100),
        )
        .await
        .unwrap();
    let parent_tx = *qc1.tx_hash();
    bob.import_proto_qc(parent_tx, alice.get_proto_qc(&parent_tx).unwrap().clone());
    let _qc2 = bob
        .send_payment_with_parent(
            scenario.accounts.bob,
            scenario.accounts.carol,
            10,
            scenario.accounts.asset,
            Expiry::MaxBlockHeight(100),
            &qc1,
        )
        .await
        .unwrap();
    let certs = carol.poll_bulletin_board().await.unwrap();
    assert!(!certs.is_empty());
}
