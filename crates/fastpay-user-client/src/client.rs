//! FastPayClient: high-level facade for send, poll, and reconcile workflows.

use std::collections::HashMap;

use alloy_signer_local::PrivateKeySigner;
use fastpay_crypto::{compute_qc_hash, Ed25519Certificate};
use fastpay_proto::v1;
use fastpay_types::{Certificate, NonceKey, QuorumAssembler, QuorumCert, TxHash, ValidationError};
use thiserror::Error;

use crate::{
    cert_manager::{CertManager, CertManagerError},
    transport::{
        MultiValidatorTransport, RequestMeta, RetryPolicy, SidecarTransport, TransportError,
    },
    tx_builder::{TxBuilder, TxBuilderError},
    wallet::{PendingStatus, PendingTx, WalletError, WalletState},
};

/// High-level client facade errors.
#[derive(Debug, Error)]
pub enum FastPayClientError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Builder(#[from] TxBuilderError),
    #[error(transparent)]
    CertManager(#[from] CertManagerError),
    #[error(transparent)]
    Wallet(#[from] WalletError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error("validator rejected request: code={code}, message={message}")]
    Rejected { code: i32, message: String },
    #[error("not enough certificates to reach threshold {threshold}; have {have}")]
    ThresholdNotMet { threshold: u32, have: usize },
    #[error("missing parent proto qc for tx {0}")]
    MissingParentProtoQc(TxHash),
    #[error("missing sender private key for address {0}")]
    MissingSenderPrivateKey(fastpay_types::Address),
}

/// High-level FastPay client that coordinates tx building, transport fan-out,
/// cert collection, QC assembly, and wallet bookkeeping.
pub struct FastPayClient<T, C, Q, A>
where
    T: SidecarTransport + Clone,
    C: Certificate + Clone,
    Q: QuorumCert<Cert = C> + Clone,
    A: QuorumAssembler<Cert = C, QC = Q>,
{
    transport: MultiValidatorTransport<T>,
    pub wallet: WalletState<Q>,
    pub cert_manager: CertManager<C, Q, A>,
    chain_id: u64,
    threshold: u32,
    default_nonce_key: NonceKey,
    cert_parser: fn(v1::ValidatorCertificate) -> Result<C, FastPayClientError>,
    proto_qcs: HashMap<TxHash, v1::QuorumCertificate>,
    sender_private_keys: HashMap<fastpay_types::Address, [u8; 32]>,
}

impl<T, C, Q, A> FastPayClient<T, C, Q, A>
where
    T: SidecarTransport + Clone,
    C: Certificate + Clone,
    Q: QuorumCert<Cert = C> + Clone,
    A: QuorumAssembler<Cert = C, QC = Q>,
{
    pub fn new(
        transport: MultiValidatorTransport<T>,
        wallet: WalletState<Q>,
        cert_manager: CertManager<C, Q, A>,
        chain_id: u64,
        threshold: u32,
        default_nonce_key: NonceKey,
        cert_parser: fn(v1::ValidatorCertificate) -> Result<C, FastPayClientError>,
    ) -> Self {
        Self {
            transport,
            wallet,
            cert_manager,
            chain_id,
            threshold,
            default_nonce_key,
            cert_parser,
            proto_qcs: HashMap::new(),
            sender_private_keys: HashMap::new(),
        }
    }

    pub fn with_sender_private_key(
        mut self,
        sender: fastpay_types::Address,
        private_key: [u8; 32],
    ) -> Result<Self, FastPayClientError> {
        let signer = PrivateKeySigner::from_slice(&private_key)
            .map_err(|err| FastPayClientError::Builder(TxBuilderError::Signing(err.to_string())))?;
        if signer.address().as_slice() != sender.as_bytes() {
            return Err(FastPayClientError::Builder(TxBuilderError::Signing(
                "sender private key does not match sender address".to_string(),
            )));
        }
        self.sender_private_keys.insert(sender, private_key);
        Ok(self)
    }

    pub async fn send_payment(
        &mut self,
        sender: fastpay_types::Address,
        recipient: fastpay_types::Address,
        amount: u64,
        asset: fastpay_types::AssetId,
        expiry: fastpay_types::Expiry,
    ) -> Result<Q, FastPayClientError> {
        self.send_payment_internal(sender, recipient, amount, asset, expiry, None)
            .await
    }

    pub async fn send_payment_with_parent(
        &mut self,
        sender: fastpay_types::Address,
        recipient: fastpay_types::Address,
        amount: u64,
        asset: fastpay_types::AssetId,
        expiry: fastpay_types::Expiry,
        parent_qc: &Q,
    ) -> Result<Q, FastPayClientError> {
        let parent_proto = self.proto_qcs.get(parent_qc.tx_hash()).cloned().ok_or(
            FastPayClientError::MissingParentProtoQc(*parent_qc.tx_hash()),
        )?;
        self.send_payment_internal(
            sender,
            recipient,
            amount,
            asset,
            expiry,
            Some((parent_qc.clone(), parent_proto)),
        )
        .await
    }

    pub async fn poll_bulletin_board(
        &mut self,
    ) -> Result<Vec<v1::ValidatorCertificate>, FastPayClientError> {
        let responses = self
            .transport
            .get_bulletin_board_all(v1::GetBulletinBoardRequest::default())
            .await;
        let mut merged = Vec::new();
        for response in responses {
            let response = response?;
            for cert in response.certs {
                merged.push(cert);
            }
        }
        Ok(merged)
    }

    pub fn assemble_qc(
        &mut self,
        tx_hash: TxHash,
        effects_hash: fastpay_types::EffectsHash,
    ) -> Result<Q, FastPayClientError> {
        Ok(self.cert_manager.assemble_qc(tx_hash, effects_hash)?)
    }

    pub async fn reconcile_once(&mut self) -> Result<(), FastPayClientError> {
        let responses = self.transport.get_chain_head_all().await;
        let has_chain_head = responses.into_iter().any(|resp| resp.is_ok());
        if has_chain_head {
            let to_settle: Vec<TxHash> = self
                .wallet
                .pending_txs
                .iter()
                .filter_map(|(tx_hash, pending)| {
                    if pending.status == PendingStatus::Pending
                        && self.wallet.qcs.contains_key(tx_hash)
                    {
                        Some(*tx_hash)
                    } else {
                        None
                    }
                })
                .collect();
            for tx_hash in to_settle {
                self.wallet.mark_pending_settled(tx_hash)?;
            }
        }
        self.wallet.prune_caches();
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn reconciliation_loop(
        &mut self,
        iterations: u32,
        interval_ms: u64,
    ) -> Result<(), FastPayClientError> {
        for _ in 0..iterations {
            self.reconcile_once().await?;
            tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
        }
        Ok(())
    }

    pub fn get_proto_qc(&self, tx_hash: &TxHash) -> Option<&v1::QuorumCertificate> {
        self.proto_qcs.get(tx_hash)
    }

    pub fn import_proto_qc(&mut self, tx_hash: TxHash, proto_qc: v1::QuorumCertificate) {
        self.proto_qcs.insert(tx_hash, proto_qc);
    }

    async fn send_payment_internal(
        &mut self,
        sender: fastpay_types::Address,
        recipient: fastpay_types::Address,
        amount: u64,
        asset: fastpay_types::AssetId,
        expiry: fastpay_types::Expiry,
        parent: Option<(Q, v1::QuorumCertificate)>,
    ) -> Result<Q, FastPayClientError> {
        let seq = self.wallet.reserve_next_nonce(self.default_nonce_key);
        let sender_private_key = self
            .sender_private_keys
            .get(&sender)
            .copied()
            .ok_or(FastPayClientError::MissingSenderPrivateKey(sender))?;

        let mut builder = TxBuilder::new(self.chain_id)
            .with_payment(sender, recipient, amount, asset)
            .with_sender_private_key(sender_private_key)
            .with_nonce_seq(self.default_nonce_key, seq)
            .with_expiry(expiry);
        let parent_proto_qc = if let Some((parent_qc, parent_proto)) = parent {
            builder = builder.with_parent_qc(&parent_qc);
            Some(parent_proto)
        } else {
            None
        };
        let built = builder.build()?;

        self.wallet.add_pending_tx(PendingTx {
            tx_hash: built.tx_hash,
            asset,
            amount,
            nonce_key: self.default_nonce_key,
            nonce_seq: seq,
            created_at: 0,
            status: PendingStatus::Pending,
        });
        self.wallet
            .apply_pending_adjustment(asset, -(amount as i64));

        let request = v1::SubmitFastPayRequest {
            tx: Some(built.tx.clone()),
            parent_qcs: parent_proto_qc.into_iter().collect(),
        };
        let responses = self
            .transport
            .submit_fastpay_all(
                request,
                RequestMeta {
                    client_request_id: built.tx.client_request_id.clone(),
                    timeout_ms: 3_000,
                    retry_policy: RetryPolicy::default(),
                },
            )
            .await;

        let mut successful_proto_certs = Vec::new();
        let mut have = 0usize;
        let mut last_reject: Option<FastPayClientError> = None;
        for result in responses {
            match result {
                Ok(resp) => match resp.result {
                    Some(v1::submit_fast_pay_response::Result::Cert(proto_cert)) => {
                        let domain_cert = (self.cert_parser)(proto_cert.clone())?;
                        self.cert_manager.collect_certificate(
                            built.tx_hash,
                            built.effects_hash,
                            domain_cert,
                        )?;
                        self.wallet.record_certificate(
                            built.tx_hash,
                            (self.cert_parser)(proto_cert.clone())?,
                        );
                        successful_proto_certs.push(proto_cert);
                        have += 1;
                    }
                    Some(v1::submit_fast_pay_response::Result::Reject(reject)) => {
                        last_reject = Some(FastPayClientError::Rejected {
                            code: reject.code,
                            message: reject.message,
                        });
                    }
                    None => {
                        last_reject = Some(FastPayClientError::Transport(
                            TransportError::Internal("missing submit result".to_string()),
                        ));
                    }
                },
                Err(err) => {
                    last_reject = Some(FastPayClientError::Transport(err));
                }
            }
        }

        if have < self.threshold as usize {
            self.wallet
                .release_reserved_nonce(self.default_nonce_key, seq)?;
            return Err(last_reject.unwrap_or(FastPayClientError::ThresholdNotMet {
                threshold: self.threshold,
                have,
            }));
        }

        let qc = self
            .cert_manager
            .assemble_qc(built.tx_hash, built.effects_hash)?;
        self.wallet.record_qc(qc.clone());
        self.wallet
            .commit_reserved_nonce(self.default_nonce_key, seq)?;

        let proto_qc = v1::QuorumCertificate {
            tx_hash: built.tx_hash.as_bytes().to_vec(),
            effects_hash: built.effects_hash.as_bytes().to_vec(),
            certs: successful_proto_certs,
            threshold: self.threshold,
            qc_hash: qc.qc_hash().as_bytes().to_vec(),
        };
        self.proto_qcs.insert(built.tx_hash, proto_qc);
        Ok(qc)
    }
}

pub fn parse_ed25519_proto_cert(
    proto_cert: v1::ValidatorCertificate,
) -> Result<Ed25519Certificate, FastPayClientError> {
    let signer = proto_cert.signer.ok_or(FastPayClientError::Validation(
        ValidationError::MissingField("signer"),
    ))?;
    let signer_id = fastpay_types::ValidatorId::from_slice(&signer.id)?;
    let tx_hash = fastpay_types::TxHash::from_slice(&proto_cert.tx_hash)?;
    let effects_hash = fastpay_types::EffectsHash::from_slice(&proto_cert.effects_hash)?;
    Ok(Ed25519Certificate::new(
        tx_hash,
        effects_hash,
        signer_id,
        proto_cert.signature,
        proto_cert.created_unix_millis,
    )?)
}

pub fn build_proto_qc_from_domain<Q>(qc: &Q) -> v1::QuorumCertificate
where
    Q: QuorumCert<Cert = Ed25519Certificate>,
{
    let certs = qc
        .certificates()
        .iter()
        .map(|cert| v1::ValidatorCertificate {
            signer: Some(v1::ValidatorId {
                name: String::new(),
                id: cert.signer().as_bytes().to_vec(),
                pubkey: Vec::new(),
            }),
            tx_hash: cert.tx_hash().as_bytes().to_vec(),
            effects_hash: cert.effects_hash().as_bytes().to_vec(),
            effects: None,
            signature: cert.signature_bytes().to_vec(),
            created_unix_millis: cert.created_at(),
        })
        .collect();
    let qc_hash = compute_qc_hash(
        qc.tx_hash(),
        qc.effects_hash(),
        qc.threshold(),
        qc.certificates(),
    );
    v1::QuorumCertificate {
        tx_hash: qc.tx_hash().as_bytes().to_vec(),
        effects_hash: qc.effects_hash().as_bytes().to_vec(),
        certs,
        threshold: qc.threshold(),
        qc_hash: qc_hash.as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use fastpay_crypto::{MultiCertQC, SimpleAssembler};
    use fastpay_sidecar_mock::DemoScenario;
    use fastpay_types::{Expiry, NonceKey, QuorumCert, ValidatorId, VerificationContext};

    use super::{parse_ed25519_proto_cert, FastPayClient};
    use crate::{
        cert_manager::CertManager,
        transport::{MockTransport, MultiValidatorTransport},
        wallet::{PendingStatus, WalletState},
    };

    fn make_client() -> FastPayClient<
        MockTransport,
        fastpay_crypto::Ed25519Certificate,
        MultiCertQC,
        SimpleAssembler,
    > {
        let scenario = DemoScenario::new(1337, 1);
        let dave_info = scenario.dave.get_validator_info().validator.unwrap();
        let edgar_info = scenario.edgar.get_validator_info().validator.unwrap();
        let mut committee = HashMap::new();
        committee.insert(
            ValidatorId::from_slice(&dave_info.id).unwrap(),
            dave_info.pubkey.as_slice().try_into().unwrap(),
        );
        committee.insert(
            ValidatorId::from_slice(&edgar_info.id).unwrap(),
            edgar_info.pubkey.as_slice().try_into().unwrap(),
        );
        let verify_ctx = VerificationContext {
            chain_id: 1337,
            domain_tag: "tempo.fastpay.cert.v1".to_string(),
            protocol_version: 1,
            epoch: 1,
            committee,
        };

        let transport = MultiValidatorTransport::new(vec![
            MockTransport::new(scenario.dave),
            MockTransport::new(scenario.edgar),
        ]);
        let accounts = scenario.accounts;
        let account_keys = scenario.account_keys;
        let wallet = WalletState::<MultiCertQC>::new(accounts.alice, crate::CacheLimits::default());
        let cert_manager = CertManager::<_, _, SimpleAssembler>::new(verify_ctx, 2);
        FastPayClient::new(
            transport,
            wallet,
            cert_manager,
            1337,
            2,
            NonceKey::new([0x5b; 32]),
            parse_ed25519_proto_cert,
        )
        .with_sender_private_key(accounts.alice, account_keys.alice)
        .expect("valid sender key")
    }

    #[tokio::test]
    async fn send_payment_success() {
        let mut client = make_client();
        let scenario = DemoScenario::new(1337, 1);
        let qc = client
            .send_payment(
                scenario.accounts.alice,
                scenario.accounts.bob,
                10,
                scenario.accounts.asset,
                Expiry::MaxBlockHeight(100),
            )
            .await
            .expect("send payment should succeed");
        assert!(qc.is_complete());
    }

    #[tokio::test]
    async fn reconcile_marks_qc_backed_pending_as_settled() {
        let mut client = make_client();
        let scenario = DemoScenario::new(1337, 1);
        let qc = client
            .send_payment(
                scenario.accounts.alice,
                scenario.accounts.bob,
                10,
                scenario.accounts.asset,
                Expiry::MaxBlockHeight(100),
            )
            .await
            .expect("send payment should succeed");
        assert_eq!(
            client
                .wallet
                .pending_txs
                .get(qc.tx_hash())
                .expect("pending tx should exist before reconciliation")
                .status,
            PendingStatus::Pending
        );

        client
            .reconcile_once()
            .await
            .expect("reconciliation should succeed");
        assert_eq!(
            client
                .wallet
                .pending_txs
                .get(qc.tx_hash())
                .expect("pending tx should remain tracked after settlement")
                .status,
            PendingStatus::Settled
        );
    }

    #[tokio::test]
    async fn reconcile_prunes_settled_when_cache_limit_reached() {
        let mut client = make_client();
        let scenario = DemoScenario::new(1337, 1);
        client.wallet.cache_limits.max_pending_txs = 0;
        let qc = client
            .send_payment(
                scenario.accounts.alice,
                scenario.accounts.bob,
                10,
                scenario.accounts.asset,
                Expiry::MaxBlockHeight(100),
            )
            .await
            .expect("send payment should succeed");
        assert!(client.wallet.pending_txs.contains_key(qc.tx_hash()));

        client
            .reconcile_once()
            .await
            .expect("reconciliation should succeed");
        assert!(
            !client.wallet.pending_txs.contains_key(qc.tx_hash()),
            "settled entries should be pruned when pending cache limit is zero"
        );
    }
}
