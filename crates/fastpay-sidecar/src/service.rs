//! gRPC service implementation for FastPaySidecar.

use std::pin::Pin;
use std::sync::Arc;

use fastpay_proto::v1::{self, fast_pay_sidecar_server::FastPaySidecar};
use fastpay_types::{Address, AssetId, NonceKey, TxHash};
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::reth::ForwardingInfo;
use crate::state::SidecarState;

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

/// gRPC server for the FastPay validator sidecar.
pub struct FastPaySidecarService {
    state: Arc<SidecarState>,
    reth_tx_sender: Option<mpsc::Sender<ForwardingInfo>>,
}

impl FastPaySidecarService {
    pub fn new(
        state: Arc<SidecarState>,
        reth_tx_sender: Option<mpsc::Sender<ForwardingInfo>>,
    ) -> Self {
        Self {
            state,
            reth_tx_sender,
        }
    }
}

#[tonic::async_trait]
impl FastPaySidecar for FastPaySidecarService {
    async fn submit_fast_pay(
        &self,
        request: Request<v1::SubmitFastPayRequest>,
    ) -> Result<Response<v1::SubmitFastPayResponse>, Status> {
        let req = request.into_inner();
        let tx_id = req
            .tx
            .as_ref()
            .map(|t| t.client_request_id.as_str())
            .unwrap_or("<none>");
        info!(request_id = tx_id, "SubmitFastPay");

        // Clone raw EVM tx bytes before submission (needed for forwarding).
        let raw_evm_tx = req
            .tx
            .as_ref()
            .and_then(|t| t.tempo_tx.as_ref())
            .map(|tt| tt.data.clone());

        let resp = self.state.submit_fastpay(req);

        match &resp.result {
            Some(v1::submit_fast_pay_response::Result::Cert(cert)) => {
                info!(
                    tx_hash = hex::encode(&cert.tx_hash),
                    "SubmitFastPay: certified"
                );
                // Forward to RETH if channel is available.
                if let Some(sender) = &self.reth_tx_sender {
                    if let Some(fwd) = build_forwarding_info(cert, raw_evm_tx.as_deref()) {
                        if let Err(e) = sender.try_send(fwd) {
                            warn!(error = %e, "failed to forward tx to RETH submission loop");
                        }
                    }
                }
            }
            Some(v1::submit_fast_pay_response::Result::Reject(reject)) => {
                warn!(
                    code = reject.code,
                    message = reject.message.as_str(),
                    "SubmitFastPay: rejected"
                );
            }
            None => {}
        }

        Ok(Response::new(resp))
    }

    type SubmitFastPayStreamStream = BoxStream<v1::SubmitFastPayEvent>;

    async fn submit_fast_pay_stream(
        &self,
        request: Request<v1::SubmitFastPayRequest>,
    ) -> Result<Response<Self::SubmitFastPayStreamStream>, Status> {
        let req = request.into_inner();

        // Clone raw EVM tx bytes before submission.
        let raw_evm_tx = req
            .tx
            .as_ref()
            .and_then(|t| t.tempo_tx.as_ref())
            .map(|tt| tt.data.clone());

        let resp = self.state.submit_fastpay(req);
        let chain_head = self.state.get_chain_head();

        let mut events: Vec<v1::SubmitFastPayEvent> = Vec::new();

        match resp.result {
            Some(v1::submit_fast_pay_response::Result::Cert(cert)) => {
                // Forward to RETH if channel is available.
                if let Some(sender) = &self.reth_tx_sender {
                    if let Some(fwd) = build_forwarding_info(&cert, raw_evm_tx.as_deref()) {
                        if let Err(e) = sender.try_send(fwd) {
                            warn!(error = %e, "failed to forward tx to RETH submission loop");
                        }
                    }
                }

                events.push(v1::SubmitFastPayEvent {
                    event: Some(v1::submit_fast_pay_event::Event::Lifecycle(
                        v1::TxLifecycleUpdate {
                            tx_hash: cert.tx_hash.clone(),
                            stage: v1::tx_lifecycle_update::Stage::Accepted as i32,
                            unix_millis: cert.created_unix_millis,
                            block_height: chain_head.block_height,
                        },
                    )),
                });
                events.push(v1::SubmitFastPayEvent {
                    event: Some(v1::submit_fast_pay_event::Event::Cert(cert.clone())),
                });
                events.push(v1::SubmitFastPayEvent {
                    event: Some(v1::submit_fast_pay_event::Event::Lifecycle(
                        v1::TxLifecycleUpdate {
                            tx_hash: cert.tx_hash,
                            stage: v1::tx_lifecycle_update::Stage::Certified as i32,
                            unix_millis: cert.created_unix_millis,
                            block_height: chain_head.block_height,
                        },
                    )),
                });
            }
            Some(v1::submit_fast_pay_response::Result::Reject(reject)) => {
                events.push(v1::SubmitFastPayEvent {
                    event: Some(v1::submit_fast_pay_event::Event::Reject(reject)),
                });
            }
            None => {
                return Err(Status::internal("empty result"));
            }
        }

        let stream = tokio_stream::iter(events.into_iter().map(Ok));
        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_bulletin_board(
        &self,
        request: Request<v1::GetBulletinBoardRequest>,
    ) -> Result<Response<v1::GetBulletinBoardResponse>, Status> {
        let req = request.into_inner();
        let resp = self.state.get_bulletin_board(req);
        info!(cert_count = resp.certs.len(), "GetBulletinBoard");
        Ok(Response::new(resp))
    }

    async fn get_validator_info(
        &self,
        _request: Request<v1::GetValidatorInfoRequest>,
    ) -> Result<Response<v1::GetValidatorInfoResponse>, Status> {
        let resp = self.state.get_validator_info();
        Ok(Response::new(resp))
    }

    async fn get_chain_head(
        &self,
        _request: Request<v1::GetChainHeadRequest>,
    ) -> Result<Response<v1::GetChainHeadResponse>, Status> {
        let resp = self.state.get_chain_head();
        Ok(Response::new(resp))
    }
}

/// Build a `ForwardingInfo` from a validator certificate and raw EVM tx bytes.
/// Returns `None` if the cert is missing required fields.
fn build_forwarding_info(
    cert: &v1::ValidatorCertificate,
    raw_evm_tx: Option<&[u8]>,
) -> Option<ForwardingInfo> {
    let raw = raw_evm_tx?;
    let effects = cert.effects.as_ref()?;
    let sender = Address::from_slice(&effects.sender.as_ref()?.data).ok()?;
    let recipient = Address::from_slice(&effects.recipient.as_ref()?.data).ok()?;
    let asset = AssetId::from_slice(&effects.asset.as_ref()?.data).ok()?;
    let nonce = effects.nonce.as_ref()?;
    let nonce_key = NonceKey::from_slice(&nonce.nonce_key_be).ok()?;
    let fastpay_tx_hash = TxHash::from_slice(&cert.tx_hash).ok()?;

    Some(ForwardingInfo {
        raw_evm_tx: raw.to_vec(),
        fastpay_tx_hash,
        sender,
        recipient,
        amount: effects.amount,
        asset,
        nonce_key,
        nonce_seq: nonce.nonce_seq,
    })
}
