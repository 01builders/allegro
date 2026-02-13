//! gRPC service implementation for FastPaySidecar.

use std::pin::Pin;
use std::sync::Arc;

use fastpay_proto::v1::{self, fast_pay_sidecar_server::FastPaySidecar};
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::state::SidecarState;

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

/// gRPC server for the FastPay validator sidecar.
pub struct FastPaySidecarService {
    state: Arc<SidecarState>,
}

impl FastPaySidecarService {
    pub fn new(state: Arc<SidecarState>) -> Self {
        Self { state }
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

        let resp = self.state.submit_fastpay(req);

        match &resp.result {
            Some(v1::submit_fast_pay_response::Result::Cert(cert)) => {
                info!(
                    tx_hash = hex::encode(&cert.tx_hash),
                    "SubmitFastPay: certified"
                );
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
        let resp = self.state.submit_fastpay(req);
        let chain_head = self.state.get_chain_head();

        let mut events: Vec<v1::SubmitFastPayEvent> = Vec::new();

        match resp.result {
            Some(v1::submit_fast_pay_response::Result::Cert(cert)) => {
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
