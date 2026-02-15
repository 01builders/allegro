use std::time::Duration;

use fastpay_proto::v1;
use futures::future::join_all;
use tonic::Code;

#[derive(Debug, Clone)]
pub struct SidecarEndpoint {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub endpoints: Vec<SidecarEndpoint>,
    pub timeout_ms: u64,
    pub pull_limit: u32,
}

pub type UpstreamResult<T> = (SidecarEndpoint, Result<T, tonic::Status>);

pub async fn fanout_get_bulletin_board(
    config: &UpstreamConfig,
    mut request: v1::GetBulletinBoardRequest,
) -> Vec<UpstreamResult<v1::GetBulletinBoardResponse>> {
    if request.limit == 0 || request.limit > config.pull_limit {
        request.limit = config.pull_limit;
    }

    let calls = config.endpoints.iter().map(|endpoint| {
        let endpoint = endpoint.clone();
        let req = request.clone();
        let timeout_ms = config.timeout_ms;
        async move {
            let result = tokio::time::timeout(Duration::from_millis(timeout_ms), async {
                let mut client = v1::fast_pay_sidecar_client::FastPaySidecarClient::connect(
                    endpoint.url.clone(),
                )
                .await
                .map_err(map_connect_error)?;
                client
                    .get_bulletin_board(req)
                    .await
                    .map(|resp| resp.into_inner())
                    .map_err(map_status_error)
            })
            .await;

            let outcome = match result {
                Ok(inner) => inner,
                Err(_) => Err(tonic::Status::new(
                    Code::DeadlineExceeded,
                    format!("upstream {} timed out", endpoint.name),
                )),
            };
            (endpoint, outcome)
        }
    });

    join_all(calls).await
}

pub async fn fanout_get_chain_head(
    config: &UpstreamConfig,
) -> Vec<UpstreamResult<v1::GetChainHeadResponse>> {
    let calls = config.endpoints.iter().map(|endpoint| {
        let endpoint = endpoint.clone();
        let timeout_ms = config.timeout_ms;
        async move {
            let result = tokio::time::timeout(Duration::from_millis(timeout_ms), async {
                let mut client = v1::fast_pay_sidecar_client::FastPaySidecarClient::connect(
                    endpoint.url.clone(),
                )
                .await
                .map_err(map_connect_error)?;
                client
                    .get_chain_head(v1::GetChainHeadRequest {})
                    .await
                    .map(|resp| resp.into_inner())
                    .map_err(map_status_error)
            })
            .await;

            let outcome = match result {
                Ok(inner) => inner,
                Err(_) => Err(tonic::Status::new(
                    Code::DeadlineExceeded,
                    format!("upstream {} timed out", endpoint.name),
                )),
            };
            (endpoint, outcome)
        }
    });

    join_all(calls).await
}

pub async fn fanout_submit_fastpay(
    config: &UpstreamConfig,
    request: v1::SubmitFastPayRequest,
) -> Vec<UpstreamResult<v1::SubmitFastPayResponse>> {
    let calls = config.endpoints.iter().map(|endpoint| {
        let endpoint = endpoint.clone();
        let req = request.clone();
        let timeout_ms = config.timeout_ms;
        async move {
            let result = tokio::time::timeout(Duration::from_millis(timeout_ms), async {
                let mut client = v1::fast_pay_sidecar_client::FastPaySidecarClient::connect(
                    endpoint.url.clone(),
                )
                .await
                .map_err(map_connect_error)?;
                client
                    .submit_fast_pay(req)
                    .await
                    .map(|resp| resp.into_inner())
                    .map_err(map_status_error)
            })
            .await;

            let outcome = match result {
                Ok(inner) => inner,
                Err(_) => Err(tonic::Status::new(
                    Code::DeadlineExceeded,
                    format!("upstream {} timed out", endpoint.name),
                )),
            };
            (endpoint, outcome)
        }
    });

    join_all(calls).await
}

fn map_connect_error(err: tonic::transport::Error) -> tonic::Status {
    tonic::Status::new(Code::Unavailable, err.to_string())
}

fn map_status_error(err: tonic::Status) -> tonic::Status {
    err
}
