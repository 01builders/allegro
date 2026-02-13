use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fastpay_proto::v1;
use fastpay_sidecar_mock::MockSidecar;
use futures::future::join_all;
use rand::Rng;
use thiserror::Error;

/// Per-request metadata used for idempotent retries and deadline control.
#[derive(Debug, Clone)]
pub struct RequestMeta {
    pub client_request_id: String,
    pub timeout_ms: u64,
    pub retry_policy: RetryPolicy,
}

/// Retry behavior for transport operations.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub jitter_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 2,
            initial_backoff_ms: 50,
            max_backoff_ms: 500,
            jitter_ms: 20,
        }
    }
}

/// Validator endpoint configuration.
#[derive(Debug, Clone)]
pub struct ValidatorEndpoint {
    pub name: String,
    pub url: String,
}

/// Transport configuration shared by sidecar clients.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub validators: Vec<ValidatorEndpoint>,
    pub request_timeout_ms: u64,
    pub retry_policy: RetryPolicy,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            validators: Vec::new(),
            request_timeout_ms: 3_000,
            retry_policy: RetryPolicy::default(),
        }
    }
}

/// Error model for transport operations.
#[derive(Debug, Error, Clone)]
pub enum TransportError {
    #[error("request timed out")]
    Timeout,
    #[error("sidecar unavailable: {0}")]
    Unavailable(String),
    #[error("request rejected: code={code}, message={message}")]
    Rejected { code: i32, message: String },
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("internal transport error: {0}")]
    Internal(String),
}

impl TransportError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Timeout | Self::Unavailable(_))
    }
}

/// Sidecar transport interface. Implementations may use in-memory mocks, gRPC, or grpc-web.
#[async_trait(?Send)]
pub trait SidecarTransport {
    async fn submit_fastpay(
        &self,
        request: v1::SubmitFastPayRequest,
        meta: RequestMeta,
    ) -> Result<v1::SubmitFastPayResponse, TransportError>;

    async fn get_bulletin_board(
        &self,
        request: v1::GetBulletinBoardRequest,
    ) -> Result<v1::GetBulletinBoardResponse, TransportError>;

    async fn get_validator_info(
        &self,
    ) -> Result<v1::GetValidatorInfoResponse, TransportError>;

    async fn get_chain_head(&self) -> Result<v1::GetChainHeadResponse, TransportError>;
}

/// In-memory transport backed by `MockSidecar`, used for Phase 1 and tests.
#[derive(Clone)]
pub struct MockTransport {
    sidecar: Arc<Mutex<MockSidecar>>,
}

impl MockTransport {
    pub fn new(sidecar: MockSidecar) -> Self {
        Self {
            sidecar: Arc::new(Mutex::new(sidecar)),
        }
    }

    fn with_sidecar<R>(
        &self,
        f: impl FnOnce(&mut MockSidecar) -> R,
    ) -> Result<R, TransportError> {
        let mut lock = self
            .sidecar
            .lock()
            .map_err(|_| TransportError::Unavailable("mutex poisoned".to_string()))?;
        Ok(f(&mut lock))
    }
}

#[async_trait(?Send)]
impl SidecarTransport for MockTransport {
    async fn submit_fastpay(
        &self,
        request: v1::SubmitFastPayRequest,
        meta: RequestMeta,
    ) -> Result<v1::SubmitFastPayResponse, TransportError> {
        retry_with_backoff(meta, || async {
            self.with_sidecar(|sidecar| sidecar.submit_fastpay(request.clone()))
        })
        .await
    }

    async fn get_bulletin_board(
        &self,
        request: v1::GetBulletinBoardRequest,
    ) -> Result<v1::GetBulletinBoardResponse, TransportError> {
        self.with_sidecar(|sidecar| sidecar.get_bulletin_board(request))
    }

    async fn get_validator_info(
        &self,
    ) -> Result<v1::GetValidatorInfoResponse, TransportError> {
        self.with_sidecar(|sidecar| sidecar.get_validator_info())
    }

    async fn get_chain_head(&self) -> Result<v1::GetChainHeadResponse, TransportError> {
        self.with_sidecar(|sidecar| sidecar.get_chain_head())
    }
}

/// Fan-out wrapper that submits the same request to multiple validators in parallel.
#[derive(Clone)]
pub struct MultiValidatorTransport<T: SidecarTransport + Clone> {
    validators: Vec<T>,
}

impl<T: SidecarTransport + Clone> MultiValidatorTransport<T> {
    pub fn new(validators: Vec<T>) -> Self {
        Self { validators }
    }

    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    pub async fn submit_fastpay_all(
        &self,
        request: v1::SubmitFastPayRequest,
        meta: RequestMeta,
    ) -> Vec<Result<v1::SubmitFastPayResponse, TransportError>> {
        join_all(
            self.validators
                .iter()
                .map(|transport| transport.submit_fastpay(request.clone(), meta.clone())),
        )
        .await
    }

    pub async fn get_bulletin_board_all(
        &self,
        request: v1::GetBulletinBoardRequest,
    ) -> Vec<Result<v1::GetBulletinBoardResponse, TransportError>> {
        join_all(
            self.validators
                .iter()
                .map(|transport| transport.get_bulletin_board(request.clone())),
        )
        .await
    }

    pub async fn get_chain_head_all(
        &self,
    ) -> Vec<Result<v1::GetChainHeadResponse, TransportError>> {
        join_all(
            self.validators
                .iter()
                .map(|transport| transport.get_chain_head()),
        )
        .await
    }
}

pub async fn retry_with_backoff<T, F, Fut>(
    meta: RequestMeta,
    mut op: F,
) -> Result<T, TransportError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, TransportError>>,
{
    let deadline = Instant::now() + Duration::from_millis(meta.timeout_ms);
    let mut attempt = 0u32;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if !err.is_retryable() {
                    return Err(err);
                }
                if attempt >= meta.retry_policy.max_retries {
                    return Err(err);
                }
                let now = Instant::now();
                if now >= deadline {
                    return Err(TransportError::Timeout);
                }

                let delay = backoff_delay_ms(attempt, &meta.retry_policy);
                attempt += 1;
                let remaining = deadline.saturating_duration_since(now).as_millis() as u64;
                if delay > remaining {
                    return Err(TransportError::Timeout);
                }
                sleep_millis(delay).await;
            }
        }
    }
}

fn backoff_delay_ms(attempt: u32, policy: &RetryPolicy) -> u64 {
    let exp = policy.initial_backoff_ms.saturating_mul(2u64.saturating_pow(attempt));
    let capped = exp.min(policy.max_backoff_ms);
    let jitter = if policy.jitter_ms == 0 {
        0
    } else {
        rand::thread_rng().gen_range(0..=policy.jitter_ms)
    };
    capped.saturating_add(jitter)
}

async fn sleep_millis(ms: u64) {
    #[cfg(not(target_arch = "wasm32"))]
    tokio::time::sleep(Duration::from_millis(ms)).await;

    #[cfg(target_arch = "wasm32")]
    {
        let _ = ms;
        futures::future::ready(()).await;
    }
}

#[cfg(test)]
mod tests {
    use fastpay_sidecar_mock::DemoScenario;

    use super::{MockTransport, MultiValidatorTransport, RequestMeta, RetryPolicy, SidecarTransport};

    fn make_transport() -> MockTransport {
        let scenario = DemoScenario::new(1337, 1);
        MockTransport::new(scenario.dave)
    }

    #[tokio::test]
    async fn multi_validator_submit_runs_in_parallel_shape() {
        let t1 = make_transport();
        let t2 = make_transport();
        let multi = MultiValidatorTransport::new(vec![t1, t2]);
        let req = fastpay_proto::v1::SubmitFastPayRequest::default();
        let results = multi
            .submit_fastpay_all(
                req,
                RequestMeta {
                    client_request_id: "req-1".to_string(),
                    timeout_ms: 100,
                    retry_policy: RetryPolicy::default(),
                },
            )
            .await;
        assert_eq!(results.len(), 2);
        for result in results {
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn get_validator_info_works() {
        let transport = make_transport();
        let info = transport.get_validator_info().await.expect("must succeed");
        assert!(info.validator.is_some());
    }
}
