use std::sync::Arc;

use fastpay_crypto::compute_qc_hash;
use fastpay_proto::v1::{self, fast_pay_aggregator_server::FastPayAggregator};
use fastpay_types::{Certificate, CryptoError, EffectsHash, TxHash, ValidationError, ValidatorId};
use tonic::{Request, Response, Status};
use tracing::warn;

use crate::state::{
    compare_chain_head, effects_hash_from_cert, signer_from_cert, tx_hash_from_cert,
    FastPayBackendState,
};
use crate::upstream::{
    fanout_get_bulletin_board, fanout_get_chain_head, fanout_submit_fastpay, UpstreamConfig,
};

pub struct FastPayBackendService {
    pub state: Arc<FastPayBackendState>,
    pub upstream: UpstreamConfig,
    pub qc_threshold: u32,
}

#[tonic::async_trait]
impl FastPayAggregator for FastPayBackendService {
    async fn submit_fast_pay(
        &self,
        request: Request<v1::SubmitFastPayRequest>,
    ) -> Result<Response<v1::SubmitFastPayFanoutResponse>, Status> {
        let req = request.into_inner();
        if req.tx.is_none() {
            return Err(Status::invalid_argument("missing tx"));
        }

        let upstream_results = fanout_submit_fastpay(&self.upstream, req).await;

        let mut certs = Vec::new();
        let mut rejects = Vec::new();
        let mut tx_hash = Vec::new();
        let mut effects_hash = Vec::new();

        for (endpoint, result) in upstream_results {
            match result {
                Ok(response) => match response.result {
                    Some(v1::submit_fast_pay_response::Result::Cert(cert)) => {
                        if tx_hash.is_empty() {
                            tx_hash = cert.tx_hash.clone();
                        }
                        if effects_hash.is_empty() {
                            effects_hash = cert.effects_hash.clone();
                        }
                        certs.push(cert);
                    }
                    Some(v1::submit_fast_pay_response::Result::Reject(reject)) => {
                        rejects.push(v1::ValidatorReject {
                            validator: Some(v1::ValidatorId {
                                name: endpoint.name,
                                id: Vec::new(),
                                pubkey: Vec::new(),
                            }),
                            reject: Some(reject),
                        });
                    }
                    None => rejects.push(v1::ValidatorReject {
                        validator: Some(v1::ValidatorId {
                            name: endpoint.name,
                            id: Vec::new(),
                            pubkey: Vec::new(),
                        }),
                        reject: Some(v1::RejectReason {
                            code: v1::RejectCode::TemporaryUnavailable as i32,
                            message: "empty upstream response".to_string(),
                        }),
                    }),
                },
                Err(err) => {
                    warn!(endpoint = endpoint.name.as_str(), error = %err, "upstream submit failed");
                    rejects.push(v1::ValidatorReject {
                        validator: Some(v1::ValidatorId {
                            name: endpoint.name,
                            id: Vec::new(),
                            pubkey: Vec::new(),
                        }),
                        reject: Some(v1::RejectReason {
                            code: v1::RejectCode::TemporaryUnavailable as i32,
                            message: err.to_string(),
                        }),
                    });
                }
            }
        }

        self.state.ingest_certs(certs.clone());

        let threshold_met = certs.len() >= self.qc_threshold as usize;
        Ok(Response::new(v1::SubmitFastPayFanoutResponse {
            tx_hash,
            effects_hash,
            certs,
            rejects,
            threshold_met,
        }))
    }

    async fn get_bulletin_board(
        &self,
        request: Request<v1::GetBulletinBoardRequest>,
    ) -> Result<Response<v1::GetBulletinBoardResponse>, Status> {
        let req = request.into_inner();
        let upstream_results = fanout_get_bulletin_board(&self.upstream, req.clone()).await;

        let mut success_count = 0usize;
        for (endpoint, result) in upstream_results {
            match result {
                Ok(response) => {
                    success_count += 1;
                    self.state.ingest_certs(response.certs);
                }
                Err(err) => {
                    warn!(endpoint = endpoint.name.as_str(), error = %err, "upstream GetBulletinBoard failed")
                }
            }
        }

        let response = self.state.get_bulletin_board_view(&req);
        if success_count == 0 && response.certs.is_empty() {
            return Err(Status::unavailable("all sidecars unavailable"));
        }

        Ok(Response::new(response))
    }

    async fn get_quorum_certificate(
        &self,
        request: Request<v1::GetQuorumCertificateRequest>,
    ) -> Result<Response<v1::GetQuorumCertificateResponse>, Status> {
        let req = request.into_inner();
        let threshold = req.threshold;
        if threshold == 0 {
            return Ok(Response::new(reject_qc(
                v1::RejectCode::InvalidFormat,
                "threshold must be > 0",
            )));
        }

        let tx_hash = match TxHash::from_slice(&req.tx_hash) {
            Ok(hash) => hash,
            Err(err) => {
                return Ok(Response::new(reject_qc(
                    v1::RejectCode::InvalidFormat,
                    format!("invalid tx_hash: {err}"),
                )));
            }
        };

        let refresh = v1::GetBulletinBoardRequest {
            filter: Some(v1::get_bulletin_board_request::Filter::TxHash(
                tx_hash.as_bytes().to_vec(),
            )),
            since_unix_millis: 0,
            limit: self.upstream.pull_limit,
        };
        let upstream_results = fanout_get_bulletin_board(&self.upstream, refresh).await;
        for (endpoint, result) in upstream_results {
            match result {
                Ok(response) => self.state.ingest_certs(response.certs),
                Err(err) => {
                    warn!(endpoint = endpoint.name.as_str(), error = %err, "upstream QC refresh failed")
                }
            }
        }

        let groups = self.state.get_certs_by_tx_effects(tx_hash);
        if groups.is_empty() {
            return Ok(Response::new(reject_qc(
                v1::RejectCode::TemporaryUnavailable,
                "no certificates found for tx_hash",
            )));
        }

        let (effects_hash, certs_for_effects) = if req.effects_hash.is_empty() {
            match dominant_effects(&groups) {
                Some(value) => value,
                None => {
                    return Ok(Response::new(reject_qc(
                        v1::RejectCode::TemporaryUnavailable,
                        "no certificates found for tx_hash",
                    )));
                }
            }
        } else {
            let effects_hash = match EffectsHash::from_slice(&req.effects_hash) {
                Ok(value) => value,
                Err(err) => {
                    return Ok(Response::new(reject_qc(
                        v1::RejectCode::InvalidFormat,
                        format!("invalid effects_hash: {err}"),
                    )));
                }
            };
            let certs = groups.get(&effects_hash).cloned().unwrap_or_default();
            (effects_hash, certs)
        };

        if certs_for_effects.len() < threshold as usize {
            return Ok(Response::new(reject_qc(
                v1::RejectCode::TemporaryUnavailable,
                format!(
                    "threshold not met: required {threshold}, have {}",
                    certs_for_effects.len()
                ),
            )));
        }

        let selected_certs = certs_for_effects
            .into_iter()
            .take(threshold as usize)
            .collect::<Vec<_>>();
        let domain_certs = match to_domain_certs(&selected_certs) {
            Ok(certs) => certs,
            Err(reject) => {
                return Ok(Response::new(v1::GetQuorumCertificateResponse {
                    result: Some(v1::get_quorum_certificate_response::Result::Reject(reject)),
                }));
            }
        };

        let qc_hash = compute_qc_hash(&tx_hash, &effects_hash, threshold, &domain_certs);

        Ok(Response::new(v1::GetQuorumCertificateResponse {
            result: Some(v1::get_quorum_certificate_response::Result::Qc(
                v1::QuorumCertificate {
                    tx_hash: tx_hash.as_bytes().to_vec(),
                    effects_hash: effects_hash.as_bytes().to_vec(),
                    certs: selected_certs,
                    threshold,
                    qc_hash: qc_hash.as_bytes().to_vec(),
                },
            )),
        }))
    }

    async fn get_chain_head(
        &self,
        _request: Request<v1::GetChainHeadRequest>,
    ) -> Result<Response<v1::GetChainHeadResponse>, Status> {
        let upstream_results = fanout_get_chain_head(&self.upstream).await;
        let mut best_head: Option<v1::GetChainHeadResponse> = None;

        for (endpoint, result) in upstream_results {
            match result {
                Ok(head) => {
                    best_head = Some(match best_head {
                        Some(current) => {
                            if compare_chain_head(&head, &current).is_gt() {
                                head
                            } else {
                                current
                            }
                        }
                        None => head,
                    });
                }
                Err(err) => {
                    warn!(endpoint = endpoint.name.as_str(), error = %err, "upstream GetChainHead failed")
                }
            }
        }

        if let Some(head) = best_head {
            self.state.set_chain_head(head.clone());
            return Ok(Response::new(head));
        }

        if let Some(head) = self.state.get_chain_head() {
            return Ok(Response::new(head));
        }

        Err(Status::unavailable("all sidecars unavailable"))
    }

    async fn get_tx_status(
        &self,
        request: Request<v1::GetTxStatusRequest>,
    ) -> Result<Response<v1::GetTxStatusResponse>, Status> {
        let req = request.into_inner();
        let tx_hash = TxHash::from_slice(&req.tx_hash)
            .map_err(|err| Status::invalid_argument(format!("invalid tx_hash: {err}")))?;

        let refresh = v1::GetBulletinBoardRequest {
            filter: Some(v1::get_bulletin_board_request::Filter::TxHash(
                tx_hash.as_bytes().to_vec(),
            )),
            since_unix_millis: 0,
            limit: self.upstream.pull_limit,
        };
        let upstream_results = fanout_get_bulletin_board(&self.upstream, refresh).await;
        for (endpoint, result) in upstream_results {
            match result {
                Ok(response) => self.state.ingest_certs(response.certs),
                Err(err) => {
                    warn!(endpoint = endpoint.name.as_str(), error = %err, "upstream tx-status refresh failed")
                }
            }
        }

        let limits = self.state.limits();
        let mut certs = self.state.get_tx_certs_deduped(tx_hash);
        certs.truncate(limits.max_tx_status_certs as usize);
        let groups = self.state.get_certs_by_tx_effects(tx_hash);

        let mut qc_formed = false;
        let mut qc_hash = Vec::new();
        if let Some((effects_hash, effect_certs)) =
            dominant_effects_with_min(&groups, self.qc_threshold)
        {
            let selected = effect_certs
                .iter()
                .take(self.qc_threshold as usize)
                .cloned()
                .collect::<Vec<_>>();
            if let Ok(domain_certs) = to_domain_certs(&selected) {
                let computed =
                    compute_qc_hash(&tx_hash, &effects_hash, self.qc_threshold, &domain_certs);
                qc_hash = computed.as_bytes().to_vec();
                qc_formed = true;
            }
        }

        let stage = if certs.is_empty() {
            v1::tx_lifecycle_update::Stage::Unspecified
        } else {
            v1::tx_lifecycle_update::Stage::Certified
        } as i32;

        let head = self.state.get_chain_head();
        let observed_block_height = head.as_ref().map(|value| value.block_height).unwrap_or(0);
        let cert_updated = certs
            .iter()
            .map(|cert| cert.created_unix_millis)
            .max()
            .unwrap_or(0);
        let head_updated = head.as_ref().map(|value| value.unix_millis).unwrap_or(0);
        let last_updated_unix_millis = cert_updated
            .max(head_updated)
            .max(self.state.get_tx_last_updated(tx_hash));

        Ok(Response::new(v1::GetTxStatusResponse {
            tx_hash: tx_hash.as_bytes().to_vec(),
            certs,
            qc_formed,
            qc_hash,
            stage,
            observed_block_height,
            last_updated_unix_millis,
        }))
    }
}

fn reject_qc(code: v1::RejectCode, message: impl Into<String>) -> v1::GetQuorumCertificateResponse {
    v1::GetQuorumCertificateResponse {
        result: Some(v1::get_quorum_certificate_response::Result::Reject(
            v1::RejectReason {
                code: code as i32,
                message: message.into(),
            },
        )),
    }
}

fn dominant_effects(
    groups: &std::collections::BTreeMap<EffectsHash, Vec<v1::ValidatorCertificate>>,
) -> Option<(EffectsHash, Vec<v1::ValidatorCertificate>)> {
    dominant_effects_with_min(groups, 0)
}

fn dominant_effects_with_min(
    groups: &std::collections::BTreeMap<EffectsHash, Vec<v1::ValidatorCertificate>>,
    min_count: u32,
) -> Option<(EffectsHash, Vec<v1::ValidatorCertificate>)> {
    let mut best: Option<(EffectsHash, Vec<v1::ValidatorCertificate>)> = None;
    for (effects_hash, certs) in groups {
        if certs.len() < min_count as usize {
            continue;
        }
        match best.as_ref() {
            Some((_, best_certs)) if best_certs.len() > certs.len() => {}
            Some((best_hash, best_certs))
                if best_certs.len() == certs.len() && best_hash <= effects_hash => {}
            _ => best = Some((*effects_hash, certs.clone())),
        }
    }
    best
}

#[derive(Clone)]
struct DomainCert {
    tx_hash: TxHash,
    effects_hash: EffectsHash,
    signer: ValidatorId,
    signature: Vec<u8>,
    created_unix_millis: u64,
}

impl Certificate for DomainCert {
    fn tx_hash(&self) -> &TxHash {
        &self.tx_hash
    }

    fn effects_hash(&self) -> &EffectsHash {
        &self.effects_hash
    }

    fn signer(&self) -> &ValidatorId {
        &self.signer
    }

    fn verify(&self, _ctx: &fastpay_types::VerificationContext) -> Result<(), CryptoError> {
        Ok(())
    }

    fn signature_bytes(&self) -> &[u8] {
        &self.signature
    }

    fn created_at(&self) -> u64 {
        self.created_unix_millis
    }
}

fn to_domain_certs(
    certs: &[v1::ValidatorCertificate],
) -> Result<Vec<DomainCert>, v1::RejectReason> {
    let mut out = Vec::with_capacity(certs.len());
    for cert in certs {
        let tx_hash = tx_hash_from_cert(cert).map_err(validation_to_reject)?;
        let effects_hash = effects_hash_from_cert(cert).map_err(validation_to_reject)?;
        let signer = signer_from_cert(cert).map_err(validation_to_reject)?;
        out.push(DomainCert {
            tx_hash,
            effects_hash,
            signer,
            signature: cert.signature.clone(),
            created_unix_millis: cert.created_unix_millis,
        });
    }
    Ok(out)
}

fn validation_to_reject(err: ValidationError) -> v1::RejectReason {
    v1::RejectReason {
        code: v1::RejectCode::InvalidFormat as i32,
        message: err.to_string(),
    }
}
