use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::RwLock;

use fastpay_proto::v1;
use fastpay_types::{Address, EffectsHash, TxHash, ValidationError, ValidatorId};

#[derive(Debug, Clone)]
pub struct BackendLimits {
    pub max_sidecars: usize,
    pub max_total_certs: usize,
    pub max_txs: usize,
    pub max_certs_per_tx_effects: usize,
    pub max_bulletin_board_response: u32,
    pub max_tx_status_certs: u32,
}

impl Default for BackendLimits {
    fn default() -> Self {
        Self {
            max_sidecars: 64,
            max_total_certs: 50_000,
            max_txs: 10_000,
            max_certs_per_tx_effects: 32,
            max_bulletin_board_response: 2_000,
            max_tx_status_certs: 256,
        }
    }
}

#[derive(Debug)]
struct TxEntry {
    certs: HashMap<EffectsHash, BTreeMap<ValidatorId, v1::ValidatorCertificate>>,
    last_updated_unix_millis: u64,
}

#[derive(Debug)]
struct Inner {
    txs: HashMap<TxHash, TxEntry>,
    total_certs: usize,
    eviction: BTreeSet<(u64, TxHash)>,
    chain_head: Option<v1::GetChainHeadResponse>,
    limits: BackendLimits,
}

#[derive(Debug)]
pub struct FastPayBackendState {
    inner: RwLock<Inner>,
}

impl FastPayBackendState {
    pub fn new(limits: BackendLimits) -> Self {
        Self {
            inner: RwLock::new(Inner {
                txs: HashMap::new(),
                total_certs: 0,
                eviction: BTreeSet::new(),
                chain_head: None,
                limits,
            }),
        }
    }

    pub fn limits(&self) -> BackendLimits {
        self.inner.read().unwrap().limits.clone()
    }

    pub fn ingest_certs(&self, certs: impl IntoIterator<Item = v1::ValidatorCertificate>) {
        let mut inner = self.inner.write().unwrap();
        for cert in certs {
            ingest_cert(&mut inner, cert);
        }
        enforce_limits(&mut inner);
    }

    pub fn get_bulletin_board_view(
        &self,
        req: &v1::GetBulletinBoardRequest,
    ) -> v1::GetBulletinBoardResponse {
        let inner = self.inner.read().unwrap();
        let mut certs: Vec<v1::ValidatorCertificate> = inner
            .txs
            .values()
            .flat_map(|entry| {
                entry
                    .certs
                    .values()
                    .flat_map(|by_signer| by_signer.values())
            })
            .cloned()
            .collect();

        certs.retain(|cert| cert.created_unix_millis >= req.since_unix_millis);
        if let Some(filter) = req.filter.as_ref() {
            certs.retain(|cert| cert_matches_filter(cert, filter));
        }

        certs.sort_by_key(cert_sort_key);

        let limit = if req.limit == 0 {
            inner.limits.max_bulletin_board_response
        } else {
            req.limit.min(inner.limits.max_bulletin_board_response)
        } as usize;
        certs.truncate(limit);

        v1::GetBulletinBoardResponse {
            certs,
            next_cursor: String::new(),
        }
    }

    pub fn get_certs_by_tx_effects(
        &self,
        tx_hash: TxHash,
    ) -> BTreeMap<EffectsHash, Vec<v1::ValidatorCertificate>> {
        let inner = self.inner.read().unwrap();
        let mut out = BTreeMap::new();
        if let Some(entry) = inner.txs.get(&tx_hash) {
            for (effects_hash, by_signer) in &entry.certs {
                let mut certs = by_signer.values().cloned().collect::<Vec<_>>();
                certs.sort_by_key(signer_key_bytes);
                out.insert(*effects_hash, certs);
            }
        }
        out
    }

    pub fn get_tx_certs_deduped(&self, tx_hash: TxHash) -> Vec<v1::ValidatorCertificate> {
        let mut certs: Vec<v1::ValidatorCertificate> = self
            .get_certs_by_tx_effects(tx_hash)
            .into_values()
            .flatten()
            .collect();
        certs.sort_by_key(cert_sort_key);
        certs
    }

    pub fn get_tx_last_updated(&self, tx_hash: TxHash) -> u64 {
        let inner = self.inner.read().unwrap();
        inner
            .txs
            .get(&tx_hash)
            .map(|entry| entry.last_updated_unix_millis)
            .unwrap_or(0)
    }

    pub fn set_chain_head(&self, head: v1::GetChainHeadResponse) {
        let mut inner = self.inner.write().unwrap();
        match inner.chain_head.as_ref() {
            Some(existing) if compare_chain_head(&head, existing).is_lt() => {}
            _ => inner.chain_head = Some(head),
        }
    }

    pub fn get_chain_head(&self) -> Option<v1::GetChainHeadResponse> {
        self.inner.read().unwrap().chain_head.clone()
    }
}

fn ingest_cert(inner: &mut Inner, cert: v1::ValidatorCertificate) {
    let tx_hash = match tx_hash_from_cert(&cert) {
        Ok(value) => value,
        Err(_) => return,
    };
    let effects_hash = match effects_hash_from_cert(&cert) {
        Ok(value) => value,
        Err(_) => return,
    };
    let signer = match signer_from_cert(&cert) {
        Ok(value) => value,
        Err(_) => return,
    };

    let previous_updated = inner
        .txs
        .get(&tx_hash)
        .map(|entry| entry.last_updated_unix_millis)
        .unwrap_or(0);

    let tx_entry = inner.txs.entry(tx_hash).or_insert_with(|| TxEntry {
        certs: HashMap::new(),
        last_updated_unix_millis: cert.created_unix_millis,
    });

    let by_signer = tx_entry.certs.entry(effects_hash).or_default();

    if !by_signer.contains_key(&signer) && by_signer.len() >= inner.limits.max_certs_per_tx_effects
    {
        if let Some(max_signer) = by_signer.keys().next_back().copied() {
            if signer >= max_signer {
                return;
            }
            by_signer.remove(&max_signer);
            inner.total_certs = inner.total_certs.saturating_sub(1);
        }
    }

    match by_signer.get(&signer) {
        Some(existing) => {
            if prefer_new_cert(&cert, existing) {
                by_signer.insert(signer, cert);
            }
        }
        None => {
            by_signer.insert(signer, cert);
            inner.total_certs += 1;
        }
    }

    tx_entry.last_updated_unix_millis = tx_entry.last_updated_unix_millis.max(
        by_signer
            .values()
            .map(|c| c.created_unix_millis)
            .max()
            .unwrap_or(tx_entry.last_updated_unix_millis),
    );

    inner.eviction.remove(&(previous_updated, tx_hash));
    inner
        .eviction
        .insert((tx_entry.last_updated_unix_millis, tx_hash));
}

fn enforce_limits(inner: &mut Inner) {
    while inner.txs.len() > inner.limits.max_txs || inner.total_certs > inner.limits.max_total_certs
    {
        let Some((_, tx_hash)) = inner.eviction.pop_first() else {
            break;
        };
        if let Some(removed) = inner.txs.remove(&tx_hash) {
            let removed_count: usize = removed
                .certs
                .values()
                .map(|by_signer| by_signer.len())
                .sum();
            inner.total_certs = inner.total_certs.saturating_sub(removed_count);
        }
    }
}

fn cert_matches_filter(
    cert: &v1::ValidatorCertificate,
    filter: &v1::get_bulletin_board_request::Filter,
) -> bool {
    match filter {
        v1::get_bulletin_board_request::Filter::TxHash(bytes) => {
            cert.tx_hash.as_slice() == bytes.as_slice()
        }
        v1::get_bulletin_board_request::Filter::Address(address) => {
            let sender = cert
                .effects
                .as_ref()
                .and_then(|effects| effects.sender.as_ref())
                .map(|addr| addr.data.as_slice() == address.data.as_slice())
                .unwrap_or(false);
            let recipient = cert
                .effects
                .as_ref()
                .and_then(|effects| effects.recipient.as_ref())
                .map(|addr| addr.data.as_slice() == address.data.as_slice())
                .unwrap_or(false);
            sender || recipient
        }
    }
}

fn cert_sort_key(cert: &v1::ValidatorCertificate) -> (u64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        cert.created_unix_millis,
        cert.tx_hash.clone(),
        cert.effects_hash.clone(),
        signer_key_bytes(cert),
        cert.signature.clone(),
    )
}

fn prefer_new_cert(
    new_cert: &v1::ValidatorCertificate,
    existing: &v1::ValidatorCertificate,
) -> bool {
    (new_cert.created_unix_millis, new_cert.signature.as_slice())
        > (existing.created_unix_millis, existing.signature.as_slice())
}

pub fn compare_chain_head(
    a: &v1::GetChainHeadResponse,
    b: &v1::GetChainHeadResponse,
) -> std::cmp::Ordering {
    a.block_height
        .cmp(&b.block_height)
        .then_with(|| b.block_hash.cmp(&a.block_hash))
}

pub fn signer_key_bytes(cert: &v1::ValidatorCertificate) -> Vec<u8> {
    signer_from_cert(cert)
        .map(|id| id.as_bytes().to_vec())
        .unwrap_or_default()
}

pub fn tx_hash_from_cert(cert: &v1::ValidatorCertificate) -> Result<TxHash, ValidationError> {
    TxHash::from_slice(&cert.tx_hash)
}

pub fn effects_hash_from_cert(
    cert: &v1::ValidatorCertificate,
) -> Result<EffectsHash, ValidationError> {
    EffectsHash::from_slice(&cert.effects_hash)
}

pub fn signer_from_cert(cert: &v1::ValidatorCertificate) -> Result<ValidatorId, ValidationError> {
    match cert.signer.as_ref() {
        Some(signer) if !signer.id.is_empty() => ValidatorId::from_slice(&signer.id),
        Some(signer) if !signer.pubkey.is_empty() => ValidatorId::from_slice(&signer.pubkey),
        _ => Err(ValidationError::MissingField("signer.id")),
    }
}

pub fn cert_involves_address(cert: &v1::ValidatorCertificate, address: Address) -> bool {
    cert.effects
        .as_ref()
        .and_then(|effects| effects.sender.as_ref())
        .map(|sender| sender.data.as_slice() == address.as_bytes().as_slice())
        .unwrap_or(false)
        || cert
            .effects
            .as_ref()
            .and_then(|effects| effects.recipient.as_ref())
            .map(|recipient| recipient.data.as_slice() == address.as_bytes().as_slice())
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(
        tx_byte: u8,
        effects_byte: u8,
        signer_byte: u8,
        created: u64,
        sig_fill: u8,
    ) -> v1::ValidatorCertificate {
        v1::ValidatorCertificate {
            signer: Some(v1::ValidatorId {
                name: String::new(),
                id: vec![signer_byte; 32],
                pubkey: vec![signer_byte; 32],
            }),
            tx_hash: vec![tx_byte; 32],
            effects_hash: vec![effects_byte; 32],
            effects: None,
            signature: vec![sig_fill; 64],
            created_unix_millis: created,
        }
    }

    #[test]
    fn dedupe_is_order_independent() {
        let state = FastPayBackendState::new(BackendLimits::default());
        let older = cert(1, 2, 3, 10, 1);
        let newer = cert(1, 2, 3, 20, 2);

        state.ingest_certs(vec![older.clone(), newer.clone()]);
        let tx = TxHash::from_slice(&[1u8; 32]).unwrap();
        let after_forward = state.get_tx_certs_deduped(tx);

        let state_rev = FastPayBackendState::new(BackendLimits::default());
        state_rev.ingest_certs(vec![newer, older]);
        let after_reverse = state_rev.get_tx_certs_deduped(tx);

        assert_eq!(after_forward.len(), 1);
        assert_eq!(after_forward, after_reverse);
        assert_eq!(after_forward[0].created_unix_millis, 20);
    }

    #[test]
    fn eviction_respects_limits() {
        let limits = BackendLimits {
            max_total_certs: 1,
            max_txs: 1,
            ..BackendLimits::default()
        };
        let state = FastPayBackendState::new(limits);

        state.ingest_certs(vec![cert(1, 2, 3, 10, 1), cert(4, 5, 6, 20, 1)]);

        let first = state.get_tx_certs_deduped(TxHash::from_slice(&[1u8; 32]).unwrap());
        let second = state.get_tx_certs_deduped(TxHash::from_slice(&[4u8; 32]).unwrap());
        assert!(first.is_empty());
        assert_eq!(second.len(), 1);
    }
}
