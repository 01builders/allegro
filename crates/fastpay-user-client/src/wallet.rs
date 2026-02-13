//! WalletState: balance tracking, nonce reservation, pending tx management, and crash recovery.

use std::collections::{HashMap, HashSet};

use fastpay_types::{Address, AssetId, Certificate, NonceKey, QuorumCert, TxHash};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Pending transaction lifecycle states tracked by the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingStatus {
    Pending,
    Settled,
    Failed,
}

/// Pending transaction metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTx {
    pub tx_hash: TxHash,
    pub asset: AssetId,
    pub amount: u64,
    pub nonce_key: NonceKey,
    pub nonce_seq: u64,
    pub created_at: u64,
    pub status: PendingStatus,
}

/// Size limits for wallet caches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheLimits {
    pub max_pending_txs: usize,
    pub max_cached_certs: usize,
    pub max_cached_qcs: usize,
}

impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            max_pending_txs: 1024,
            max_cached_certs: 4096,
            max_cached_qcs: 1024,
        }
    }
}

/// Durable state event used for journal replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Q: Serialize, Q::Cert: Serialize",
    deserialize = "Q: Deserialize<'de>, Q::Cert: Deserialize<'de>"
))]
pub enum StateEvent<Q>
where
    Q: QuorumCert,
{
    NonceReserved { key: NonceKey, seq: u64 },
    NonceReleased { key: NonceKey, seq: u64 },
    NonceCommitted { key: NonceKey, seq: u64 },
    PendingAdded { pending: PendingTx },
    PendingSettled { tx_hash: TxHash },
    QcStored { tx_hash: TxHash, qc: Q },
    CertStored { tx_hash: TxHash, cert: Q::Cert },
    BalanceSet { asset: AssetId, amount: u64 },
    PendingAdjustment { asset: AssetId, delta: i64 },
}

/// Serializable wallet snapshot persisted for crash recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Q: Serialize, Q::Cert: Serialize",
    deserialize = "Q: Deserialize<'de>, Q::Cert: Deserialize<'de>"
))]
pub struct WalletSnapshot<Q>
where
    Q: QuorumCert,
{
    pub address: Address,
    pub base_balances: HashMap<AssetId, u64>,
    pub pending_adjustments: HashMap<AssetId, i64>,
    pub nonce_sequences: HashMap<NonceKey, u64>,
    pub reserved_nonces: HashSet<(NonceKey, u64)>,
    pub pending_txs: HashMap<TxHash, PendingTx>,
    pub received_certs: HashMap<TxHash, Vec<Q::Cert>>,
    pub qcs: HashMap<TxHash, Q>,
    pub cache_limits: CacheLimits,
}

/// Wallet state errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WalletError {
    #[error("reserved nonce not found for key {key} seq {seq}")]
    MissingReservation { key: NonceKey, seq: u64 },
    #[error("pending tx not found")]
    PendingTxNotFound,
}

/// In-memory wallet state with bounded caches and replay journal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Q: Serialize, Q::Cert: Serialize",
    deserialize = "Q: Deserialize<'de>, Q::Cert: Deserialize<'de>"
))]
pub struct WalletState<Q>
where
    Q: QuorumCert,
{
    pub address: Address,
    pub base_balances: HashMap<AssetId, u64>,
    pub pending_adjustments: HashMap<AssetId, i64>,
    pub nonce_sequences: HashMap<NonceKey, u64>,
    pub reserved_nonces: HashSet<(NonceKey, u64)>,
    pub pending_txs: HashMap<TxHash, PendingTx>,
    pub received_certs: HashMap<TxHash, Vec<Q::Cert>>,
    pub qcs: HashMap<TxHash, Q>,
    pub cache_limits: CacheLimits,
    pub journal: Vec<StateEvent<Q>>,
}

impl<Q> WalletState<Q>
where
    Q: QuorumCert + Clone,
    Q::Cert: Clone,
{
    pub fn new(address: Address, cache_limits: CacheLimits) -> Self {
        Self {
            address,
            base_balances: HashMap::new(),
            pending_adjustments: HashMap::new(),
            nonce_sequences: HashMap::new(),
            reserved_nonces: HashSet::new(),
            pending_txs: HashMap::new(),
            received_certs: HashMap::new(),
            qcs: HashMap::new(),
            cache_limits,
            journal: Vec::new(),
        }
    }

    pub fn set_base_balance(&mut self, asset: AssetId, amount: u64) {
        self.base_balances.insert(asset, amount);
        self.journal.push(StateEvent::BalanceSet { asset, amount });
    }

    pub fn base_balance(&self, asset: AssetId) -> u64 {
        self.base_balances.get(&asset).copied().unwrap_or(0)
    }

    pub fn apply_pending_adjustment(&mut self, asset: AssetId, delta: i64) {
        self.pending_adjustments
            .entry(asset)
            .and_modify(|v| *v += delta)
            .or_insert(delta);
        self.journal
            .push(StateEvent::PendingAdjustment { asset, delta });
    }

    pub fn available_balance(&self, asset: AssetId) -> i128 {
        let base = self.base_balances.get(&asset).copied().unwrap_or(0) as i128;
        let pending = self.pending_adjustments.get(&asset).copied().unwrap_or(0) as i128;
        base + pending
    }

    pub fn reserve_next_nonce(&mut self, key: NonceKey) -> u64 {
        let seq = *self.nonce_sequences.entry(key).or_insert(0);
        self.nonce_sequences.insert(key, seq + 1);
        self.reserved_nonces.insert((key, seq));
        self.journal.push(StateEvent::NonceReserved { key, seq });
        seq
    }

    pub fn release_reserved_nonce(&mut self, key: NonceKey, seq: u64) -> Result<(), WalletError> {
        if !self.reserved_nonces.remove(&(key, seq)) {
            return Err(WalletError::MissingReservation { key, seq });
        }
        self.journal.push(StateEvent::NonceReleased { key, seq });
        Ok(())
    }

    pub fn commit_reserved_nonce(&mut self, key: NonceKey, seq: u64) -> Result<(), WalletError> {
        if !self.reserved_nonces.remove(&(key, seq)) {
            return Err(WalletError::MissingReservation { key, seq });
        }
        self.journal.push(StateEvent::NonceCommitted { key, seq });
        Ok(())
    }

    pub fn add_pending_tx(&mut self, pending: PendingTx) {
        self.pending_txs.insert(pending.tx_hash, pending.clone());
        self.journal.push(StateEvent::PendingAdded { pending });
    }

    pub fn mark_pending_settled(&mut self, tx_hash: TxHash) -> Result<(), WalletError> {
        let tx = self
            .pending_txs
            .get_mut(&tx_hash)
            .ok_or(WalletError::PendingTxNotFound)?;
        tx.status = PendingStatus::Settled;
        self.journal.push(StateEvent::PendingSettled { tx_hash });
        Ok(())
    }

    pub fn store_qc(&mut self, qc: Q) {
        let tx_hash = *qc.tx_hash();
        self.qcs.insert(tx_hash, qc.clone());
        self.journal.push(StateEvent::QcStored { tx_hash, qc });
    }

    pub fn record_certificate(&mut self, tx_hash: TxHash, cert: Q::Cert) {
        let signer = *cert.signer();
        let certs = self.received_certs.entry(tx_hash).or_default();
        if certs.iter().any(|c| c.signer() == &signer) {
            return;
        }
        certs.push(cert.clone());
        self.journal.push(StateEvent::CertStored { tx_hash, cert });
    }

    pub fn record_qc(&mut self, qc: Q) {
        let tx_hash = *qc.tx_hash();
        self.qcs.insert(tx_hash, qc.clone());
        self.journal.push(StateEvent::QcStored { tx_hash, qc });
    }

    pub fn get_qc(&self, tx_hash: &TxHash) -> Option<&Q> {
        self.qcs.get(tx_hash)
    }

    pub fn prune_caches(&mut self) {
        prune_pending(&mut self.pending_txs, self.cache_limits.max_pending_txs);
        prune_certs(
            &mut self.received_certs,
            self.cache_limits.max_cached_certs,
            &self.pending_txs,
        );
        prune_qcs(
            &mut self.qcs,
            self.cache_limits.max_cached_qcs,
            &self.pending_txs,
        );
    }

    pub fn snapshot(&self) -> WalletSnapshot<Q> {
        WalletSnapshot {
            address: self.address,
            base_balances: self.base_balances.clone(),
            pending_adjustments: self.pending_adjustments.clone(),
            nonce_sequences: self.nonce_sequences.clone(),
            reserved_nonces: self.reserved_nonces.clone(),
            pending_txs: self.pending_txs.clone(),
            received_certs: self.received_certs.clone(),
            qcs: self.qcs.clone(),
            cache_limits: self.cache_limits,
        }
    }

    pub fn recover_from_snapshot_and_journal(
        &mut self,
        snapshot: WalletSnapshot<Q>,
        events: &[StateEvent<Q>],
    ) {
        self.address = snapshot.address;
        self.base_balances = snapshot.base_balances;
        self.pending_adjustments = snapshot.pending_adjustments;
        self.nonce_sequences = snapshot.nonce_sequences;
        self.reserved_nonces = snapshot.reserved_nonces;
        self.pending_txs = snapshot.pending_txs;
        self.received_certs = snapshot.received_certs;
        self.qcs = snapshot.qcs;
        self.cache_limits = snapshot.cache_limits;
        self.journal.clear();

        for event in events {
            self.apply_event(event.clone());
            self.journal.push(event.clone());
        }
    }

    fn apply_event(&mut self, event: StateEvent<Q>) {
        match event {
            StateEvent::NonceReserved { key, seq } => {
                self.reserved_nonces.insert((key, seq));
                self.nonce_sequences
                    .entry(key)
                    .and_modify(|v| *v = (*v).max(seq + 1))
                    .or_insert(seq + 1);
            }
            StateEvent::NonceReleased { key, seq } | StateEvent::NonceCommitted { key, seq } => {
                self.reserved_nonces.remove(&(key, seq));
            }
            StateEvent::PendingAdded { pending } => {
                self.pending_txs.insert(pending.tx_hash, pending);
            }
            StateEvent::PendingSettled { tx_hash } => {
                if let Some(tx) = self.pending_txs.get_mut(&tx_hash) {
                    tx.status = PendingStatus::Settled;
                }
            }
            StateEvent::QcStored { tx_hash, qc } => {
                self.qcs.insert(tx_hash, qc);
            }
            StateEvent::CertStored { tx_hash, cert } => {
                let signer = *cert.signer();
                let certs = self.received_certs.entry(tx_hash).or_default();
                if certs.iter().any(|existing| existing.signer() == &signer) {
                    return;
                }
                certs.push(cert);
            }
            StateEvent::BalanceSet { asset, amount } => {
                self.base_balances.insert(asset, amount);
            }
            StateEvent::PendingAdjustment { asset, delta } => {
                self.pending_adjustments
                    .entry(asset)
                    .and_modify(|v| *v += delta)
                    .or_insert(delta);
            }
        }
    }
}

fn prune_pending(pending: &mut HashMap<TxHash, PendingTx>, max: usize) {
    if pending.len() <= max {
        return;
    }
    let mut keys: Vec<TxHash> = pending
        .iter()
        .filter(|(_, tx)| tx.status != PendingStatus::Pending)
        .map(|(k, _)| *k)
        .collect();
    keys.sort_unstable();
    for key in keys.into_iter().take(pending.len().saturating_sub(max)) {
        pending.remove(&key);
    }
}

fn prune_certs<C>(
    certs: &mut HashMap<TxHash, Vec<C>>,
    max: usize,
    pending: &HashMap<TxHash, PendingTx>,
) {
    let current: usize = certs.values().map(Vec::len).sum();
    if current <= max {
        return;
    }
    let mut keys: Vec<TxHash> = certs
        .keys()
        .copied()
        .filter(|k| !pending.contains_key(k))
        .collect();
    keys.sort_unstable();
    for key in keys {
        if certs.values().map(Vec::len).sum::<usize>() <= max {
            break;
        }
        certs.remove(&key);
    }
}

fn prune_qcs<Q>(qcs: &mut HashMap<TxHash, Q>, max: usize, pending: &HashMap<TxHash, PendingTx>) {
    if qcs.len() <= max {
        return;
    }
    let mut keys: Vec<TxHash> = qcs
        .keys()
        .copied()
        .filter(|k| !pending.contains_key(k))
        .collect();
    keys.sort_unstable();
    for key in keys.into_iter().take(qcs.len().saturating_sub(max)) {
        qcs.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use fastpay_crypto::{Ed25519Signer, MultiCertQC, SimpleAssembler};
    use fastpay_types::{
        AssetId, CertSigningContext, Expiry, NonceKey, QuorumAssembler, QuorumCert, Signer,
        ValidatorId,
    };

    use super::{CacheLimits, PendingStatus, PendingTx, WalletState};
    use crate::tx_builder::TxBuilder;
    use fastpay_types::Address;

    fn make_qc() -> (MultiCertQC, AssetId, NonceKey, u64) {
        let sender = Address::new([0x01; 20]);
        let recipient = Address::new([0x02; 20]);
        let asset = AssetId::new([0xaa; 20]);
        let key = NonceKey::new([0x5b; 32]);
        let built = TxBuilder::new(1337)
            .with_payment(sender, recipient, 10, asset)
            .with_nonce(key)
            .with_expiry(Expiry::MaxBlockHeight(100))
            .build()
            .unwrap();

        let signer_a = Ed25519Signer::from_seed(ValidatorId::new([0x11; 32]), [0x21; 32]);
        let signer_b = Ed25519Signer::from_seed(ValidatorId::new([0x12; 32]), [0x22; 32]);
        let ctx = CertSigningContext {
            chain_id: 1337,
            domain_tag: "tempo.fastpay.cert.v1",
            protocol_version: 1,
            epoch: 1,
        };
        let cert_a = signer_a
            .sign(&ctx, &built.tx_hash, &built.effects_hash)
            .unwrap();
        let cert_b = signer_b
            .sign(&ctx, &built.tx_hash, &built.effects_hash)
            .unwrap();
        let mut assembler = SimpleAssembler::new(built.tx_hash, built.effects_hash, 2);
        assembler.add_certificate(cert_a).unwrap();
        assembler.add_certificate(cert_b).unwrap();
        (assembler.finalize().unwrap(), asset, key, 0)
    }

    #[test]
    fn reserve_release_commit_nonce_flow() {
        let address = Address::new([0x01; 20]);
        let mut wallet = WalletState::<MultiCertQC>::new(address, CacheLimits::default());
        let key = NonceKey::new([0x5b; 32]);

        let seq = wallet.reserve_next_nonce(key);
        assert_eq!(seq, 0);
        assert!(wallet.reserved_nonces.contains(&(key, 0)));
        wallet.release_reserved_nonce(key, 0).unwrap();
        assert!(!wallet.reserved_nonces.contains(&(key, 0)));

        let seq2 = wallet.reserve_next_nonce(key);
        assert_eq!(seq2, 1);
        wallet.commit_reserved_nonce(key, 1).unwrap();
        assert!(!wallet.reserved_nonces.contains(&(key, 1)));
    }

    #[test]
    fn tracks_balances_pending_and_qcs() {
        let address = Address::new([0x01; 20]);
        let (qc, asset, key, seq) = make_qc();
        let mut wallet = WalletState::<MultiCertQC>::new(
            address,
            CacheLimits {
                max_pending_txs: 10,
                max_cached_certs: 10,
                max_cached_qcs: 10,
            },
        );
        wallet.set_base_balance(asset, 15);
        wallet.apply_pending_adjustment(asset, -10);
        assert_eq!(wallet.available_balance(asset), 5);

        wallet.add_pending_tx(PendingTx {
            tx_hash: *qc.tx_hash(),
            asset,
            amount: 10,
            nonce_key: key,
            nonce_seq: seq,
            created_at: 1,
            status: PendingStatus::Pending,
        });
        wallet.record_qc(qc.clone());
        assert!(wallet.get_qc(qc.tx_hash()).is_some());
        assert!(wallet.pending_txs.contains_key(qc.tx_hash()));
    }

    #[test]
    fn prunes_and_recovers_from_snapshot_journal() {
        let address = Address::new([0x01; 20]);
        let (qc, asset, key, _) = make_qc();
        let mut wallet = WalletState::<MultiCertQC>::new(
            address,
            CacheLimits {
                max_pending_txs: 1,
                max_cached_certs: 1,
                max_cached_qcs: 1,
            },
        );
        wallet.set_base_balance(asset, 15);
        wallet.reserve_next_nonce(key);
        wallet.store_qc(qc.clone());
        wallet.record_certificate(*qc.tx_hash(), qc.certificates()[0].clone());
        wallet.record_certificate(*qc.tx_hash(), qc.certificates()[1].clone());
        wallet.prune_caches();

        let snapshot = wallet.snapshot();
        let replay_events = wallet.journal.clone();

        let mut recovered = WalletState::<MultiCertQC>::new(address, CacheLimits::default());
        recovered.recover_from_snapshot_and_journal(snapshot, &replay_events);
        assert_eq!(recovered.base_balance(asset), 15);
        assert!(recovered.nonce_sequences.get(&key).copied().unwrap_or(0) >= 1);
        assert!(recovered.get_qc(qc.tx_hash()).is_some());
    }

    #[test]
    fn replay_delta_reconstructs_pending_and_certs() {
        let address = Address::new([0x01; 20]);
        let (qc, asset, key, seq) = make_qc();
        let mut wallet = WalletState::<MultiCertQC>::new(address, CacheLimits::default());
        wallet.set_base_balance(asset, 15);

        let snapshot = wallet.snapshot();
        let checkpoint = wallet.journal.len();

        wallet.reserve_next_nonce(key);
        wallet.add_pending_tx(PendingTx {
            tx_hash: *qc.tx_hash(),
            asset,
            amount: 10,
            nonce_key: key,
            nonce_seq: seq,
            created_at: 1,
            status: PendingStatus::Pending,
        });
        wallet.record_certificate(*qc.tx_hash(), qc.certificates()[0].clone());

        let replay_events = wallet.journal[checkpoint..].to_vec();
        let mut recovered = WalletState::<MultiCertQC>::new(address, CacheLimits::default());
        recovered.recover_from_snapshot_and_journal(snapshot, &replay_events);

        assert!(recovered.pending_txs.contains_key(qc.tx_hash()));
        assert_eq!(
            recovered
                .received_certs
                .get(qc.tx_hash())
                .map(Vec::len)
                .unwrap_or(0),
            1
        );
    }
}
