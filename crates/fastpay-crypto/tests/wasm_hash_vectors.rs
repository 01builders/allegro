//! WASM golden vector tests to verify hash parity across native and browser builds.

#![cfg(target_arch = "wasm32")]

use fastpay_crypto::{
    build_cert_signing_preimage, compute_cert_message_digest, compute_effects_hash,
    compute_qc_hash, compute_tx_hash, EffectsHashInput, TxHashInput,
};
use fastpay_types::{Address, AssetId, EffectsHash, Expiry, NonceKey, QcHash, TxHash, ValidatorId};
use wasm_bindgen_test::wasm_bindgen_test;

#[derive(Clone)]
struct DummyCert {
    tx_hash: TxHash,
    effects_hash: EffectsHash,
    signer: ValidatorId,
    signature: Vec<u8>,
    created_at: u64,
}

impl fastpay_types::Certificate for DummyCert {
    fn tx_hash(&self) -> &TxHash {
        &self.tx_hash
    }

    fn effects_hash(&self) -> &EffectsHash {
        &self.effects_hash
    }

    fn signer(&self) -> &ValidatorId {
        &self.signer
    }

    fn verify(
        &self,
        _ctx: &fastpay_types::VerificationContext,
    ) -> Result<(), fastpay_types::CryptoError> {
        Ok(())
    }

    fn signature_bytes(&self) -> &[u8] {
        &self.signature
    }

    fn created_at(&self) -> u64 {
        self.created_at
    }
}

#[wasm_bindgen_test]
fn wasm_golden_vectors_match_native_expectations() {
    let tx_input = TxHashInput {
        chain_id: 1337,
        tempo_tx: b"tempo:transfer:alice:bob:10".to_vec(),
        nonce_key: NonceKey::new([0x5b; 32]),
        nonce_seq: 7,
        expiry: Expiry::MaxBlockHeight(99),
        parent_qc_hash: Some(QcHash::new([0x11; 32])),
    };
    let effects_input = EffectsHashInput {
        sender: Address::new([0x01; 20]),
        recipient: Address::new([0x02; 20]),
        amount: 10,
        asset: AssetId::new([0x03; 20]),
        nonce_key: NonceKey::new([0x5b; 32]),
        nonce_seq: 7,
    };

    let tx_hash = compute_tx_hash(&tx_input);
    let effects_hash = compute_effects_hash(&effects_input);
    let preimage = build_cert_signing_preimage(
        1337,
        "tempo.fastpay.cert.v1",
        1,
        42,
        &tx_hash,
        &effects_hash,
    );
    let preimage_digest = compute_cert_message_digest(
        1337,
        "tempo.fastpay.cert.v1",
        1,
        42,
        &tx_hash,
        &effects_hash,
    );

    let cert_a = DummyCert {
        tx_hash,
        effects_hash,
        signer: ValidatorId::new([0x0a; 32]),
        signature: vec![0xaa; 64],
        created_at: 1000,
    };
    let cert_b = DummyCert {
        tx_hash,
        effects_hash,
        signer: ValidatorId::new([0x0b; 32]),
        signature: vec![0xbb; 64],
        created_at: 1001,
    };
    let qc_hash = compute_qc_hash(
        &tx_hash,
        &effects_hash,
        2,
        &[cert_b.clone(), cert_a.clone()],
    );
    let qc_hash_reordered = compute_qc_hash(&tx_hash, &effects_hash, 2, &[cert_a, cert_b]);

    assert_eq!(
        hex::encode(tx_hash.as_bytes()),
        "80f0bddcad91b05df8b0f96fe3b42fea9a5b5d358a61664616ec17289d80d8df"
    );
    assert_eq!(
        hex::encode(effects_hash.as_bytes()),
        "7ff26a3ecef7a937adaa2f13bcbb2dc349b1daaa63b5ede4b18f20d130f8859e"
    );
    assert_eq!(
        hex::encode(preimage),
        "74656d706f2e666173747061792e636572742e707265696d6167652e76310000001574656d706f2e666173747061792e636572742e763100010000000000000539000000000000002a80f0bddcad91b05df8b0f96fe3b42fea9a5b5d358a61664616ec17289d80d8df7ff26a3ecef7a937adaa2f13bcbb2dc349b1daaa63b5ede4b18f20d130f8859e"
    );
    assert_eq!(
        hex::encode(preimage_digest),
        "02bf6c27eb0c808a9fbda3cad277eab0634e6050a068054b878eeccc3e712313"
    );
    assert_eq!(
        hex::encode(qc_hash.as_bytes()),
        "fee9c0774bd5e57638e46c265bba36430f22e76ce9fa203a5eba6972a7809737"
    );
    assert_eq!(qc_hash, qc_hash_reordered);
}
