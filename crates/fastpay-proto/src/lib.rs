//! Generated protobuf types and serialization tests.

pub mod convert;

#[allow(clippy::large_enum_variant)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/tempo.fastpay.v1.rs"));
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::v1;

    #[test]
    fn fastpay_tx_round_trip() {
        let payment = v1::PaymentIntent {
            sender: Some(v1::Address {
                data: [1u8; 20].to_vec(),
            }),
            recipient: Some(v1::Address {
                data: [2u8; 20].to_vec(),
            }),
            amount: 10,
            asset: Some(v1::AssetId {
                data: [3u8; 20].to_vec(),
            }),
        };

        let tx = v1::FastPayTx {
            chain_id: Some(v1::ChainId { value: 1337 }),
            tempo_tx: Some(v1::TempoTxBytes {
                data: b"tempo-opaque-bytes".to_vec(),
            }),
            intent: Some(payment.clone()),
            nonce: Some(v1::Nonce2D {
                nonce_key_be: [4u8; 32].to_vec(),
                nonce_seq: 7,
            }),
            expiry: Some(v1::Expiry {
                kind: Some(v1::expiry::Kind::MaxBlockHeight(99)),
            }),
            parent_qc_hash: [5u8; 32].to_vec(),
            client_request_id: "demo-request-id".to_string(),
            tempo_tx_format: v1::TempoTxFormat::EvmOpaqueBytesV1 as i32,
            overlay: Some(v1::OverlayMetadata {
                payment: Some(payment),
            }),
        };

        let encoded = tx.encode_to_vec();
        let decoded = v1::FastPayTx::decode(encoded.as_slice()).expect("decode should succeed");
        assert_eq!(tx, decoded);
    }

    #[test]
    fn validator_certificate_round_trip() {
        let cert = v1::ValidatorCertificate {
            signer: Some(v1::ValidatorId {
                name: "Dave".to_string(),
                id: [9u8; 32].to_vec(),
                pubkey: [7u8; 32].to_vec(),
            }),
            tx_hash: [1u8; 32].to_vec(),
            effects_hash: [2u8; 32].to_vec(),
            effects: Some(v1::EffectsSummary {
                sender: Some(v1::Address {
                    data: [11u8; 20].to_vec(),
                }),
                recipient: Some(v1::Address {
                    data: [12u8; 20].to_vec(),
                }),
                amount: 42,
                asset: Some(v1::AssetId {
                    data: [13u8; 20].to_vec(),
                }),
                nonce: Some(v1::Nonce2D {
                    nonce_key_be: [14u8; 32].to_vec(),
                    nonce_seq: 8,
                }),
            }),
            signature: [3u8; 64].to_vec(),
            created_unix_millis: 1234,
        };

        let encoded = cert.encode_to_vec();
        let decoded =
            v1::ValidatorCertificate::decode(encoded.as_slice()).expect("decode should succeed");
        assert_eq!(cert, decoded);
    }
}
