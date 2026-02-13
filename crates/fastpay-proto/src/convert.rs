use fastpay_types::{
    Address, AssetId, ChainId, EffectsHash, Expiry, Nonce2D, NonceKey, PaymentIntent, QcHash,
    TxHash, ValidationError, ValidatorId,
};

use crate::v1;

impl From<Address> for v1::Address {
    fn from(value: Address) -> Self {
        Self {
            data: value.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<v1::Address> for Address {
    type Error = ValidationError;

    fn try_from(value: v1::Address) -> Result<Self, Self::Error> {
        Address::from_slice(&value.data)
    }
}

impl From<AssetId> for v1::AssetId {
    fn from(value: AssetId) -> Self {
        Self {
            data: value.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<v1::AssetId> for AssetId {
    type Error = ValidationError;

    fn try_from(value: v1::AssetId) -> Result<Self, Self::Error> {
        AssetId::from_slice(&value.data)
    }
}

impl From<ChainId> for v1::ChainId {
    fn from(value: ChainId) -> Self {
        Self { value }
    }
}

impl From<v1::ChainId> for ChainId {
    fn from(value: v1::ChainId) -> Self {
        value.value
    }
}

impl From<Nonce2D> for v1::Nonce2D {
    fn from(value: Nonce2D) -> Self {
        Self {
            nonce_key_be: value.key.as_bytes().to_vec(),
            nonce_seq: value.seq,
        }
    }
}

impl TryFrom<v1::Nonce2D> for Nonce2D {
    type Error = ValidationError;

    fn try_from(value: v1::Nonce2D) -> Result<Self, Self::Error> {
        Ok(Self {
            key: NonceKey::from_slice(&value.nonce_key_be)?,
            seq: value.nonce_seq,
        })
    }
}

impl From<Expiry> for v1::Expiry {
    fn from(value: Expiry) -> Self {
        let kind = match value {
            Expiry::MaxBlockHeight(height) => v1::expiry::Kind::MaxBlockHeight(height),
            Expiry::UnixMillis(ms) => v1::expiry::Kind::UnixMillis(ms),
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<v1::Expiry> for Expiry {
    type Error = ValidationError;

    fn try_from(value: v1::Expiry) -> Result<Self, Self::Error> {
        match value.kind {
            Some(v1::expiry::Kind::MaxBlockHeight(height)) => Ok(Expiry::MaxBlockHeight(height)),
            Some(v1::expiry::Kind::UnixMillis(ms)) => Ok(Expiry::UnixMillis(ms)),
            None => Err(ValidationError::MissingField("expiry.kind")),
        }
    }
}

impl From<PaymentIntent> for v1::PaymentIntent {
    fn from(value: PaymentIntent) -> Self {
        Self {
            sender: Some(value.sender.into()),
            recipient: Some(value.recipient.into()),
            amount: value.amount,
            asset: Some(value.asset.into()),
        }
    }
}

impl TryFrom<v1::PaymentIntent> for PaymentIntent {
    type Error = ValidationError;

    fn try_from(value: v1::PaymentIntent) -> Result<Self, Self::Error> {
        Ok(Self {
            sender: value
                .sender
                .ok_or(ValidationError::MissingField("intent.sender"))?
                .try_into()?,
            recipient: value
                .recipient
                .ok_or(ValidationError::MissingField("intent.recipient"))?
                .try_into()?,
            amount: value.amount,
            asset: value
                .asset
                .ok_or(ValidationError::MissingField("intent.asset"))?
                .try_into()?,
        })
    }
}

impl From<ValidatorId> for v1::ValidatorId {
    fn from(value: ValidatorId) -> Self {
        Self {
            name: String::new(),
            id: value.as_bytes().to_vec(),
            pubkey: Vec::new(),
        }
    }
}

impl TryFrom<v1::ValidatorId> for ValidatorId {
    type Error = ValidationError;

    fn try_from(value: v1::ValidatorId) -> Result<Self, Self::Error> {
        if !value.id.is_empty() {
            return ValidatorId::from_slice(&value.id);
        }
        if !value.pubkey.is_empty() {
            return ValidatorId::from_slice(&value.pubkey);
        }
        Err(ValidationError::MissingField("validator_id.id"))
    }
}

pub fn tx_hash_from_bytes(bytes: &[u8]) -> Result<TxHash, ValidationError> {
    TxHash::from_slice(bytes)
}

pub fn effects_hash_from_bytes(bytes: &[u8]) -> Result<EffectsHash, ValidationError> {
    EffectsHash::from_slice(bytes)
}

pub fn qc_hash_from_bytes(bytes: &[u8]) -> Result<QcHash, ValidationError> {
    QcHash::from_slice(bytes)
}

pub fn tx_hash_to_bytes(hash: TxHash) -> Vec<u8> {
    hash.as_bytes().to_vec()
}

pub fn effects_hash_to_bytes(hash: EffectsHash) -> Vec<u8> {
    hash.as_bytes().to_vec()
}

pub fn qc_hash_to_bytes(hash: QcHash) -> Vec<u8> {
    hash.as_bytes().to_vec()
}
