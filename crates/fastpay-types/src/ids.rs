use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::ValidationError;

pub type ChainId = u64;

macro_rules! impl_fixed_bytes_id {
    ($name:ident, $len:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub struct $name([u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            pub const fn new(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub fn from_slice(bytes: &[u8]) -> Result<Self, ValidationError> {
                if bytes.len() != Self::LEN {
                    return Err(ValidationError::InvalidLength {
                        kind: stringify!($name),
                        expected: Self::LEN,
                        actual: bytes.len(),
                    });
                }
                let mut out = [0u8; Self::LEN];
                out.copy_from_slice(bytes);
                Ok(Self(out))
            }

            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            pub const fn into_inner(self) -> [u8; $len] {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self([0u8; Self::LEN])
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "0x{}", hex::encode(self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self)
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(value: [u8; $len]) -> Self {
                Self::new(value)
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = ValidationError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                Self::from_slice(value)
            }
        }
    };
}

impl_fixed_bytes_id!(Address, 20);
impl_fixed_bytes_id!(AssetId, 20);
impl_fixed_bytes_id!(ValidatorId, 32);
impl_fixed_bytes_id!(TxHash, 32);
impl_fixed_bytes_id!(EffectsHash, 32);
impl_fixed_bytes_id!(QcHash, 32);
impl_fixed_bytes_id!(NonceKey, 32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nonce2D {
    pub key: NonceKey,
    pub seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expiry {
    MaxBlockHeight(u64),
    UnixMillis(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentIntent {
    pub sender: Address,
    pub recipient: Address,
    pub amount: u64,
    pub asset: AssetId,
}
