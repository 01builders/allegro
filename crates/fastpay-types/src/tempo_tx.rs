//! Shared decoder for Tempo native transactions (type 0x76).
//!
//! Wire format: `0x76 || RLP([fields...]) || signature(65)`
//!
//! RLP field order (from ox/tempo source):
//!   0: chainId (uint)
//!   1: maxPriorityFeePerGas (uint)
//!   2: maxFeePerGas (uint)
//!   3: gas (uint)
//!   4: calls (list of [to, value, data] tuples)
//!   5: accessList (EIP-2930 list)
//!   6: nonceKey (uint192)
//!   7: nonce (uint64)
//!   8..12: optional fields

use alloy_primitives::Signature;
use alloy_rlp::Header;

use crate::{Address, AssetId, NonceKey};

/// Tempo native transaction type byte.
pub const TEMPO_TX_TYPE: u8 = 0x76;

/// secp256k1 signature: r(32) || s(32) || yParity(1).
const SIG_LEN: usize = 65;

/// ERC-20 `transfer(address,uint256)` selector.
const ERC20_TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// TIP-20 payment address prefix.
const TIP20_PREFIX: [u8; 2] = [0x20, 0xc0];

/// Decoded fields from a Tempo native transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTempoTx {
    pub sender: Address,
    pub recipient: Address,
    pub amount: u64,
    pub asset: AssetId,
    pub nonce_key: NonceKey,
    pub nonce_seq: u64,
}

/// Returns true if `bytes` starts with the Tempo native tx type byte (0x76).
pub fn is_tempo_native(bytes: &[u8]) -> bool {
    bytes.first() == Some(&TEMPO_TX_TYPE)
}

/// Fully decode a Tempo native transaction.
///
/// Recovers sender via ecrecover, extracts payment details from `calls[0]`,
/// and reads 2D nonce fields (nonceKey, nonce).
pub fn decode_tempo_native_tx(bytes: &[u8]) -> Result<DecodedTempoTx, String> {
    if !is_tempo_native(bytes) {
        return Err("not a Tempo native tx (expected 0x76 prefix)".into());
    }
    if bytes.len() < 1 + 3 + SIG_LEN {
        return Err("tempo tx too short".into());
    }

    let sig_start = bytes.len() - SIG_LEN;
    let sig_bytes = &bytes[sig_start..];

    // Signing hash: keccak256(type_byte || rlp_payload)
    let signing_hash = alloy_primitives::keccak256(&bytes[..sig_start]);

    // Recover sender
    let sig = parse_signature(sig_bytes);
    let sender_alloy = sig
        .recover_address_from_prehash(&signing_hash)
        .map_err(|e| format!("cannot recover sender: {e}"))?;
    let sender =
        Address::from_slice(sender_alloy.as_slice()).map_err(|e| format!("sender: {e}"))?;

    // Decode RLP list body
    let mut buf: &[u8] = &bytes[1..sig_start];
    let list_hdr = Header::decode(&mut buf).map_err(|e| format!("RLP list header: {e}"))?;
    if !list_hdr.list {
        return Err("expected RLP list for tx body".into());
    }

    // Items 0-3: chainId, maxPriorityFeePerGas, maxFeePerGas, gas — skip
    for i in 0..4u8 {
        skip_item(&mut buf).map_err(|e| format!("skip field {i}: {e}"))?;
    }

    // Item 4: calls — decode first call
    let (recipient, amount, asset) = decode_calls_field(&mut buf)?;

    // Item 5: accessList — skip
    skip_item(&mut buf).map_err(|e| format!("skip accessList: {e}"))?;

    // Item 6: nonceKey (uint192, up to 24 bytes → left-pad to 32)
    let nk_bytes = read_bytes(&mut buf).map_err(|e| format!("nonceKey: {e}"))?;
    if nk_bytes.len() > 32 {
        return Err(format!("nonceKey too large: {} bytes", nk_bytes.len()));
    }
    let mut nk = [0u8; 32];
    nk[32 - nk_bytes.len()..].copy_from_slice(nk_bytes);
    let nonce_key = NonceKey::new(nk);

    // Item 7: nonce (uint64)
    let n_bytes = read_bytes(&mut buf).map_err(|e| format!("nonce: {e}"))?;
    if n_bytes.len() > 8 {
        return Err("nonce does not fit u64".into());
    }
    let mut nb = [0u8; 8];
    nb[8 - n_bytes.len()..].copy_from_slice(n_bytes);
    let nonce_seq = u64::from_be_bytes(nb);

    Ok(DecodedTempoTx {
        sender,
        recipient,
        amount,
        asset,
        nonce_key,
        nonce_seq,
    })
}

/// Recover only the sender address from a Tempo native transaction.
pub fn recover_tempo_native_sender(bytes: &[u8]) -> Result<Address, String> {
    if !is_tempo_native(bytes) {
        return Err("not a Tempo native tx".into());
    }
    if bytes.len() < 1 + 3 + SIG_LEN {
        return Err("tempo tx too short".into());
    }

    let sig_start = bytes.len() - SIG_LEN;
    let signing_hash = alloy_primitives::keccak256(&bytes[..sig_start]);
    let sig = parse_signature(&bytes[sig_start..]);

    let sender_alloy = sig
        .recover_address_from_prehash(&signing_hash)
        .map_err(|e| format!("cannot recover sender: {e}"))?;

    Address::from_slice(sender_alloy.as_slice()).map_err(|e| format!("sender: {e}"))
}

// ---------------------------------------------------------------------------
// RLP helpers
// ---------------------------------------------------------------------------

fn parse_signature(sig_bytes: &[u8]) -> Signature {
    Signature::from_bytes_and_parity(&sig_bytes[..64], sig_bytes[64] != 0)
}

/// Skip one RLP item (scalar or list) by advancing past it.
fn skip_item(buf: &mut &[u8]) -> Result<(), String> {
    let hdr = Header::decode(buf).map_err(|e| format!("header: {e}"))?;
    if buf.len() < hdr.payload_length {
        return Err("truncated".into());
    }
    *buf = &buf[hdr.payload_length..];
    Ok(())
}

/// Read one RLP scalar (non-list) item as a byte slice.
fn read_bytes<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], String> {
    let hdr = Header::decode(buf).map_err(|e| format!("header: {e}"))?;
    if hdr.list {
        *buf = &buf[hdr.payload_length..];
        return Err("expected bytes, got list".into());
    }
    if buf.len() < hdr.payload_length {
        return Err("truncated".into());
    }
    let data = &buf[..hdr.payload_length];
    *buf = &buf[hdr.payload_length..];
    Ok(data)
}

/// Decode the `calls` field (item 4): list of `[to, value, data]` tuples.
/// Returns `(recipient, amount, asset)` from `calls[0]`.
fn decode_calls_field(buf: &mut &[u8]) -> Result<(Address, u64, AssetId), String> {
    let calls_hdr = Header::decode(buf).map_err(|e| format!("calls header: {e}"))?;
    if !calls_hdr.list {
        return Err("calls must be a list".into());
    }
    if calls_hdr.payload_length == 0 {
        return Err("calls list is empty".into());
    }

    // Bookmark end of calls so we can skip remaining calls after parsing the first
    let calls_end = &buf[calls_hdr.payload_length..];
    let mut inner = &buf[..calls_hdr.payload_length];

    // First call: [to, value, data]
    let call_hdr = Header::decode(&mut inner).map_err(|e| format!("call[0] header: {e}"))?;
    if !call_hdr.list {
        return Err("call[0] must be a list".into());
    }

    // to: 20-byte address = token contract
    let to_bytes = read_bytes(&mut inner).map_err(|e| format!("call[0].to: {e}"))?;
    if to_bytes.len() != 20 {
        return Err(format!(
            "call[0].to: expected 20 bytes, got {}",
            to_bytes.len()
        ));
    }
    if !to_bytes.starts_with(&TIP20_PREFIX) {
        return Err("token address is not TIP-20 payment-prefixed".into());
    }
    let asset = AssetId::from_slice(to_bytes).map_err(|e| format!("asset: {e}"))?;

    // value: must be zero (canonical RLP for 0 is empty bytes)
    let value_bytes = read_bytes(&mut inner).map_err(|e| format!("call[0].value: {e}"))?;
    if !value_bytes.is_empty() {
        return Err("native value transfers not supported".into());
    }

    // data: ERC-20 transfer(address,uint256) calldata
    let calldata = read_bytes(&mut inner).map_err(|e| format!("call[0].data: {e}"))?;
    if calldata.len() != 68 || calldata[0..4] != ERC20_TRANSFER_SELECTOR {
        return Err("unsupported call data (expected ERC-20 transfer)".into());
    }
    if calldata[4..16].iter().any(|b| *b != 0) {
        return Err("invalid recipient encoding".into());
    }
    if calldata[36..60].iter().any(|b| *b != 0) {
        return Err("amount does not fit u64".into());
    }

    let recipient =
        Address::from_slice(&calldata[16..36]).map_err(|e| format!("recipient: {e}"))?;
    let amount = u64::from_be_bytes(
        calldata[60..68]
            .try_into()
            .map_err(|_| "amount bytes".to_string())?,
    );

    // Advance past entire calls payload
    *buf = calls_end;

    Ok((recipient, amount, asset))
}
