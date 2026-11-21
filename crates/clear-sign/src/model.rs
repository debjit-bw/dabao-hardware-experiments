//! Compiled ERC-7730 descriptors (RLP). Produced on the host, trusted on the device because it
//! is part of the signed firmware (never supplied by the host at runtime).

use alloy_primitives::{Address, Bytes, U256};
use alloy_rlp::{RlpDecodable, RlpEncodable};

pub const SET_VERSION: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct DescriptorSet {
    pub version: u64,
    pub descriptors: Vec<Descriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Descriptor {
    /// `context.$id`.
    pub id: Bytes,
    /// Where the JSON came from (file name / registry path).
    pub source: Bytes,
    /// `context.contract.deployments`: the descriptor applies only to these.
    pub deployments: Vec<Deployment>,
    pub functions: Vec<Function>,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Deployment {
    pub chain_id: u64,
    pub address: Address,
}

/// One `display.formats` entry.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Function {
    /// 4-byte selector of the canonical signature.
    pub selector: Bytes,
    /// The format's key, e.g. "exactInputSingle((address tokenIn, ...) params)".
    pub signature: Bytes,
    /// Canonical parameter tuple for decoding, e.g. "((address,address,uint24,...))".
    pub params_type: Bytes,
    pub intent: Bytes,
    pub fields: Vec<Field>,
}

/// Field formats (ERC-7730 `format`), as far as the check needs to tell them apart.
pub mod format {
    pub const RAW: u8 = 0;
    /// `amount`: native currency amount.
    pub const AMOUNT: u8 = 1;
    pub const TOKEN_AMOUNT: u8 = 2;
    pub const ADDRESS_NAME: u8 = 3;
    pub const DATE: u8 = 4;
    pub const DURATION: u8 = 5;
    pub const UNIT: u8 = 6;
    /// Formats displayed as raw values by this device (enum, nftName, calldata, chainId, ...).
    pub const OTHER: u8 = 7;
}

/// Path roots.
pub mod root {
    pub const NONE: u8 = 0;
    /// Decoded calldata parameters, `steps` = indices (see [`super::step`]).
    pub const CALLDATA: u8 = 1;
    /// `@.value`
    pub const VALUE: u8 = 2;
    /// `@.to`
    pub const TO: u8 = 3;
    /// `@.from`
    pub const FROM: u8 = 4;
    /// A constant address (`params.token` in the descriptor), in `Field::token_const`.
    pub const CONST: u8 = 5;
}

/// Index steps: tuple member / array element `i`, or from the end of an array.
pub mod step {
    pub const FROM_END: u64 = 1 << 63;
    pub fn index(i: i64) -> u64 {
        if i >= 0 { i as u64 } else { FROM_END | (-i) as u64 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Path {
    pub root: u8,
    pub steps: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Field {
    pub label: Bytes,
    pub format: u8,
    pub value: Path,
    /// `tokenAmount`: where the token address comes from (`tokenPath`, or `token` as CONST).
    pub token: Path,
    pub token_const: Address,
    /// `nativeCurrencyAddress`: token addresses that mean "ETH".
    pub native_currency: Vec<Address>,
    /// `threshold` (0 = none): amounts at or above it are displayed as `message`.
    pub threshold: U256,
    pub message: Bytes,
}
