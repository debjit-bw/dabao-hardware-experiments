//! What a deposit into a vault is worth, measured on the simulated state.
//!
//! An event log says how many shares a deposit minted, not what they are worth. That depends on
//! the vault's state after the transaction (its assets and supply), which only an execution on
//! verified state can read. [`read_pre`] / [`read_post`] read, for each vault, the sender's share
//! balance before and after the transaction and `previewRedeem` of the gain after it. The
//! policy compares that value with what the sender paid (`policy::evaluate`).

use alloy_primitives::{Address, U256};
use sim_types::{SimResult, VaultReceipt};

use crate::sim::{At, PostCall};

const BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
const ASSET: [u8; 4] = [0x38, 0xd5, 0x2e, 0x0f];
const PREVIEW_REDEEM: [u8; 4] = [0x4c, 0xda, 0xd5, 0x06];

/// The policy's vaults this transaction changed: only those are read (an untouched vault's
/// slots needn't be in the witness, and nothing about it changed).
pub fn touched(sim: &SimResult, vaults: &[Address]) -> Vec<Address> {
    let mut v: Vec<Address> =
        vaults.iter().copied().filter(|a| sim.changes.iter().any(|c| c.address == *a && !c.slots.is_empty())).collect();
    v.sort();
    v.dedup();
    v
}

fn word(call: &mut PostCall, at: At, to: Address, data: Vec<u8>, what: &str) -> Result<U256, String> {
    match call(at, to, data)? {
        (true, out) if out.len() == 32 => Ok(U256::from_be_slice(&out)),
        _ => Err(format!("vault {to}: can't read {what} ({at:?})")),
    }
}

fn with_word(sel: [u8; 4], w: [u8; 32]) -> Vec<u8> {
    let mut d = sel.to_vec();
    d.extend_from_slice(&w);
    d
}

/// The sender's share balance in each vault before the transaction. Must run before the first
/// [`At::Post`] call.
pub fn read_pre(vaults: &[Address], me: Address, call: &mut PostCall) -> Result<Vec<U256>, String> {
    vaults.iter().map(|v| word(call, At::Pre, *v, with_word(BALANCE_OF, me.into_word().0), "balanceOf")).collect()
}

/// The receipts, after the transaction.
pub fn read_post(vaults: &[Address], me: Address, pre: &[U256], call: &mut PostCall) -> Result<Vec<VaultReceipt>, String> {
    vaults
        .iter()
        .zip(pre)
        .map(|(v, before)| {
            let after = word(call, At::Post, *v, with_word(BALANCE_OF, me.into_word().0), "balanceOf")?;
            let asset = word(call, At::Post, *v, ASSET.to_vec(), "asset()")?;
            if asset >> 160 != U256::ZERO {
                return Err(format!("vault {v}: asset() isn't an address"));
            }
            let gain = after.saturating_sub(*before);
            let value = if gain.is_zero() {
                U256::ZERO
            } else {
                word(call, At::Post, *v, with_word(PREVIEW_REDEEM, gain.to_be_bytes()), "previewRedeem")?
            };
            Ok(VaultReceipt {
                vault: *v,
                asset: Address::from_word(asset.into()),
                shares_before: *before,
                shares_after: after,
                value,
            })
        })
        .collect()
}

/// The receipts of the `vaults` this transaction changed, read around `between` (which may make
/// its own before- and after-state calls, e.g. the Safe postcondition): the before-state reads
/// come first, as [`At::Pre`] requires. A reverted transaction has no receipts.
pub fn around<T>(
    sim: &SimResult,
    vaults: &[Address],
    me: Address,
    call: &mut PostCall,
    between: impl FnOnce(&mut PostCall) -> T,
) -> (Result<Vec<VaultReceipt>, String>, T) {
    let vaults = if sim.success { touched(sim, vaults) } else { Vec::new() };
    let pre = read_pre(&vaults, me, call);
    let t = between(call);
    (pre.and_then(|pre| read_post(&vaults, me, &pre, call)), t)
}
