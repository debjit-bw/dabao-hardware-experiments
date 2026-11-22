//! The on-chain postcondition the device puts around every Safe call it co-signs.
//!
//! The device simulates on a proven parent block, but the Safe transaction executes later, on
//! whatever state is current then. The co-signed SafeTx is therefore a DELEGATECALL to
//! MultiSendCallOnly with three CALLs from the Safe:
//!
//! 1. `DabaoPostcondition.begin(assets)`: snapshot the Safe's balances;
//! 2. the simulated call;
//! 3. `check(device, threshold, deadline, assets, minDeltas)`: reverts unless the device is
//!    still an owner, the threshold is unchanged, there is no module and no guard, the deadline
//!    hasn't passed, and each balance changed by at least `minDeltas[i]` since `begin`.
//!
//! `minDeltas` = the simulated change of each balance, minus the slippage the user was shown
//! for that asset. Changes, not absolute balances, so a deposit before execution can't absorb
//! a loss. The deadline makes a published or abandoned co-signature expire.
//!
//! Assets checked: ETH, every asset the policy limits on this chain, and every token the
//! simulation moved to or from the Safe. Other assets and approvals are not checked.

use alloy_primitives::{Address, B256, U256};
use sim_types::{SimResult, SimTx, effect, safe};

use crate::sim::{At, PostCall};

/// How long a co-signature can be executed, from the simulated block's (proven) time. The light
/// client trails the head by a few blocks, so this can't be a block or two.
pub const VALID_SECS: u64 = 600;

/// What the device co-signs for a Safe call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Postcondition {
    pub assets: Vec<Address>,
    /// int256, two's complement.
    pub min_deltas: Vec<U256>,
    pub deadline: u64,
    /// `multiSend` calldata: [begin(...), the call, check(...)].
    pub safe_data: Vec<u8>,
}

/// Accounts whose code hashes [`build`] needs, in order (put them in `sim::Options::code_hashes`).
pub const CODE_HASH_ACCOUNTS: [Address; 2] = [safe::MULTISEND_CALL_ONLY, safe::POSTCONDITION];

/// The assets [`build`] checks, given the policy's limited assets on this chain.
pub fn assets(sim: &SimResult, safe_addr: Address, extra: &[Address]) -> Vec<Address> {
    let mut a: Vec<Address> = Vec::from([Address::ZERO]);
    a.extend_from_slice(extra);
    for e in &sim.effects {
        let moves = matches!(e.kind, effect::ERC20_TRANSFER | effect::WRAP | effect::UNWRAP);
        if moves && (e.from == safe_addr || e.to == safe_addr) && !e.contract.is_zero() {
            a.push(e.contract);
        }
    }
    a.sort();
    a.dedup();
    a
}

/// Build the postcondition for `tx` (from = the Safe), on the post-state `call` runs on.
/// `code_hashes`: the verified code hashes of [`CODE_HASH_ACCOUNTS`].
pub fn build(
    sim: &SimResult,
    tx: &SimTx,
    device: Address,
    threshold: U256,
    block_time: u64,
    code_hashes: &[B256],
    extra_assets: &[Address],
    call: &mut PostCall,
) -> Result<Postcondition, String> {
    if code_hashes != [safe::MULTISEND_CALL_ONLY_CODEHASH, safe::POSTCONDITION_CODEHASH] {
        return Err(format!(
            "MultiSendCallOnly / DabaoPostcondition not deployed as expected on this chain (code hashes {code_hashes:?})"
        ));
    }
    if tx.to == tx.from || tx.to == safe::MULTISEND_CALL_ONLY || tx.to == safe::POSTCONDITION {
        return Err(format!("a Safe call to {} is not co-signed (the Safe itself, MultiSend or the postcondition)", tx.to));
    }
    let assets = assets(sim, tx.from, extra_assets);
    let deadline = block_time.checked_add(VALID_SECS).ok_or("postcondition: block time out of range")?;
    let mut read = |at: At| -> Result<Vec<U256>, String> {
        let (ok, out) = call(at, safe::POSTCONDITION, safe::balances_calldata(tx.from, &assets))?;
        let b = if ok { safe::decode_uint_array(&out) } else { None };
        b.filter(|b| b.len() == assets.len() && b.iter().all(|x| !x.bit(255)))
            .ok_or_else(|| format!("postcondition: can't read the Safe's {at:?} balances"))
    };
    let pre = read(At::Pre)?; // first: the first Post call commits the transaction
    let post = read(At::Post)?;
    let min_deltas: Vec<U256> = assets
        .iter()
        .zip(pre.iter().zip(&post))
        .map(|(a, (before, after))| {
            // the loosest single shown minimum, not their sum
            let slack = sim
                .clear_sign
                .min_receive
                .iter()
                .filter(|m| m.asset == *a)
                .map(|m| m.simulated.saturating_sub(m.shown))
                .max()
                .unwrap_or(U256::ZERO);
            after.wrapping_sub(*before).wrapping_sub(slack)
        })
        .collect();
    let verify = safe::verify_calldata(device, threshold, deadline, &assets, &pre, &min_deltas);
    let (ok, out) = call(At::Post, safe::POSTCONDITION, verify)?;
    if !ok {
        return Err(format!("postcondition fails even on the simulated state: {}", revert_reason(&out)));
    }
    let own = |data| safe::Call { to: safe::POSTCONDITION, value: U256::ZERO, data };
    let safe_data = safe::multisend_calldata(&[
        own(safe::begin_calldata(&assets)),
        safe::Call { to: tx.to, value: tx.value, data: tx.data.to_vec() },
        own(safe::check_calldata(device, threshold, deadline, &assets, &min_deltas)),
    ]);
    Ok(Postcondition { assets, min_deltas, deadline, safe_data })
}

/// `Error(string)` revert data -> the string (else hex).
pub fn revert_reason(out: &[u8]) -> String {
    if out.len() >= 68 && out[..4] == [0x08, 0xc3, 0x79, 0xa0] {
        let n = U256::from_be_slice(&out[36..68]).saturating_to::<usize>();
        if let Some(s) = out.get(68..68 + n) {
            return String::from_utf8_lossy(s).into_owned();
        }
    }
    alloy_primitives::hex::encode_prefixed(out)
}
