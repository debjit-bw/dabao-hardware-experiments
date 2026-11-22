//! The on-chain postcondition the device appends to every Safe call it co-signs.
//!
//! The device simulates on a proven parent block, but the Safe transaction executes later, on
//! whatever state is current then. The co-signed SafeTx is therefore not the call itself but a
//! DELEGATECALL to MultiSendCallOnly with two CALLs from the Safe:
//!
//! 1. the simulated call;
//! 2. `DabaoPostcondition.check(device, threshold, assets, floors)`
//!    (contracts/src/DabaoPostcondition.sol), which reverts unless the device is still an
//!    owner, the threshold is unchanged, there is no module and no guard, and the Safe holds
//!    at least `floors[i]` of each asset.
//!
//! `floors` = the Safe's simulated post-balance of each asset, minus the slippage the user was
//! shown for that asset (the simulated output minus the shown minimum). So at inclusion the
//! Safe may end up with more than simulated, or with the shown minimum, but not with less of
//! the assets checked here. Other assets and approvals are not checked.
//! If not, the whole Safe transaction reverts (GS013: safeTxGas = gasPrice = 0).
//!
//! Assets checked: ETH, every asset the policy limits on this chain, and every token the
//! simulation moved to or from the Safe. Allowances are not checked here (the policy counts
//! them at their full amount when granted).

use alloy_primitives::{Address, B256, U256};
use sim_types::{SimResult, SimTx, effect, safe};

use crate::sim::PostCall;

/// What the device co-signs for a Safe call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Postcondition {
    pub assets: Vec<Address>,
    pub floors: Vec<U256>,
    /// `multiSend` calldata: [the call, check(...)].
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
    let (ok, out) = call(safe::POSTCONDITION, safe::balances_calldata(tx.from, &assets))?;
    let post = if ok { safe::decode_uint_array(&out) } else { None };
    let post = post.filter(|p| p.len() == assets.len()).ok_or("postcondition: can't read the Safe's simulated balances")?;
    let floors: Vec<U256> = assets
        .iter()
        .zip(&post)
        .map(|(a, b)| {
            let slack: U256 = sim
                .clear_sign
                .min_receive
                .iter()
                .filter(|m| m.asset == *a)
                .map(|m| m.simulated.saturating_sub(m.shown))
                .fold(U256::ZERO, |x, y| x.saturating_add(y));
            b.saturating_sub(slack)
        })
        .collect();
    let check = safe::check_calldata(device, threshold, &assets, &floors);
    let (ok, out) = call(safe::POSTCONDITION, check.clone())?;
    if !ok {
        return Err(format!("postcondition fails even on the simulated state: {}", revert_reason(&out)));
    }
    let safe_data = safe::multisend_calldata(&[
        safe::Call { to: tx.to, value: tx.value, data: tx.data.to_vec() },
        safe::Call { to: safe::POSTCONDITION, value: U256::ZERO, data: check },
    ]);
    Ok(Postcondition { assets, floors, safe_data })
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
