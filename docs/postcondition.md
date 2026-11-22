# On-chain postcondition: closing the gap between simulation and inclusion

The device simulates a Safe call on a block the light client proved. The agent executes it
later, on whatever state is current then. Anything the call depends on can change in
between: an upgradeable proxy, a token's fee, a pool's price, a contract whose owner flips a
switch. The device's checks would then have checked the wrong transaction.

So the device never co-signs the call itself. It co-signs a **DELEGATECALL to Safe's
MultiSendCallOnly 1.4.1** with two CALLs from the Safe:

1. the simulated call;
2. `DabaoPostcondition.check(device, threshold, assets, floors)`
   ([contracts/src/DabaoPostcondition.sol](../contracts/src/DabaoPostcondition.sol)).

`check` reverts unless, **at inclusion**:

- the device is still an owner, the threshold is unchanged, and there is no module and no guard;
- for every asset (ETH, every asset the policy limits, every token the simulation moved to or
  from the Safe), the Safe's balance is at least its **simulated post-balance minus the
  slippage the user was shown** (the simulated output minus the shown minimum).

If `check` reverts, the whole Safe transaction reverts (GS013: safeTxGas = gasPrice = 0). The
Safe can end up *better* than simulated, never worse.

## Why it can be trusted

| Piece | How the device knows it |
|---|---|
| MultiSendCallOnly | Canonical address. Its code hash `0xecd5…9939` (same on mainnet and Sepolia) is checked in the verified witness. Its batch can only CALL, so the DELEGATECALL can't run arbitrary code as the Safe. |
| DabaoPostcondition | Deployed with the deterministic CREATE2 deployer (salt 0) at `0xf864…310F`, so the address commits to the init code (compiler settings are pinned in `contracts/foundry.toml`). Its code hash is also checked in the witness. This matters: a call to an address without code *succeeds*, which would make the check a no-op. Stateless, no owner, no upgrade path. |
| The floors | The device runs `balances(...)` and then `check(...)` itself, on the simulated post-state (revm with a `CacheDB` over the verified trie: `xous_evm::sim::simulate_then`). It co-signs only if the check passes there. |
| The batch | Built by the verifier (`xous_evm::postcondition::build`). The signer re-checks the shape before hashing: DELEGATECALL only to MultiSendCallOnly, value 0, exactly [call, postcondition]. A bare Safe call (operation CALL) is no longer signed at all. |

The host checks that the batch's first call is exactly the requested one, prints what the
postcondition asserts, compares the SafeTx hash with the Safe's own `getTransactionHash`
(operation 1), and runs a pre-flight via `Safe.simulateAndRevert` (a DELEGATECALL from the Safe's
context on the latest state, no signatures needed).

A useful side effect: a co-signed SafeTx stays valid until its nonce is used, for example
after a revert. With the postcondition, executing it later is safe whenever it happens. It
either does what was shown, or nothing.

## On the board (Sepolia, 2026-11-22)

Demo contract: [contracts/src/DemoPayRouter.sol](../contracts/src/DemoPayRouter.sol) at
`0x1ab7…5Fc7`. `pay(to, amount)` forwards `amount` and refunds the change, unless its owner
has switched on `keepChange`. It's allowlisted and has a 7730 descriptor, as a trusted
contract whose behaviour can still change would.

| Case | Result |
|---|---|
| Safe → 0.0001 ETH to 0x…dEaD, wrapped | co-signed; floor "Safe ≥ 0.00139 ETH"; [executed](https://sepolia.etherscan.io/tx/0xc6508b507b7a81a7279aa043d932fadcd7043578fe914a1eb7440b42e87d4ff8), logs identical. Same SafeTx hash as the host's `--local` run of the same pipeline |
| Safe pays 0.0001 through the router (sends 0.0005, 0.0004 change), and the router's owner switches `keepChange` on **after the device co-signed** (`demo/postcondition/run.sh`) | floor "Safe ≥ 0.00129 ETH". The agent executes anyway (`--force`): **[reverted on chain](https://sepolia.etherscan.io/tx/0xfc14899229365f302888ffcbd471214ee46d96d35dbb52aff638e4a1b5f878df)**, the Safe kept all 0.00139 ETH (without the postcondition it would have lost 0.0005) |
| the same, by accident a second time (a stray run of the script) | [reverted](https://sepolia.etherscan.io/tx/0x3e573dd9b66374ced179275e5810584856538310bbe9e8df73159e7367f58874); the Safe lost nothing |
| the honest router payment (`run.sh honest`) | co-signed, [executed](https://sepolia.etherscan.io/tx/0x64726b33951c06efb71ca981f229259771c4175fd5ee752b9d79a3e1776431d2). The proven parent block was still from before the switch-back, so the device simulated (and showed, and counted) the 0.0005 cost. At inclusion the router refunded the change, so the Safe ended above the floor, which the postcondition allows |

Cost on the device: witness ~95–99 KB (the postcondition reads the policy's assets, and
Sepolia USDC is a proxy, so its code comes along), verifier ~1.0 s including the light client,
peak heap 615–651 KB. The first version kept the witness twice more in RAM (a copy of the
request buffer, and the decoded input during the simulation) and the verifier died on the
router request. Both copies are gone (emulator: 799 → 740 KB, plus the uncounted ~98 KB
buffer copy).

## Limits

- **Allowances aren't asserted.** An approval the call grants is counted by the policy at its
  full amount, but `check` only looks at balances.
- **Strict for exact-output trades.** The floor uses the simulated loss. A swap whose input
  varies (exact output, `amountInMaximum`) reverts if it costs more than simulated, even
  within the shown maximum. That's fail-safe, not fail-open.
- **The light client trails the head by a few blocks.** A Safe transaction simulated right
  after a state change can be simulated on the state before it (row 4). The postcondition
  makes that safe; it can only make the result stricter.
- **Gas.** The batch costs ~30–40k gas more, paid by the executor.
