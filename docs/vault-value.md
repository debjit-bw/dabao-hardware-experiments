# Vault deposits valued on the simulated state

Most of the policy works from the effects the simulation reports: transfers, approvals, the
sender's net gain and loss per asset. Those come from events, and for honest tokens events are
exact. But some losses are invisible in events. A deposit into a vault emits "1 share minted",
and nothing in the log says what that share is worth.

The rule here doesn't use events. After simulating a deposit, the board asks the vault, on the
simulated state after the transaction, what the shares the sender just gained redeem for. It
refuses if they are worth less than what was paid, beyond the policy's slippage allowance.

Code: `crates/xous-evm/src/vaults.rs` (the reads), `crates/policy/src/lib.rs` (the rule),
`contracts/src/DemoVault.sol` (the demo vault), `demo/vault/` (the attack).

## The attack it stops: share inflation

A vault prices its shares as `totalAssets / totalSupply`. Anyone can raise that price by sending
assets straight to the vault. On a new or nearly empty vault:

1. the attacker deposits 1 wei and gets 1 share;
2. the attacker donates 0.00006 ETH to the vault (a plain transfer, no shares);
3. a victim deposits 0.0001 ETH and gets `0.0001 × 1 / 0.00006`, rounded down: **1 share**;
4. the vault now holds 0.00016 ETH for 2 shares. The victim's share is worth 0.00008 ETH, and
   the attacker's share is worth the same: the attacker made 0.00002 ETH.

This is the ERC-4626 "inflation attack". OpenZeppelin's ERC-4626 added virtual shares against
it. Our demo vault deliberately doesn't have them. The attacker is a stranger: the vault has no
owner and nothing can be switched. The vault, the request and the agent are all honest. The
attack is entirely in the chain's state.

What each check sees for the victim's deposit:

| Check | Sees | Verdict |
|---|---|---|
| ERC-7730 | 0.0001 ETH sent (shown), shares minted to the Safe (shown) | "every effect is explained by what is shown" |
| Events-based policy | 0.0001 ETH out, 1 share in, to the sender | nothing wrong |
| This rule | `previewRedeem(1)` on the state after the transaction = 0.00008 ETH | **refused**: 20% less than paid |

## How it works

For each vault listed in the policy whose storage the transaction changed, the verifier runs
three view calls from the sender, on the same verified state as the simulation (revm over the
proven trie):

1. `balanceOf(sender)` before the transaction;
2. `balanceOf(sender)` and `asset()` after it;
3. `previewRedeem(gained shares)` after it.

The policy compares that value with what the sender lost of the vault's asset (its net loss;
for ETH, from the balance changes in the state). It refuses when the value is more than
`maxSlippageBps` below that. A listed vault may keep the deposit. Every other contract still
may not keep funds.

- **The shares are counted from state, not events.** Both balances are read from the vault.
- **The value is the vault's own answer.** `previewRedeem` is what the vault's code says it would
  pay out, run on the state the deposit leaves behind. The vault's code is trusted because it is
  in the policy. A vault whose code lies about redemption is out of scope, like a malicious
  token.
- **It fails closed.** If a read reverts or isn't covered by the witness, the policy refuses
  ("can't value a vault's shares").
- **It runs in both signing modes**: the device's own account and the Safe. Follow-up calls were
  Safe-only before; in direct mode they now run as views at gas price 0 after the transaction.
- **For the Safe, the postcondition backs it up at inclusion.** It requires the Safe to gain at
  least the simulated number of shares. A donation after the board co-signed would mint fewer
  shares, so the Safe transaction would revert.

## On the board (Sepolia, 2026-11-28)

The vault is `DemoVault` at
[`0x1837…F163`](https://sepolia.etherscan.io/address/0x18375B9E9cDA8Cd25ecbCB69AE94c74f7d02F163),
deployed with the CREATE2 deployer (salt 0). Policy v4 lists it as callable and as a vault. The
agent is the Claude API agent (`api_agent.py --scenario vault`), with the same honest prompt and
the same request each time: deposit 0.0001 ETH, shares to the Safe.

| Vault state | Result |
|---|---|
| attacked (`demo/vault/attack.sh`: 1 wei deposit, then a 0.00006 ETH donation, from a stranger's key) | **refused**: "0.0001 ETH buys 0.000000000000000001 dvETH, redeemable for 0.00008 ETH after this transaction: 2000 bps less than paid (policy max 300 bps)". ERC-7730 passed it. The agent reported the refusal and didn't retry ($0.075) |
| after `demo/vault/reset.sh` (the attacker redeems; the vault is empty) | co-signed; the Safe [deposited](https://sepolia.etherscan.io/tx/0xb1db79721258e0fa5fe5e959d4bff34b39099413f5d2fe8ab964c55d608c0db6) and received 0.0001 dvETH, logs identical; the postcondition asserted "Safe gains at least 0.0001 dvETH" ($0.074) |
| the Safe withdraws (`redeem`), so the demo can be repeated | [co-signed and executed](https://sepolia.etherscan.io/tx/0x3038a845575aabd90452c9831ea0fc9d8501334dbb49efa0120d7124ac2275d7), logs identical; verifier 0.92 s, peak heap 378 KB, request 98 KB |

The first withdrawal attempt was refused as "the transaction reverts". The light client trails
the chain head by a few blocks, and the block it proved was from before the deposit was
included, when the Safe had no shares yet. A minute later it went through. This is the
light-client lag described in docs/postcondition.md, not a fault in the rule.

The same rule in the emulator, on live Sepolia state, gave the same two verdicts before the
board was flashed. Host tests: `crates/policy/tests/policy.rs` (`vault_*`, three tests) and
`contracts/test/DemoVault.t.sol` (the attack's arithmetic).

## Run it

```sh
demo/vault/attack.sh
set -a; source claude.env; set +a
python3 demo/agent/api_agent.py --scenario vault
demo/vault/reset.sh
python3 demo/agent/api_agent.py --scenario vault
```

The first agent run must be refused, and the second executes (0.0001 ETH from the Safe into the
vault). To repeat, withdraw the Safe's shares first, because the attack needs an empty vault:

```sh
SAFE=0x265871a72567419AE2f799a1288271C09B589fd9
VAULT=0x18375B9E9cDA8Cd25ecbCB69AE94c74f7d02F163
target/debug/dabao-host --chain sepolia safe send --to $VAULT --data $(cast calldata "redeem(uint256,address,address)" 100000000000000 $SAFE $SAFE) --broadcast
```

The attacker is `.dabao-keys/attacker.key` (gitignored; funded with 0.0005 Sepolia ETH). It gets
its ETH back with `reset.sh`.

## Limits

- **Listed vaults only.** The rule values vaults named in the policy. A deposit into anything
  else is still refused, because the contract would keep the funds.
- **Tested with an ETH vault only.** The reads are ERC-4626's (`asset`, `balanceOf`,
  `previewRedeem`), and the rule handles a token asset through the sender's net loss of it, but
  a token vault needs an approval first and hasn't been tried.
- **Withdrawals aren't valued.** A `redeem` is counted against the share token's daily limit
  (0.002 dvETH), like any spending. Its payout isn't compared with anything.
- **The value isn't asserted on chain.** The postcondition holds the share count, not the value.
  A loss inside the vault between co-signing and inclusion (not a donation, which only raises
  the price) would leave the shares worth less.
- **The vault's code is trusted.** A vault in the policy that lies in `previewRedeem` defeats the
  rule, as a malicious token defeats any balance check.
