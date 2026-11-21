#!/usr/bin/env python3
"""Calldata for a tiny Uniswap V3 swap paid in ETH via SwapRouter02 (Sepolia by default).

Usage: scripts/uniswap-calldata.py <from> [amount_wei] [token_out] [fee] [--multicall] [--slippage-bps N]

Quotes the swap by eth_call-ing exactInputSingle from <from> with value=amount and
amountOutMinimum=0, then sets amountOutMinimum to the quote minus N basis points (default 100 = 1%;
the device's policy refuses more than 300). Prints the calldata: exactInputSingle(...) or multicall(deadline, [exactInputSingle(...)]).
RPC_URL defaults to publicnode Sepolia. Stdlib only.
"""
import json, os, sys, time, urllib.request

RPC = os.environ.get("RPC_URL", "https://ethereum-sepolia-rpc.publicnode.com")
ROUTER = "0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E"   # SwapRouter02, Sepolia
WETH = "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14"     # router's WETH9
USDC = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"     # Circle test USDC, Sepolia


def w(x):  # one ABI word
    if isinstance(x, str):
        return x[2:].lower().rjust(64, "0")
    return format(x, "064x")


def exact_input_single(token_in, token_out, fee, recipient, amount_in, min_out):
    # exactInputSingle((address,address,uint24,address,uint256,uint256,uint160)), all static
    return "04e45aaf" + "".join(w(v) for v in (token_in, token_out, fee, recipient, amount_in, min_out, 0))


def multicall(deadline, calls):
    # multicall(uint256 deadline, bytes[] data)
    head = w(deadline) + w(64)                       # deadline, offset of bytes[]
    arr = w(len(calls))
    offs, bodies, pos = [], [], 32 * len(calls)
    for c in calls:
        b = bytes.fromhex(c)
        body = w(len(b)) + b.hex().ljust(((len(b) + 31) // 32) * 64, "0")
        offs.append(w(pos)); bodies.append(body); pos += len(body) // 2
    return "5ae401dc" + head + arr + "".join(offs) + "".join(bodies)


def eth_call(frm, to, data, value):
    req = {"jsonrpc": "2.0", "id": 1, "method": "eth_call",
           "params": [{"from": frm, "to": to, "data": "0x" + data, "value": hex(value)}, "latest"]}
    r = json.load(urllib.request.urlopen(urllib.request.Request(RPC, json.dumps(req).encode(), {"content-type": "application/json"}), timeout=30))
    if "error" in r:
        sys.exit(f"quote failed: {r['error']}")
    return r["result"]


def main():
    argv = sys.argv[1:]
    bps = 100
    if "--slippage-bps" in argv:
        i = argv.index("--slippage-bps")
        bps = int(argv[i + 1])
        del argv[i:i + 2]
    args = [a for a in argv if a != "--multicall"]
    use_mc = "--multicall" in argv
    if not args:
        sys.exit(__doc__)
    frm = args[0]
    amount = int(args[1]) if len(args) > 1 else 10_000_000_000      # 1e10 wei
    token_out = args[2] if len(args) > 2 else USDC
    fee = int(args[3]) if len(args) > 3 else 500
    quote = int(eth_call(frm, ROUTER, exact_input_single(WETH, token_out, fee, frm, amount, 0), amount), 16)
    min_out = quote * (10_000 - bps) // 10_000
    call = exact_input_single(WETH, token_out, fee, frm, amount, min_out)
    data = multicall(int(time.time()) + 1800, [call]) if use_mc else call
    print(f"# quote: {amount} wei -> {quote} units of {token_out} (fee {fee}); amountOutMinimum {min_out}", file=sys.stderr)
    print("0x" + data)


if __name__ == "__main__":
    main()
