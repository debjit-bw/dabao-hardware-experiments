#!/bin/bash
# Run the verifier + signer + transport under hosted Xous (cargo xtask dabao-emu). The transport
# listens on 127.0.0.1:$DABAO_PORT (default 7610); talk to it with
#   cargo run -p dabao-host -- send <input.rlp> --tcp 127.0.0.1:7610
# Note: hosted builds empty xous-core's shared target/SVD_PATH; build-device.sh copes.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
XOUS_CORE="${DABAO_XOUS_CORE:-$here/vendor/xous-core}"
(cd "$here" && cargo build --release -p verifier -p signer -p transport)
cd "$XOUS_CORE" && exec cargo xtask dabao-emu "$here/target/release/verifier" "$here/target/release/signer" "$here/target/release/transport"
