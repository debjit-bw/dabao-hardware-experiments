#!/bin/bash
# Build a dabao device image: our engine as an XIP service in the system image
# (xous.img), and one detached app (default: eth-burner) in the apps image.
#
#   scripts/build-device.sh [path/to/app-elf] [extra xtask args...]
#
# Afterwards it checks both images against their real RRAM regions, because
# xous-sign-image only checks the system image against the *end of RRAM*
# (its "N bytes free remaining" ignores dabao's app region), and boot1 accepts
# UF2 writes anywhere from the loader to the end of storage. An oversized
# xous.img would silently overwrite the start of the apps image; the loader
# would then report "No valid detached app found" (or KERNFAIL, depending on
# flash order). Recoverable by reflashing, but confusing; so fail the build.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
XOUS_CORE="${XOUS_CORE:-$here/../dabao-workshop/xous-core}"
XOUS_CORE="$(cd "$XOUS_CORE" && pwd)"
app="${1:-$XOUS_CORE/../ethereum-app/dabao-app-eth-burner/target/riscv32imac-unknown-xous-elf/release/eth-burner}"
shift || true
app="$(cd "$(dirname "$app")" && pwd)/$(basename "$app")"

# Region sizes, from xous-core libs/bao1x-api/src/offsets/{common,dabao}.rs and signatures.rs:
#   SIGBLOCK_LEN   = 0x300
#   KERNEL_START   = 0x600A_0000 - SIGBLOCK_LEN
#   APP_RRAM_START = 0x6030_0000 - SIGBLOCK_LEN
#   APP_RRAM_LEN   = 0xD_A000 + SIGBLOCK_LEN      (ends exactly at RRAM_STORAGE_LEN = 0x3D_A000)
SYSTEM_MAX=$(( 0x260000 ))   # APP_RRAM_START - KERNEL_START
APPS_MAX=$(( 0xDA300 ))      # APP_RRAM_LEN

(cd "$here" && cargo build --release -p engine-spike --target riscv32imac-unknown-xous-elf)
engine="$here/target/riscv32imac-unknown-xous-elf/release/engine-spike"

# Upstream's Rust 1.100 fix (betrusted-io/xous-core#1023) keeps ONE target/SVD_PATH shared by
# all targets. Any hosted build (e.g. `cargo xtask dabao-emu`) rewrites it empty, and a cached
# riscv utralib won't rewrite it, so xtask panics (`index out of bounds` in builder.rs) or, with
# --change-target, hits NotFound. Touching the SVD reruns utralib's build script (slower rebuild).
if [ ! -s "$XOUS_CORE/target/SVD_PATH" ]; then
    echo "target/SVD_PATH missing or empty (hosted build since last device build?): forcing utralib rerun"
    touch "$XOUS_CORE/utralib/bao1x/core.svd"
fi

(cd "$XOUS_CORE" && cargo xtask dabao "$app" --feature usb-bao1x/generic-hid \
    --service "engine-spike~flash:$engine" "$@")

out="$XOUS_CORE/target/riscv32imac-unknown-xous-elf/release"
fail=0
check() { # name file max
    local size; size=$(stat -f %z "$2")
    if (( size > $3 )); then
        echo "ERROR: $1 is $size bytes, region is $3 ($(( size - $3 )) bytes over)" >&2; fail=1
    else
        echo "$1: $size / $3 bytes ($(( $3 - size )) free)"
    fi
}
check "system image (xous.img)" "$out/xous.img" $SYSTEM_MAX
check "apps image (apps.img)" "$out/apps.img" $APPS_MAX
(( fail == 0 )) || exit 1
echo "UF2s: $out/{loader,xous,apps}.uf2"
