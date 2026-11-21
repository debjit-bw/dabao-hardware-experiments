#!/bin/bash
# Build a dabao device image. Default: the verifier (process 2) as an XIP service in the
# system image (xous.img); the transport (process 1, USB HID) and the signer (process 3,
# keystore app slots) in the apps image.
#
#   scripts/build-device.sh [path/to/app-elf | xous-core-app-crate] [extra xtask args...]
#   SERVICE=engine-spike GENERIC_HID=0 scripts/build-device.sh dabao-console   # the benchmark spike,
#                                    # with a USB serial console (logs mirrored), no HID
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
app="${1:-$here/target/riscv32imac-unknown-xous-elf/release/transport}"
shift || true
# paths are made absolute (xtask runs in $XOUS_CORE); bare names are xous-core app crates
case "$app" in */*) app="$(cd "$(dirname "$app")" && pwd)/$(basename "$app")" ;; esac
# generic-hid (eth-burner's transport) replaces the composite USB device, so there is no USB
# serial console and logs only reach the DUART (PB13/PB14). GENERIC_HID=0 keeps the console.
usb_feature=(--feature usb-bao1x/generic-hid)
[ "${GENERIC_HID:-1}" = 0 ] && usb_feature=()

# Region sizes, from xous-core libs/bao1x-api/src/offsets/{common,dabao}.rs and signatures.rs:
#   SIGBLOCK_LEN   = 0x300
#   KERNEL_START   = 0x600A_0000 - SIGBLOCK_LEN
#   APP_RRAM_START = 0x6030_0000 - SIGBLOCK_LEN
#   APP_RRAM_LEN   = 0xD_A000 + SIGBLOCK_LEN      (ends exactly at RRAM_STORAGE_LEN = 0x3D_A000)
SYSTEM_MAX=$(( 0x260000 ))   # APP_RRAM_START - KERNEL_START
APPS_MAX=$(( 0xDA300 ))      # APP_RRAM_LEN

SERVICE="${SERVICE:-verifier}"
svc_features=()
[ "$SERVICE" = verifier ] && svc_features=(--features board-dabao)   # keystore slots for policy counters
(cd "$here" && cargo build --release -p "$SERVICE" --target riscv32imac-unknown-xous-elf ${svc_features[@]+"${svc_features[@]}"})
(cd "$here" && cargo build --release -p transport --target riscv32imac-unknown-xous-elf --features board-dabao,bao1x)
(cd "$here" && cargo build --release -p signer --target riscv32imac-unknown-xous-elf --features board-dabao,bao1x)
# the signer goes into the apps image next to the app (unless building something else)
extra_apps=()
[ "$SERVICE" = verifier ] && extra_apps=("$here/target/riscv32imac-unknown-xous-elf/release/signer")
engine="$here/target/riscv32imac-unknown-xous-elf/release/$SERVICE"

# Upstream's Rust 1.100 fix (betrusted-io/xous-core#1023) keeps ONE target/SVD_PATH shared by
# all targets. Any hosted build (e.g. `cargo xtask dabao-emu`) rewrites it empty, and a cached
# riscv utralib won't rewrite it, so xtask panics (`index out of bounds` in builder.rs) or, with
# --change-target, hits NotFound. Touching the SVD reruns utralib's build script (slower rebuild).
if [ ! -s "$XOUS_CORE/target/SVD_PATH" ]; then
    echo "target/SVD_PATH missing or empty (hosted build since last device build?): forcing utralib rerun"
    touch "$XOUS_CORE/utralib/bao1x/core.svd"
fi

(cd "$XOUS_CORE" && cargo xtask dabao "$app" ${extra_apps[@]+"${extra_apps[@]}"} ${usb_feature[@]+"${usb_feature[@]}"} \
    --service "$SERVICE~flash:$engine" "$@")

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
