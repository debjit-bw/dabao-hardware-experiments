#!/bin/bash
# Build a dabao device image. Default: the verifier (process 2) as an XIP service in the
# system image (xous.img); the signer (process 3) also in the system image, as PID 3 in place
# of the keystore (fork xtask --trusted-service); the transport (process 1, USB HID) in the
# apps image.
#
# DABAO_SIGNER_ADDRESS=0x...: the signer then never creates a key, and refuses to run unless
# the RRAM slots hold the key for this address.
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
# not $XOUS_CORE: other projects export it, and our crates always build against the submodule
XOUS_CORE="${DABAO_XOUS_CORE:-$here/vendor/xous-core}"
XOUS_CORE="$(cd "$XOUS_CORE" && pwd)"
echo "xous-core: $XOUS_CORE"
app="${1:-$here/target/riscv32imac-unknown-xous-elf/release/transport}"
shift || true
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

# Reproducible images: the same commit must give the same bytes on any machine.
# - xous-core stamps build times into ticktimer, boot0 and boot1 unless SOURCE_DATE_EPOCH is
#   set; use the commit's own time.
# - rustc embeds absolute source paths (panic locations); map the checkout, the Cargo home and
#   the toolchain to fixed names. The device targets already have rustflags in xous-core's
#   .cargo/config.toml; target-specific variables repeat them, because they take precedence.
: "${SOURCE_DATE_EPOCH:=$(git -C "$here" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
cargo_home="$(cd "$cargo_home" && pwd)"
sysroot="$(cd "$XOUS_CORE" && rustc --print sysroot)"
case "$here$cargo_home$sysroot" in *" "*)
    echo "ERROR: the checkout, CARGO_HOME and toolchain paths must not contain spaces (rustflags are space-separated)" >&2
    exit 1 ;;
esac
remap="--remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$here=/build --remap-path-prefix=$sysroot=/rust"
export CARGO_TARGET_RISCV32IMAC_UNKNOWN_XOUS_ELF_RUSTFLAGS="--cfg curve25519_dalek_backend=\"u32e_backend\" $remap"
export CARGO_TARGET_RISCV32IMAC_UNKNOWN_NONE_ELF_RUSTFLAGS="--cfg curve25519_dalek_backend=\"fiat\" $remap"

SERVICE="${SERVICE:-verifier}"
svc_features=()
[ "$SERVICE" = verifier ] && svc_features=(--features board-dabao)
# our crates have no rustflags of their own: only the remap, not xous-core's --cfg
(cd "$here" && CARGO_TARGET_RISCV32IMAC_UNKNOWN_XOUS_ELF_RUSTFLAGS="$remap" cargo build --release -p "$SERVICE" --target riscv32imac-unknown-xous-elf ${svc_features[@]+"${svc_features[@]}"})
(cd "$here" && CARGO_TARGET_RISCV32IMAC_UNKNOWN_XOUS_ELF_RUSTFLAGS="$remap" cargo build --release -p transport --target riscv32imac-unknown-xous-elf --features board-dabao,bao1x)
(cd "$here" && CARGO_TARGET_RISCV32IMAC_UNKNOWN_XOUS_ELF_RUSTFLAGS="$remap" cargo build --release -p signer --target riscv32imac-unknown-xous-elf --features board-dabao,bao1x)
# the signer runs as PID 3 in the system image, and the keystore is left out (unless building
# something else: then the stock keystore stays)
trusted=()
[ "$SERVICE" = verifier ] && trusted=(--trusted-service "signer~flash:$here/target/riscv32imac-unknown-xous-elf/release/signer")
[ -n "${DABAO_SIGNER_ADDRESS:-}" ] && echo "signer: expects $DABAO_SIGNER_ADDRESS, never creates a key"
engine="$here/target/riscv32imac-unknown-xous-elf/release/$SERVICE"
# Paths are made absolute (xtask runs in $XOUS_CORE); bare names are xous-core app crates.
# Only now: on a fresh clone the default app's directory doesn't exist until the builds above.
case "$app" in */*)
    [ -f "$app" ] || { echo "ERROR: app not found: $app" >&2; exit 1; }
    app_dir="$(cd "$(dirname "$app")" && pwd)"
    app="$app_dir/$(basename "$app")" ;;
esac

# Upstream's Rust 1.100 fix (betrusted-io/xous-core#1023) keeps ONE target/SVD_PATH shared by
# all targets. Any hosted build (e.g. `cargo xtask dabao-emu`) rewrites it empty, and a cached
# riscv utralib won't rewrite it, so xtask panics (`index out of bounds` in builder.rs) or, with
# --change-target, hits NotFound. Touching the SVD reruns utralib's build script (slower rebuild).
if [ ! -s "$XOUS_CORE/target/SVD_PATH" ]; then
    echo "target/SVD_PATH missing or empty (hosted build since last device build?): forcing utralib rerun"
    touch "$XOUS_CORE/utralib/bao1x/core.svd"
fi

# Image signing embeds `git describe`, which needs upstream's version tags. A clone of the fork
# has none, so give the pinned commit's version. (Another commit must bring its own tags.)
PINNED_REV=ec255a6cffa493f872544b428fe420fd92073b55
PINNED_DESCRIBE=v0.10.2-183-gec255a6cf
version_args=()
if ! git -C "$XOUS_CORE" describe --long --match 'v[0-9]*' >/dev/null 2>&1; then
    if [ "$(git -C "$XOUS_CORE" rev-parse HEAD)" = "$PINNED_REV" ]; then
        version_args=(--git-describe "$PINNED_DESCRIBE")
        echo "no version tags in xous-core: using $PINNED_DESCRIBE (the pinned commit)"
    else
        echo "ERROR: xous-core has no version tags to sign images with. Run:" >&2
        echo "  git -C '$XOUS_CORE' fetch https://github.com/betrusted-io/xous-core.git 'refs/tags/v*:refs/tags/v*'" >&2
        exit 1
    fi
fi

# FIRMWARE_KEY: sign loader, kernel and apps with our own key instead of the developer key.
# Only a boot1 that carries that key (docs/custom-boot1.md) boots such images. The board's stock
# boot1 refuses them, so don't flash them there.
if [ -n "${FIRMWARE_KEY:-}" ]; then
    [ -f "$FIRMWARE_KEY" ] || { echo "ERROR: FIRMWARE_KEY not found: $FIRMWARE_KEY" >&2; exit 1; }
    FIRMWARE_KEY="$(cd "$(dirname "$FIRMWARE_KEY")" && pwd)/$(basename "$FIRMWARE_KEY")"
    version_args+=(--lkey "$FIRMWARE_KEY" --kkey "$FIRMWARE_KEY")
    echo "WARNING: signing with $FIRMWARE_KEY. These images boot only under our own boot1, not the stock one."
fi

(cd "$XOUS_CORE" && cargo xtask dabao "$app" ${trusted[@]+"${trusted[@]}"} ${usb_feature[@]+"${usb_feature[@]}"} \
    ${version_args[@]+"${version_args[@]}"} --service "$SERVICE~flash:$engine" "$@")

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
