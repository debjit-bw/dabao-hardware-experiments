#!/bin/bash
# Fetch the pinned xous-core (submodule vendor/xous-core, debjit-bw/xous-core at 36861b013 =
# btchip devcon8-workshop + the SVD_PATH backport) and apply this project's patches on top
# (patches/README.md). Idempotent: an already-applied patch is skipped.
#
#   scripts/setup-xous-core.sh            # then: scripts/build-device.sh
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here"
git submodule update --init vendor/xous-core
x="$here/vendor/xous-core"
for p in patches/xous-core-keystore-app-slot-claims.patch; do
    if git -C "$x" apply --reverse --check "$here/$p" 2>/dev/null; then
        echo "already applied: $p"
    else
        git -C "$x" apply "$here/$p"
        echo "applied: $p"
    fi
done
# patch 1 (SVD_PATH) is the pinned commit itself
git -C "$x" apply --reverse --check "$here/patches/xous-core-backport-pr1023-svd-path.patch" && echo "in the pinned commit: patches/xous-core-backport-pr1023-svd-path.patch"
echo "xous-core ready at vendor/xous-core ($(git -C "$x" rev-parse --short HEAD) + patches)"
