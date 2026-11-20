#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <stub_subdir_name>" >&2
    exit 1
fi

export PATH="/mnt/d/adb/kernel_workspace/clang18/bin:/mnt/d/adb/kernel_workspace/build-tools/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${OUT_DIR:-/tmp/okg_kbuild_out}"
STUB_NAME="$1"
STUB_DIR="$SCRIPT_DIR/stubs/$STUB_NAME"
BUILD_OUT="$SCRIPT_DIR/out"

if [ ! -d "$OUT_DIR/include/config" ]; then
    bash "$SCRIPT_DIR/prepare_kbuild.sh"
fi

mkdir -p "$BUILD_OUT"
rm -f "$STUB_DIR"/*.o "$STUB_DIR"/*.ko "$STUB_DIR"/*.mod* "$STUB_DIR"/.*.cmd "$STUB_DIR"/modules.order "$STUB_DIR"/Module.symvers

make -C "$OUT_DIR" \
    M="$STUB_DIR" \
    LLVM=1 \
    ARCH=arm64 \
    CROSS_COMPILE=aarch64-linux-gnu- \
    LOCALVERSION="" \
    KBUILD_MODPOST_WARN=1 \
    -j"$(nproc --all)" \
    modules

cp -f "$STUB_DIR"/*.ko "$BUILD_OUT/"
echo "BUILT_OK:"
ls -la "$BUILD_OUT"/*.ko
