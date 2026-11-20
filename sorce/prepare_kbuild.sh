#!/bin/bash
set -e

export PATH="/mnt/d/adb/kernel_workspace/clang18/bin:/mnt/d/adb/kernel_workspace/build-tools/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_TREE="${SRC_TREE:-/mnt/d/adb/kernel_workspace/common}"
OUT_DIR="${OUT_DIR:-/tmp/okg_kbuild_out}"
BASE_CFG="${BASE_CFG:-/mnt/d/adb/kernel/.config}"
SYMVERS="${SYMVERS:-$SCRIPT_DIR/stock_sym_crcs.txt}"

if [ ! -d "$SRC_TREE" ]; then
    echo "ERROR: Kernel source tree not found: $SRC_TREE" >&2
    exit 1
fi
if [ ! -f "$BASE_CFG" ]; then
    echo "ERROR: Base .config not found: $BASE_CFG" >&2
    exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
cp -f "$BASE_CFG" "$OUT_DIR/.config"

# 精确对齐 MT6991 目标内核 vermagic 与模块选项
sed -i '/^CONFIG_LOCALVERSION=/d;/^CONFIG_LOCALVERSION_AUTO=/d;/^CONFIG_MODULE_SIG_ALL=/d' "$OUT_DIR/.config"
cat << 'EOF' >> "$OUT_DIR/.config"
CONFIG_LOCALVERSION="-android15-8-o-g15bab650beb0-4k"
# CONFIG_LOCALVERSION_AUTO is not set
# CONFIG_MODULE_SIG_ALL is not set
EOF

make -C "$SRC_TREE" O="$OUT_DIR" LLVM=1 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- LOCALVERSION="" olddefconfig
make -C "$SRC_TREE" O="$OUT_DIR" LLVM=1 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- LOCALVERSION="" -j"$(nproc --all)" modules_prepare

cp -f "$SYMVERS" "$OUT_DIR/Module.symvers"
echo "KBUILD_READY: $OUT_DIR"
echo "UTS_RELEASE=$(cat "$OUT_DIR/include/config/kernel.release" 2>/dev/null || echo unknown)"
