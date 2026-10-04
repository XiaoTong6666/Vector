#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "Usage: $0 ANDROID_NDK_HOME ABI /path/libfusehide.so ADB_SERIAL" >&2
    exit 2
fi
ndk=$1
abi=$2
library=$3
serial=$4
case "$abi" in
    arm64-v8a) target=aarch64-linux-android31 ;;
    x86_64) target=x86_64-linux-android31 ;;
    *) echo "Unsupported review ABI: $abi" >&2; exit 2 ;;
esac
root=$(cd "$(dirname "$0")/../.." && pwd)
toolchain="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
out="${TMPDIR:-/tmp}/vector-native-dso-registry-$abi"
"$toolchain/${target}-clang++" -std=c++23 -O2 -pthread -static-libstdc++ \
  -I"$root/native/include" \
  "$root/native/tests/native_module_callback_dso_test.cpp" -ldl -o "$out"

remote="/data/local/tmp/vector-native-dso-registry-$$-$abi"
adb -s "$serial" shell "mkdir -p $remote"
trap 'adb -s "$serial" shell "rm -rf $remote" >/dev/null 2>&1 || :' EXIT
adb -s "$serial" push "$out" "$remote/review" >/dev/null
adb -s "$serial" push "$library" "$remote/libfusehide.so" >/dev/null
adb -s "$serial" shell "chmod 755 $remote/review"
adb -s "$serial" shell "$remote/review $remote/libfusehide.so"
