#!/usr/bin/env bash
set -euo pipefail

cxx=${CXX:-c++}
root=$(cd "$(dirname "$0")/../.." && pwd)
out=${TMPDIR:-/tmp}/vector-native-module-registry-test
"$cxx" -std=c++23 -O2 -pthread -Wall -Wextra -Werror \
  -I"$root/native/include" \
  "$root/native/tests/native_module_registry_test.cpp" \
  -o "$out"
"$out"
