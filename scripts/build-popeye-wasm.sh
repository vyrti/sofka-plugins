#!/bin/sh
set -eu

output=${1:-target/popeye.wasm}
source=target/wasm32-unknown-unknown/wasm-release/sofka_plugin_popeye.wasm

cargo build \
  --locked \
  --profile wasm-release \
  --target wasm32-unknown-unknown \
  --package sofka-plugin-popeye \
  --lib
mkdir -p "$(dirname "$output")"
wasm-opt \
  --enable-bulk-memory \
  -O4 \
  --converge \
  --strip-debug \
  "$source" \
  -o "$output"
