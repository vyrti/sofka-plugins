#!/bin/sh
set -eu

output=${1:-target/chaos-kill.wasm}
source=target/wasm32-unknown-unknown/wasm-release/sofka_plugin_chaos_kill.wasm

cargo build \
  --locked \
  --profile wasm-release \
  --target wasm32-unknown-unknown \
  --package sofka-plugin-chaos-kill \
  --lib
mkdir -p "$(dirname "$output")"
wasm-opt \
  --enable-bulk-memory \
  -O4 \
  --converge \
  --strip-debug \
  "$source" \
  -o "$output"
