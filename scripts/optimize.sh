#!/usr/bin/env bash
# ============================================================================
# Build a Safrochain-compatible optimized wasm for the `winsaf` contract.
#
# IMPORTANT: Safrochain's wasmvm v2.2.4 has BULK-MEMORY DISABLED. The stock
# cosmwasm/optimizer Docker image emits bulk-memory ops (memory.copy/fill) and
# its artifacts are REJECTED on-chain ("bulk memory support is not enabled").
# So we build with the host toolchain and lower bulk-memory with wasm-opt —
# the same two-pass approach the Safrimba contract uses on this chain.
#
# Requires: rustup wasm32-unknown-unknown target, binaryen (`wasm-opt`).
#   brew install binaryen   /   rustup target add wasm32-unknown-unknown
#
# Output: contracts/cosmwasm/artifacts/winsaf.wasm + checksums.txt
# ============================================================================
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

RAW="target/wasm32-unknown-unknown/release/winsaf.wasm"
OUT="artifacts/winsaf.wasm"
mkdir -p artifacts

echo "▸ building winsaf.wasm (release, wasm32-unknown-unknown)…"
cargo build --release --lib --target wasm32-unknown-unknown -p winsaf

command -v wasm-opt >/dev/null || { echo "✗ wasm-opt (binaryen) not found — 'brew install binaryen'"; exit 1; }

echo "▸ pass 1: lowering bulk-memory (memory.copy/fill → loops)…"
wasm-opt --enable-bulk-memory --enable-sign-ext --enable-nontrapping-float-to-int \
  --enable-mutable-globals --enable-multivalue \
  --llvm-memory-copy-fill-lowering "$RAW" -o /tmp/winsaf.nobulk.wasm

echo "▸ pass 2: -Os + strip (bulk-memory NOT re-enabled)…"
wasm-opt -Os --enable-sign-ext --enable-nontrapping-float-to-int \
  --enable-mutable-globals --enable-multivalue \
  --strip-debug --strip-producers --strip-target-features \
  /tmp/winsaf.nobulk.wasm -o "$OUT"
rm -f /tmp/winsaf.nobulk.wasm

# Guards: no bulk-memory ops, no float ops (cosmwasm rejects floats).
BULK="$(wasm-opt --enable-all --print "$OUT" 2>/dev/null | grep -cE 'memory\.copy|memory\.fill' || true)"
FLOAT="$(wasm-opt --enable-all --print "$OUT" 2>/dev/null | grep -cE '\bf32\.|\bf64\.' || true)"
[[ "$BULK" == "0" ]] || { echo "✗ bulk-memory ops still present ($BULK)"; exit 1; }
[[ "$FLOAT" == "0" ]] || { echo "✗ float ops present ($FLOAT) — cosmwasm forbids floats"; exit 1; }

( cd artifacts && shasum -a 256 winsaf.wasm > checksums.txt )
echo "✓ $OUT ($(du -h "$OUT" | cut -f1)) — bulk-memory-free, float-free, Safrochain-compatible"
cat artifacts/checksums.txt
