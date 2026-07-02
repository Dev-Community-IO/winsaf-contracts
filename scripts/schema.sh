#!/usr/bin/env bash
#
# Regenerate JSON schemas for every contract in the workspace.
#
# Each contract crate is expected to provide a `src/bin/schema.rs` binary that
# calls `cosmwasm_schema::write_api!`. This script runs `cargo run --bin schema`
# for each such crate, emitting `<crate>/schema/*.json`. Those schemas are what
# the CosmJS / @winsaf clients use to generate typed message builders.
#
# It can run either locally (needs the Rust toolchain) or inside the optimizer
# image for a hermetic build (SCHEMA_IN_DOCKER=1).
#
# Usage:
#   ./scripts/schema.sh
#   SCHEMA_IN_DOCKER=1 ./scripts/schema.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONTRACTS_DIR="${WORKSPACE_DIR}/contracts"

generate_local() {
  shopt -s nullglob
  local found=0
  for crate_dir in "${CONTRACTS_DIR}"/*/; do
    [[ -f "${crate_dir}/Cargo.toml" ]] || continue
    if [[ ! -f "${crate_dir}/src/bin/schema.rs" ]]; then
      echo "==> Skipping $(basename "${crate_dir}"): no src/bin/schema.rs"
      continue
    fi
    found=1
    local name
    name="$(basename "${crate_dir}")"
    echo "==> Generating schema for ${name}"
    ( cargo run --manifest-path "${crate_dir}/Cargo.toml" --bin schema )
    echo "    -> ${crate_dir}schema/"
  done
  if [[ "${found}" -eq 0 ]]; then
    echo "==> No contract crates with a schema binary found under ${CONTRACTS_DIR}."
    echo "    Add a contract under contracts/ with src/bin/schema.rs to generate schemas."
  fi
}

if [[ "${SCHEMA_IN_DOCKER:-0}" == "1" ]]; then
  echo "==> Generating schemas inside cosmwasm/optimizer:0.16.0"
  docker run --rm \
    -v "${WORKSPACE_DIR}":/code \
    -v "winsaf_cache_target":/target \
    -v "winsaf_cache_registry":/usr/local/cargo/registry \
    --entrypoint /bin/bash \
    cosmwasm/optimizer:0.16.0 \
    -c 'set -e; cd /code; for d in contracts/*/; do
          [ -f "$d/src/bin/schema.rs" ] || continue;
          echo "==> schema: $d";
          cargo run --manifest-path "$d/Cargo.toml" --bin schema;
        done'
else
  generate_local
fi

echo "==> Schema generation complete."
