//! Generates the JSON API schema for the consolidated winsaf contract.
//!
//! Run with `cargo schema` (see `.cargo/config.toml`) from this crate; it writes
//! `schema/winsaf.json` + per-message files under `schema/` for the CosmJS
//! client SDK to consume.

// This is a NATIVE build tool (`cargo schema`). The `write_api!` macro cannot
// compile for the `wasm32` arch, and there is no reason to build the schema
// generator for wasm. Gate it out on wasm32 so a plain
// `cargo build --target wasm32-unknown-unknown -p winsaf` (which also touches
// this bin target) succeeds; the deployable artifact is the cdylib lib anyway.
#[cfg(not(target_arch = "wasm32"))]
fn main() {
    use cosmwasm_schema::write_api;
    use winsaf::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};

    write_api! {
        instantiate: InstantiateMsg,
        execute: ExecuteMsg,
        query: QueryMsg,
        migrate: MigrateMsg,
    }
}

#[cfg(target_arch = "wasm32")]
fn main() {}
