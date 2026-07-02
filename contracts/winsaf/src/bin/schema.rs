//! Generates the JSON API schema for the consolidated winsaf contract.
//!
//! Run with `cargo schema` (see `.cargo/config.toml`) from this crate; it writes
//! `schema/winsaf.json` + per-message files under `schema/` for the CosmJS
//! client SDK to consume.

use cosmwasm_schema::write_api;

use winsaf::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        execute: ExecuteMsg,
        query: QueryMsg,
        migrate: MigrateMsg,
    }
}
