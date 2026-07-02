//! # winsaf-shared
//!
//! Shared types, constants and helpers for the WinSaf lottery contracts on
//! **Safrochain** (CosmWasm / wasmvm 2.2.x, Cosmos SDK v0.50).
//!
//! This crate is deliberately free of contract entry points — it is a plain
//! library consumed by every contract in the workspace to keep money math,
//! fund-split validation, round lifecycle and randomness-beacon handling
//! consistent across the whole system.
//!
//! ## Modules
//! - [`constants`] — protocol invariants (denom, decimals, bps, economics defaults).
//! - [`error`]     — [`SharedError`] variants reused by contract error enums.
//! - [`money`]     — `usaf` payment validation helpers.
//! - [`split`]     — [`FundSplitBps`] revenue split (prize / referral / treasury).
//! - [`status`]    — [`RoundStatus`] lottery-round state machine.
//! - [`beacon`]    — [`BeaconRef`] external drand/nois randomness references.
//!
//! ## Safrochain facts baked into this crate
//! - Base denom is `usaf`; `1 SAF = 1_000_000 usaf`; amounts are integer usaf.
//! - Address HRP is `addr_safro`, coin type 118, secp256k1.
//! - Randomness comes from an external beacon (drand/nois) or commit-reveal —
//!   never from block hash or block time.
//! - There is NO EVM. This is CosmWasm-only.

#![forbid(unsafe_code)]

pub mod beacon;
pub mod constants;
pub mod error;
pub mod money;
pub mod split;
pub mod status;

// --- Flat re-exports for ergonomic `use winsaf_shared::{...}` ----------------

pub use beacon::{BeaconRef, BeaconSource};
pub use constants::{
    BECH32_PREFIX, BPS_DENOM, COIN_TYPE, DEFAULT_DRAW_INTERVAL_SECONDS, DEFAULT_NUMBER_MAX,
    DEFAULT_NUMBER_MIN, DEFAULT_PICK_COUNT, DEFAULT_PRIZE_BPS, DEFAULT_REFERRAL_BPS,
    DEFAULT_TICKET_PRICE_USAF, DEFAULT_TREASURY_BPS, DENOM, DISPLAY_DENOM, SAF_DECIMALS,
    USAF_PER_SAF,
};
pub use error::SharedError;
pub use money::{assert_exact_usaf, assert_min_usaf, must_pay_usaf_only, saf_to_usaf, usaf};
pub use split::{FundSplitBps, SplitAmounts};
pub use status::RoundStatus;
