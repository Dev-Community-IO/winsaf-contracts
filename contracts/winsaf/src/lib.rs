//! # WinSaf — the single, self-contained lottery contract
//!
//! One CosmWasm contract for **Safrochain** (wasmvm 2.2.x, Cosmos SDK v0.50)
//! that internalizes everything the WinSaf system used to split across four
//! contracts. There are **no inter-contract calls**:
//!
//! - **Lottery** — rounds, ticket sales in `usaf`, per-purchase fund split into
//!   prize / referral / treasury buckets, on-chain randomness draws and
//!   pull-based prize claims.
//! - **Treasury** — the treasury cut of each buy accrues in-contract on a
//!   tracked balance; the admin withdraws it via `WithdrawTreasury`.
//! - **Referral** — the referral cut credits an internal per-referrer earnings
//!   ledger; referrers pull their balance via `ClaimReferral`. Bindings are
//!   set once, immutable, self-referral blocked.
//! - **Randomness** — authorized submitters push randomness (mock / drand /
//!   commit-reveal) which is verified in-contract and consumed by `Draw`.
//!
//! ## Modules
//! - [`contract`] — entry points (`instantiate`/`execute`/`query`/`migrate`) + logic.
//! - [`msg`]      — `InstantiateMsg`/`ExecuteMsg`/`QueryMsg`/`MigrateMsg` + responses.
//! - [`state`]    — all storage (`Item`/`Map`) and the persisted types.
//! - [`error`]    — [`error::ContractError`].
//! - [`verify`]   — randomness verification (mock / drand-BLS / commit-reveal).
//!
//! ## Money & randomness invariants (see the Safrochain facts)
//! - All amounts are integer `usaf` (`Uint128`); overflow-checks stay on and all
//!   arithmetic is checked/saturating.
//! - Funds in == `ticket_price * count`; the split always sums to 10_000 bps.
//! - Every `usaf` a buyer pays is accounted: prize pool + referral ledger +
//!   treasury balance == the amount paid (rounding dust goes to treasury).
//! - The prize pool is tracked per round and can never be paid below zero.
//! - A ticket is claimable exactly once by its owner.
//! - Winning numbers come ONLY from verified submitted randomness (never from
//!   block hash/time). Mock verification is structural-only — NEVER for mainnet.

#![forbid(unsafe_code)]

pub mod contract;
pub mod error;
pub mod msg;
pub mod state;
pub mod verify;

pub use crate::error::ContractError;
