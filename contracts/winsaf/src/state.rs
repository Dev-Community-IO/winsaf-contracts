//! Persistent state for the consolidated WinSaf contract.
//!
//! All four former subsystems keep their storage here, in one contract:
//!
//! Lottery:
//! - [`CONFIG`] `Item<Config>` — protocol parameters, roles & randomness config.
//! - [`CURRENT_ROUND`] `Item<u64>` — id of the round currently open.
//! - [`ROUNDS`] `Map<u64, Round>` — every round by id.
//! - [`TICKETS`] `Map<(u64,&str), Ticket>` — tickets keyed by `(round_id, ticket_id)`;
//!   ticket_id is the zero-padded per-round sequence so range scans are ordered.
//! - [`TICKET_SEQ`] `Map<u64, u64>` — next ticket sequence per round.
//! - [`PLAYERS`] `Map<(u64,&Addr), u8>` — presence set to count distinct players.
//!
//! Treasury:
//! - [`TREASURY`] `Item<Uint128>` — the in-contract treasury balance (usaf).
//!   The treasury cut of each buy accrues here; the admin withdraws from it.
//!
//! Referral:
//! - [`REFERRER`] `Map<&Addr, Addr>` — `referee -> referrer` (set once, immutable).
//! - [`REFERRAL_EARNINGS`] `Map<&Addr, Uint128>` — `referrer -> accrued usaf`.
//! - [`REFERRAL_CODES`] `Map<&str, Addr>` — `code (lowercased) -> referrer`.
//! - [`REFERRAL_TOTALS`] `Map<&Addr, ReferrerTotals>` — lifetime aggregates.
//!
//! Randomness:
//! - [`RANDOMNESS`] `Map<u64, RandomnessRequest>` — per-round randomness state
//!   (commitment / delivered randomness / signature).
//!
//! All monetary fields are integer `usaf` [`Uint128`]; every decrement uses
//! checked math and can never go negative.

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Coin, HexBinary, Uint128};
use cw_storage_plus::{Item, Map};
use winsaf_shared::{FundSplitBps, RoundStatus};

// ===========================================================================
// Randomness configuration types (ported from randomness-beacon)
// ===========================================================================

/// Which randomness mechanism this contract operates.
#[cw_serde]
pub enum RandomnessMode {
    /// External drand beacon delivered by an authorized relayer.
    Drand,
    /// On-chain commit-reveal fallback.
    CommitReveal,
    /// Localnet mock: any authorized submitter can push randomness with no
    /// crypto verification. NEVER for mainnet.
    Mock,
}

impl RandomnessMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            RandomnessMode::Drand => "drand",
            RandomnessMode::CommitReveal => "commit_reveal",
            RandomnessMode::Mock => "mock",
        }
    }
}

/// How delivered drand randomness is verified before it is accepted.
#[cw_serde]
pub enum VerifyMode {
    /// Full drand BLS verification against `drand_pubkey` + `drand_chain_hash`.
    /// The ONLY mode that should be used on mainnet with `RandomnessMode::Drand`.
    Bls,
    /// Development verifier: structural checks only (length, randomness ==
    /// sha256(sig)) — NO BLS pairing check. Gated behind config so it can never
    /// be silently active in production.
    Dev,
}

// ===========================================================================
// Config
// ===========================================================================

/// Protocol configuration and privileged roles. Mutable by `admin` via
/// `SetConfig`. Consolidates config from all four former contracts.
#[cw_serde]
pub struct Config {
    /// Address allowed to change config, pause/unpause, withdraw treasury and
    /// manage submitters.
    pub admin: Addr,
    /// Base micro-denom everything is accounted and paid in (`usaf`).
    pub denom: String,
    /// Fixed ticket price. Denom must equal `denom`.
    pub ticket_price: Coin,
    /// Seconds a round stays open before it may be closed (`opens_at + interval`).
    pub draw_interval: u64,
    /// How many distinct numbers each ticket picks (default 6).
    pub numbers_per_ticket: u8,
    /// Inclusive upper bound of the number domain `1..=number_max` (default 45).
    pub number_max: u8,
    /// Revenue split in bps (prize / referral / treasury), sums to 10_000.
    pub split: FundSplitBps,
    /// If true and a round has no jackpot winner, its leftover prize pool rolls
    /// into the next round instead of being retained.
    pub rollover_on_no_winner: bool,
    /// Global kill-switch: when true, ticket sales are blocked.
    pub paused: bool,
    /// Randomness mechanism (mock / drand / commit-reveal).
    pub randomness_mode: RandomnessMode,
    /// How drand randomness is verified (bls / dev).
    pub verify_mode: VerifyMode,
    /// drand group public key (BLS12-381 G1, 48 bytes). Empty unless drand+bls.
    pub drand_pubkey: HexBinary,
    /// drand chain hash — identifies the beacon chain the pubkey belongs to.
    pub drand_chain_hash: String,
    /// Addresses permitted to submit randomness / commit / reveal. The admin is
    /// always implicitly authorized.
    pub authorized_submitters: Vec<Addr>,
    /// Minimum accrued earnings (usaf) a referrer must hold before `ClaimReferral`.
    pub min_claim_usaf: Uint128,
}

impl Config {
    /// Whether `addr` may submit randomness, commit or reveal.
    /// The admin is always implicitly authorized.
    pub fn is_submitter(&self, addr: &Addr) -> bool {
        *addr == self.admin || self.authorized_submitters.iter().any(|a| a == addr)
    }

    /// Whether `addr` is the admin.
    pub fn is_admin(&self, addr: &Addr) -> bool {
        *addr == self.admin
    }
}

// ===========================================================================
// Lottery types
// ===========================================================================

/// Prize amount assigned to each matching tier. `tier_N` is the reward for a
/// ticket matching exactly N of the winning numbers. `tier_6` is the jackpot.
/// Computed at draw time from the round pool and the number of winners per tier
/// so the contract only ever promises what it holds.
#[cw_serde]
#[derive(Default)]
pub struct PrizeTiers {
    /// Per-winner payout for a 3-match.
    pub tier_3: Uint128,
    /// Per-winner payout for a 4-match.
    pub tier_4: Uint128,
    /// Per-winner payout for a 5-match.
    pub tier_5: Uint128,
    /// Per-winner payout for a 6-match (jackpot).
    pub tier_6: Uint128,
}

/// A single lottery round.
#[cw_serde]
pub struct Round {
    /// Monotonic round id (also the storage key).
    pub id: u64,
    /// Lifecycle state: `Open` (selling) → `Drawing` (closed) →
    /// `Drawn` (numbers known / prizes fixed) → `Settled` (finalized).
    pub status: RoundStatus,
    /// Prize pool held in-contract for this round (usaf). Decremented on claims.
    pub pool: Uint128,
    /// Total tickets sold.
    pub ticket_count: u64,
    /// Distinct player count.
    pub player_count: u64,
    /// Unix seconds the round opened.
    pub opens_at: u64,
    /// Unix seconds the round may be closed at / after.
    pub closes_at: u64,
    /// Winning numbers, present once a draw has run.
    pub winning_numbers: Option<Vec<u8>>,
    /// Per-tier payouts fixed at draw time.
    pub prize_tiers: PrizeTiers,
    /// If this round was seeded by a rollover, the round id the pool came from.
    pub rolled_over_from: Option<u64>,
    /// Number of tickets that won a non-zero prize (any tier).
    pub winning_tickets: u64,
}

impl Round {
    /// A fresh open round with an (optional) rolled-over pool.
    pub fn new_open(
        id: u64,
        opens_at: u64,
        closes_at: u64,
        pool: Uint128,
        rolled_over_from: Option<u64>,
    ) -> Self {
        Round {
            id,
            status: RoundStatus::Open,
            pool,
            ticket_count: 0,
            player_count: 0,
            opens_at,
            closes_at,
            winning_numbers: None,
            prize_tiers: PrizeTiers::default(),
            rolled_over_from,
            winning_tickets: 0,
        }
    }
}

/// A purchased ticket.
#[cw_serde]
pub struct Ticket {
    /// Buyer / prize recipient.
    pub owner: Addr,
    /// The `numbers_per_ticket` distinct picks (sorted ascending).
    pub numbers: Vec<u8>,
    /// How many of `numbers` matched the winning numbers. `0` until drawn.
    pub matches: u8,
    /// Prize owed to this ticket (usaf). `0` until drawn / non-winning.
    pub prize: Uint128,
    /// Whether the prize has been claimed. Guards double-spend.
    pub claimed: bool,
}

// ===========================================================================
// Referral types
// ===========================================================================

/// Per-referrer lifetime aggregates, surfaced by the `ReferralSummary` query.
///
/// `pending` is NOT stored here (it lives in [`REFERRAL_EARNINGS`], the source of
/// truth for claims); the summary query joins the two.
#[cw_serde]
#[derive(Default)]
pub struct ReferrerTotals {
    /// Number of referees bound to this referrer.
    pub referees: u64,
    /// Lifetime earnings attributed (claimed + pending), in usaf.
    pub lifetime_earned: Uint128,
    /// Lifetime earnings already claimed, in usaf.
    pub lifetime_claimed: Uint128,
}

// ===========================================================================
// Randomness types
// ===========================================================================

/// Lifecycle of a round's randomness.
#[cw_serde]
pub enum RandomnessStatus {
    /// Awaiting randomness (or a commitment).
    Pending,
    /// Commit-reveal only: a commitment hash is stored, awaiting reveal.
    Committed,
    /// Randomness delivered and verified. The round can be drawn.
    Fulfilled,
}

/// The randomness state for a single lottery round.
#[cw_serde]
pub struct RandomnessRequest {
    /// The lottery round this randomness is for.
    pub round_id: u64,
    /// The drand/beacon round the randomness must correspond to. For
    /// commit-reveal / mock this mirrors `round_id`.
    pub beacon_round: u64,
    /// Current status.
    pub status: RandomnessStatus,
    /// Commit-reveal: the committed `sha256(value)` hash. `None` otherwise.
    pub commitment: Option<HexBinary>,
    /// The 32-byte verified randomness once delivered. `None` while pending.
    pub randomness: Option<HexBinary>,
    /// The beacon signature that was verified (audit trail). `None` otherwise.
    pub signature: Option<HexBinary>,
}

// ===========================================================================
// Storage items
// ===========================================================================

// --- Lottery ---------------------------------------------------------------

pub const CONFIG: Item<Config> = Item::new("config");

/// Id of the round currently accepting tickets.
pub const CURRENT_ROUND: Item<u64> = Item::new("current_round");

/// All rounds keyed by id.
pub const ROUNDS: Map<u64, Round> = Map::new("rounds");

/// Tickets keyed by `(round_id, ticket_id)`. `ticket_id` is a zero-padded
/// decimal sequence so lexical range scans return tickets in purchase order.
pub const TICKETS: Map<(u64, &str), Ticket> = Map::new("tickets");

/// Next ticket sequence number per round.
pub const TICKET_SEQ: Map<u64, u64> = Map::new("ticket_seq");

/// Presence set of distinct players per round: key `(round_id, player)`.
pub const PLAYERS: Map<(u64, &Addr), u8> = Map::new("players");

// --- Treasury --------------------------------------------------------------

/// The in-contract treasury balance (usaf). Accrues the treasury cut of each
/// buy; decremented by admin `WithdrawTreasury`.
pub const TREASURY: Item<Uint128> = Item::new("treasury");

// --- Referral --------------------------------------------------------------

/// `referee -> referrer`. Presence means the referee is permanently bound.
pub const REFERRER: Map<&Addr, Addr> = Map::new("referrer");

/// `referrer -> accrued, unclaimed usaf`. Absent key == zero.
pub const REFERRAL_EARNINGS: Map<&Addr, Uint128> = Map::new("referral_earnings");

/// `code (lowercased) -> referrer`. Index for `BindReferrer { code }`.
pub const REFERRAL_CODES: Map<&str, Addr> = Map::new("referral_codes");

/// `referrer -> lifetime aggregates`. Absent key == default (all zero).
pub const REFERRAL_TOTALS: Map<&Addr, ReferrerTotals> = Map::new("referral_totals");

// --- Randomness ------------------------------------------------------------

/// Per-round randomness state keyed by lottery round id.
pub const RANDOMNESS: Map<u64, RandomnessRequest> = Map::new("randomness");
