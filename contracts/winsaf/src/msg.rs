//! Message & response types for the consolidated WinSaf contract.
//!
//! All types derive `JsonSchema` (via `cw_serde` / `cosmwasm_schema`) so the
//! `schema` binary can emit a JSON API consumed by the CosmJS client SDK.
//!
//! The deploy script depends on [`InstantiateMsg`]'s exact shape — every
//! `Option` field has a sane default so a bare `{}`-ish instantiate works.

use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Coin, HexBinary, Uint128};
use winsaf_shared::{FundSplitBps, RoundStatus};

use crate::state::{PrizeTiers, RandomnessMode, RandomnessRequest, Ticket, VerifyMode};

// ===========================================================================
// Instantiate
// ===========================================================================

/// Instantiate parameters. Every `Option` has a sane default (see the field
/// docs); the deploy script relies on this exact layout.
#[cw_serde]
pub struct InstantiateMsg {
    /// Admin address. `None` → the instantiator (`info.sender`).
    pub admin: Option<String>,
    /// Base denom. `None` → `"usaf"`.
    pub denom: Option<String>,
    /// Ticket price. `None` → 5_000_000 usaf. Denom must equal `denom`.
    pub ticket_price: Option<Coin>,
    /// Round duration in seconds. `None` → 86400 (24h).
    pub draw_interval: Option<u64>,
    /// Numbers per ticket. `None` → 6.
    pub numbers_per_ticket: Option<u8>,
    /// Number domain upper bound. `None` → 45.
    pub number_max: Option<u8>,
    /// Revenue split. `None` → 7500/1000/1500 (must sum to 10000).
    pub split: Option<FundSplitBps>,
    /// Rollover leftover pool to next round on no jackpot winner. `None` → true.
    pub rollover_on_no_winner: Option<bool>,
    /// Randomness mechanism. `None` → `Mock`.
    pub randomness_mode: Option<RandomnessMode>,
    /// drand verification strategy. `None` → `Dev`.
    pub verify_mode: Option<VerifyMode>,
    /// drand group public key — required for drand + bls.
    pub drand_pubkey: Option<HexBinary>,
    /// drand chain hash — required for drand.
    pub drand_chain_hash: Option<String>,
    /// drand beacon genesis time (unix seconds). `None` → drand quicknet default
    /// (1692803367). Only meaningful in drand mode.
    pub drand_genesis_time: Option<u64>,
    /// drand beacon period (seconds). `None` → drand quicknet default (3).
    pub drand_period: Option<u64>,
    /// Randomness submitters (relayer / keeper). Defaults to empty (admin-only).
    #[serde(default)]
    pub authorized_submitters: Vec<String>,
    /// Referral claim floor (usaf). `None` → 0 (no floor).
    pub min_claim_usaf: Option<Uint128>,
    /// Commit-reveal reveal timeout (seconds). `None` → 3600.
    pub reveal_timeout: Option<u64>,
    /// Allow permissionless `RegisterCode`. `None`/`false` → admin-only code
    /// registration (prevents referral-code squatting).
    pub open_code_registration: Option<bool>,
    /// "Must Be Won" cap: max consecutive dry rounds before a forced jackpot
    /// rolldown to the best present lower tier. `None` → 5. `0` disables it.
    pub max_dry_rounds: Option<u64>,
}

// ===========================================================================
// Execute
// ===========================================================================

#[cw_serde]
pub enum ExecuteMsg {
    /// Buy `count` tickets for the current open round. Must send exactly
    /// `count * ticket_price` in `denom`. `numbers` (when provided) sets the
    /// picks for the FIRST ticket; remaining tickets (and all tickets when
    /// omitted) are quick-picked. `referral_code` binds/uses a referral code.
    BuyTickets {
        count: u32,
        /// Explicit picks for the first ticket; `None` = quick-pick all.
        numbers: Option<Vec<u8>>,
        /// Optional referral code identifying the buyer's referrer.
        referral_code: Option<String>,
    },

    /// Authorized-submitter-or-admin only: mint `count` operator-sponsored bonus
    /// tickets OWNED BY `owner`, flagged free, into the current open round. Backs
    /// an off-chain "redeem XP for a free ticket" feature. The caller MUST attach
    /// exactly `count * ticket_price` in `denom` (the operator sponsors the pool
    /// contribution so the user pays nothing); the full amount is added to the
    /// round pool so the granted tickets are honestly funded and can win / be
    /// claimed by `owner` like any paid ticket. `numbers` (when provided) sets the
    /// picks for the FIRST ticket; remaining tickets (and all when omitted) are
    /// quick-picked — exactly like `BuyTickets`.
    GrantBonusTicket {
        /// Beneficiary who OWNS the minted bonus tickets.
        owner: String,
        count: u32,
        /// Explicit picks for the first ticket; `None` = quick-pick all.
        numbers: Option<Vec<u8>>,
    },

    /// Permissionless: close the current round once `closes_at` has passed.
    /// Transitions `Open → Drawing`.
    CloseRound {},

    /// Authorized-submitter-only: deliver randomness for a closed round and
    /// (once verified per mode) mark it fulfilled so it can be drawn.
    SubmitRandomness {
        round_id: u64,
        /// 32-byte beacon output (hex).
        randomness: HexBinary,
        /// drand/nois BLS signature (verified in drand mode; ignored in mock).
        signature: Option<HexBinary>,
    },

    /// Commit-reveal mode only — step 1. An authorized submitter commits to
    /// `sha256(value)` for a closed round without revealing `value`.
    CommitRandomness {
        round_id: u64,
        commitment: HexBinary,
    },

    /// Commit-reveal mode only — step 2. Reveal the pre-image `value`; the
    /// contract checks `sha256(value) == commitment` then fulfils the round.
    RevealRandomness { round_id: u64, value: HexBinary },

    /// Compute matches per ticket, fix per-tier prizes from the pool, mark
    /// winners and finalize. Consumes the round's fulfilled randomness. If no
    /// jackpot winner and rollover is enabled the leftover pool moves to the
    /// next round. Transitions `Drawing → Settled` and opens the next round.
    Draw { round_id: u64 },

    /// Recover a stuck `Drawing` round whose randomness never fulfilled.
    /// Admin may call at any time; anyone may call once
    /// `closes_at + CANCEL_GRACE_SECONDS` has passed (or, in commit-reveal, once
    /// the commitment's `reveal_deadline` has passed). Marks the round
    /// `Cancelled`, converts the retained pool into pro-rata pull-refunds for
    /// ticket buyers (claimed via `ClaimReward`), and opens the next round so the
    /// lifecycle is never permanently blocked.
    CancelRound { round_id: u64 },

    /// Pull-based prize payout (or, for a `Cancelled` round, the buyer's pro-rata
    /// refund). Only the ticket owner may claim, only if the assigned amount is
    /// non-zero and not yet claimed.
    ClaimReward { round_id: u64, ticket_id: String },

    /// Bind the caller (referee) to a referrer, once and immutably. Provide a
    /// `referrer` address and/or a `code` that resolves to one. Self-referral is
    /// rejected.
    BindReferrer {
        referrer: Option<String>,
        code: Option<String>,
    },

    /// Register a unique, case-insensitive referral `code` for the caller.
    RegisterCode { code: String },

    /// Referrer pulls their accrued, unclaimed earnings (subject to
    /// `min_claim_usaf`). Sends the full pending balance.
    ClaimReferral {},

    /// Admin-only: move `amount` usaf from the tracked treasury balance to `to`.
    WithdrawTreasury { to: String, amount: Uint128 },

    /// Admin-only: update mutable config fields (any `None` field is unchanged).
    SetConfig {
        admin: Option<String>,
        ticket_price: Option<Coin>,
        draw_interval: Option<u64>,
        split: Option<FundSplitBps>,
        rollover_on_no_winner: Option<bool>,
        randomness_mode: Option<RandomnessMode>,
        verify_mode: Option<VerifyMode>,
        drand_pubkey: Option<HexBinary>,
        drand_chain_hash: Option<String>,
        drand_genesis_time: Option<u64>,
        drand_period: Option<u64>,
        min_claim_usaf: Option<Uint128>,
        /// Commit-reveal reveal timeout (seconds).
        reveal_timeout: Option<u64>,
        /// Toggle permissionless referral-code registration.
        open_code_registration: Option<bool>,
        /// "Must Be Won" cap: max consecutive dry rounds before a forced
        /// jackpot rolldown. `0` disables the feature.
        max_dry_rounds: Option<u64>,
        /// Submitters to ADD to the authorized set.
        add_submitters: Option<Vec<String>>,
        /// Submitters to REMOVE from the authorized set.
        remove_submitters: Option<Vec<String>>,
    },

    /// Admin-only kill switch (blocks buys).
    Pause {},
    /// Admin-only resume.
    Unpause {},
}

// ===========================================================================
// Query
// ===========================================================================

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Current protocol config.
    #[returns(crate::state::Config)]
    Config {},

    /// The round currently accepting tickets.
    #[returns(RoundResponse)]
    CurrentRound {},

    /// A specific round by id.
    #[returns(RoundResponse)]
    Round { round_id: u64 },

    /// Paginated tickets for a round, optionally filtered by owner.
    #[returns(TicketsResponse)]
    Tickets {
        round_id: u64,
        owner: Option<String>,
        start_after: Option<String>,
        limit: Option<u32>,
    },

    /// Total prize owed to `owner` across their tickets in a round, split into
    /// claimable (unclaimed) and already-claimed totals.
    #[returns(PrizeResponse)]
    Prize { round_id: u64, owner: String },

    /// The referrer a referee is bound to (if any).
    #[returns(ReferrerResponse)]
    Referrer { referee: String },

    /// Full referrer summary: pending + lifetime aggregates.
    #[returns(ReferralSummaryResponse)]
    ReferralSummary { addr: String },

    /// The in-contract treasury balance (usaf).
    #[returns(TreasuryBalanceResponse)]
    TreasuryBalance {},
}

#[cw_serde]
pub struct MigrateMsg {}

// ===========================================================================
// Response types
// ===========================================================================

#[cw_serde]
pub struct RoundResponse {
    pub id: u64,
    pub status: RoundStatus,
    pub pool: Uint128,
    pub ticket_count: u64,
    pub player_count: u64,
    pub opens_at: u64,
    pub closes_at: u64,
    pub winning_numbers: Option<Vec<u8>>,
    pub prize_tiers: PrizeTiers,
    pub rolled_over_from: Option<u64>,
    pub winning_tickets: u64,
    /// Randomness state for this round, if any has been requested/delivered.
    pub randomness: Option<RandomnessRequest>,
    /// Current global "Must Be Won" dry streak (consecutive settled rounds with
    /// no jackpot winner that were not force-distributed). Lets the UI show
    /// "must be won in K rounds" where `K = max_dry_rounds - dry_streak`.
    ///
    /// `#[serde(default)]` so responses/clients predating this field still
    /// deserialize; it is populated on every round query from the global
    /// `DRY_STREAK` item.
    #[serde(default)]
    pub dry_streak: u64,
}

/// A ticket paired with its stable id (round-local sequence).
#[cw_serde]
pub struct TicketInfo {
    pub ticket_id: String,
    pub ticket: Ticket,
}

#[cw_serde]
pub struct TicketsResponse {
    pub tickets: Vec<TicketInfo>,
}

#[cw_serde]
pub struct PrizeResponse {
    pub round_id: u64,
    pub owner: String,
    /// Sum of prizes on unclaimed winning tickets (still claimable).
    pub claimable: Uint128,
    /// Sum of prizes already paid out.
    pub claimed: Uint128,
    /// The owner's winning ticket ids in this round.
    pub winning_ticket_ids: Vec<String>,
}

#[cw_serde]
pub struct ReferrerResponse {
    /// `None` when the referee is unbound.
    pub referrer: Option<String>,
}

#[cw_serde]
pub struct ReferralSummaryResponse {
    pub addr: String,
    pub denom: String,
    /// Accrued, unclaimed usaf.
    pub pending: Uint128,
    /// Number of referees bound to this referrer.
    pub referees: u64,
    /// Lifetime earnings attributed (claimed + pending).
    pub lifetime_earned: Uint128,
    /// Lifetime earnings already claimed.
    pub lifetime_claimed: Uint128,
}

#[cw_serde]
pub struct TreasuryBalanceResponse {
    /// In-contract treasury balance in usaf (withdrawable by the admin).
    pub balance: Uint128,
    pub denom: String,
}
