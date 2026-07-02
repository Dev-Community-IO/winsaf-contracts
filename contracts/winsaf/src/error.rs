//! Contract error type for the consolidated WinSaf contract.
//!
//! Wraps `StdError` and the workspace-shared [`SharedError`] (money/split/beacon
//! validation) and gathers the domain-specific variants from all four merged
//! subsystems (lottery, treasury, referral, randomness). Entry points return
//! `Result<Response, ContractError>`; every failing guard maps to one of these —
//! the contract never panics on user input.

use cosmwasm_std::{OverflowError, StdError};
use cw_utils::PaymentError;
use thiserror::Error;
use winsaf_shared::SharedError;

/// All the ways a `winsaf` `execute`/`instantiate`/`migrate` call can fail.
#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    /// Shared money/split/beacon validation errors (denom, payment amount,
    /// split-sum, beacon shape).
    #[error("{0}")]
    Shared(#[from] SharedError),

    #[error("{0}")]
    Overflow(#[from] OverflowError),

    #[error("{0}")]
    Payment(#[from] PaymentError),

    #[error("unauthorized: caller is not {role}")]
    Unauthorized { role: String },

    #[error("contract is paused")]
    Paused,

    #[error("invalid config: {reason}")]
    InvalidConfig { reason: String },

    // --- Lottery -----------------------------------------------------------
    #[error("round {round_id} not found")]
    RoundNotFound { round_id: u64 },

    #[error("ticket {ticket_id} not found in round {round_id}")]
    TicketNotFound { round_id: u64, ticket_id: String },

    #[error("round {round_id} is not open for ticket sales (status: {status})")]
    RoundNotOpen { round_id: u64, status: String },

    #[error("round {round_id} has not closed yet (closes at {closes_at}, now {now})")]
    RoundNotClosed {
        round_id: u64,
        closes_at: u64,
        now: u64,
    },

    #[error("round {round_id} is in status '{status}', expected '{expected}'")]
    UnexpectedStatus {
        round_id: u64,
        status: String,
        expected: String,
    },

    #[error("count must be between 1 and {max} (got {count})")]
    InvalidTicketCount { count: u32, max: u32 },

    #[error("ticket must have exactly {expected} distinct numbers in 1..={number_max} (got {reason})")]
    InvalidNumbers {
        expected: u8,
        number_max: u8,
        reason: String,
    },

    #[error("prize for ticket {ticket_id} (round {round_id}) is zero — nothing to claim")]
    NoPrize { round_id: u64, ticket_id: String },

    #[error("prize for ticket {ticket_id} (round {round_id}) already claimed")]
    AlreadyClaimed { round_id: u64, ticket_id: String },

    /// Pool accounting guard: a payout/transfer would push the tracked pool
    /// below zero. Surfaced instead of silently under/over-paying.
    #[error("pool underflow in round {round_id}: pool {pool} < requested {requested}")]
    PoolUnderflow {
        round_id: u64,
        pool: String,
        requested: String,
    },

    // --- Treasury ----------------------------------------------------------
    /// A `WithdrawTreasury` requested more than the tracked treasury balance.
    #[error("insufficient treasury balance: requested {requested} usaf, available {available} usaf")]
    InsufficientTreasury {
        requested: String,
        available: String,
    },

    /// A zero-amount withdrawal was requested.
    #[error("withdraw amount must be greater than zero")]
    ZeroWithdraw,

    // --- Referral ----------------------------------------------------------
    /// The referee already bound a referrer; bindings are immutable.
    #[error("referee {referee} is already bound to a referrer")]
    AlreadyBound { referee: String },

    /// A referee cannot refer themselves.
    #[error("self-referral is not allowed")]
    SelfReferral,

    /// The referral code supplied did not resolve to a registered referrer.
    #[error("unknown referral code: {code}")]
    UnknownReferralCode { code: String },

    /// A referrer has nothing to claim (or below the `min_claim_usaf` floor).
    #[error("nothing to claim")]
    NothingToClaim,

    // --- Randomness --------------------------------------------------------
    /// Caller is not in the authorized-submitter set (nor the admin).
    #[error("unauthorized: sender is not an authorized submitter")]
    UnauthorizedSubmitter,

    /// Randomness for a round has already been submitted / the round is drawn.
    #[error("randomness for round {round_id} already submitted")]
    AlreadyFulfilled { round_id: u64 },

    /// The randomness step is not valid for the configured randomness mode.
    #[error("operation not allowed in '{mode}' randomness mode")]
    WrongMode { mode: String },

    /// The delivered randomness failed cryptographic / structural verification.
    #[error("randomness verification failed: {reason}")]
    VerificationFailed { reason: String },

    /// Randomness must be exactly 32 bytes.
    #[error("randomness must be 32 bytes, got {actual}")]
    InvalidRandomnessLength { actual: usize },

    /// Commit-reveal: the revealed value does not hash to the stored commitment.
    #[error("reveal does not match commitment")]
    RevealMismatch,

    /// Commit-reveal: no commitment stored for this round yet.
    #[error("no commitment stored for round {round_id}")]
    NoCommitment { round_id: u64 },

    /// The BLS public key (drand) is missing or malformed.
    #[error("invalid drand public key: {reason}")]
    InvalidPubkey { reason: String },

    /// Migration was invoked with an incompatible on-chain contract name.
    #[error("cannot migrate from contract '{found}' to '{expected}'")]
    InvalidMigration { expected: String, found: String },
}

impl ContractError {
    /// Helper for role-based auth failures.
    pub fn unauthorized(role: impl Into<String>) -> Self {
        ContractError::Unauthorized { role: role.into() }
    }

    /// Helper for verification failures with a free-form reason.
    pub fn verification_failed(reason: impl Into<String>) -> Self {
        ContractError::VerificationFailed {
            reason: reason.into(),
        }
    }
}

impl From<ContractError> for StdError {
    fn from(err: ContractError) -> Self {
        match err {
            ContractError::Std(e) => e,
            other => StdError::generic_err(other.to_string()),
        }
    }
}
