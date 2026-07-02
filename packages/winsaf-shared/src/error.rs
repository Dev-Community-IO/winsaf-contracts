//! Common error variants shared across WinSaf contracts.
//!
//! Each contract typically defines its own `ContractError` enum with a
//! `#[from] StdError` arm and domain-specific variants, then embeds the shared
//! variants via `#[from] SharedError`. This keeps money/split/beacon validation
//! errors consistent everywhere while leaving room for contract-specific ones.

use cosmwasm_std::{OverflowError, StdError};
use thiserror::Error;

/// Errors that can arise from the shared helpers in this crate.
#[derive(Error, Debug, PartialEq)]
pub enum SharedError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    Overflow(#[from] OverflowError),

    #[error("unauthorized")]
    Unauthorized,

    #[error("fund split must sum to 10000 bps (got {actual})")]
    InvalidSplitSum { actual: u32 },

    #[error("invalid denom: expected '{expected}', got '{actual}'")]
    InvalidDenom { expected: String, actual: String },

    #[error("no funds sent (expected exactly '{expected}')")]
    NoFunds { expected: String },

    #[error("unexpected funds: only '{expected}' is accepted")]
    UnexpectedFunds { expected: String },

    #[error("incorrect payment amount: expected {expected}, got {actual}")]
    IncorrectPayment { expected: String, actual: String },

    #[error("zero amount not allowed")]
    ZeroAmount,

    #[error("invalid basis points value {value}: must be <= 10000")]
    BpsOutOfRange { value: u16 },

    #[error("invalid beacon reference: {reason}")]
    InvalidBeacon { reason: String },
}

impl SharedError {
    /// Convenience constructor for denom mismatches.
    pub fn invalid_denom(expected: impl Into<String>, actual: impl Into<String>) -> Self {
        SharedError::InvalidDenom {
            expected: expected.into(),
            actual: actual.into(),
        }
    }
}

/// Allow shared errors to bubble up into `StdError` when a contract has not yet
/// migrated to a rich error enum (keeps early integration simple).
impl From<SharedError> for StdError {
    fn from(err: SharedError) -> Self {
        match err {
            SharedError::Std(e) => e,
            other => StdError::generic_err(other.to_string()),
        }
    }
}
