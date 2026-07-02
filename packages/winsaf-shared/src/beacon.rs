//! Randomness beacon reference types.
//!
//! Safrochain lotteries source randomness from an external drand/nois beacon
//! consumed on-chain (primary), with commit-reveal as a fallback. Contracts
//! NEVER derive randomness from block hash or block time — those are
//! validator-influenceable and unsuitable for a lottery.
//!
//! [`BeaconRef`] identifies *which* beacon round a draw consumed, so results are
//! auditable: anyone can re-fetch that drand round and verify the derived
//! winning numbers.

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Binary, HexBinary};

use crate::error::SharedError;

/// The source of randomness used for a draw.
#[cw_serde]
pub enum BeaconSource {
    /// External drand beacon (League of Entropy) — identified by chain hash.
    Drand,
    /// Nois network proxy contract delivering drand rounds on-chain.
    Nois,
    /// Fallback: on-chain commit-reveal among participants/operators.
    CommitReveal,
}

/// A reference to the randomness that seeded (or will seed) a draw.
///
/// For drand/nois, `round` is the beacon round number and `randomness` holds the
/// 32-byte beacon output once delivered. For commit-reveal, `round` mirrors the
/// lottery round id and `randomness` is the revealed seed.
#[cw_serde]
pub struct BeaconRef {
    /// Which randomness mechanism produced this value.
    pub source: BeaconSource,
    /// drand chain hash (hex) or nois job id; empty for commit-reveal.
    pub chain_hash: String,
    /// Beacon round number the draw is/was pinned to.
    pub round: u64,
    /// The 32-byte randomness, present once the beacon has been delivered.
    /// `None` while the draw is still pending the beacon.
    pub randomness: Option<HexBinary>,
}

impl BeaconRef {
    /// Create a pending drand reference pinned to `round` (randomness not yet
    /// delivered).
    pub fn pending_drand(chain_hash: impl Into<String>, round: u64) -> Self {
        Self {
            source: BeaconSource::Drand,
            chain_hash: chain_hash.into(),
            round,
            randomness: None,
        }
    }

    /// Whether the randomness has been delivered and this reference is usable.
    pub fn is_fulfilled(&self) -> bool {
        self.randomness.is_some()
    }

    /// Attach delivered randomness, validating it is exactly 32 bytes.
    pub fn fulfill(&mut self, randomness: HexBinary) -> Result<(), SharedError> {
        if randomness.len() != 32 {
            return Err(SharedError::InvalidBeacon {
                reason: format!("randomness must be 32 bytes, got {}", randomness.len()),
            });
        }
        self.randomness = Some(randomness);
        Ok(())
    }

    /// Return the raw randomness bytes, erroring if not yet fulfilled.
    pub fn randomness_bytes(&self) -> Result<Binary, SharedError> {
        self.randomness
            .as_ref()
            .map(|r| Binary::from(r.as_slice()))
            .ok_or_else(|| SharedError::InvalidBeacon {
                reason: "beacon randomness not yet delivered".to_string(),
            })
    }

    /// Basic structural validation of the reference.
    pub fn validate(&self) -> Result<(), SharedError> {
        match self.source {
            BeaconSource::Drand | BeaconSource::Nois => {
                if self.chain_hash.is_empty() {
                    return Err(SharedError::InvalidBeacon {
                        reason: "chain_hash required for drand/nois beacon".to_string(),
                    });
                }
                if self.round == 0 {
                    return Err(SharedError::InvalidBeacon {
                        reason: "round must be non-zero for drand/nois beacon".to_string(),
                    });
                }
            }
            BeaconSource::CommitReveal => {}
        }
        if let Some(r) = &self.randomness {
            if r.len() != 32 {
                return Err(SharedError::InvalidBeacon {
                    reason: format!("randomness must be 32 bytes, got {}", r.len()),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h32() -> HexBinary {
        HexBinary::from(vec![7u8; 32])
    }

    #[test]
    fn pending_is_not_fulfilled() {
        let b = BeaconRef::pending_drand("abcd", 1234);
        assert!(!b.is_fulfilled());
        assert!(b.randomness_bytes().is_err());
    }

    #[test]
    fn fulfill_requires_32_bytes() {
        let mut b = BeaconRef::pending_drand("abcd", 1234);
        assert!(b.fulfill(HexBinary::from(vec![1u8; 16])).is_err());
        assert!(b.fulfill(h32()).is_ok());
        assert!(b.is_fulfilled());
        assert!(b.randomness_bytes().is_ok());
    }

    #[test]
    fn validate_drand_requires_chain_hash_and_round() {
        let b = BeaconRef {
            source: BeaconSource::Drand,
            chain_hash: String::new(),
            round: 1,
            randomness: None,
        };
        assert!(b.validate().is_err());

        let b2 = BeaconRef::pending_drand("hash", 0);
        assert!(b2.validate().is_err());

        let ok = BeaconRef::pending_drand("hash", 42);
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn commit_reveal_needs_no_chain_hash() {
        let b = BeaconRef {
            source: BeaconSource::CommitReveal,
            chain_hash: String::new(),
            round: 7,
            randomness: None,
        };
        assert!(b.validate().is_ok());
    }
}
