//! Fund-split configuration for lottery revenue distribution.
//!
//! Each ticket's proceeds are split into three buckets — prize pool, referral
//! rewards and treasury — expressed in basis points that MUST sum to 10_000.

use cosmwasm_schema::cw_serde;
use cosmwasm_std::Uint128;

use crate::constants::{BPS_DENOM, DEFAULT_PRIZE_BPS, DEFAULT_REFERRAL_BPS, DEFAULT_TREASURY_BPS};
use crate::error::SharedError;

/// Revenue split in basis points. Invariant: `prize + referral + treasury == 10000`.
#[cw_serde]
#[derive(Copy)]
pub struct FundSplitBps {
    pub prize_bps: u16,
    pub referral_bps: u16,
    pub treasury_bps: u16,
}

impl FundSplitBps {
    /// Construct a split without validating. Prefer [`FundSplitBps::new`] which
    /// validates, or call [`FundSplitBps::validate`] before use.
    pub const fn new_unchecked(prize_bps: u16, referral_bps: u16, treasury_bps: u16) -> Self {
        Self {
            prize_bps,
            referral_bps,
            treasury_bps,
        }
    }

    /// Construct and validate a split in one step.
    pub fn new(prize_bps: u16, referral_bps: u16, treasury_bps: u16) -> Result<Self, SharedError> {
        let split = Self::new_unchecked(prize_bps, referral_bps, treasury_bps);
        split.validate()?;
        Ok(split)
    }

    /// Protocol default: 7500 / 1000 / 1500.
    pub const fn default_split() -> Self {
        Self::new_unchecked(
            DEFAULT_PRIZE_BPS,
            DEFAULT_REFERRAL_BPS,
            DEFAULT_TREASURY_BPS,
        )
    }

    /// Sum of all three buckets (fits in u32; max is 3 * u16::MAX).
    pub fn sum(&self) -> u32 {
        self.prize_bps as u32 + self.referral_bps as u32 + self.treasury_bps as u32
    }

    /// Ensure the split is well-formed: every bucket in range and the total is
    /// exactly `BPS_DENOM` (10_000).
    pub fn validate(&self) -> Result<(), SharedError> {
        for value in [self.prize_bps, self.referral_bps, self.treasury_bps] {
            if value > BPS_DENOM {
                return Err(SharedError::BpsOutOfRange { value });
            }
        }
        let sum = self.sum();
        if sum != BPS_DENOM as u32 {
            return Err(SharedError::InvalidSplitSum { actual: sum });
        }
        Ok(())
    }

    /// Apply the split to a gross `amount` of usaf, returning the three parts.
    ///
    /// Rounding: prize and referral are floor-rounded (`amount * bps / 10000`)
    /// and the treasury receives the remainder, so `prize + referral + treasury`
    /// always equals `amount` exactly (no dust is lost or minted).
    pub fn apply(&self, amount: Uint128) -> Result<SplitAmounts, SharedError> {
        let denom = Uint128::from(BPS_DENOM);
        let prize = amount
            .checked_mul(Uint128::from(self.prize_bps))?
            .checked_div(denom)
            .map_err(|e| SharedError::Std(e.into()))?;
        let referral = amount
            .checked_mul(Uint128::from(self.referral_bps))?
            .checked_div(denom)
            .map_err(|e| SharedError::Std(e.into()))?;
        // Treasury takes the remainder to guarantee the parts sum to `amount`.
        let treasury = amount.checked_sub(prize)?.checked_sub(referral)?;
        Ok(SplitAmounts {
            prize,
            referral,
            treasury,
        })
    }
}

impl Default for FundSplitBps {
    fn default() -> Self {
        Self::default_split()
    }
}

/// Concrete usaf amounts produced by applying a [`FundSplitBps`] to a total.
#[cw_serde]
#[derive(Copy)]
pub struct SplitAmounts {
    pub prize: Uint128,
    pub referral: Uint128,
    pub treasury: Uint128,
}

impl SplitAmounts {
    /// Sum of all buckets — should equal the input amount to `apply`.
    pub fn total(&self) -> Uint128 {
        self.prize + self.referral + self.treasury
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_split_validates() {
        assert!(FundSplitBps::default_split().validate().is_ok());
    }

    #[test]
    fn rejects_wrong_sum() {
        let bad = FundSplitBps::new_unchecked(5000, 1000, 1500); // 7500 total
        assert_eq!(
            bad.validate().unwrap_err(),
            SharedError::InvalidSplitSum { actual: 7500 }
        );
    }

    #[test]
    fn rejects_out_of_range_bucket() {
        let bad = FundSplitBps::new_unchecked(10_001, 0, 0);
        assert_eq!(
            bad.validate().unwrap_err(),
            SharedError::BpsOutOfRange { value: 10_001 }
        );
    }

    #[test]
    fn new_validates_on_construction() {
        assert!(FundSplitBps::new(7500, 1000, 1500).is_ok());
        assert!(FundSplitBps::new(7500, 1000, 1000).is_err());
    }

    #[test]
    fn apply_preserves_total_no_dust() {
        // 5 SAF ticket with the default split.
        let split = FundSplitBps::default_split();
        let parts = split.apply(Uint128::new(5_000_000)).unwrap();
        assert_eq!(parts.prize, Uint128::new(3_750_000));
        assert_eq!(parts.referral, Uint128::new(500_000));
        assert_eq!(parts.treasury, Uint128::new(750_000));
        assert_eq!(parts.total(), Uint128::new(5_000_000));
    }

    #[test]
    fn apply_routes_rounding_dust_to_treasury() {
        // An amount that does not divide evenly by 10000 with these bps.
        let split = FundSplitBps::default_split();
        let amount = Uint128::new(7); // tiny amount forces flooring
        let parts = split.apply(amount).unwrap();
        // prize = floor(7*7500/10000)=5, referral=floor(7*1000/10000)=0,
        // treasury = 7 - 5 - 0 = 2 (absorbs the dust).
        assert_eq!(parts.prize, Uint128::new(5));
        assert_eq!(parts.referral, Uint128::zero());
        assert_eq!(parts.treasury, Uint128::new(2));
        assert_eq!(parts.total(), amount);
    }
}
