//! Money helpers for the SAF token (`usaf` base denom, 6 decimals).
//!
//! All amounts on-chain are integer `usaf` represented as [`Uint128`]. These
//! helpers centralise the common "check the sent funds are exactly N usaf"
//! pattern so every contract validates payments identically.

use cosmwasm_std::{Coin, Uint128};

use crate::constants::{DENOM, USAF_PER_SAF};
use crate::error::SharedError;

/// Build a `Coin` of `usaf` from an integer usaf amount.
pub fn usaf(amount: impl Into<Uint128>) -> Coin {
    Coin {
        denom: DENOM.to_string(),
        amount: amount.into(),
    }
}

/// Convert a whole-SAF amount into `usaf`. Checked against overflow.
///
/// Example: `saf_to_usaf(5) == 5_000_000 usaf`.
pub fn saf_to_usaf(whole_saf: u128) -> Result<Uint128, SharedError> {
    Uint128::from(whole_saf)
        .checked_mul(Uint128::from(USAF_PER_SAF))
        .map_err(SharedError::from)
}

/// Extract the amount of `usaf` from a slice of `funds` (as delivered in
/// `MessageInfo::funds`), enforcing that *only* `usaf` was sent.
///
/// Returns:
/// - `Err(NoFunds)` if the slice is empty,
/// - `Err(UnexpectedFunds)` if any non-`usaf` coin is present,
/// - the summed `usaf` amount otherwise.
pub fn must_pay_usaf_only(funds: &[Coin]) -> Result<Uint128, SharedError> {
    if funds.is_empty() {
        return Err(SharedError::NoFunds {
            expected: DENOM.to_string(),
        });
    }
    let mut total = Uint128::zero();
    for coin in funds {
        if coin.denom != DENOM {
            return Err(SharedError::UnexpectedFunds {
                expected: DENOM.to_string(),
            });
        }
        total = total.checked_add(coin.amount).map_err(SharedError::from)?;
    }
    if total.is_zero() {
        return Err(SharedError::ZeroAmount);
    }
    Ok(total)
}

/// Assert that exactly `expected` usaf (and nothing else) was sent.
///
/// Combines [`must_pay_usaf_only`] with an exact-amount check — the canonical
/// guard for fixed-price actions like buying a ticket.
pub fn assert_exact_usaf(funds: &[Coin], expected: Uint128) -> Result<(), SharedError> {
    let paid = must_pay_usaf_only(funds)?;
    if paid != expected {
        return Err(SharedError::IncorrectPayment {
            expected: expected.to_string(),
            actual: paid.to_string(),
        });
    }
    Ok(())
}

/// Assert that at least `min` usaf (and only usaf) was sent, returning the paid
/// amount. Useful when a caller may overpay (e.g. buying multiple tickets).
pub fn assert_min_usaf(funds: &[Coin], min: Uint128) -> Result<Uint128, SharedError> {
    let paid = must_pay_usaf_only(funds)?;
    if paid < min {
        return Err(SharedError::IncorrectPayment {
            expected: format!(">= {min}"),
            actual: paid.to_string(),
        });
    }
    Ok(paid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(denom: &str, amount: u128) -> Coin {
        Coin {
            denom: denom.to_string(),
            amount: Uint128::new(amount),
        }
    }

    #[test]
    fn usaf_builder() {
        let coin = usaf(5_000_000u128);
        assert_eq!(coin.denom, "usaf");
        assert_eq!(coin.amount, Uint128::new(5_000_000));
    }

    #[test]
    fn saf_conversion() {
        assert_eq!(saf_to_usaf(5).unwrap(), Uint128::new(5_000_000));
    }

    #[test]
    fn empty_funds_rejected() {
        assert!(matches!(
            must_pay_usaf_only(&[]),
            Err(SharedError::NoFunds { .. })
        ));
    }

    #[test]
    fn foreign_denom_rejected() {
        let funds = vec![c("uatom", 10)];
        assert!(matches!(
            must_pay_usaf_only(&funds),
            Err(SharedError::UnexpectedFunds { .. })
        ));
    }

    #[test]
    fn sums_multiple_usaf_coins() {
        let funds = vec![c("usaf", 3_000_000), c("usaf", 2_000_000)];
        assert_eq!(must_pay_usaf_only(&funds).unwrap(), Uint128::new(5_000_000));
    }

    #[test]
    fn exact_payment_ok() {
        let funds = vec![c("usaf", 5_000_000)];
        assert!(assert_exact_usaf(&funds, Uint128::new(5_000_000)).is_ok());
    }

    #[test]
    fn exact_payment_mismatch() {
        let funds = vec![c("usaf", 4_000_000)];
        assert!(matches!(
            assert_exact_usaf(&funds, Uint128::new(5_000_000)),
            Err(SharedError::IncorrectPayment { .. })
        ));
    }

    #[test]
    fn min_payment_allows_overpay() {
        let funds = vec![c("usaf", 15_000_000)];
        assert_eq!(
            assert_min_usaf(&funds, Uint128::new(5_000_000)).unwrap(),
            Uint128::new(15_000_000)
        );
    }
}
