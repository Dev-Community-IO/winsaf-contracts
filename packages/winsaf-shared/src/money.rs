//! Money helpers for WinSaf settlement denoms.
//!
//! All amounts on-chain are integer base units represented as [`Uint128`].
//! These helpers centralise the common "check the sent funds are exactly N of
//! denom D" pattern so every contract validates payments identically.
//!
//! A WinSaf instance settles in exactly ONE denom (`Config.denom`): `usaf` for
//! the SAF lottery, the IBC USDC denom for the USDC lottery. The generic
//! [`must_pay_denom_only`] / [`assert_exact_denom`] take that denom explicitly;
//! the `*_usaf` variants are thin wrappers kept for SAF-only call sites.

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

/// Extract the amount of `denom` from a slice of `funds` (as delivered in
/// `MessageInfo::funds`), enforcing that *only* `denom` was sent.
///
/// Returns:
/// - `Err(NoFunds)` if the slice is empty,
/// - `Err(UnexpectedFunds)` if any coin of another denom is present,
/// - the summed amount otherwise.
pub fn must_pay_denom_only(funds: &[Coin], denom: &str) -> Result<Uint128, SharedError> {
    if funds.is_empty() {
        return Err(SharedError::NoFunds {
            expected: denom.to_string(),
        });
    }
    let mut total = Uint128::zero();
    for coin in funds {
        if coin.denom != denom {
            return Err(SharedError::UnexpectedFunds {
                expected: denom.to_string(),
            });
        }
        total = total.checked_add(coin.amount).map_err(SharedError::from)?;
    }
    if total.is_zero() {
        return Err(SharedError::ZeroAmount);
    }
    Ok(total)
}

/// Assert that exactly `expected` of `denom` (and nothing else) was sent.
///
/// Combines [`must_pay_denom_only`] with an exact-amount check — the canonical
/// guard for fixed-price actions like buying a ticket.
pub fn assert_exact_denom(
    funds: &[Coin],
    denom: &str,
    expected: Uint128,
) -> Result<(), SharedError> {
    let paid = must_pay_denom_only(funds, denom)?;
    if paid != expected {
        return Err(SharedError::IncorrectPayment {
            expected: expected.to_string(),
            actual: paid.to_string(),
        });
    }
    Ok(())
}

/// [`must_pay_denom_only`] pinned to the SAF base denom.
pub fn must_pay_usaf_only(funds: &[Coin]) -> Result<Uint128, SharedError> {
    must_pay_denom_only(funds, DENOM)
}

/// [`assert_exact_denom`] pinned to the SAF base denom.
pub fn assert_exact_usaf(funds: &[Coin], expected: Uint128) -> Result<(), SharedError> {
    assert_exact_denom(funds, DENOM, expected)
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

    const IBC_USDC: &str = "ibc/1E180C085A3A2688CDF2A781E5990BE8AA92CE69CB62A8CC6BB9F5EE17DD5C38";

    #[test]
    fn generic_denom_accepts_ibc_usdc() {
        let funds = vec![c(IBC_USDC, 1_000_000)];
        assert_eq!(
            must_pay_denom_only(&funds, IBC_USDC).unwrap(),
            Uint128::new(1_000_000)
        );
        assert!(assert_exact_denom(&funds, IBC_USDC, Uint128::new(1_000_000)).is_ok());
    }

    #[test]
    fn generic_denom_rejects_cross_denom_payment() {
        // usaf must not pay a USDC-settled instance, and vice versa.
        let usaf_funds = vec![c("usaf", 1_000_000)];
        assert!(matches!(
            must_pay_denom_only(&usaf_funds, IBC_USDC),
            Err(SharedError::UnexpectedFunds { .. })
        ));

        let usdc_funds = vec![c(IBC_USDC, 1_000_000)];
        assert!(matches!(
            must_pay_denom_only(&usdc_funds, "usaf"),
            Err(SharedError::UnexpectedFunds { .. })
        ));
    }

    #[test]
    fn generic_denom_rejects_mixed_funds() {
        let funds = vec![c(IBC_USDC, 1_000_000), c("usaf", 5_000_000)];
        assert!(matches!(
            must_pay_denom_only(&funds, IBC_USDC),
            Err(SharedError::UnexpectedFunds { .. })
        ));
    }
}
