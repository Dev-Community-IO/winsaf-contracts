//! Chain- and protocol-level constants for Safrochain / WinSaf.
//!
//! These MUST stay in sync with the single source of truth at
//! `config/chains/{mainnet,testnet,localnet}.json`. Values that can differ per
//! deployment (endpoints, contract addresses) belong in config/env, NOT here —
//! only truly invariant protocol constants live in this module.

use cosmwasm_std::Uint128;

/// Base micro-denomination of the SAF token. All on-chain amounts are integer
/// `usaf` (never floats, never fractional SAF).
pub const DENOM: &str = "usaf";

/// Human-readable display denom. `1 SAF = 10^SAF_DECIMALS usaf`.
pub const DISPLAY_DENOM: &str = "SAF";

/// Number of decimals between `SAF` and `usaf`. `1 SAF = 1_000_000 usaf`.
pub const SAF_DECIMALS: u32 = 6;

/// Multiplier to convert whole SAF into `usaf` (`10^SAF_DECIMALS`).
pub const USAF_PER_SAF: u128 = 1_000_000;

/// bech32 human-readable prefix (HRP) for Safrochain account addresses.
pub const BECH32_PREFIX: &str = "addr_safro";

/// SLIP-0044 / BIP-44 coin type. Safrochain reuses the Cosmos Hub coin type.
pub const COIN_TYPE: u32 = 118;

/// Basis-point denominator. All split percentages are expressed in bps and must
/// sum to this value (100% = 10_000 bps).
pub const BPS_DENOM: u16 = 10_000;

// --- Economics defaults -----------------------------------------------------
// These are protocol defaults; a contract MAY expose them as instantiate params.
// They are provided here so services and tests share one canonical source.

/// Default ticket price: 5 SAF = 5_000_000 usaf.
pub const DEFAULT_TICKET_PRICE_USAF: Uint128 = Uint128::new(5 * USAF_PER_SAF);

/// Default draw interval in seconds (24h).
pub const DEFAULT_DRAW_INTERVAL_SECONDS: u64 = 24 * 60 * 60;

/// Default lottery number domain: pick `DEFAULT_PICK_COUNT` distinct numbers
/// from the inclusive range `[DEFAULT_NUMBER_MIN, DEFAULT_NUMBER_MAX]`.
pub const DEFAULT_NUMBER_MIN: u8 = 1;
pub const DEFAULT_NUMBER_MAX: u8 = 45;
pub const DEFAULT_PICK_COUNT: u8 = 6;

/// Default fund split in basis points (sums to `BPS_DENOM`).
pub const DEFAULT_PRIZE_BPS: u16 = 7_500;
pub const DEFAULT_REFERRAL_BPS: u16 = 1_000;
pub const DEFAULT_TREASURY_BPS: u16 = 1_500;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usaf_per_saf_matches_decimals() {
        assert_eq!(USAF_PER_SAF, 10u128.pow(SAF_DECIMALS));
    }

    #[test]
    fn default_ticket_price_is_five_saf() {
        assert_eq!(DEFAULT_TICKET_PRICE_USAF.u128(), 5_000_000);
    }

    #[test]
    fn default_split_sums_to_bps_denom() {
        let sum = DEFAULT_PRIZE_BPS + DEFAULT_REFERRAL_BPS + DEFAULT_TREASURY_BPS;
        assert_eq!(sum, BPS_DENOM);
    }
}
