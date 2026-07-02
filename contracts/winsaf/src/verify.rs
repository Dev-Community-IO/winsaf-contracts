//! Randomness verification (ported from the standalone randomness-beacon).
//!
//! # Why verification matters
//! A lottery is only fair if the randomness that picks the winners cannot be
//! predicted or grinded by whoever *delivers* it. We therefore never trust a
//! submitter blindly: for drand we cryptographically verify the beacon
//! signature against the configured group public key before the randomness is
//! ever consumed by a draw.
//!
//! # drand verification (the real thing)
//! drand **quicknet** (`bls-unchained-g1-rfc9380`) works as follows:
//!
//! - The group public key `pk` is a point in **G2** (96 bytes, compressed).
//! - For beacon `round`, the signed message is `H = sha256(round_be_bytes)`
//!   (unchained: the previous signature is NOT mixed in).
//! - The signature `sig` is a point in **G1** (48 bytes, compressed) — quicknet
//!   uses short G1 signatures.
//! - Verification is the pairing check `e(sig, G2_gen) == e(hash_to_G1(H), pk)`,
//!   evaluated with the host BLS primitives.
//! - The delivered `randomness` is then `sha256(sig)` — we recompute it and
//!   require a match, so the 32-byte value a draw consumes is provably bound to
//!   the verified signature.
//!
//! # Dev verifier
//! On localnet / early testnet a real drand relayer may not be wired up. The
//! `Dev` verifier performs the structural checks (lengths, randomness ==
//! sha256(sig)) but SKIPS the pairing check. It is gated behind
//! `config.verify_mode` so it can never be silently active in production.
//!
//! # Mock verifier
//! `Mock` mode only length-checks the randomness. NEVER for mainnet.

use cosmwasm_std::{Api, HashFunction, HexBinary};
use sha2::{Digest, Sha256};

use crate::error::ContractError;
use crate::state::VerifyMode;

/// BLS12-381 G1 compressed point length (drand quicknet round signature).
pub const G1_LEN: usize = 48;
/// BLS12-381 G2 compressed point length (drand quicknet group public key).
pub const G2_LEN: usize = 96;
/// Length of a beacon randomness value / SHA-256 digest.
pub const RANDOMNESS_LEN: usize = 32;

/// Domain separation tag for drand quicknet's hash-to-curve on G1 (RFC 9380,
/// `BLS12381G1_XMD:SHA-256_SSWU_RO_`, NUL ciphersuite) — the `bls-unchained-
/// g1-rfc9380` scheme quicknet uses (short G1 signatures, G2 group pubkey).
const DRAND_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// The drand message for a given round under the unchained scheme:
/// `sha256(round.to_be_bytes())`.
pub fn drand_message(round: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(round.to_be_bytes());
    hasher.finalize().into()
}

/// `sha256(bytes)` helper (also used to verify commit-reveal commitments).
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Verify delivered drand randomness for `round`.
///
/// On success the (already length-checked) randomness is guaranteed to equal
/// `sha256(signature)`; under `VerifyMode::Bls` the signature is additionally
/// proven to be a valid drand beacon signature for `round` under `pubkey`.
pub fn verify_drand(
    api: &dyn Api,
    verify_mode: &VerifyMode,
    pubkey: &[u8],
    round: u64,
    randomness: &HexBinary,
    signature: &[u8],
) -> Result<(), ContractError> {
    // --- Structural checks (both Bls and Dev) -------------------------------
    if randomness.len() != RANDOMNESS_LEN {
        return Err(ContractError::InvalidRandomnessLength {
            actual: randomness.len(),
        });
    }
    if signature.len() != G1_LEN {
        return Err(ContractError::verification_failed(format!(
            "drand signature must be {G1_LEN} bytes (G1), got {}",
            signature.len()
        )));
    }

    // The randomness a draw consumes MUST be bound to the signature, so a
    // submitter cannot deliver a valid signature but an unrelated 32-byte value.
    let expected_randomness = sha256(signature);
    if expected_randomness != randomness.as_slice() {
        return Err(ContractError::verification_failed(
            "randomness != sha256(signature)",
        ));
    }

    match verify_mode {
        VerifyMode::Dev => {
            // Structural checks only — see module docs. No pairing check.
            Ok(())
        }
        VerifyMode::Bls => {
            if pubkey.len() != G2_LEN {
                return Err(ContractError::InvalidPubkey {
                    reason: format!("drand group pubkey must be {G2_LEN} bytes (G2)"),
                });
            }

            // quicknet (bls-unchained-g1-rfc9380): the message hashes to G1 and
            // the signature is a G1 point; the group pubkey is a G2 point.
            // H = hash_to_G1(sha256(round))
            let msg = drand_message(round);
            let hashed_on_curve = api
                .bls12_381_hash_to_g1(HashFunction::Sha256, &msg, DRAND_DST)
                .map_err(|e| {
                    ContractError::verification_failed(format!("hash_to_g1 failed: {e}"))
                })?;

            // Pairing check: e(sig, G2_gen) == e(H, pk)
            let ok = api
                .bls12_381_pairing_equality(
                    signature,
                    &cosmwasm_std::BLS12_381_G2_GENERATOR,
                    &hashed_on_curve,
                    pubkey,
                )
                .map_err(|e| {
                    ContractError::verification_failed(format!("pairing check errored: {e}"))
                })?;

            if !ok {
                return Err(ContractError::verification_failed(
                    "BLS pairing check did not hold (bad signature/pubkey/round)",
                ));
            }
            Ok(())
        }
    }
}

/// Verify a commit-reveal reveal: `sha256(value) == commitment`.
pub fn verify_reveal(commitment: &HexBinary, value: &HexBinary) -> Result<(), ContractError> {
    let digest = sha256(value.as_slice());
    if digest != commitment.as_slice() {
        return Err(ContractError::RevealMismatch);
    }
    Ok(())
}

/// Mock-mode acceptance: only a length check. NEVER for mainnet.
pub fn verify_mock(randomness: &HexBinary) -> Result<(), ContractError> {
    if randomness.len() != RANDOMNESS_LEN {
        return Err(ContractError::InvalidRandomnessLength {
            actual: randomness.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drand_message_is_sha256_of_be_round() {
        let m = drand_message(1);
        let expected = sha256(&1u64.to_be_bytes());
        assert_eq!(m, expected);
    }

    #[test]
    fn reveal_matches_commitment() {
        let value = HexBinary::from(vec![9u8; 32]);
        let commitment = HexBinary::from(sha256(value.as_slice()));
        assert!(verify_reveal(&commitment, &value).is_ok());

        let wrong = HexBinary::from(vec![1u8; 32]);
        assert_eq!(
            verify_reveal(&commitment, &wrong),
            Err(ContractError::RevealMismatch)
        );
    }

    #[test]
    fn dev_verifier_binds_randomness_to_signature() {
        let api = cosmwasm_std::testing::MockApi::default();
        let sig = HexBinary::from(vec![3u8; G1_LEN]);
        let good = HexBinary::from(sha256(sig.as_slice()));
        assert!(verify_drand(&api, &VerifyMode::Dev, &[], 7, &good, sig.as_slice()).is_ok());

        // Randomness not bound to signature -> rejected even in Dev mode.
        let bad = HexBinary::from(vec![0u8; 32]);
        assert!(verify_drand(&api, &VerifyMode::Dev, &[], 7, &bad, sig.as_slice()).is_err());
    }

    #[test]
    fn bls_verifier_rejects_wrong_pubkey_len() {
        let api = cosmwasm_std::testing::MockApi::default();
        let sig = HexBinary::from(vec![3u8; G1_LEN]);
        let rnd = HexBinary::from(sha256(sig.as_slice()));
        let err =
            verify_drand(&api, &VerifyMode::Bls, &[0u8; 10], 7, &rnd, sig.as_slice()).unwrap_err();
        assert!(matches!(err, ContractError::InvalidPubkey { .. }));
    }

    #[test]
    fn mock_verifier_length_only() {
        assert!(verify_mock(&HexBinary::from(vec![1u8; 32])).is_ok());
        assert!(matches!(
            verify_mock(&HexBinary::from(vec![1u8; 16])),
            Err(ContractError::InvalidRandomnessLength { .. })
        ));
    }
}
