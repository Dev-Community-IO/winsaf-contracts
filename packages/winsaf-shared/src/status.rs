//! Lifecycle status for a lottery round.

use cosmwasm_schema::cw_serde;

/// State machine for a single lottery round.
///
/// Typical progression:
/// `Open` → `Drawing` → `Drawn` → `Settled`
///
/// `Cancelled` is a terminal state reachable from `Open`/`Drawing` (e.g. the
/// randomness beacon never arrived and admins refund tickets).
#[cw_serde]
pub enum RoundStatus {
    /// Accepting ticket purchases.
    Open,
    /// Sales closed; awaiting randomness (beacon or reveal) to pick numbers.
    Drawing,
    /// Winning numbers determined; prizes computed but not yet all claimed.
    Drawn,
    /// All payouts distributed / claim window closed; round is finalized.
    Settled,
    /// Round aborted; stakes are refundable.
    Cancelled,
}

impl RoundStatus {
    /// Whether new tickets may be sold in this state.
    pub fn accepts_tickets(&self) -> bool {
        matches!(self, RoundStatus::Open)
    }

    /// Whether the round has reached a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, RoundStatus::Settled | RoundStatus::Cancelled)
    }

    /// Whether a draw (number selection) is still expected/allowed.
    pub fn awaits_draw(&self) -> bool {
        matches!(self, RoundStatus::Drawing)
    }

    /// Validate a proposed transition. Returns `true` if allowed.
    pub fn can_transition_to(&self, next: &RoundStatus) -> bool {
        use RoundStatus::*;
        matches!(
            (self, next),
            (Open, Drawing)
                | (Open, Cancelled)
                | (Drawing, Drawn)
                | (Drawing, Cancelled)
                | (Drawn, Settled)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_open_accepts_tickets() {
        assert!(RoundStatus::Open.accepts_tickets());
        assert!(!RoundStatus::Drawing.accepts_tickets());
        assert!(!RoundStatus::Settled.accepts_tickets());
    }

    #[test]
    fn terminal_states() {
        assert!(RoundStatus::Settled.is_terminal());
        assert!(RoundStatus::Cancelled.is_terminal());
        assert!(!RoundStatus::Open.is_terminal());
    }

    #[test]
    fn valid_transitions() {
        assert!(RoundStatus::Open.can_transition_to(&RoundStatus::Drawing));
        assert!(RoundStatus::Drawing.can_transition_to(&RoundStatus::Drawn));
        assert!(RoundStatus::Drawn.can_transition_to(&RoundStatus::Settled));
        assert!(RoundStatus::Open.can_transition_to(&RoundStatus::Cancelled));
    }

    #[test]
    fn invalid_transitions() {
        assert!(!RoundStatus::Open.can_transition_to(&RoundStatus::Drawn));
        assert!(!RoundStatus::Settled.can_transition_to(&RoundStatus::Open));
        assert!(!RoundStatus::Drawn.can_transition_to(&RoundStatus::Cancelled));
    }
}
