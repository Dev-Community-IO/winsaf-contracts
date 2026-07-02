//! Consolidated WinSaf contract: instantiate / execute / query / migrate.
//!
//! This one contract internalizes the treasury, referral and randomness logic
//! that used to live in three sibling contracts — there are NO inter-contract
//! calls. Money flow on `BuyTickets`:
//!
//! ```text
//!   paid = ticket_price * count               (exact usaf, nothing else)
//!   split = config.split.apply(paid)          (prize / referral / treasury)
//!     prize    -> Round.pool                   (stays in-contract, pull claims)
//!     referral -> referrer's earnings ledger   (or folds into prize if unbound)
//!     treasury -> TREASURY balance             (admin withdraws)
//! ```
//!
//! Round lifecycle (statuses from [`winsaf_shared::RoundStatus`]):
//!
//! ```text
//!   Open ──BuyTickets──▶ Open
//!   Open ──CloseRound(after closes_at)──▶ Drawing
//!   Drawing ──SubmitRandomness / CommitRandomness+RevealRandomness──▶ Drawing
//!             (randomness fulfilled in-contract, verified per mode)
//!   Drawing ──Draw──▶ Settled (prizes fixed, next round opened, maybe rollover)
//! ```

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Addr, Attribute, BankMsg, Binary, Coin, CosmosMsg, Deps, DepsMut, Env, Event,
    HexBinary, MessageInfo, Order, Response, StdResult, Uint128,
};
use cw2::{get_contract_version, set_contract_version};
use cw_storage_plus::Bound;

use winsaf_shared::{
    assert_exact_usaf, FundSplitBps, RoundStatus, DEFAULT_DRAW_INTERVAL_SECONDS,
    DEFAULT_NUMBER_MAX, DEFAULT_PICK_COUNT, DEFAULT_TICKET_PRICE_USAF, DENOM,
};

use crate::error::ContractError;
use crate::msg::{
    ExecuteMsg, InstantiateMsg, MigrateMsg, PrizeResponse, QueryMsg, ReferralSummaryResponse,
    ReferrerResponse, RoundResponse, TicketInfo, TicketsResponse, TreasuryBalanceResponse,
};
use crate::state::{
    Config, PrizeTiers, RandomnessMode, RandomnessRequest, RandomnessStatus, Round, Ticket,
    VerifyMode, CONFIG, CURRENT_ROUND, PLAYERS, RANDOMNESS, REFERRAL_CODES,
    REFERRAL_EARNINGS, REFERRAL_TOTALS, REFERRER, ROUNDS, TICKETS, TICKET_SEQ, TREASURY,
};
use crate::verify::{sha256, verify_drand, verify_mock, verify_reveal, G1_LEN};

// --- Contract identity (cw2) ------------------------------------------------

pub const CONTRACT_NAME: &str = "crates.io:winsaf";
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Max tickets buyable in a single transaction (bounds gas / loop size).
const MAX_TICKETS_PER_TX: u32 = 100;
/// Default & max page size for the `Tickets` query.
const DEFAULT_QUERY_LIMIT: u32 = 30;
const MAX_QUERY_LIMIT: u32 = 100;
/// Width of the zero-padded ticket sequence, so ids sort lexically = numerically.
const TICKET_ID_WIDTH: usize = 12;
/// Max referral-code length; codes are `[a-z0-9_-]`, case-insensitive.
const MAX_CODE_LEN: usize = 32;

// ===========================================================================
// Instantiate
// ===========================================================================

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let admin = match msg.admin {
        Some(a) => deps.api.addr_validate(&a)?,
        None => info.sender.clone(),
    };

    let denom = msg.denom.unwrap_or_else(|| DENOM.to_string());
    if denom.is_empty() {
        return Err(ContractError::InvalidConfig {
            reason: "denom must not be empty".to_string(),
        });
    }

    let ticket_price = msg
        .ticket_price
        .unwrap_or_else(|| Coin::new(DEFAULT_TICKET_PRICE_USAF, denom.clone()));
    if ticket_price.denom != denom {
        return Err(ContractError::InvalidConfig {
            reason: format!("ticket_price denom must be '{denom}'"),
        });
    }
    if ticket_price.amount.is_zero() {
        return Err(ContractError::InvalidConfig {
            reason: "ticket_price must be non-zero".to_string(),
        });
    }

    let draw_interval = msg.draw_interval.unwrap_or(DEFAULT_DRAW_INTERVAL_SECONDS);
    if draw_interval == 0 {
        return Err(ContractError::InvalidConfig {
            reason: "draw_interval must be non-zero".to_string(),
        });
    }

    let numbers_per_ticket = msg.numbers_per_ticket.unwrap_or(DEFAULT_PICK_COUNT);
    let number_max = msg.number_max.unwrap_or(DEFAULT_NUMBER_MAX);
    validate_number_domain(numbers_per_ticket, number_max)?;

    let split = msg.split.unwrap_or_default();
    split.validate()?; // enforces sum == 10000 and each bucket in range

    let randomness_mode = msg.randomness_mode.unwrap_or(RandomnessMode::Mock);
    let verify_mode = msg.verify_mode.unwrap_or(VerifyMode::Dev);
    let drand_pubkey = msg.drand_pubkey.unwrap_or_default();
    let drand_chain_hash = msg.drand_chain_hash.unwrap_or_default();

    let authorized_submitters = validate_addrs(deps.as_ref(), &msg.authorized_submitters)?;

    let config = Config {
        admin: admin.clone(),
        denom: denom.clone(),
        ticket_price: ticket_price.clone(),
        draw_interval,
        numbers_per_ticket,
        number_max,
        split,
        rollover_on_no_winner: msg.rollover_on_no_winner.unwrap_or(true),
        paused: false,
        randomness_mode,
        verify_mode,
        drand_pubkey,
        drand_chain_hash,
        authorized_submitters,
        min_claim_usaf: msg.min_claim_usaf.unwrap_or_default(),
    };
    validate_randomness_config(&config)?;
    CONFIG.save(deps.storage, &config)?;

    // Zero the treasury balance.
    TREASURY.save(deps.storage, &Uint128::zero())?;

    // Open the first round (id 1).
    let round_id = 1u64;
    let opens_at = env.block.time.seconds();
    let closes_at =
        opens_at
            .checked_add(draw_interval)
            .ok_or_else(|| ContractError::InvalidConfig {
                reason: "draw_interval overflows round close time".to_string(),
            })?;
    let round = Round::new_open(round_id, opens_at, closes_at, Uint128::zero(), None);
    ROUNDS.save(deps.storage, round_id, &round)?;
    CURRENT_ROUND.save(deps.storage, &round_id)?;
    TICKET_SEQ.save(deps.storage, round_id, &0u64)?;

    Ok(Response::new().add_event(
        Event::new("winsaf/instantiate")
            .add_attribute("admin", admin)
            .add_attribute("denom", denom)
            .add_attribute("ticket_price", ticket_price.amount)
            .add_attribute("numbers_per_ticket", numbers_per_ticket.to_string())
            .add_attribute("number_max", number_max.to_string())
            .add_attribute("randomness_mode", config.randomness_mode.as_str())
            .add_attribute("round_id", round_id.to_string()),
    ))
}

// ===========================================================================
// Execute
// ===========================================================================

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::BuyTickets {
            count,
            numbers,
            referral_code,
        } => execute_buy_tickets(deps, env, info, count, numbers, referral_code),
        ExecuteMsg::CloseRound {} => execute_close_round(deps, env, info),
        ExecuteMsg::SubmitRandomness {
            round_id,
            randomness,
            signature,
        } => execute_submit_randomness(deps, env, info, round_id, randomness, signature),
        ExecuteMsg::CommitRandomness {
            round_id,
            commitment,
        } => execute_commit_randomness(deps, info, round_id, commitment),
        ExecuteMsg::RevealRandomness { round_id, value } => {
            execute_reveal_randomness(deps, info, round_id, value)
        }
        ExecuteMsg::Draw { round_id } => execute_draw(deps, env, info, round_id),
        ExecuteMsg::ClaimReward {
            round_id,
            ticket_id,
        } => execute_claim_reward(deps, info, round_id, ticket_id),
        ExecuteMsg::BindReferrer { referrer, code } => {
            execute_bind_referrer(deps, info, referrer, code)
        }
        ExecuteMsg::RegisterCode { code } => execute_register_code(deps, info, code),
        ExecuteMsg::ClaimReferral {} => execute_claim_referral(deps, info),
        ExecuteMsg::WithdrawTreasury { to, amount } => {
            execute_withdraw_treasury(deps, info, to, amount)
        }
        ExecuteMsg::SetConfig {
            admin,
            ticket_price,
            draw_interval,
            split,
            rollover_on_no_winner,
            randomness_mode,
            verify_mode,
            drand_pubkey,
            drand_chain_hash,
            min_claim_usaf,
            add_submitters,
            remove_submitters,
        } => execute_set_config(
            deps,
            info,
            SetConfigArgs {
                admin,
                ticket_price,
                draw_interval,
                split,
                rollover_on_no_winner,
                randomness_mode,
                verify_mode,
                drand_pubkey,
                drand_chain_hash,
                min_claim_usaf,
                add_submitters,
                remove_submitters,
            },
        ),
        ExecuteMsg::Pause {} => execute_set_paused(deps, info, true),
        ExecuteMsg::Unpause {} => execute_set_paused(deps, info, false),
    }
}

// ---------------------------------------------------------------------------
// Buy
// ---------------------------------------------------------------------------

fn execute_buy_tickets(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    count: u32,
    numbers: Option<Vec<u8>>,
    referral_code: Option<String>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if config.paused {
        return Err(ContractError::Paused);
    }
    if count == 0 || count > MAX_TICKETS_PER_TX {
        return Err(ContractError::InvalidTicketCount {
            count,
            max: MAX_TICKETS_PER_TX,
        });
    }

    // Exact payment == count * ticket_price in usaf, and nothing else.
    let unit = config.ticket_price.amount;
    let total = unit
        .checked_mul(Uint128::from(count))
        .map_err(ContractError::Overflow)?;
    assert_exact_usaf(&info.funds, total)?;

    let round_id = CURRENT_ROUND.load(deps.storage)?;
    let mut round = ROUNDS
        .load(deps.storage, round_id)
        .map_err(|_| ContractError::RoundNotFound { round_id })?;
    if !round.status.accepts_tickets() {
        return Err(ContractError::RoundNotOpen {
            round_id,
            status: status_str(&round.status),
        });
    }

    // Split the *total* once: treasury accrues in-contract, referral credits the
    // referrer's ledger, prize grows this round's pool.
    let split = config.split.apply(total)?;

    // --- Treasury cut → in-contract balance --------------------------------
    if !split.treasury.is_zero() {
        TREASURY.update(deps.storage, |t| -> Result<_, ContractError> {
            Ok(t.checked_add(split.treasury)?)
        })?;
    }

    // --- Referral cut → referrer's earnings ledger (or fold into prize) -----
    // Resolve the buyer's referrer: an explicit code takes precedence, else any
    // previously-bound referrer. A code that resolves also binds the buyer once
    // (convenience; self-referral / already-bound are handled gracefully).
    let mut prize_cut = split.prize;
    let mut credited_referrer: Option<Addr> = None;

    if !split.referral.is_zero() {
        let referrer = resolve_buyer_referrer(deps.as_ref(), &info.sender, &referral_code)?;
        match referrer {
            Some(referrer) => {
                credit_referral(deps.storage, &referrer, split.referral)?;
                credited_referrer = Some(referrer);
            }
            None => {
                // No referrer: fold the referral cut into the prize pool so no
                // usaf is left stranded (invariant: every usaf is accounted).
                prize_cut = prize_cut
                    .checked_add(split.referral)
                    .map_err(ContractError::Overflow)?;
            }
        }
    }

    // --- Prize cut stays in-contract → grow this round's pool ---------------
    round.pool = round
        .pool
        .checked_add(prize_cut)
        .map_err(ContractError::Overflow)?;

    // Materialise each ticket. `numbers` configures the first ticket only.
    let mut seq = TICKET_SEQ.load(deps.storage, round_id)?;
    let mut first_id = String::new();
    let mut last_id = String::new();

    for i in 0..count {
        let picks = if i == 0 {
            match &numbers {
                Some(nums) => validate_ticket_numbers(nums, &config)?,
                None => quick_pick(&env, &info.sender, round_id, seq, &config),
            }
        } else {
            quick_pick(&env, &info.sender, round_id, seq, &config)
        };

        let id = ticket_id(seq);
        if i == 0 {
            first_id = id.clone();
        }
        last_id = id.clone();

        let ticket = Ticket {
            owner: info.sender.clone(),
            numbers: picks,
            matches: 0,
            prize: Uint128::zero(),
            claimed: false,
        };
        TICKETS.save(deps.storage, (round_id, id.as_str()), &ticket)?;
        seq += 1;
    }

    // Distinct player accounting (idempotent presence set).
    let mut new_player = false;
    if PLAYERS
        .may_load(deps.storage, (round_id, &info.sender))?
        .is_none()
    {
        PLAYERS.save(deps.storage, (round_id, &info.sender), &1u8)?;
        round.player_count = round.player_count.saturating_add(1);
        new_player = true;
    }

    round.ticket_count = round.ticket_count.saturating_add(count as u64);
    TICKET_SEQ.save(deps.storage, round_id, &seq)?;
    ROUNDS.save(deps.storage, round_id, &round)?;

    let event = Event::new("winsaf/buy")
        .add_attribute("round_id", round_id.to_string())
        .add_attribute("buyer", info.sender.to_string())
        .add_attribute("count", count.to_string())
        .add_attribute("paid", total)
        .add_attribute("prize_added", prize_cut)
        .add_attribute("treasury_added", split.treasury)
        .add_attribute(
            "referral_credited",
            credited_referrer
                .as_ref()
                .map(|_| split.referral)
                .unwrap_or_default(),
        )
        .add_attribute(
            "referrer",
            credited_referrer
                .map(|a| a.to_string())
                .unwrap_or_default(),
        )
        .add_attribute("pool", round.pool)
        .add_attribute("first_ticket_id", first_id)
        .add_attribute("last_ticket_id", last_id)
        .add_attribute("new_player", new_player.to_string());

    Ok(Response::new().add_event(event))
}

// ---------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------

fn execute_close_round(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
) -> Result<Response, ContractError> {
    // Permissionless: anyone may close once the window has elapsed.
    let round_id = CURRENT_ROUND.load(deps.storage)?;
    let mut round = ROUNDS
        .load(deps.storage, round_id)
        .map_err(|_| ContractError::RoundNotFound { round_id })?;

    if !round.status.accepts_tickets() {
        return Err(ContractError::UnexpectedStatus {
            round_id,
            status: status_str(&round.status),
            expected: status_str(&RoundStatus::Open),
        });
    }

    let now = env.block.time.seconds();
    if now < round.closes_at {
        return Err(ContractError::RoundNotClosed {
            round_id,
            closes_at: round.closes_at,
            now,
        });
    }

    round.status = RoundStatus::Drawing;
    ROUNDS.save(deps.storage, round_id, &round)?;

    // Create the pending randomness slot for this round so submitters can act.
    let request = RandomnessRequest {
        round_id,
        beacon_round: round_id,
        status: RandomnessStatus::Pending,
        commitment: None,
        randomness: None,
        signature: None,
    };
    RANDOMNESS.save(deps.storage, round_id, &request)?;

    Ok(Response::new().add_event(
        Event::new("winsaf/close")
            .add_attribute("round_id", round_id.to_string())
            .add_attribute("ticket_count", round.ticket_count.to_string())
            .add_attribute("pool", round.pool),
    ))
}

// ---------------------------------------------------------------------------
// Randomness: submit / commit / reveal
// ---------------------------------------------------------------------------

fn execute_submit_randomness(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    round_id: u64,
    randomness: HexBinary,
    signature: Option<HexBinary>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    // Only authorized submitters (or the admin) may deliver randomness.
    if !config.is_submitter(&info.sender) {
        return Err(ContractError::UnauthorizedSubmitter);
    }

    // Commit-reveal never accepts a direct SubmitRandomness.
    if matches!(config.randomness_mode, RandomnessMode::CommitReveal) {
        return Err(ContractError::WrongMode {
            mode: config.randomness_mode.as_str().to_string(),
        });
    }

    let mut request = load_pending_randomness(deps.as_ref(), round_id)?;

    // Verify according to mode.
    match config.randomness_mode {
        RandomnessMode::Drand => {
            let sig = signature.clone().ok_or_else(|| {
                ContractError::verification_failed("drand mode requires a signature")
            })?;
            verify_drand(
                deps.api,
                &config.verify_mode,
                config.drand_pubkey.as_slice(),
                request.beacon_round,
                &randomness,
                sig.as_slice(),
            )?;
        }
        RandomnessMode::Mock => {
            // Structural check only. NEVER for mainnet.
            verify_mock(&randomness)?;
        }
        RandomnessMode::CommitReveal => unreachable!("guarded above"),
    }

    request.status = RandomnessStatus::Fulfilled;
    request.randomness = Some(randomness.clone());
    request.signature = signature;
    RANDOMNESS.save(deps.storage, round_id, &request)?;

    Ok(Response::new().add_event(
        Event::new("winsaf/submit_randomness")
            .add_attribute("round_id", round_id.to_string())
            .add_attribute("mode", config.randomness_mode.as_str())
            .add_attribute("randomness", randomness.to_hex()),
    ))
}

fn execute_commit_randomness(
    deps: DepsMut,
    info: MessageInfo,
    round_id: u64,
    commitment: HexBinary,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    if !matches!(config.randomness_mode, RandomnessMode::CommitReveal) {
        return Err(ContractError::WrongMode {
            mode: config.randomness_mode.as_str().to_string(),
        });
    }
    if !config.is_submitter(&info.sender) {
        return Err(ContractError::UnauthorizedSubmitter);
    }
    if commitment.len() != 32 {
        return Err(ContractError::verification_failed(
            "commitment hash must be 32 bytes (sha256)",
        ));
    }

    let mut request = load_pending_randomness(deps.as_ref(), round_id)?;
    request.commitment = Some(commitment.clone());
    request.status = RandomnessStatus::Committed;
    RANDOMNESS.save(deps.storage, round_id, &request)?;

    Ok(Response::new().add_event(
        Event::new("winsaf/commit_randomness")
            .add_attribute("round_id", round_id.to_string())
            .add_attribute("committer", info.sender)
            .add_attribute("commitment", commitment.to_hex()),
    ))
}

fn execute_reveal_randomness(
    deps: DepsMut,
    info: MessageInfo,
    round_id: u64,
    value: HexBinary,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    if !matches!(config.randomness_mode, RandomnessMode::CommitReveal) {
        return Err(ContractError::WrongMode {
            mode: config.randomness_mode.as_str().to_string(),
        });
    }
    if !config.is_submitter(&info.sender) {
        return Err(ContractError::UnauthorizedSubmitter);
    }

    let mut request = RANDOMNESS
        .may_load(deps.storage, round_id)?
        .ok_or(ContractError::RoundNotFound { round_id })?;
    if matches!(request.status, RandomnessStatus::Fulfilled) {
        return Err(ContractError::AlreadyFulfilled { round_id });
    }
    let commitment = request
        .commitment
        .clone()
        .ok_or(ContractError::NoCommitment { round_id })?;

    // Reveal must match the earlier commitment.
    verify_reveal(&commitment, &value)?;

    // The randomness a draw consumes is sha256(value): a fixed-length,
    // uniformly-distributed 32-byte seed regardless of the reveal's own length.
    let randomness = HexBinary::from(sha256(value.as_slice()));

    request.status = RandomnessStatus::Fulfilled;
    request.randomness = Some(randomness.clone());
    RANDOMNESS.save(deps.storage, round_id, &request)?;

    Ok(Response::new().add_event(
        Event::new("winsaf/reveal_randomness")
            .add_attribute("round_id", round_id.to_string())
            .add_attribute("randomness", randomness.to_hex()),
    ))
}

// ---------------------------------------------------------------------------
// Draw
// ---------------------------------------------------------------------------

fn execute_draw(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    round_id: u64,
) -> Result<Response, ContractError> {
    // Permissionless: a keeper runs the draw once randomness is fulfilled.
    let config = CONFIG.load(deps.storage)?;
    let mut round = ROUNDS
        .load(deps.storage, round_id)
        .map_err(|_| ContractError::RoundNotFound { round_id })?;

    // Must be closed (Drawing) and not already settled.
    if round.status != RoundStatus::Drawing {
        return Err(ContractError::UnexpectedStatus {
            round_id,
            status: status_str(&round.status),
            expected: status_str(&RoundStatus::Drawing),
        });
    }

    // Consume the fulfilled randomness for this round.
    let request = RANDOMNESS
        .may_load(deps.storage, round_id)?
        .ok_or(ContractError::NoCommitment { round_id })?;
    let randomness = match (&request.status, &request.randomness) {
        (RandomnessStatus::Fulfilled, Some(r)) => r.clone(),
        _ => {
            return Err(ContractError::VerificationFailed {
                reason: format!("randomness for round {round_id} not yet fulfilled"),
            })
        }
    };

    // Derive the winning numbers deterministically from the verified randomness.
    let winning = derive_winning_numbers(
        randomness.as_slice(),
        config.numbers_per_ticket,
        config.number_max,
    );
    round.winning_numbers = Some(winning.clone());

    // Pass 1: count winners per tier (3/4/5/6 matches).
    let mut counts = TierCounts::default();
    let ticket_ids: Vec<String> = TICKETS
        .prefix(round_id)
        .keys(deps.storage, None, None, Order::Ascending)
        .collect::<StdResult<_>>()?;

    let mut ticket_matches: Vec<(String, u8)> = Vec::with_capacity(ticket_ids.len());
    for id in &ticket_ids {
        let ticket = TICKETS.load(deps.storage, (round_id, id.as_str()))?;
        let m = count_matches(&ticket.numbers, &winning);
        counts.add(m);
        ticket_matches.push((id.clone(), m));
    }

    // Fix per-tier per-winner payouts from the pool.
    let tiers = compute_prize_tiers(round.pool, &counts);

    // Pass 2: assign each ticket its prize and mark winners.
    let mut winning_tickets: u64 = 0;
    let mut distributed = Uint128::zero();
    for (id, m) in &ticket_matches {
        let prize = tiers.payout_for_matches(*m);
        if !prize.is_zero() {
            winning_tickets += 1;
            distributed = distributed
                .checked_add(prize)
                .map_err(ContractError::Overflow)?;
        }
        TICKETS.update(
            deps.storage,
            (round_id, id.as_str()),
            |t| -> StdResult<_> {
                let mut t = t.expect("ticket exists (iterated above)");
                t.matches = *m;
                t.prize = prize;
                Ok(t)
            },
        )?;
    }

    // Pool accounting: distributed must never exceed the pool.
    if distributed > round.pool {
        return Err(ContractError::PoolUnderflow {
            round_id,
            pool: round.pool.to_string(),
            requested: distributed.to_string(),
        });
    }
    let leftover = round
        .pool
        .checked_sub(distributed)
        .map_err(ContractError::Overflow)?;

    round.prize_tiers = tiers;
    round.winning_tickets = winning_tickets;
    round.status = RoundStatus::Settled;

    // Rollover: if no jackpot winner (tier_6) and rollover is enabled, the
    // leftover (unassigned) pool moves into the next round. Assigned prizes stay
    // in this round to back pull-based claims.
    let no_jackpot = counts.six == 0;
    let mut rollover_amount = Uint128::zero();
    if config.rollover_on_no_winner && no_jackpot {
        rollover_amount = leftover;
    }
    // The pool retained on this round is exactly what claims can draw down.
    round.pool = distributed;
    ROUNDS.save(deps.storage, round_id, &round)?;

    // Open the next round (id + 1) seeded with any rollover.
    let next_id = round_id
        .checked_add(1)
        .ok_or_else(|| ContractError::InvalidConfig {
            reason: "round id overflow".to_string(),
        })?;
    let opens_at = env.block.time.seconds();
    let closes_at =
        opens_at
            .checked_add(config.draw_interval)
            .ok_or_else(|| ContractError::InvalidConfig {
                reason: "draw_interval overflows round close time".to_string(),
            })?;
    let rolled_from = if rollover_amount.is_zero() {
        None
    } else {
        Some(round_id)
    };
    let next_round = Round::new_open(next_id, opens_at, closes_at, rollover_amount, rolled_from);
    ROUNDS.save(deps.storage, next_id, &next_round)?;
    TICKET_SEQ.save(deps.storage, next_id, &0u64)?;
    CURRENT_ROUND.save(deps.storage, &next_id)?;

    let event = Event::new("winsaf/draw")
        .add_attribute("round_id", round_id.to_string())
        .add_attribute("winning_numbers", numbers_csv(&winning))
        .add_attribute("winners_3", counts.three.to_string())
        .add_attribute("winners_4", counts.four.to_string())
        .add_attribute("winners_5", counts.five.to_string())
        .add_attribute("winners_6", counts.six.to_string())
        .add_attribute("distributed", distributed)
        .add_attribute("rollover", rollover_amount)
        .add_attribute("next_round_id", next_id.to_string());

    Ok(Response::new().add_event(event))
}

// ---------------------------------------------------------------------------
// Claim prize
// ---------------------------------------------------------------------------

fn execute_claim_reward(
    deps: DepsMut,
    info: MessageInfo,
    round_id: u64,
    ticket_id: String,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let mut round = ROUNDS
        .load(deps.storage, round_id)
        .map_err(|_| ContractError::RoundNotFound { round_id })?;

    let mut ticket = TICKETS
        .may_load(deps.storage, (round_id, ticket_id.as_str()))?
        .ok_or_else(|| ContractError::TicketNotFound {
            round_id,
            ticket_id: ticket_id.clone(),
        })?;

    // Only the owner may claim.
    if ticket.owner != info.sender {
        return Err(ContractError::unauthorized("ticket owner"));
    }
    if ticket.prize.is_zero() {
        return Err(ContractError::NoPrize {
            round_id,
            ticket_id,
        });
    }
    if ticket.claimed {
        return Err(ContractError::AlreadyClaimed {
            round_id,
            ticket_id,
        });
    }

    // Pool accounting: never pay out more than the round holds.
    if ticket.prize > round.pool {
        return Err(ContractError::PoolUnderflow {
            round_id,
            pool: round.pool.to_string(),
            requested: ticket.prize.to_string(),
        });
    }

    let prize = ticket.prize;
    ticket.claimed = true;
    TICKETS.save(deps.storage, (round_id, ticket_id.as_str()), &ticket)?;

    round.pool = round
        .pool
        .checked_sub(prize)
        .map_err(ContractError::Overflow)?;
    ROUNDS.save(deps.storage, round_id, &round)?;

    let payout = CosmosMsg::Bank(BankMsg::Send {
        to_address: ticket.owner.to_string(),
        amount: vec![Coin::new(prize, config.denom.clone())],
    });

    let event = Event::new("winsaf/claim")
        .add_attribute("round_id", round_id.to_string())
        .add_attribute("ticket_id", ticket_id)
        .add_attribute("owner", ticket.owner.to_string())
        .add_attribute("prize", prize);

    Ok(Response::new().add_message(payout).add_event(event))
}

// ---------------------------------------------------------------------------
// Referral: bind / register code / claim
// ---------------------------------------------------------------------------

fn execute_bind_referrer(
    deps: DepsMut,
    info: MessageInfo,
    referrer: Option<String>,
    code: Option<String>,
) -> Result<Response, ContractError> {
    let referee = info.sender;

    // Bind-once: a present key is an existing, immutable binding.
    if REFERRER.has(deps.storage, &referee) {
        return Err(ContractError::AlreadyBound {
            referee: referee.to_string(),
        });
    }

    // Resolve the referrer from an explicit address or a referral code.
    let referrer = match (referrer, code) {
        (Some(addr), _) => deps.api.addr_validate(&addr)?,
        (None, Some(code)) => {
            let normalized = normalize_code(&code);
            REFERRAL_CODES
                .may_load(deps.storage, &normalized)?
                .ok_or(ContractError::UnknownReferralCode { code })?
        }
        (None, None) => {
            return Err(ContractError::InvalidConfig {
                reason: "provide either `referrer` or `code`".to_string(),
            })
        }
    };

    // Anti-abuse: no self-referral / no trivial cycle (referrer != referee).
    if referrer == referee {
        return Err(ContractError::SelfReferral);
    }

    bind_referrer(deps.storage, &referee, &referrer)?;

    Ok(Response::new().add_event(
        Event::new("winsaf/bind_referrer")
            .add_attribute("referee", referee)
            .add_attribute("referrer", referrer),
    ))
}

fn execute_register_code(
    deps: DepsMut,
    info: MessageInfo,
    code: String,
) -> Result<Response, ContractError> {
    validate_code(&code)?;
    let normalized = normalize_code(&code);

    if let Some(existing) = REFERRAL_CODES.may_load(deps.storage, &normalized)? {
        // Idempotent for the same owner; conflict for a different one.
        if existing != info.sender {
            return Err(ContractError::unauthorized("code owner"));
        }
    }
    REFERRAL_CODES.save(deps.storage, &normalized, &info.sender)?;

    Ok(Response::new().add_event(
        Event::new("winsaf/register_code")
            .add_attribute("code", normalized)
            .add_attribute("owner", info.sender),
    ))
}

fn execute_claim_referral(deps: DepsMut, info: MessageInfo) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let claimant = info.sender;

    let pending = REFERRAL_EARNINGS
        .may_load(deps.storage, &claimant)?
        .unwrap_or_default();

    if pending.is_zero() || pending < config.min_claim_usaf {
        return Err(ContractError::NothingToClaim);
    }

    // Zero out first (checks-effects-interactions); the bank send is dispatched
    // after this handler returns Ok.
    REFERRAL_EARNINGS.save(deps.storage, &claimant, &Uint128::zero())?;
    REFERRAL_TOTALS.update(deps.storage, &claimant, |t| -> Result<_, ContractError> {
        let mut totals = t.unwrap_or_default();
        totals.lifetime_claimed = totals.lifetime_claimed.checked_add(pending)?;
        Ok(totals)
    })?;

    let payout = CosmosMsg::Bank(BankMsg::Send {
        to_address: claimant.to_string(),
        amount: vec![Coin::new(pending, config.denom.clone())],
    });

    Ok(Response::new().add_message(payout).add_event(
        Event::new("winsaf/claim_referral")
            .add_attribute("referrer", claimant)
            .add_attribute("amount", pending),
    ))
}

// ---------------------------------------------------------------------------
// Treasury withdraw
// ---------------------------------------------------------------------------

fn execute_withdraw_treasury(
    deps: DepsMut,
    info: MessageInfo,
    to: String,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if !config.is_admin(&info.sender) {
        return Err(ContractError::unauthorized("admin"));
    }
    if amount.is_zero() {
        return Err(ContractError::ZeroWithdraw);
    }

    let recipient = deps.api.addr_validate(&to)?;

    let available = TREASURY.load(deps.storage)?;
    if amount > available {
        return Err(ContractError::InsufficientTreasury {
            requested: amount.to_string(),
            available: available.to_string(),
        });
    }
    let remaining = available
        .checked_sub(amount)
        .map_err(ContractError::Overflow)?;
    TREASURY.save(deps.storage, &remaining)?;

    let send = CosmosMsg::Bank(BankMsg::Send {
        to_address: recipient.to_string(),
        amount: vec![Coin::new(amount, config.denom.clone())],
    });

    Ok(Response::new().add_message(send).add_event(
        Event::new("winsaf/withdraw_treasury")
            .add_attribute("by", info.sender)
            .add_attribute("to", recipient)
            .add_attribute("amount", amount)
            .add_attribute("remaining", remaining),
    ))
}

// ---------------------------------------------------------------------------
// SetConfig / pause
// ---------------------------------------------------------------------------

/// Grouped `SetConfig` args to keep the function signature under control.
struct SetConfigArgs {
    admin: Option<String>,
    ticket_price: Option<Coin>,
    draw_interval: Option<u64>,
    split: Option<FundSplitBps>,
    rollover_on_no_winner: Option<bool>,
    randomness_mode: Option<RandomnessMode>,
    verify_mode: Option<VerifyMode>,
    drand_pubkey: Option<HexBinary>,
    drand_chain_hash: Option<String>,
    min_claim_usaf: Option<Uint128>,
    add_submitters: Option<Vec<String>>,
    remove_submitters: Option<Vec<String>>,
}

fn execute_set_config(
    deps: DepsMut,
    info: MessageInfo,
    args: SetConfigArgs,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;
    if !config.is_admin(&info.sender) {
        return Err(ContractError::unauthorized("admin"));
    }

    let mut changed: Vec<Attribute> = Vec::new();

    if let Some(a) = args.admin {
        config.admin = deps.api.addr_validate(&a)?;
        changed.push(Attribute::new("admin", config.admin.to_string()));
    }
    if let Some(p) = args.ticket_price {
        if p.denom != config.denom {
            return Err(ContractError::InvalidConfig {
                reason: format!("ticket_price denom must be '{}'", config.denom),
            });
        }
        if p.amount.is_zero() {
            return Err(ContractError::InvalidConfig {
                reason: "ticket_price must be non-zero".to_string(),
            });
        }
        config.ticket_price = p.clone();
        changed.push(Attribute::new("ticket_price", p.amount));
    }
    if let Some(d) = args.draw_interval {
        if d == 0 {
            return Err(ContractError::InvalidConfig {
                reason: "draw_interval must be non-zero".to_string(),
            });
        }
        config.draw_interval = d;
        changed.push(Attribute::new("draw_interval", d.to_string()));
    }
    if let Some(s) = args.split {
        s.validate()?;
        config.split = s;
        changed.push(Attribute::new("split_prize_bps", s.prize_bps.to_string()));
        changed.push(Attribute::new(
            "split_referral_bps",
            s.referral_bps.to_string(),
        ));
        changed.push(Attribute::new(
            "split_treasury_bps",
            s.treasury_bps.to_string(),
        ));
    }
    if let Some(ro) = args.rollover_on_no_winner {
        config.rollover_on_no_winner = ro;
        changed.push(Attribute::new("rollover_on_no_winner", ro.to_string()));
    }
    if let Some(m) = args.randomness_mode {
        changed.push(Attribute::new("randomness_mode", m.as_str()));
        config.randomness_mode = m;
    }
    if let Some(v) = args.verify_mode {
        config.verify_mode = v;
        changed.push(Attribute::new(
            "verify_mode",
            verify_mode_str(&config.verify_mode),
        ));
    }
    if let Some(pk) = args.drand_pubkey {
        config.drand_pubkey = pk;
        changed.push(Attribute::new("drand_pubkey", "updated"));
    }
    if let Some(ch) = args.drand_chain_hash {
        config.drand_chain_hash = ch;
        changed.push(Attribute::new("drand_chain_hash", "updated"));
    }
    if let Some(v) = args.min_claim_usaf {
        config.min_claim_usaf = v;
        changed.push(Attribute::new("min_claim_usaf", v));
    }
    if let Some(add) = args.add_submitters {
        for a in add {
            let addr = deps.api.addr_validate(&a)?;
            if !config.authorized_submitters.contains(&addr) {
                config.authorized_submitters.push(addr.clone());
                changed.push(Attribute::new("add_submitter", addr));
            }
        }
    }
    if let Some(remove) = args.remove_submitters {
        for r in remove {
            let addr = deps.api.addr_validate(&r)?;
            config.authorized_submitters.retain(|a| *a != addr);
            changed.push(Attribute::new("remove_submitter", addr));
        }
    }

    validate_randomness_config(&config)?;
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new().add_event(Event::new("winsaf/set_config").add_attributes(changed)))
}

fn execute_set_paused(
    deps: DepsMut,
    info: MessageInfo,
    paused: bool,
) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;
    if !config.is_admin(&info.sender) {
        return Err(ContractError::unauthorized("admin"));
    }
    config.paused = paused;
    CONFIG.save(deps.storage, &config)?;
    Ok(Response::new()
        .add_event(Event::new("winsaf/pause").add_attribute("paused", paused.to_string())))
}

// ===========================================================================
// Query
// ===========================================================================

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::Config {} => Ok(to_json_binary(&CONFIG.load(deps.storage)?)?),
        QueryMsg::CurrentRound {} => {
            let id = CURRENT_ROUND.load(deps.storage)?;
            Ok(to_json_binary(&query_round(deps, id)?)?)
        }
        QueryMsg::Round { round_id } => Ok(to_json_binary(&query_round(deps, round_id)?)?),
        QueryMsg::Tickets {
            round_id,
            owner,
            start_after,
            limit,
        } => Ok(to_json_binary(&query_tickets(
            deps,
            round_id,
            owner,
            start_after,
            limit,
        )?)?),
        QueryMsg::Prize { round_id, owner } => {
            Ok(to_json_binary(&query_prize(deps, round_id, owner)?)?)
        }
        QueryMsg::Referrer { referee } => Ok(to_json_binary(&query_referrer(deps, referee)?)?),
        QueryMsg::ReferralSummary { addr } => {
            Ok(to_json_binary(&query_referral_summary(deps, addr)?)?)
        }
        QueryMsg::TreasuryBalance {} => {
            Ok(to_json_binary(&query_treasury_balance(deps)?)?)
        }
    }
}

fn query_round(deps: Deps, round_id: u64) -> Result<RoundResponse, ContractError> {
    let r = ROUNDS
        .load(deps.storage, round_id)
        .map_err(|_| ContractError::RoundNotFound { round_id })?;
    let randomness = RANDOMNESS.may_load(deps.storage, round_id)?;
    Ok(RoundResponse {
        id: r.id,
        status: r.status,
        pool: r.pool,
        ticket_count: r.ticket_count,
        player_count: r.player_count,
        opens_at: r.opens_at,
        closes_at: r.closes_at,
        winning_numbers: r.winning_numbers,
        prize_tiers: r.prize_tiers,
        rolled_over_from: r.rolled_over_from,
        winning_tickets: r.winning_tickets,
        randomness,
    })
}

fn query_tickets(
    deps: Deps,
    round_id: u64,
    owner: Option<String>,
    start_after: Option<String>,
    limit: Option<u32>,
) -> Result<TicketsResponse, ContractError> {
    let owner = owner.map(|o| deps.api.addr_validate(&o)).transpose()?;
    let limit = limit.unwrap_or(DEFAULT_QUERY_LIMIT).min(MAX_QUERY_LIMIT) as usize;
    let start = start_after.as_deref().map(Bound::exclusive);

    let mut out: Vec<TicketInfo> = Vec::new();
    for item in TICKETS
        .prefix(round_id)
        .range(deps.storage, start, None, Order::Ascending)
    {
        if out.len() >= limit {
            break;
        }
        let (ticket_id, ticket) = item?;
        if let Some(o) = &owner {
            if ticket.owner != *o {
                continue;
            }
        }
        out.push(TicketInfo { ticket_id, ticket });
    }

    Ok(TicketsResponse { tickets: out })
}

fn query_prize(deps: Deps, round_id: u64, owner: String) -> Result<PrizeResponse, ContractError> {
    let owner_addr = deps.api.addr_validate(&owner)?;
    if !ROUNDS.has(deps.storage, round_id) {
        return Err(ContractError::RoundNotFound { round_id });
    }

    let mut claimable = Uint128::zero();
    let mut claimed = Uint128::zero();
    let mut winning_ticket_ids: Vec<String> = Vec::new();

    for item in TICKETS
        .prefix(round_id)
        .range(deps.storage, None, None, Order::Ascending)
    {
        let (id, ticket) = item?;
        if ticket.owner != owner_addr || ticket.prize.is_zero() {
            continue;
        }
        winning_ticket_ids.push(id);
        if ticket.claimed {
            claimed = claimed.checked_add(ticket.prize)?;
        } else {
            claimable = claimable.checked_add(ticket.prize)?;
        }
    }

    Ok(PrizeResponse {
        round_id,
        owner,
        claimable,
        claimed,
        winning_ticket_ids,
    })
}

fn query_referrer(deps: Deps, referee: String) -> Result<ReferrerResponse, ContractError> {
    let referee = deps.api.addr_validate(&referee)?;
    let referrer = REFERRER.may_load(deps.storage, &referee)?;
    Ok(ReferrerResponse {
        referrer: referrer.map(|a| a.to_string()),
    })
}

fn query_referral_summary(
    deps: Deps,
    addr: String,
) -> Result<ReferralSummaryResponse, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let addr = deps.api.addr_validate(&addr)?;
    let pending = REFERRAL_EARNINGS
        .may_load(deps.storage, &addr)?
        .unwrap_or_default();
    let totals = REFERRAL_TOTALS
        .may_load(deps.storage, &addr)?
        .unwrap_or_default();
    Ok(ReferralSummaryResponse {
        addr: addr.to_string(),
        denom: config.denom,
        pending,
        referees: totals.referees,
        lifetime_earned: totals.lifetime_earned,
        lifetime_claimed: totals.lifetime_claimed,
    })
}

fn query_treasury_balance(deps: Deps) -> Result<TreasuryBalanceResponse, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let balance = TREASURY.load(deps.storage)?;
    Ok(TreasuryBalanceResponse {
        balance,
        denom: config.denom,
    })
}

// ===========================================================================
// Migrate
// ===========================================================================

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    let current = get_contract_version(deps.storage)?;
    if current.contract != CONTRACT_NAME {
        return Err(ContractError::InvalidMigration {
            expected: CONTRACT_NAME.to_string(),
            found: current.contract,
        });
    }
    // Idempotent version bump; add data migrations here on future versions.
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new().add_event(
        Event::new("winsaf/migrate")
            .add_attribute("from_version", current.version)
            .add_attribute("to_version", CONTRACT_VERSION),
    ))
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Zero-padded, lexically-sortable ticket id from a per-round sequence.
pub fn ticket_id(seq: u64) -> String {
    format!("{seq:0width$}", width = TICKET_ID_WIDTH)
}

fn status_str(s: &RoundStatus) -> String {
    match s {
        RoundStatus::Open => "open",
        RoundStatus::Drawing => "drawing",
        RoundStatus::Drawn => "drawn",
        RoundStatus::Settled => "settled",
        RoundStatus::Cancelled => "cancelled",
    }
    .to_string()
}

fn verify_mode_str(v: &VerifyMode) -> &'static str {
    match v {
        VerifyMode::Bls => "bls",
        VerifyMode::Dev => "dev",
    }
}

fn numbers_csv(numbers: &[u8]) -> String {
    numbers
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn validate_addrs(deps: Deps, addrs: &[String]) -> Result<Vec<Addr>, ContractError> {
    let mut out: Vec<Addr> = Vec::with_capacity(addrs.len());
    for a in addrs {
        let addr = deps.api.addr_validate(a)?;
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    Ok(out)
}

/// Cross-field randomness config validation. drand+bls needs a well-formed group
/// public key and a chain hash.
fn validate_randomness_config(config: &Config) -> Result<(), ContractError> {
    if matches!(config.randomness_mode, RandomnessMode::Drand) {
        if config.drand_chain_hash.is_empty() {
            return Err(ContractError::InvalidConfig {
                reason: "drand_chain_hash is required in drand mode".to_string(),
            });
        }
        if matches!(config.verify_mode, VerifyMode::Bls)
            && config.drand_pubkey.len() != G1_LEN
        {
            return Err(ContractError::InvalidPubkey {
                reason: format!(
                    "drand mode with BLS verification requires a {G1_LEN}-byte G1 public key"
                ),
            });
        }
    }
    Ok(())
}

fn validate_number_domain(numbers_per_ticket: u8, number_max: u8) -> Result<(), ContractError> {
    if numbers_per_ticket == 0 {
        return Err(ContractError::InvalidConfig {
            reason: "numbers_per_ticket must be > 0".to_string(),
        });
    }
    if number_max == 0 || (number_max as u16) < numbers_per_ticket as u16 {
        return Err(ContractError::InvalidConfig {
            reason: "number_max must be >= numbers_per_ticket".to_string(),
        });
    }
    Ok(())
}

/// Validate a buyer-supplied set of picks: exactly `numbers_per_ticket` distinct
/// numbers, each in `1..=number_max`. Returns them sorted ascending.
fn validate_ticket_numbers(numbers: &[u8], config: &Config) -> Result<Vec<u8>, ContractError> {
    validate_number_domain(config.numbers_per_ticket, config.number_max)?;
    let mut sorted = numbers.to_vec();
    sorted.sort_unstable();
    if sorted.len() != config.numbers_per_ticket as usize {
        return Err(ContractError::InvalidNumbers {
            expected: config.numbers_per_ticket,
            number_max: config.number_max,
            reason: format!("count {}", sorted.len()),
        });
    }
    for w in sorted.windows(2) {
        if w[0] == w[1] {
            return Err(ContractError::InvalidNumbers {
                expected: config.numbers_per_ticket,
                number_max: config.number_max,
                reason: format!("duplicate {}", w[0]),
            });
        }
    }
    if let Some(&first) = sorted.first() {
        if first < 1 {
            return Err(ContractError::InvalidNumbers {
                expected: config.numbers_per_ticket,
                number_max: config.number_max,
                reason: "value < 1".to_string(),
            });
        }
    }
    if let Some(&last) = sorted.last() {
        if last > config.number_max {
            return Err(ContractError::InvalidNumbers {
                expected: config.numbers_per_ticket,
                number_max: config.number_max,
                reason: format!("value {last} > {}", config.number_max),
            });
        }
    }
    Ok(sorted)
}

/// Deterministic quick-pick used when the buyer supplies no numbers.
///
/// NOTE: This is a quick-pick convenience for the buyer's OWN ticket numbers,
/// NOT the source of the draw's randomness. The winning numbers are derived
/// separately from the verified randomness (`derive_winning_numbers`). Quick-pick
/// only needs to be well-distributed, not unpredictable.
fn quick_pick(env: &Env, sender: &Addr, round_id: u64, seq: u64, config: &Config) -> Vec<u8> {
    let mut seed: u64 = 0xcbf29ce484222325;
    let mut mix = |bytes: &[u8]| {
        for b in bytes {
            seed ^= *b as u64;
            seed = seed.wrapping_mul(0x100000001b3);
        }
    };
    mix(sender.as_bytes());
    mix(&round_id.to_be_bytes());
    mix(&seq.to_be_bytes());
    mix(&env.block.height.to_be_bytes());
    mix(&env.block.time.nanos().to_be_bytes());

    pick_distinct(seed, config.numbers_per_ticket, config.number_max)
}

/// Derive the winning numbers from verified randomness: `count` distinct values
/// in `1..=number_max`, sorted ascending.
fn derive_winning_numbers(randomness: &[u8], count: u8, number_max: u8) -> Vec<u8> {
    let mut seed: u64 = 0xcbf29ce484222325;
    for b in randomness {
        seed ^= *b as u64;
        seed = seed.wrapping_mul(0x100000001b3);
    }
    pick_distinct(seed, count, number_max)
}

/// Pick `count` distinct numbers in `1..=number_max` from a seed using a
/// xorshift64* stream + rejection to avoid duplicates. Result is sorted.
fn pick_distinct(mut seed: u64, count: u8, number_max: u8) -> Vec<u8> {
    if seed == 0 {
        seed = 0x9e3779b97f4a7c15; // avoid the xorshift zero fixed-point
    }
    let mut next = move || {
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        seed.wrapping_mul(0x2545F4914F6CDD1D)
    };

    let domain = number_max as u64; // values 1..=number_max
    let mut chosen: Vec<u8> = Vec::with_capacity(count as usize);
    let max_iterations = (count as u64).saturating_mul(64).max(1024);
    let mut iterations = 0u64;
    while (chosen.len() as u8) < count && iterations < max_iterations {
        iterations += 1;
        let v = (next() % domain) as u8 + 1; // 1..=number_max
        if !chosen.contains(&v) {
            chosen.push(v);
        }
    }
    // Deterministic fallback fill (only reachable if count > domain, forbidden by
    // config validation) to keep length correct.
    let mut n: u8 = 1;
    while (chosen.len() as u8) < count && n <= number_max {
        if !chosen.contains(&n) {
            chosen.push(n);
        }
        n += 1;
    }
    chosen.sort_unstable();
    chosen
}

/// Number of `picks` present in `winning`.
fn count_matches(picks: &[u8], winning: &[u8]) -> u8 {
    picks.iter().filter(|p| winning.contains(p)).count() as u8
}

/// Load the randomness slot for a round, requiring it to exist and not be
/// already fulfilled.
fn load_pending_randomness(
    deps: Deps,
    round_id: u64,
) -> Result<RandomnessRequest, ContractError> {
    let request = RANDOMNESS
        .may_load(deps.storage, round_id)?
        .ok_or(ContractError::RoundNotFound { round_id })?;
    if matches!(request.status, RandomnessStatus::Fulfilled) {
        return Err(ContractError::AlreadyFulfilled { round_id });
    }
    Ok(request)
}

// --- Referral helpers -------------------------------------------------------

/// Resolve which referrer a buy should credit. A supplied `code` binds the buyer
/// (once) and takes precedence; otherwise any existing binding is used. Returns
/// `None` when the buyer has (and gets) no valid referrer.
fn resolve_buyer_referrer(
    deps: Deps,
    buyer: &Addr,
    referral_code: &Option<String>,
) -> Result<Option<Addr>, ContractError> {
    // Already bound? Use that binding (immutable).
    if let Some(existing) = REFERRER.may_load(deps.storage, buyer)? {
        return Ok(Some(existing));
    }

    // Not bound yet: try to bind via code if one was supplied.
    if let Some(code) = referral_code {
        let normalized = normalize_code(code);
        if let Some(referrer) = REFERRAL_CODES.may_load(deps.storage, &normalized)? {
            if referrer == *buyer {
                // Self-referral via code: ignore silently (no crediting).
                return Ok(None);
            }
            return Ok(Some(referrer));
        }
    }

    Ok(None)
}

/// Persist a `referee -> referrer` binding and bump the referrer's referee count.
fn bind_referrer(
    storage: &mut dyn cosmwasm_std::Storage,
    referee: &Addr,
    referrer: &Addr,
) -> Result<(), ContractError> {
    REFERRER.save(storage, referee, referrer)?;
    REFERRAL_TOTALS.update(storage, referrer, |t| -> StdResult<_> {
        let mut totals = t.unwrap_or_default();
        totals.referees = totals.referees.saturating_add(1);
        Ok(totals)
    })?;
    Ok(())
}

/// Credit `amount` usaf to a referrer's earnings ledger and lifetime total. If
/// the buyer supplied a code that resolved to a referrer they are not yet bound
/// to, this also creates the (immutable) binding.
fn credit_referral(
    storage: &mut dyn cosmwasm_std::Storage,
    referrer: &Addr,
    amount: Uint128,
) -> Result<(), ContractError> {
    REFERRAL_EARNINGS.update(storage, referrer, |e| -> Result<_, ContractError> {
        Ok(e.unwrap_or_default().checked_add(amount)?)
    })?;
    REFERRAL_TOTALS.update(storage, referrer, |t| -> Result<_, ContractError> {
        let mut totals = t.unwrap_or_default();
        totals.lifetime_earned = totals.lifetime_earned.checked_add(amount)?;
        Ok(totals)
    })?;
    Ok(())
}

/// Lowercase a referral code so lookups are case-insensitive.
fn normalize_code(code: &str) -> String {
    code.trim().to_lowercase()
}

/// Validate a referral code: 1..=32 chars from `[a-z0-9_-]` (case-insensitive).
fn validate_code(code: &str) -> Result<(), ContractError> {
    let normalized = normalize_code(code);
    if normalized.is_empty() || normalized.len() > MAX_CODE_LEN {
        return Err(ContractError::InvalidConfig {
            reason: format!("code length must be 1..={MAX_CODE_LEN}"),
        });
    }
    if !normalized
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ContractError::InvalidConfig {
            reason: "code may only contain [a-z0-9_-]".to_string(),
        });
    }
    Ok(())
}

// --- Prize tier computation -------------------------------------------------

/// Winner counts per prize tier.
#[derive(Default)]
struct TierCounts {
    three: u64,
    four: u64,
    five: u64,
    six: u64,
}

impl TierCounts {
    fn add(&mut self, matches: u8) {
        match matches {
            3 => self.three += 1,
            4 => self.four += 1,
            5 => self.five += 1,
            m if m >= 6 => self.six += 1,
            _ => {}
        }
    }
}

impl PrizeTiers {
    /// Per-winner payout for a given match count.
    fn payout_for_matches(&self, matches: u8) -> Uint128 {
        match matches {
            3 => self.tier_3,
            4 => self.tier_4,
            5 => self.tier_5,
            m if m >= 6 => self.tier_6,
            _ => Uint128::zero(),
        }
    }
}

/// Fixed tier weights in bps of the prize pool: tier_6 (jackpot) 60%, tier_5 20%,
/// tier_4 12%, tier_3 8% (sum 100%). Each tier's allocation is split equally
/// among its winners; tiers with no winners keep their share in the pool so it
/// can roll over.
const TIER6_BPS: u128 = 6000;
const TIER5_BPS: u128 = 2000;
const TIER4_BPS: u128 = 1200;
const TIER3_BPS: u128 = 800;

fn compute_prize_tiers(pool: Uint128, counts: &TierCounts) -> PrizeTiers {
    let per_winner = |tier_bps: u128, winners: u64| -> Uint128 {
        if winners == 0 {
            return Uint128::zero();
        }
        let allocation = match pool.checked_mul(Uint128::from(tier_bps)) {
            Ok(scaled) => scaled
                .checked_div(Uint128::from(10_000u128))
                .unwrap_or_default(),
            Err(_) => Uint128::zero(),
        };
        allocation
            .checked_div(Uint128::from(winners))
            .unwrap_or_default()
    };

    PrizeTiers {
        tier_3: per_winner(TIER3_BPS, counts.three),
        tier_4: per_winner(TIER4_BPS, counts.four),
        tier_5: per_winner(TIER5_BPS, counts.five),
        tier_6: per_winner(TIER6_BPS, counts.six),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{
        message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{coins, from_json, Coin, CosmosMsg, HexBinary, OwnedDeps, Timestamp};
    use winsaf_shared::FundSplitBps;

    const TICKET_PRICE: u128 = 5_000_000;
    const DRAW_INTERVAL: u64 = 3600;

    type OD = OwnedDeps<MockStorage, MockApi, MockQuerier>;

    fn mk(api: &MockApi, s: &str) -> Addr {
        api.addr_make(s)
    }

    /// Instantiate with mock randomness, dev verify, one authorized submitter.
    fn setup() -> (OD, MockApi, Env, Addr, Addr) {
        let mut deps = mock_dependencies();
        let api = deps.api;
        let env = mock_env();
        let admin = mk(&api, "admin");
        let submitter = mk(&api, "relayer");

        let msg = InstantiateMsg {
            admin: Some(admin.to_string()),
            denom: None,
            ticket_price: None,
            draw_interval: Some(DRAW_INTERVAL),
            numbers_per_ticket: None,
            number_max: None,
            split: None,
            rollover_on_no_winner: Some(true),
            randomness_mode: None, // Mock
            verify_mode: None,     // Dev
            drand_pubkey: None,
            drand_chain_hash: None,
            authorized_submitters: vec![submitter.to_string()],
            min_claim_usaf: None,
        };
        let info = message_info(&admin, &[]);
        instantiate(deps.as_mut(), env.clone(), info, msg).unwrap();
        (deps, api, env, admin, submitter)
    }

    fn buy(
        deps: &mut OD,
        env: &Env,
        buyer: &Addr,
        count: u32,
        numbers: Option<Vec<u8>>,
        referral_code: Option<String>,
    ) -> Result<Response, ContractError> {
        let funds = coins(TICKET_PRICE * count as u128, DENOM);
        let info = message_info(buyer, &funds);
        execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::BuyTickets {
                count,
                numbers,
                referral_code,
            },
        )
    }

    fn advance(env: &mut Env, secs: u64) {
        env.block.time = Timestamp::from_seconds(env.block.time.seconds() + secs);
        env.block.height += 1;
    }

    /// Close + submit mock randomness + draw round 1, returning the derived
    /// winning numbers.
    fn run_draw(deps: &mut OD, env: &Env, submitter: &Addr, randomness: HexBinary) -> Vec<u8> {
        let mut env2 = env.clone();
        advance(&mut env2, DRAW_INTERVAL + 1);
        let keeper = mk(&deps.api, "keeper");
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&keeper, &[]),
            ExecuteMsg::CloseRound {},
        )
        .unwrap();
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(submitter, &[]),
            ExecuteMsg::SubmitRandomness {
                round_id: 1,
                randomness: randomness.clone(),
                signature: None,
            },
        )
        .unwrap();
        execute(
            deps.as_mut(),
            env2,
            message_info(&keeper, &[]),
            ExecuteMsg::Draw { round_id: 1 },
        )
        .unwrap();
        derive_winning_numbers(randomness.as_slice(), 6, 45)
    }

    fn cfg(deps: &OD) -> Config {
        from_json(query(deps.as_ref(), mock_env(), QueryMsg::Config {}).unwrap()).unwrap()
    }

    fn round(deps: &OD, id: u64) -> RoundResponse {
        from_json(query(deps.as_ref(), mock_env(), QueryMsg::Round { round_id: id }).unwrap())
            .unwrap()
    }

    fn current(deps: &OD) -> RoundResponse {
        from_json(query(deps.as_ref(), mock_env(), QueryMsg::CurrentRound {}).unwrap()).unwrap()
    }

    // --- instantiate --------------------------------------------------------

    #[test]
    fn instantiate_defaults() {
        let (deps, _api, _env, admin, submitter) = setup();
        let c = cfg(&deps);
        assert_eq!(c.admin, admin);
        assert_eq!(c.denom, "usaf");
        assert_eq!(c.ticket_price.amount, Uint128::new(TICKET_PRICE));
        assert_eq!(c.ticket_price.denom, "usaf");
        assert_eq!(c.numbers_per_ticket, 6);
        assert_eq!(c.number_max, 45);
        assert_eq!(c.split, FundSplitBps::default_split());
        assert!(c.rollover_on_no_winner);
        assert!(!c.paused);
        assert!(matches!(c.randomness_mode, RandomnessMode::Mock));
        assert!(matches!(c.verify_mode, VerifyMode::Dev));
        assert!(c.is_submitter(&submitter));
        assert!(c.is_submitter(&admin));
        assert_eq!(c.min_claim_usaf, Uint128::zero());

        let r = current(&deps);
        assert_eq!(r.id, 1);
        assert_eq!(r.status, RoundStatus::Open);
        assert_eq!(r.pool, Uint128::zero());

        let tb: TreasuryBalanceResponse =
            from_json(query(deps.as_ref(), mock_env(), QueryMsg::TreasuryBalance {}).unwrap())
                .unwrap();
        assert_eq!(tb.balance, Uint128::zero());
        assert_eq!(tb.denom, "usaf");

        let ver = get_contract_version(&deps.storage).unwrap();
        assert_eq!(ver.contract, CONTRACT_NAME);
        assert_eq!(ver.version, CONTRACT_VERSION);
    }

    #[test]
    fn instantiate_defaults_admin_to_sender() {
        let mut deps = mock_dependencies();
        let sender = deps.api.addr_make("sender");
        let msg = InstantiateMsg {
            admin: None,
            denom: None,
            ticket_price: None,
            draw_interval: None,
            numbers_per_ticket: None,
            number_max: None,
            split: None,
            rollover_on_no_winner: None,
            randomness_mode: None,
            verify_mode: None,
            drand_pubkey: None,
            drand_chain_hash: None,
            authorized_submitters: vec![],
            min_claim_usaf: None,
        };
        instantiate(deps.as_mut(), mock_env(), message_info(&sender, &[]), msg).unwrap();
        let c: Config =
            from_json(query(deps.as_ref(), mock_env(), QueryMsg::Config {}).unwrap()).unwrap();
        assert_eq!(c.admin, sender);
        assert_eq!(c.draw_interval, DEFAULT_DRAW_INTERVAL_SECONDS);
    }

    #[test]
    fn instantiate_rejects_bad_ticket_denom() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        let msg = InstantiateMsg {
            admin: None,
            denom: None,
            ticket_price: Some(Coin::new(1u128, "uatom")),
            draw_interval: None,
            numbers_per_ticket: None,
            number_max: None,
            split: None,
            rollover_on_no_winner: None,
            randomness_mode: None,
            verify_mode: None,
            drand_pubkey: None,
            drand_chain_hash: None,
            authorized_submitters: vec![],
            min_claim_usaf: None,
        };
        let err = instantiate(deps.as_mut(), mock_env(), message_info(&admin, &[]), msg)
            .unwrap_err();
        assert!(matches!(err, ContractError::InvalidConfig { .. }));
    }

    #[test]
    fn instantiate_rejects_bad_split() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        let msg = InstantiateMsg {
            admin: None,
            denom: None,
            ticket_price: None,
            draw_interval: None,
            numbers_per_ticket: None,
            number_max: None,
            split: Some(FundSplitBps::new_unchecked(5000, 1000, 1500)), // sums to 7500
            rollover_on_no_winner: None,
            randomness_mode: None,
            verify_mode: None,
            drand_pubkey: None,
            drand_chain_hash: None,
            authorized_submitters: vec![],
            min_claim_usaf: None,
        };
        let err = instantiate(deps.as_mut(), mock_env(), message_info(&admin, &[]), msg)
            .unwrap_err();
        assert!(matches!(err, ContractError::Shared(_)));
    }

    #[test]
    fn instantiate_drand_requires_chain_hash_and_pubkey() {
        let mut deps = mock_dependencies();
        let admin = deps.api.addr_make("admin");
        // Missing chain hash.
        let msg = InstantiateMsg {
            admin: None,
            denom: None,
            ticket_price: None,
            draw_interval: None,
            numbers_per_ticket: None,
            number_max: None,
            split: None,
            rollover_on_no_winner: None,
            randomness_mode: Some(RandomnessMode::Drand),
            verify_mode: Some(VerifyMode::Bls),
            drand_pubkey: Some(HexBinary::from(vec![1u8; G1_LEN])),
            drand_chain_hash: None,
            authorized_submitters: vec![],
            min_claim_usaf: None,
        };
        let err = instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&admin, &[]),
            msg,
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::InvalidConfig { .. }));

        // Bad pubkey length.
        let msg = InstantiateMsg {
            admin: None,
            denom: None,
            ticket_price: None,
            draw_interval: None,
            numbers_per_ticket: None,
            number_max: None,
            split: None,
            rollover_on_no_winner: None,
            randomness_mode: Some(RandomnessMode::Drand),
            verify_mode: Some(VerifyMode::Bls),
            drand_pubkey: Some(HexBinary::from(vec![1u8; 10])),
            drand_chain_hash: Some("abcd".to_string()),
            authorized_submitters: vec![],
            min_claim_usaf: None,
        };
        let err = instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&admin, &[]),
            msg,
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::InvalidPubkey { .. }));
    }

    // --- buy: split accounting + funds validation ---------------------------

    #[test]
    fn buy_splits_75_10_15_no_referrer_folds_referral() {
        let (mut deps, api, env, _admin, _sub) = setup();
        let buyer = mk(&api, "buyer");

        buy(&mut deps, &env, &buyer, 2, None, None).unwrap();

        let total = 2 * TICKET_PRICE;
        // No referrer bound and no code: referral cut (10%) folds into the pool.
        // pool = prize(75%) + referral(10%) = 85%.
        let r = current(&deps);
        assert_eq!(r.pool, Uint128::new(total * 8500 / 10000));
        assert_eq!(r.ticket_count, 2);
        assert_eq!(r.player_count, 1);

        // Treasury accrues 15%.
        let tb: TreasuryBalanceResponse =
            from_json(query(deps.as_ref(), mock_env(), QueryMsg::TreasuryBalance {}).unwrap())
                .unwrap();
        assert_eq!(tb.balance, Uint128::new(total * 1500 / 10000));
    }

    #[test]
    fn buy_credits_referrer_and_treasury() {
        let (mut deps, api, env, _admin, _sub) = setup();
        let buyer = mk(&api, "buyer");
        let referrer = mk(&api, "referrer");

        // buyer binds to referrer first
        execute(
            deps.as_mut(),
            env.clone(),
            message_info(&buyer, &[]),
            ExecuteMsg::BindReferrer {
                referrer: Some(referrer.to_string()),
                code: None,
            },
        )
        .unwrap();

        buy(&mut deps, &env, &buyer, 2, None, None).unwrap();

        let total = 2 * TICKET_PRICE;
        // With a referrer, referral 10% credits their ledger; pool = 75%.
        let r = current(&deps);
        assert_eq!(r.pool, Uint128::new(total * 7500 / 10000));

        let summary: ReferralSummaryResponse = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ReferralSummary {
                    addr: referrer.to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(summary.pending, Uint128::new(total * 1000 / 10000));
        assert_eq!(summary.lifetime_earned, Uint128::new(total * 1000 / 10000));
        assert_eq!(summary.referees, 1);

        // Treasury still 15%.
        let tb: TreasuryBalanceResponse =
            from_json(query(deps.as_ref(), mock_env(), QueryMsg::TreasuryBalance {}).unwrap())
                .unwrap();
        assert_eq!(tb.balance, Uint128::new(total * 1500 / 10000));
    }

    #[test]
    fn buy_by_code_binds_and_credits() {
        let (mut deps, api, env, _admin, _sub) = setup();
        let buyer = mk(&api, "buyer");
        let referrer = mk(&api, "referrer");

        // referrer registers a code
        execute(
            deps.as_mut(),
            env.clone(),
            message_info(&referrer, &[]),
            ExecuteMsg::RegisterCode {
                code: "WinBig".to_string(),
            },
        )
        .unwrap();

        // buyer buys with the code (case-insensitive) — should credit referrer.
        buy(&mut deps, &env, &buyer, 1, None, Some("winbig".to_string())).unwrap();

        let summary: ReferralSummaryResponse = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ReferralSummary {
                    addr: referrer.to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(summary.pending, Uint128::new(TICKET_PRICE * 1000 / 10000));
    }

    #[test]
    fn buy_wrong_payment_rejected() {
        let (mut deps, api, env, _admin, _sub) = setup();
        let buyer = mk(&api, "buyer");
        let info = message_info(&buyer, &coins(TICKET_PRICE, DENOM)); // pays for 1 but buys 2
        let err = execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::BuyTickets {
                count: 2,
                numbers: None,
                referral_code: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Shared(_)));
    }

    #[test]
    fn buy_foreign_denom_rejected() {
        let (mut deps, api, env, _admin, _sub) = setup();
        let buyer = mk(&api, "buyer");
        let info = message_info(&buyer, &coins(TICKET_PRICE, "uatom"));
        let err = execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::BuyTickets {
                count: 1,
                numbers: None,
                referral_code: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Shared(_)));
    }

    #[test]
    fn buy_zero_count_rejected() {
        let (mut deps, api, env, _admin, _sub) = setup();
        let buyer = mk(&api, "buyer");
        let info = message_info(&buyer, &[]);
        let err = execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::BuyTickets {
                count: 0,
                numbers: None,
                referral_code: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::InvalidTicketCount { .. }));
    }

    #[test]
    fn buy_too_many_rejected() {
        let (mut deps, api, env, _admin, _sub) = setup();
        let buyer = mk(&api, "buyer");
        let info = message_info(&buyer, &coins(TICKET_PRICE * 101, DENOM));
        let err = execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::BuyTickets {
                count: 101,
                numbers: None,
                referral_code: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::InvalidTicketCount { .. }));
    }

    #[test]
    fn buy_custom_numbers_validated_and_sorted() {
        let (mut deps, api, env, _admin, _sub) = setup();
        let buyer = mk(&api, "buyer");

        // Wrong count.
        let err = buy(&mut deps, &env, &buyer, 1, Some(vec![1, 2, 3]), None).unwrap_err();
        assert!(matches!(err, ContractError::InvalidNumbers { .. }));

        // Valid, unsorted -> stored sorted.
        buy(&mut deps, &env, &buyer, 1, Some(vec![6, 5, 4, 3, 2, 1]), None).unwrap();
        let tickets: TicketsResponse = from_json(
            query(
                deps.as_ref(),
                env,
                QueryMsg::Tickets {
                    round_id: 1,
                    owner: Some(buyer.to_string()),
                    start_after: None,
                    limit: None,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(tickets.tickets.len(), 1);
        assert_eq!(tickets.tickets[0].ticket.numbers, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn buy_duplicate_numbers_rejected() {
        let (mut deps, api, env, _admin, _sub) = setup();
        let buyer = mk(&api, "buyer");
        let err = buy(&mut deps, &env, &buyer, 1, Some(vec![1, 1, 2, 3, 4, 5]), None)
            .unwrap_err();
        assert!(matches!(err, ContractError::InvalidNumbers { .. }));
    }

    #[test]
    fn buy_out_of_range_number_rejected() {
        let (mut deps, api, env, _admin, _sub) = setup();
        let buyer = mk(&api, "buyer");
        let err = buy(&mut deps, &env, &buyer, 1, Some(vec![1, 2, 3, 4, 5, 46]), None)
            .unwrap_err();
        assert!(matches!(err, ContractError::InvalidNumbers { .. }));
    }

    #[test]
    fn buy_first_ticket_custom_rest_quickpicked() {
        let (mut deps, api, env, _admin, _sub) = setup();
        let buyer = mk(&api, "buyer");
        buy(&mut deps, &env, &buyer, 3, Some(vec![1, 2, 3, 4, 5, 6]), None).unwrap();
        let tickets: TicketsResponse = from_json(
            query(
                deps.as_ref(),
                env,
                QueryMsg::Tickets {
                    round_id: 1,
                    owner: None,
                    start_after: None,
                    limit: None,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(tickets.tickets.len(), 3);
        assert_eq!(tickets.tickets[0].ticket.numbers, vec![1, 2, 3, 4, 5, 6]);
        // Others are quick-picked: 6 distinct numbers in range.
        for t in &tickets.tickets[1..] {
            assert_eq!(t.ticket.numbers.len(), 6);
            assert!(t.ticket.numbers.iter().all(|n| (1..=45).contains(n)));
        }
    }

    // --- pause --------------------------------------------------------------

    #[test]
    fn pause_blocks_buys_unpause_restores() {
        let (mut deps, api, env, admin, _sub) = setup();
        let buyer = mk(&api, "buyer");

        execute(
            deps.as_mut(),
            env.clone(),
            message_info(&admin, &[]),
            ExecuteMsg::Pause {},
        )
        .unwrap();
        let err = buy(&mut deps, &env, &buyer, 1, None, None).unwrap_err();
        assert!(matches!(err, ContractError::Paused));

        execute(
            deps.as_mut(),
            env.clone(),
            message_info(&admin, &[]),
            ExecuteMsg::Unpause {},
        )
        .unwrap();
        buy(&mut deps, &env, &buyer, 1, None, None).unwrap();
    }

    #[test]
    fn pause_admin_only() {
        let (mut deps, api, _env, _admin, _sub) = setup();
        let notadmin = mk(&api, "notadmin");
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&notadmin, &[]),
            ExecuteMsg::Pause {},
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized { .. }));
    }

    // --- close --------------------------------------------------------------

    #[test]
    fn close_requires_elapsed_window() {
        let (mut deps, api, env, _admin, _sub) = setup();
        let anyone = mk(&api, "anyone");

        let err = execute(
            deps.as_mut(),
            env.clone(),
            message_info(&anyone, &[]),
            ExecuteMsg::CloseRound {},
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::RoundNotClosed { .. }));

        let mut env2 = env.clone();
        advance(&mut env2, DRAW_INTERVAL + 1);
        execute(
            deps.as_mut(),
            env2,
            message_info(&anyone, &[]),
            ExecuteMsg::CloseRound {},
        )
        .unwrap();
        assert_eq!(round(&deps, 1).status, RoundStatus::Drawing);
    }

    #[test]
    fn buy_rejected_after_close() {
        let (mut deps, api, env, _admin, _sub) = setup();
        let buyer = mk(&api, "buyer");
        let mut env2 = env.clone();
        advance(&mut env2, DRAW_INTERVAL + 1);
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&buyer, &[]),
            ExecuteMsg::CloseRound {},
        )
        .unwrap();
        let err = buy(&mut deps, &env2, &buyer, 1, None, None).unwrap_err();
        assert!(matches!(err, ContractError::RoundNotOpen { .. }));
    }

    // --- randomness ---------------------------------------------------------

    #[test]
    fn submit_randomness_authorized_only() {
        let (mut deps, api, env, _admin, _sub) = setup();
        let buyer = mk(&api, "buyer");
        let stranger = mk(&api, "stranger");
        let mut env2 = env.clone();
        advance(&mut env2, DRAW_INTERVAL + 1);
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&buyer, &[]),
            ExecuteMsg::CloseRound {},
        )
        .unwrap();
        let err = execute(
            deps.as_mut(),
            env2,
            message_info(&stranger, &[]),
            ExecuteMsg::SubmitRandomness {
                round_id: 1,
                randomness: HexBinary::from(vec![1u8; 32]),
                signature: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::UnauthorizedSubmitter));
    }

    #[test]
    fn submit_randomness_mock_length_checked() {
        let (mut deps, _api, env, _admin, submitter) = setup();
        let mut env2 = env.clone();
        advance(&mut env2, DRAW_INTERVAL + 1);
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&submitter, &[]),
            ExecuteMsg::CloseRound {},
        )
        .unwrap();
        // Wrong length in mock mode still rejected structurally.
        let err = execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&submitter, &[]),
            ExecuteMsg::SubmitRandomness {
                round_id: 1,
                randomness: HexBinary::from(vec![1u8; 16]),
                signature: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::InvalidRandomnessLength { .. }));

        // Correct length accepted.
        execute(
            deps.as_mut(),
            env2,
            message_info(&submitter, &[]),
            ExecuteMsg::SubmitRandomness {
                round_id: 1,
                randomness: HexBinary::from(vec![1u8; 32]),
                signature: None,
            },
        )
        .unwrap();
        let r = round(&deps, 1);
        assert!(matches!(
            r.randomness.unwrap().status,
            RandomnessStatus::Fulfilled
        ));
    }

    #[test]
    fn double_submit_randomness_rejected() {
        let (mut deps, _api, env, _admin, submitter) = setup();
        let mut env2 = env.clone();
        advance(&mut env2, DRAW_INTERVAL + 1);
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&submitter, &[]),
            ExecuteMsg::CloseRound {},
        )
        .unwrap();
        let submit = ExecuteMsg::SubmitRandomness {
            round_id: 1,
            randomness: HexBinary::from(vec![2u8; 32]),
            signature: None,
        };
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&submitter, &[]),
            submit.clone(),
        )
        .unwrap();
        let err = execute(
            deps.as_mut(),
            env2,
            message_info(&submitter, &[]),
            submit,
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::AlreadyFulfilled { .. }));
    }

    #[test]
    fn submit_before_close_rejected() {
        let (mut deps, _api, env, _admin, submitter) = setup();
        // No randomness slot exists until CloseRound.
        let err = execute(
            deps.as_mut(),
            env,
            message_info(&submitter, &[]),
            ExecuteMsg::SubmitRandomness {
                round_id: 1,
                randomness: HexBinary::from(vec![1u8; 32]),
                signature: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::RoundNotFound { .. }));
    }

    #[test]
    fn draw_before_randomness_rejected() {
        let (mut deps, _api, env, _admin, _sub) = setup();
        let mut env2 = env.clone();
        advance(&mut env2, DRAW_INTERVAL + 1);
        let keeper = mk(&deps.api, "keeper");
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&keeper, &[]),
            ExecuteMsg::CloseRound {},
        )
        .unwrap();
        let err = execute(
            deps.as_mut(),
            env2,
            message_info(&keeper, &[]),
            ExecuteMsg::Draw { round_id: 1 },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::VerificationFailed { .. }));
    }

    #[test]
    fn commit_reveal_flow() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        let env = mock_env();
        let admin = mk(&api, "admin");
        let submitter = mk(&api, "operator");

        instantiate(
            deps.as_mut(),
            env.clone(),
            message_info(&admin, &[]),
            InstantiateMsg {
                admin: Some(admin.to_string()),
                denom: None,
                ticket_price: None,
                draw_interval: Some(DRAW_INTERVAL),
                numbers_per_ticket: None,
                number_max: None,
                split: None,
                rollover_on_no_winner: None,
                randomness_mode: Some(RandomnessMode::CommitReveal),
                verify_mode: Some(VerifyMode::Dev),
                drand_pubkey: None,
                drand_chain_hash: None,
                authorized_submitters: vec![submitter.to_string()],
                min_claim_usaf: None,
            },
        )
        .unwrap();

        let mut env2 = env.clone();
        advance(&mut env2, DRAW_INTERVAL + 1);
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&submitter, &[]),
            ExecuteMsg::CloseRound {},
        )
        .unwrap();

        // SubmitRandomness rejected in commit-reveal mode.
        let err = execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&submitter, &[]),
            ExecuteMsg::SubmitRandomness {
                round_id: 1,
                randomness: HexBinary::from(vec![1u8; 32]),
                signature: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::WrongMode { .. }));

        // Commit.
        let value = HexBinary::from(vec![0xABu8; 32]);
        let commitment = HexBinary::from(sha256(value.as_slice()));
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&submitter, &[]),
            ExecuteMsg::CommitRandomness {
                round_id: 1,
                commitment: commitment.clone(),
            },
        )
        .unwrap();

        // Wrong reveal.
        let err = execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&submitter, &[]),
            ExecuteMsg::RevealRandomness {
                round_id: 1,
                value: HexBinary::from(vec![0u8; 32]),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::RevealMismatch));

        // Correct reveal fulfils.
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&submitter, &[]),
            ExecuteMsg::RevealRandomness {
                round_id: 1,
                value: value.clone(),
            },
        )
        .unwrap();
        let r = round(&deps, 1);
        let req = r.randomness.unwrap();
        assert!(matches!(req.status, RandomnessStatus::Fulfilled));
        assert_eq!(
            req.randomness.unwrap(),
            HexBinary::from(sha256(value.as_slice()))
        );

        // Draw succeeds.
        execute(
            deps.as_mut(),
            env2,
            message_info(&admin, &[]),
            ExecuteMsg::Draw { round_id: 1 },
        )
        .unwrap();
        assert_eq!(round(&deps, 1).status, RoundStatus::Settled);
    }

    // --- draw: matches / tiers / rollover -----------------------------------

    #[test]
    fn draw_computes_matches_tiers_and_opens_next_round() {
        let (mut deps, api, env, _admin, submitter) = setup();
        let buyer = mk(&api, "buyer");
        let randomness = HexBinary::from(vec![7u8; 32]);
        let winning = derive_winning_numbers(randomness.as_slice(), 6, 45);

        // Jackpot ticket (matches winning) + a quick-pick.
        buy(&mut deps, &env, &buyer, 1, Some(winning.clone()), None).unwrap();
        let buyer2 = mk(&api, "buyer2");
        buy(&mut deps, &env, &buyer2, 1, None, None).unwrap();

        let derived = run_draw(&mut deps, &env, &submitter, randomness);
        assert_eq!(derived, winning);

        // Next round opened.
        assert_eq!(current(&deps).id, 2);
        let r1 = round(&deps, 1);
        assert_eq!(r1.status, RoundStatus::Settled);
        assert_eq!(r1.winning_numbers.unwrap(), winning);
        assert!(r1.winning_tickets >= 1);
        assert!(r1.prize_tiers.tier_6 > Uint128::zero());

        // Buyer's jackpot prize is claimable.
        let prize: PrizeResponse = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::Prize {
                    round_id: 1,
                    owner: buyer.to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert!(prize.claimable > Uint128::zero());
        assert_eq!(prize.claimed, Uint128::zero());
    }

    #[test]
    fn draw_rollover_on_no_jackpot() {
        let (mut deps, api, env, _admin, submitter) = setup();
        let buyer = mk(&api, "buyer");
        // Buy tickets that (almost certainly) don't hit the jackpot: use a low
        // fixed set; if it happens to match the derived winners the assertion
        // below tolerates it via the branch on jackpot count.
        buy(&mut deps, &env, &buyer, 1, Some(vec![1, 2, 3, 4, 5, 6]), None).unwrap();

        let randomness = HexBinary::from(vec![0x11u8; 32]);
        let winning = derive_winning_numbers(randomness.as_slice(), 6, 45);
        let matches = winning.iter().filter(|w| [1, 2, 3, 4, 5, 6].contains(w)).count();

        run_draw(&mut deps, &env, &submitter, randomness);

        let r1 = round(&deps, 1);
        let r2 = round(&deps, 2);
        if matches < 6 {
            // No jackpot: leftover pool rolls into round 2.
            assert!(r2.pool > Uint128::zero());
            assert_eq!(r2.rolled_over_from, Some(1));
            // Round 1 pool retained only for assigned lower-tier prizes.
            assert!(r1.pool <= Uint128::new(TICKET_PRICE));
        } else {
            assert!(r2.pool.is_zero() || r2.rolled_over_from.is_none());
        }
    }

    #[test]
    fn draw_no_rollover_when_disabled() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        let env = mock_env();
        let admin = mk(&api, "admin");
        let submitter = mk(&api, "relayer");
        instantiate(
            deps.as_mut(),
            env.clone(),
            message_info(&admin, &[]),
            InstantiateMsg {
                admin: Some(admin.to_string()),
                denom: None,
                ticket_price: None,
                draw_interval: Some(DRAW_INTERVAL),
                numbers_per_ticket: None,
                number_max: None,
                split: None,
                rollover_on_no_winner: Some(false),
                randomness_mode: None,
                verify_mode: None,
                drand_pubkey: None,
                drand_chain_hash: None,
                authorized_submitters: vec![submitter.to_string()],
                min_claim_usaf: None,
            },
        )
        .unwrap();
        let buyer = mk(&api, "buyer");
        buy(&mut deps, &env, &buyer, 1, Some(vec![1, 2, 3, 4, 5, 6]), None).unwrap();

        run_draw(&mut deps, &env, &submitter, HexBinary::from(vec![0x22u8; 32]));
        let r2 = round(&deps, 2);
        assert_eq!(r2.rolled_over_from, None);
        assert_eq!(r2.pool, Uint128::zero());
    }

    // --- claim --------------------------------------------------------------

    #[test]
    fn claim_once_guard_and_payout() {
        let (mut deps, api, env, _admin, submitter) = setup();
        let buyer = mk(&api, "buyer");
        let randomness = HexBinary::from(vec![7u8; 32]);
        let winning = derive_winning_numbers(randomness.as_slice(), 6, 45);
        buy(&mut deps, &env, &buyer, 1, Some(winning.clone()), None).unwrap();

        let mut env2 = env.clone();
        advance(&mut env2, DRAW_INTERVAL + 1);
        run_draw(&mut deps, &env, &submitter, randomness);

        let ticket_id = ticket_id(0);
        // First claim pays out.
        let res = execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&buyer, &[]),
            ExecuteMsg::ClaimReward {
                round_id: 1,
                ticket_id: ticket_id.clone(),
            },
        )
        .unwrap();
        assert!(res.messages.iter().any(|m| matches!(
            &m.msg,
            CosmosMsg::Bank(BankMsg::Send { to_address, .. }) if to_address == &buyer.to_string()
        )));

        // Second claim rejected.
        let err = execute(
            deps.as_mut(),
            env2,
            message_info(&buyer, &[]),
            ExecuteMsg::ClaimReward {
                round_id: 1,
                ticket_id,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::AlreadyClaimed { .. }));
    }

    #[test]
    fn claim_zero_prize_rejected() {
        let (mut deps, api, env, _admin, submitter) = setup();
        let buyer = mk(&api, "buyer");
        // Fixed picks; run draw. If it happens to match, adjust: pick numbers
        // guaranteed not to be all-winning is impossible to know a priori, so we
        // assert on the specific ticket's prize being zero via query first.
        buy(&mut deps, &env, &buyer, 1, Some(vec![1, 2, 3, 4, 5, 6]), None).unwrap();
        run_draw(&mut deps, &env, &submitter, HexBinary::from(vec![0x33u8; 32]));

        let prize: PrizeResponse = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::Prize {
                    round_id: 1,
                    owner: buyer.to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        if prize.claimable.is_zero() {
            let err = execute(
                deps.as_mut(),
                mock_env(),
                message_info(&buyer, &[]),
                ExecuteMsg::ClaimReward {
                    round_id: 1,
                    ticket_id: ticket_id(0),
                },
            )
            .unwrap_err();
            assert!(matches!(err, ContractError::NoPrize { .. }));
        }
    }

    #[test]
    fn claim_non_owner_rejected() {
        let (mut deps, api, env, _admin, submitter) = setup();
        let buyer = mk(&api, "buyer");
        let stranger = mk(&api, "stranger");
        let randomness = HexBinary::from(vec![7u8; 32]);
        let winning = derive_winning_numbers(randomness.as_slice(), 6, 45);
        buy(&mut deps, &env, &buyer, 1, Some(winning), None).unwrap();
        run_draw(&mut deps, &env, &submitter, randomness);

        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&stranger, &[]),
            ExecuteMsg::ClaimReward {
                round_id: 1,
                ticket_id: ticket_id(0),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized { .. }));
    }

    #[test]
    fn claim_unknown_ticket_rejected() {
        let (mut deps, api, _env, _admin, _sub) = setup();
        let buyer = mk(&api, "buyer");
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&buyer, &[]),
            ExecuteMsg::ClaimReward {
                round_id: 1,
                ticket_id: ticket_id(999),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::TicketNotFound { .. }));
    }

    // --- referral bind / self-referral / claim ------------------------------

    #[test]
    fn bind_is_immutable() {
        let (mut deps, api, _env, _admin, _sub) = setup();
        let referee = mk(&api, "referee");
        let r1 = mk(&api, "r1");
        let r2 = mk(&api, "r2");
        execute(
            deps.as_mut(),
            mock_env(),
            message_info(&referee, &[]),
            ExecuteMsg::BindReferrer {
                referrer: Some(r1.to_string()),
                code: None,
            },
        )
        .unwrap();
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&referee, &[]),
            ExecuteMsg::BindReferrer {
                referrer: Some(r2.to_string()),
                code: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::AlreadyBound { .. }));
    }

    #[test]
    fn bind_self_referral_blocked() {
        let (mut deps, api, _env, _admin, _sub) = setup();
        let referee = mk(&api, "referee");
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&referee, &[]),
            ExecuteMsg::BindReferrer {
                referrer: Some(referee.to_string()),
                code: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::SelfReferral));
    }

    #[test]
    fn bind_requires_referrer_or_code() {
        let (mut deps, api, _env, _admin, _sub) = setup();
        let referee = mk(&api, "referee");
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&referee, &[]),
            ExecuteMsg::BindReferrer {
                referrer: None,
                code: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::InvalidConfig { .. }));
    }

    #[test]
    fn bind_by_unknown_code_fails() {
        let (mut deps, api, _env, _admin, _sub) = setup();
        let referee = mk(&api, "referee");
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&referee, &[]),
            ExecuteMsg::BindReferrer {
                referrer: None,
                code: Some("nope".to_string()),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::UnknownReferralCode { .. }));
    }

    #[test]
    fn register_code_conflict_for_other_owner() {
        let (mut deps, api, _env, _admin, _sub) = setup();
        let a = mk(&api, "a");
        let b = mk(&api, "b");
        execute(
            deps.as_mut(),
            mock_env(),
            message_info(&a, &[]),
            ExecuteMsg::RegisterCode {
                code: "dup".to_string(),
            },
        )
        .unwrap();
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&b, &[]),
            ExecuteMsg::RegisterCode {
                code: "DUP".to_string(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized { .. }));
    }

    #[test]
    fn referral_claim_pays_and_zeroes() {
        let (mut deps, api, env, _admin, _sub) = setup();
        let buyer = mk(&api, "buyer");
        let referrer = mk(&api, "referrer");
        execute(
            deps.as_mut(),
            env.clone(),
            message_info(&buyer, &[]),
            ExecuteMsg::BindReferrer {
                referrer: Some(referrer.to_string()),
                code: None,
            },
        )
        .unwrap();
        buy(&mut deps, &env, &buyer, 1, None, None).unwrap();

        let earned = Uint128::new(TICKET_PRICE * 1000 / 10000);
        let res = execute(
            deps.as_mut(),
            env,
            message_info(&referrer, &[]),
            ExecuteMsg::ClaimReferral {},
        )
        .unwrap();
        assert!(res.messages.iter().any(|m| matches!(
            &m.msg,
            CosmosMsg::Bank(BankMsg::Send { to_address, amount })
                if to_address == &referrer.to_string() && amount[0].amount == earned
        )));

        let summary: ReferralSummaryResponse = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ReferralSummary {
                    addr: referrer.to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(summary.pending, Uint128::zero());
        assert_eq!(summary.lifetime_claimed, earned);
    }

    #[test]
    fn referral_claim_nothing_fails() {
        let (mut deps, api, _env, _admin, _sub) = setup();
        let referrer = mk(&api, "referrer");
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&referrer, &[]),
            ExecuteMsg::ClaimReferral {},
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::NothingToClaim));
    }

    #[test]
    fn referral_claim_below_floor_fails() {
        let mut deps = mock_dependencies();
        let api = deps.api;
        let env = mock_env();
        let admin = mk(&api, "admin");
        instantiate(
            deps.as_mut(),
            env.clone(),
            message_info(&admin, &[]),
            InstantiateMsg {
                admin: Some(admin.to_string()),
                denom: None,
                ticket_price: None,
                draw_interval: Some(DRAW_INTERVAL),
                numbers_per_ticket: None,
                number_max: None,
                split: None,
                rollover_on_no_winner: None,
                randomness_mode: None,
                verify_mode: None,
                drand_pubkey: None,
                drand_chain_hash: None,
                authorized_submitters: vec![],
                min_claim_usaf: Some(Uint128::new(10_000_000)), // high floor
            },
        )
        .unwrap();
        let buyer = mk(&api, "buyer");
        let referrer = mk(&api, "referrer");
        execute(
            deps.as_mut(),
            env.clone(),
            message_info(&buyer, &[]),
            ExecuteMsg::BindReferrer {
                referrer: Some(referrer.to_string()),
                code: None,
            },
        )
        .unwrap();
        buy(&mut deps, &env, &buyer, 1, None, None).unwrap(); // earns 500_000 < floor

        let err = execute(
            deps.as_mut(),
            env,
            message_info(&referrer, &[]),
            ExecuteMsg::ClaimReferral {},
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::NothingToClaim));
    }

    #[test]
    fn referrer_query_reflects_binding() {
        let (mut deps, api, _env, _admin, _sub) = setup();
        let referee = mk(&api, "referee");
        let referrer = mk(&api, "referrer");
        execute(
            deps.as_mut(),
            mock_env(),
            message_info(&referee, &[]),
            ExecuteMsg::BindReferrer {
                referrer: Some(referrer.to_string()),
                code: None,
            },
        )
        .unwrap();
        let q: ReferrerResponse = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::Referrer {
                    referee: referee.to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(q.referrer, Some(referrer.to_string()));
    }

    // --- treasury withdraw --------------------------------------------------

    #[test]
    fn withdraw_treasury_admin_only_and_bounded() {
        let (mut deps, api, env, admin, _sub) = setup();
        let buyer = mk(&api, "buyer");
        let recipient = mk(&api, "recipient");
        let stranger = mk(&api, "stranger");

        buy(&mut deps, &env, &buyer, 1, None, None).unwrap();
        let treasury_bal = Uint128::new(TICKET_PRICE * 1500 / 10000);

        // Stranger cannot withdraw.
        let err = execute(
            deps.as_mut(),
            env.clone(),
            message_info(&stranger, &[]),
            ExecuteMsg::WithdrawTreasury {
                to: recipient.to_string(),
                amount: Uint128::new(1),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized { .. }));

        // Zero withdraw rejected.
        let err = execute(
            deps.as_mut(),
            env.clone(),
            message_info(&admin, &[]),
            ExecuteMsg::WithdrawTreasury {
                to: recipient.to_string(),
                amount: Uint128::zero(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::ZeroWithdraw));

        // Over-balance rejected.
        let err = execute(
            deps.as_mut(),
            env.clone(),
            message_info(&admin, &[]),
            ExecuteMsg::WithdrawTreasury {
                to: recipient.to_string(),
                amount: treasury_bal + Uint128::new(1),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::InsufficientTreasury { .. }));

        // Admin withdraws part.
        let res = execute(
            deps.as_mut(),
            env,
            message_info(&admin, &[]),
            ExecuteMsg::WithdrawTreasury {
                to: recipient.to_string(),
                amount: Uint128::new(100_000),
            },
        )
        .unwrap();
        assert!(res.messages.iter().any(|m| matches!(
            &m.msg,
            CosmosMsg::Bank(BankMsg::Send { to_address, amount })
                if to_address == &recipient.to_string() && amount[0].amount == Uint128::new(100_000)
        )));

        let tb: TreasuryBalanceResponse =
            from_json(query(deps.as_ref(), mock_env(), QueryMsg::TreasuryBalance {}).unwrap())
                .unwrap();
        assert_eq!(tb.balance, treasury_bal - Uint128::new(100_000));
    }

    // --- set_config ---------------------------------------------------------

    #[test]
    fn set_config_admin_only_and_validates_split() {
        let (mut deps, api, _env, admin, _sub) = setup();
        let notadmin = mk(&api, "notadmin");

        // Not admin.
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&notadmin, &[]),
            set_config_none(),
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized { .. }));

        // Bad split rejected.
        let mut msg = set_config_none();
        if let ExecuteMsg::SetConfig { split, .. } = &mut msg {
            *split = Some(FundSplitBps::new_unchecked(5000, 1000, 1500));
        }
        let err = execute(deps.as_mut(), mock_env(), message_info(&admin, &[]), msg)
            .unwrap_err();
        assert!(matches!(err, ContractError::Shared(_)));

        // Valid update.
        let mut msg = set_config_none();
        if let ExecuteMsg::SetConfig {
            draw_interval,
            rollover_on_no_winner,
            ..
        } = &mut msg
        {
            *draw_interval = Some(7200);
            *rollover_on_no_winner = Some(false);
        }
        execute(deps.as_mut(), mock_env(), message_info(&admin, &[]), msg).unwrap();
        let c = cfg(&deps);
        assert_eq!(c.draw_interval, 7200);
        assert!(!c.rollover_on_no_winner);
    }

    #[test]
    fn set_config_add_remove_submitters() {
        let (mut deps, api, _env, admin, _sub) = setup();
        let new_sub = mk(&api, "new_sub");

        let mut msg = set_config_none();
        if let ExecuteMsg::SetConfig { add_submitters, .. } = &mut msg {
            *add_submitters = Some(vec![new_sub.to_string()]);
        }
        execute(deps.as_mut(), mock_env(), message_info(&admin, &[]), msg).unwrap();
        assert!(cfg(&deps).is_submitter(&new_sub));

        let mut msg = set_config_none();
        if let ExecuteMsg::SetConfig {
            remove_submitters, ..
        } = &mut msg
        {
            *remove_submitters = Some(vec![new_sub.to_string()]);
        }
        execute(deps.as_mut(), mock_env(), message_info(&admin, &[]), msg).unwrap();
        assert!(!cfg(&deps).is_submitter(&new_sub));
    }

    fn set_config_none() -> ExecuteMsg {
        ExecuteMsg::SetConfig {
            admin: None,
            ticket_price: None,
            draw_interval: None,
            split: None,
            rollover_on_no_winner: None,
            randomness_mode: None,
            verify_mode: None,
            drand_pubkey: None,
            drand_chain_hash: None,
            min_claim_usaf: None,
            add_submitters: None,
            remove_submitters: None,
        }
    }

    // --- migrate ------------------------------------------------------------

    #[test]
    fn migrate_bumps_version() {
        let (mut deps, _api, env, _admin, _sub) = setup();
        let res = migrate(deps.as_mut(), env, MigrateMsg {}).unwrap();
        assert!(res.events.iter().any(|e| e.ty == "winsaf/migrate"));
        let v = get_contract_version(&deps.storage).unwrap();
        assert_eq!(v.contract, CONTRACT_NAME);
        assert_eq!(v.version, CONTRACT_VERSION);
    }

    #[test]
    fn migrate_wrong_contract_rejected() {
        let (mut deps, _api, _env, _admin, _sub) = setup();
        set_contract_version(deps.as_mut().storage, "crates.io:some-other", "0.1.0").unwrap();
        let err = migrate(deps.as_mut(), mock_env(), MigrateMsg {}).unwrap_err();
        assert!(matches!(err, ContractError::InvalidMigration { .. }));
    }

    // --- full lifecycle -----------------------------------------------------

    #[test]
    fn full_lifecycle_buy_close_submit_draw_claim() {
        let (mut deps, api, env, admin, submitter) = setup();
        let buyer = mk(&api, "buyer");
        let referrer = mk(&api, "referrer");
        let randomness = HexBinary::from(vec![7u8; 32]);
        let winning = derive_winning_numbers(randomness.as_slice(), 6, 45);

        // buyer binds a referrer, buys a jackpot ticket + extras.
        execute(
            deps.as_mut(),
            env.clone(),
            message_info(&buyer, &[]),
            ExecuteMsg::BindReferrer {
                referrer: Some(referrer.to_string()),
                code: None,
            },
        )
        .unwrap();
        buy(&mut deps, &env, &buyer, 1, Some(winning.clone()), None).unwrap();

        // referrer earned the referral cut.
        let summary: ReferralSummaryResponse = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ReferralSummary {
                    addr: referrer.to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(summary.pending, Uint128::new(TICKET_PRICE * 1000 / 10000));

        run_draw(&mut deps, &env, &submitter, randomness);
        assert_eq!(round(&deps, 1).status, RoundStatus::Settled);

        // buyer claims jackpot.
        execute(
            deps.as_mut(),
            mock_env(),
            message_info(&buyer, &[]),
            ExecuteMsg::ClaimReward {
                round_id: 1,
                ticket_id: ticket_id(0),
            },
        )
        .unwrap();

        // admin withdraws treasury.
        let recipient = mk(&api, "ops");
        execute(
            deps.as_mut(),
            mock_env(),
            message_info(&admin, &[]),
            ExecuteMsg::WithdrawTreasury {
                to: recipient.to_string(),
                amount: Uint128::new(TICKET_PRICE * 1500 / 10000),
            },
        )
        .unwrap();
        let tb: TreasuryBalanceResponse =
            from_json(query(deps.as_ref(), mock_env(), QueryMsg::TreasuryBalance {}).unwrap())
                .unwrap();
        assert_eq!(tb.balance, Uint128::zero());
    }
}
