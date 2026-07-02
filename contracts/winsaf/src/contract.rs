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
//!   Drawing ──CancelRound (randomness never fulfilled)──▶ Cancelled
//!             (retained pool becomes pro-rata pull-refunds, next round opened)
//! ```
//!
//! # Randomness fairness & recommended production mode
//!
//! For PRODUCTION the recommended configuration is **Drand + BLS**
//! (`randomness_mode = Drand`, `verify_mode = Bls`) wired to a real drand beacon
//! (`drand_pubkey` + `drand_chain_hash`) and an actual relayer. In that mode the
//! consumed randomness is an externally-verified beacon signature the submitter
//! cannot grind — [`crate::verify::verify_drand`] enforces the BLS pairing.
//!
//! `CommitReveal` is a defense-in-depth fallback for testnet. It is hardened so a
//! single submitter cannot pick the outcome: the finalised seed mixes a
//! per-round ticket-entropy accumulator and the reveal block's height/time
//! (neither known when the commitment must be posted during `Open`), the
//! commitment is bound to the committer, and the reveal is forced to a strictly
//! later block. `Mock`/`Dev` remain localnet-only and can never be switched into
//! a production wasm via `SetConfig` (compile-gated behind `dev-randomness`).

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
    default_max_dry_rounds, Config, PrizeTiers, RandomnessMode, RandomnessRequest,
    RandomnessStatus, Round, Ticket, VerifyMode, CANCEL_GRACE_SECONDS, CONFIG, CURRENT_ROUND,
    DEFAULT_REVEAL_TIMEOUT_SECONDS, DRAND_QUICKNET_GENESIS, DRAND_QUICKNET_PERIOD, DRY_STREAK,
    MIN_REVEAL_DELAY_BLOCKS, PLAYERS, RANDOMNESS, REFERRAL_CODES, REFERRAL_EARNINGS,
    REFERRAL_TOTALS, REFERRER, ROUNDS, TICKETS, TICKET_SEQ, TREASURY,
};
use crate::verify::{sha256, verify_drand, verify_mock, verify_reveal, G2_LEN};

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
    let drand_genesis_time = msg.drand_genesis_time.unwrap_or(DRAND_QUICKNET_GENESIS);
    let drand_period = msg.drand_period.unwrap_or(DRAND_QUICKNET_PERIOD);

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
        drand_genesis_time,
        drand_period,
        authorized_submitters,
        min_claim_usaf: msg.min_claim_usaf.unwrap_or_default(),
        reveal_timeout: msg
            .reveal_timeout
            .unwrap_or(DEFAULT_REVEAL_TIMEOUT_SECONDS),
        open_code_registration: msg.open_code_registration.unwrap_or(false),
        max_dry_rounds: msg.max_dry_rounds.unwrap_or_else(default_max_dry_rounds),
    };
    validate_randomness_config(&config)?;
    CONFIG.save(deps.storage, &config)?;

    // Zero the treasury balance.
    TREASURY.save(deps.storage, &Uint128::zero())?;

    // No dry rounds yet ("Must Be Won" streak starts at 0).
    DRY_STREAK.save(deps.storage, &0u64)?;

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
        ExecuteMsg::GrantBonusTicket {
            owner,
            count,
            numbers,
        } => execute_grant_bonus_ticket(deps, env, info, owner, count, numbers),
        ExecuteMsg::CloseRound {} => execute_close_round(deps, env, info),
        ExecuteMsg::SubmitRandomness {
            round_id,
            randomness,
            signature,
        } => execute_submit_randomness(deps, env, info, round_id, randomness, signature),
        ExecuteMsg::CommitRandomness {
            round_id,
            commitment,
        } => execute_commit_randomness(deps, env, info, round_id, commitment),
        ExecuteMsg::RevealRandomness { round_id, value } => {
            execute_reveal_randomness(deps, env, info, round_id, value)
        }
        ExecuteMsg::Draw { round_id } => execute_draw(deps, env, info, round_id),
        ExecuteMsg::CancelRound { round_id } => execute_cancel_round(deps, env, info, round_id),
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
            drand_genesis_time,
            drand_period,
            min_claim_usaf,
            reveal_timeout,
            open_code_registration,
            max_dry_rounds,
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
                drand_genesis_time,
                drand_period,
                min_claim_usaf,
                reveal_timeout,
                open_code_registration,
                max_dry_rounds,
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

    // Materialise each ticket. `numbers` configures the first ticket only;
    // remaining tickets (and all when omitted) are quick-picked. Shared with the
    // bonus-ticket grant path via `mint_tickets` (which handles id allocation,
    // entropy folding, ticket storage, player and ticket-count accounting).
    let minted = mint_tickets(
        deps.storage,
        &env,
        &config,
        &mut round,
        round_id,
        &info.sender,
        count,
        numbers.as_deref(),
        false, // paid ticket
    )?;
    let (first_id, last_id, new_player) = (minted.first_id, minted.last_id, minted.new_player);
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

/// Outcome of materialising a batch of tickets into a round.
struct MintOutcome {
    /// Id of the first minted ticket.
    first_id: String,
    /// Id of the last minted ticket.
    last_id: String,
    /// Whether `owner` was newly counted as a player in this round.
    new_player: bool,
}

/// Materialise `count` tickets owned by `owner` into `round` (in-memory) and
/// storage. Shared by the paid `BuyTickets` path and the operator-sponsored
/// `GrantBonusTicket` path so the two mint tickets identically:
///
/// - `numbers` (when `Some`) configures the FIRST ticket only; remaining tickets
///   (and all tickets when `None`) are quick-picked — exactly as `BuyTickets`.
/// - each ticket is folded into the round's ticket-entropy accumulator,
/// - ticket ids are the zero-padded per-round sequence,
/// - `owner` is counted once in the distinct-player presence set,
/// - `round.ticket_count`, `round.ticket_entropy` and `TICKET_SEQ` are updated.
///
/// Pool accounting stays with the caller (buy splits the payment; grant adds the
/// full sponsored price), and the caller persists `round` after any further
/// mutations. `free` flags the tickets as operator-granted bonus tickets.
#[allow(clippy::too_many_arguments)]
fn mint_tickets(
    storage: &mut dyn cosmwasm_std::Storage,
    env: &Env,
    config: &Config,
    round: &mut Round,
    round_id: u64,
    owner: &Addr,
    count: u32,
    numbers: Option<&[u8]>,
    free: bool,
) -> Result<MintOutcome, ContractError> {
    let mut seq = TICKET_SEQ.load(storage, round_id)?;
    let mut first_id = String::new();
    let mut last_id = String::new();
    // Running ticket-entropy accumulator (defense-in-depth for commit-reveal).
    let mut entropy = round.ticket_entropy;

    for i in 0..count {
        let picks = if i == 0 {
            match numbers {
                Some(nums) => validate_ticket_numbers(nums, config)?,
                None => quick_pick(env, owner, round_id, seq, config),
            }
        } else {
            quick_pick(env, owner, round_id, seq, config)
        };

        let id = ticket_id(seq);
        if i == 0 {
            first_id = id.clone();
        }
        last_id = id.clone();

        // Fold this ticket into the per-round entropy accumulator:
        // entropy = sha256(entropy || owner || ticket_id || picks). The final
        // value is unknown until the round closes, so a commit-reveal submitter
        // cannot grind it while committing during the Open phase.
        entropy = fold_ticket_entropy(&entropy, owner, &id, &picks);

        let ticket = Ticket {
            owner: owner.clone(),
            numbers: picks,
            matches: 0,
            prize: Uint128::zero(),
            claimed: false,
            free,
        };
        TICKETS.save(storage, (round_id, id.as_str()), &ticket)?;
        seq += 1;
    }
    round.ticket_entropy = entropy;

    // Distinct player accounting (idempotent presence set).
    let mut new_player = false;
    if PLAYERS.may_load(storage, (round_id, owner))?.is_none() {
        PLAYERS.save(storage, (round_id, owner), &1u8)?;
        round.player_count = round.player_count.saturating_add(1);
        new_player = true;
    }

    round.ticket_count = round.ticket_count.saturating_add(count as u64);
    TICKET_SEQ.save(storage, round_id, &seq)?;

    Ok(MintOutcome {
        first_id,
        last_id,
        new_player,
    })
}

// ---------------------------------------------------------------------------
// Grant bonus ticket (operator-sponsored, off-chain "redeem XP for a free ticket")
// ---------------------------------------------------------------------------

/// Mint `count` operator-sponsored bonus tickets OWNED BY `owner`, flagged
/// `free`, into the current open round. Backs an off-chain "redeem XP for a free
/// ticket" feature: the caller (admin or an authorized submitter) attaches the
/// full `count * ticket_price` so the pool stays honest — the granted tickets are
/// fully funded and can win / be claimed by `owner` exactly like paid tickets.
///
/// Unlike a paid buy, the ENTIRE attached amount goes to the round pool (no
/// treasury/referral split): the operator sponsors the prize contribution
/// directly so the user pays nothing and the pool is never diluted.
fn execute_grant_bonus_ticket(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    owner: String,
    count: u32,
    numbers: Option<Vec<u8>>,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    // Authorization: admin or an authorized submitter, exactly like the check
    // `SubmitRandomness` uses.
    if !config.is_submitter(&info.sender) {
        return Err(ContractError::UnauthorizedSubmitter);
    }

    if count == 0 || count > MAX_TICKETS_PER_TX {
        return Err(ContractError::InvalidTicketCount {
            count,
            max: MAX_TICKETS_PER_TX,
        });
    }

    // Validate / normalize the beneficiary address, like other addr params.
    let owner_addr = deps.api.addr_validate(&owner)?;

    // Honesty funding: require exactly `count * ticket_price` usaf attached — the
    // same guard a paid buy of `count` tickets uses — and add ALL of it to the
    // pool so the bonus ticket is fully funded.
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

    // Sponsored funds grow this round's pool in full.
    round.pool = round
        .pool
        .checked_add(total)
        .map_err(ContractError::Overflow)?;

    // Mint the tickets owned by `owner`, flagged free.
    let minted = mint_tickets(
        deps.storage,
        &env,
        &config,
        &mut round,
        round_id,
        &owner_addr,
        count,
        numbers.as_deref(),
        true, // free bonus ticket
    )?;
    ROUNDS.save(deps.storage, round_id, &round)?;

    let event = Event::new("winsaf/grant_bonus_ticket")
        .add_attribute("round_id", round_id.to_string())
        .add_attribute("granted_by", info.sender.to_string())
        .add_attribute("owner", owner_addr.to_string())
        .add_attribute("count", count.to_string())
        .add_attribute("sponsored", total)
        .add_attribute("pool", round.pool)
        .add_attribute("first_ticket_id", minted.first_id)
        .add_attribute("last_ticket_id", minted.last_id)
        .add_attribute("new_player", minted.new_player.to_string());

    Ok(Response::new().add_event(event))
}

// ---------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------

/// The first drand beacon round published strictly AFTER `close_time`. drand
/// round `R` is published at `genesis + (R-1) * period`, so this returns the
/// smallest `R` whose publish time is `> close_time`. Binding a WinSaf round to
/// a beacon that does not yet exist at close is what makes the draw unpredictable
/// and un-grindable by whoever relays it.
fn drand_round_after(close_time: u64, genesis: u64, period: u64) -> u64 {
    if period == 0 || close_time < genesis {
        // Defensive fallback (config validation rejects drand mode with a zero
        // period; clock skew before genesis cannot happen for a live round).
        return 1;
    }
    // publish(R) = genesis + (R-1)*period > close_time
    //   => R = floor((close_time - genesis) / period) + 2
    (close_time - genesis) / period + 2
}

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

    // Bind the beacon this round will consume. In drand mode it is the FIRST
    // drand round published strictly AFTER `closes_at` — so the beacon does not
    // yet exist when tickets are bought or the round closes, and the submitter
    // cannot grind it. In mock/commit-reveal modes there is no external beacon,
    // so we keep `round_id` as an inert placeholder.
    let config = CONFIG.load(deps.storage)?;
    let beacon_round = match config.randomness_mode {
        RandomnessMode::Drand => {
            drand_round_after(round.closes_at, config.drand_genesis_time, config.drand_period)
        }
        _ => round_id,
    };

    // Create the pending randomness slot for this round so submitters can act.
    let request = RandomnessRequest {
        round_id,
        beacon_round,
        status: RandomnessStatus::Pending,
        commitment: None,
        randomness: None,
        signature: None,
        committer: None,
        commit_height: None,
        reveal_deadline: None,
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
    env: Env,
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
    // Bind the commitment to its committer and record the commit height/time so
    // (a) only the same submitter may reveal, (b) the reveal is forced to a
    // strictly later block, and (c) a never-revealed commitment can be recovered
    // via CancelRound after `reveal_deadline`.
    // A zero timeout (e.g. after a migration that defaulted the field) falls back
    // to the sane default so a never-revealed round isn't instantly cancellable.
    let timeout = if config.reveal_timeout == 0 {
        DEFAULT_REVEAL_TIMEOUT_SECONDS
    } else {
        config.reveal_timeout
    };
    request.commitment = Some(commitment.clone());
    request.status = RandomnessStatus::Committed;
    request.committer = Some(info.sender.clone());
    request.commit_height = Some(env.block.height);
    request.reveal_deadline = Some(env.block.time.seconds().saturating_add(timeout));
    RANDOMNESS.save(deps.storage, round_id, &request)?;

    Ok(Response::new().add_event(
        Event::new("winsaf/commit_randomness")
            .add_attribute("round_id", round_id.to_string())
            .add_attribute("committer", info.sender)
            .add_attribute("commit_height", env.block.height.to_string())
            .add_attribute(
                "reveal_deadline",
                request.reveal_deadline.unwrap_or_default().to_string(),
            )
            .add_attribute("commitment", commitment.to_hex()),
    ))
}

fn execute_reveal_randomness(
    deps: DepsMut,
    env: Env,
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

    // Bind the reveal to the committer: only the address that posted the
    // commitment may reveal it (HIGH #7). Falls back to the submitter check
    // above for legacy requests with no recorded committer.
    if let Some(committer) = &request.committer {
        if committer != &info.sender {
            return Err(ContractError::NotCommitter { round_id });
        }
    }

    // Enforce the minimum reveal-delay window: the reveal must land at a
    // strictly-later block than the commit (CRITICAL #1c). The reveal block's
    // height/time are mixed into the seed below and are unknown at commit time,
    // so the outcome cannot be precomputed when the commitment is posted.
    if let Some(commit_height) = request.commit_height {
        let min_height = commit_height.saturating_add(MIN_REVEAL_DELAY_BLOCKS);
        if env.block.height < min_height {
            return Err(ContractError::RevealTooEarly {
                round_id,
                commit_height,
                min_height,
            });
        }
    }

    // Reveal must match the earlier commitment.
    verify_reveal(&commitment, &value)?;

    // Defense-in-depth seed derivation (CRITICAL #1b). The consumed seed is NOT
    // just sha256(value) — it also folds in inputs the submitter did not control
    // when committing:
    //   randomness = sha256( value
    //                      || round.ticket_entropy      (fixed at close, unknown at commit)
    //                      || reveal block time (be)     (unknown at commit)
    //                      || reveal block height (be) ) (unknown at commit)
    // so grinding `value` offline can no longer steer the draw outcome.
    let round = ROUNDS
        .load(deps.storage, round_id)
        .map_err(|_| ContractError::RoundNotFound { round_id })?;
    let mut preimage: Vec<u8> = Vec::with_capacity(value.len() + 32 + 8 + 8);
    preimage.extend_from_slice(value.as_slice());
    preimage.extend_from_slice(&round.ticket_entropy);
    preimage.extend_from_slice(&env.block.time.seconds().to_be_bytes());
    preimage.extend_from_slice(&env.block.height.to_be_bytes());
    let randomness = HexBinary::from(sha256(&preimage));

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
    let mut tiers = compute_prize_tiers(round.pool, &counts);

    // --- "Must Be Won" forced rolldown ------------------------------------
    // The jackpot pool must never roll over more than `max_dry_rounds`
    // consecutive dry rounds (no match-6 winner). On the round that would push
    // the streak to the cap, we FORCE the tier-6 (jackpot) allocation to roll
    // DOWN to the best-matching lower tier present, guaranteeing distribution.
    let jackpot_won = counts.six > 0;
    let dry_streak = DRY_STREAK.may_load(deps.storage)?.unwrap_or(0);
    // Would settling this round WITHOUT a jackpot winner reach the cap?
    let force =
        !jackpot_won && config.max_dry_rounds > 0 && (dry_streak + 1) >= config.max_dry_rounds;

    let mut forced_paid = false;
    let mut boost_tier: u8 = 0;
    let mut rolldown_amount = Uint128::zero();
    if force {
        // Pick the best present lower tier in order [5, 4, 3].
        if let Some(b) = [5u8, 4u8, 3u8]
            .into_iter()
            .find(|t| counts.for_tier(*t) > 0)
        {
            // The jackpot (tier-6) allocation that would otherwise roll over.
            // Same checked math as `compute_prize_tiers` (guard div-by-zero).
            let jackpot_alloc = match round.pool.checked_mul(Uint128::from(TIER6_BPS)) {
                Ok(scaled) => scaled
                    .checked_div(Uint128::from(10_000u128))
                    .unwrap_or_default(),
                Err(_) => Uint128::zero(),
            };
            let winners = counts.for_tier(b);
            // Redistribute the jackpot allocation equally among tier-b winners.
            // Any integer remainder/dust (jackpot_alloc % winners) is NOT added
            // to any per-winner payout, so it stays in `leftover` and
            // rolls/sweeps as today — every usaf remains accounted for.
            let per_winner = jackpot_alloc
                .checked_div(Uint128::from(winners))
                .unwrap_or_default();
            if !per_winner.is_zero() {
                tiers.boost_tier(b, per_winner);
                forced_paid = true;
                boost_tier = b;
                // Amount actually redistributed to winners (excludes the dust
                // remainder, which rolls/sweeps unchanged).
                rolldown_amount = per_winner
                    .checked_mul(Uint128::from(winners))
                    .unwrap_or_default();
            }
        }
        // Edge case: if NO lower tier has any winner (no ticket matched >= 3),
        // we cannot force a payout from nothing. `forced_paid` stays false, the
        // jackpot allocation rolls over as usual, and the streak persists. The
        // "Must Be Won" guarantee therefore holds whenever the forced round has
        // any ticket matching >= 3 — which is the only case a payout is possible.
    }

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

    // Dust disposal (LOW #25): every usaf must be accounted. `distributed` backs
    // this round's pull-claims; the remainder `leftover` (unassigned tier
    // allocations for tiers with no winners + rounding dust) must go somewhere or
    // it strands as untracked contract balance. Previously it only rolled over on
    // a no-jackpot round with rollover enabled — on a jackpot win (or with
    // rollover disabled) it leaked and quietly accumulated. We now dispose of the
    // FULL leftover in every branch:
    //   - roll it into the next round when rollover is enabled (player-favourable,
    //     keeps funds in the prize system), OR
    //   - sweep it to the treasury when rollover is disabled, so WithdrawTreasury
    //     can reconcile it.
    // By construction `distributed + leftover == round.pool` (pre-draw), so
    // either disposition keeps every usaf accounted for.
    let rollover_amount = if config.rollover_on_no_winner {
        leftover
    } else {
        if !leftover.is_zero() {
            TREASURY.update(deps.storage, |t| -> Result<_, ContractError> {
                Ok(t.checked_add(leftover)?)
            })?;
        }
        Uint128::zero()
    };
    // The pool retained on this round is exactly what claims can draw down.
    round.pool = distributed;
    ROUNDS.save(deps.storage, round_id, &round)?;

    // Update the "Must Be Won" dry streak: reset to 0 when the jackpot was won
    // (naturally) or forced down to a lower tier; otherwise it grew by one.
    let new_dry_streak = if jackpot_won || forced_paid {
        0
    } else {
        dry_streak + 1
    };
    DRY_STREAK.save(deps.storage, &new_dry_streak)?;

    // Open the next round (id + 1) seeded with any rollover.
    let next_id = open_next_round(
        deps.storage,
        round_id,
        &config,
        env.block.time.seconds(),
        rollover_amount,
    )?;

    let mut event = Event::new("winsaf/draw")
        .add_attribute("round_id", round_id.to_string())
        .add_attribute("winning_numbers", numbers_csv(&winning))
        .add_attribute("winners_3", counts.three.to_string())
        .add_attribute("winners_4", counts.four.to_string())
        .add_attribute("winners_5", counts.five.to_string())
        .add_attribute("winners_6", counts.six.to_string())
        .add_attribute("distributed", distributed)
        .add_attribute("rollover", rollover_amount)
        .add_attribute("dry_streak", new_dry_streak.to_string())
        .add_attribute("rolldown", forced_paid.to_string())
        .add_attribute("next_round_id", next_id.to_string());
    if forced_paid {
        event = event
            .add_attribute("rolldown_tier", boost_tier.to_string())
            .add_attribute("rolldown_amount", rolldown_amount);
    }

    Ok(Response::new().add_event(event))
}

/// Open the round following `prev_id`, seeded with `rollover_amount`, and make it
/// the current round. Shared by `execute_draw` (settle) and `execute_cancel_round`
/// (recovery) so the lifecycle always advances and never permanently halts.
/// Returns the new round id.
fn open_next_round(
    storage: &mut dyn cosmwasm_std::Storage,
    prev_id: u64,
    config: &Config,
    now: u64,
    rollover_amount: Uint128,
) -> Result<u64, ContractError> {
    let next_id = prev_id
        .checked_add(1)
        .ok_or_else(|| ContractError::InvalidConfig {
            reason: "round id overflow".to_string(),
        })?;
    let closes_at = now
        .checked_add(config.draw_interval)
        .ok_or_else(|| ContractError::InvalidConfig {
            reason: "draw_interval overflows round close time".to_string(),
        })?;
    let rolled_from = if rollover_amount.is_zero() {
        None
    } else {
        Some(prev_id)
    };
    let next_round = Round::new_open(next_id, now, closes_at, rollover_amount, rolled_from);
    ROUNDS.save(storage, next_id, &next_round)?;
    TICKET_SEQ.save(storage, next_id, &0u64)?;
    CURRENT_ROUND.save(storage, &next_id)?;
    Ok(next_id)
}

// ---------------------------------------------------------------------------
// Cancel (recovery) — MEDIUM #15 / HIGH #7
// ---------------------------------------------------------------------------

/// Recover a `Drawing` round whose randomness never fulfilled, so buyer funds are
/// never trapped and the protocol never halts on an unfulfillable round.
///
/// Authorization / timing:
///   - the admin may cancel a stuck `Drawing` round at any time, OR
///   - anyone may cancel once EITHER the commit-reveal `reveal_deadline` has
///     passed OR `closes_at + CANCEL_GRACE_SECONDS` has elapsed.
/// A round whose randomness is already `Fulfilled` must be drawn, not cancelled.
///
/// Effect:
///   - marks the round `Cancelled`,
///   - converts the retained `pool` into a pro-rata pull-refund per ticket
///     (assigned to `Ticket.prize`, claimed via `ClaimReward`, double-refund
///     guarded by `Ticket.claimed`) — capped at funds actually held so no
///     underflow can occur, and
///   - opens the next round (carrying any un-refundable rounding dust as
///     rollover) so `CURRENT_ROUND` advances and sales resume.
fn execute_cancel_round(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    round_id: u64,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let mut round = ROUNDS
        .load(deps.storage, round_id)
        .map_err(|_| ContractError::RoundNotFound { round_id })?;

    // Only a stuck round awaiting randomness can be cancelled.
    if round.status != RoundStatus::Drawing {
        return Err(ContractError::CannotCancel {
            round_id,
            reason: format!("round is {}, not drawing", status_str(&round.status)),
        });
    }

    // If randomness is already fulfilled the round must be drawn, not cancelled.
    let request = RANDOMNESS.may_load(deps.storage, round_id)?;
    if let Some(req) = &request {
        if matches!(req.status, RandomnessStatus::Fulfilled) {
            return Err(ContractError::CannotCancel {
                round_id,
                reason: "randomness already fulfilled — draw it instead".to_string(),
            });
        }
    }

    // Authorization: admin any time; otherwise a timeout must have passed.
    let now = env.block.time.seconds();
    let is_admin = config.is_admin(&info.sender);
    if !is_admin {
        let reveal_deadline_passed = request
            .as_ref()
            .and_then(|r| r.reveal_deadline)
            .map(|d| now > d)
            .unwrap_or(false);
        let grace_passed = now >= round.closes_at.saturating_add(CANCEL_GRACE_SECONDS);
        if !reveal_deadline_passed && !grace_passed {
            return Err(ContractError::CannotCancel {
                round_id,
                reason: "not admin and recovery timeout has not elapsed".to_string(),
            });
        }
    }

    // Trustless pro-rata refund: only the prize cut reached `round.pool`
    // (treasury/referral already left it), so we can only repay from what is
    // held. Distribute the retained pool evenly across tickets, floor-divided;
    // this caps total refunds at `pool` so `PoolUnderflow` can never trigger. Any
    // rounding dust rolls to the next round.
    let ticket_count = round.ticket_count;
    let pool = round.pool;
    let per_ticket = if ticket_count == 0 {
        Uint128::zero()
    } else {
        pool.checked_div(Uint128::from(ticket_count))
            .unwrap_or_default()
    };

    let mut assigned = Uint128::zero();
    if !per_ticket.is_zero() {
        let ids: Vec<String> = TICKETS
            .prefix(round_id)
            .keys(deps.storage, None, None, Order::Ascending)
            .collect::<StdResult<_>>()?;
        for id in &ids {
            TICKETS.update(
                deps.storage,
                (round_id, id.as_str()),
                |t| -> StdResult<_> {
                    let mut t = t.expect("ticket exists (iterated above)");
                    // Refund overrides any (non-existent) prize; not yet claimed.
                    t.prize = per_ticket;
                    t.matches = 0;
                    t.claimed = false;
                    Ok(t)
                },
            )?;
            assigned = assigned
                .checked_add(per_ticket)
                .map_err(ContractError::Overflow)?;
        }
    }

    // Dust that can't be refunded (rounding remainder) rolls into the next round.
    let dust = pool.checked_sub(assigned).map_err(ContractError::Overflow)?;

    round.status = RoundStatus::Cancelled;
    // Retain exactly the assigned refunds on this round to back pull-claims.
    round.pool = assigned;
    ROUNDS.save(deps.storage, round_id, &round)?;

    // CRITICAL for liveness: advance the lifecycle so future rounds/sales resume.
    let next_id = open_next_round(deps.storage, round_id, &config, now, dust)?;

    let event = Event::new("winsaf/cancel")
        .add_attribute("round_id", round_id.to_string())
        .add_attribute("by", info.sender.to_string())
        .add_attribute("admin", is_admin.to_string())
        .add_attribute("refund_per_ticket", per_ticket)
        .add_attribute("refund_total", assigned)
        .add_attribute("rollover_dust", dust)
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
    let config = CONFIG.load(deps.storage)?;
    validate_code(&code)?;
    let normalized = normalize_code(&code);

    if let Some(existing) = REFERRAL_CODES.may_load(deps.storage, &normalized)? {
        // Idempotent for the same owner; conflict for a different one.
        if existing != info.sender {
            return Err(ContractError::unauthorized("code owner"));
        }
    } else if !config.open_code_registration && !config.is_admin(&info.sender) {
        // Anti-squatting (LOW #26): when permissionless registration is off
        // (default), only the admin may claim a NEW code, so reserved
        // brand/influencer codes cannot be front-run. Owners may still
        // re-register (idempotently) their existing codes above regardless.
        return Err(ContractError::unauthorized("admin (code registration is closed)"));
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
    drand_genesis_time: Option<u64>,
    drand_period: Option<u64>,
    min_claim_usaf: Option<Uint128>,
    reveal_timeout: Option<u64>,
    open_code_registration: Option<bool>,
    max_dry_rounds: Option<u64>,
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

    // --- MEDIUM #16 guardrails ---------------------------------------------
    // (1) Refuse security downgrades to Mock randomness / Dev verify unless this
    //     wasm was compiled with the `dev-randomness` feature. The deployable
    //     artifact is built WITHOUT it (scripts/optimize.sh), so a live/testnet
    //     contract holding real funds can never be switched to attacker-chosen
    //     randomness via SetConfig.
    #[cfg(not(feature = "dev-randomness"))]
    if matches!(args.randomness_mode, Some(RandomnessMode::Mock)) {
        return Err(ContractError::InvalidConfig {
            reason: "Mock randomness cannot be enabled in a production build".to_string(),
        });
    }
    #[cfg(not(feature = "dev-randomness"))]
    if matches!(args.verify_mode, Some(VerifyMode::Dev)) {
        return Err(ContractError::InvalidConfig {
            reason: "Dev verify mode cannot be enabled in a production build".to_string(),
        });
    }

    // (2) Freeze fairness/economics-affecting config while a round is in flight
    //     (Open or Drawing) so tickets sold under the old economics/randomness
    //     are never re-priced or re-randomized mid-round. These changes apply
    //     from the NEXT round only. Admin/rollover/min_claim/submitter/timeout
    //     edits stay allowed mid-round.
    let round_id = CURRENT_ROUND.load(deps.storage)?;
    let status = ROUNDS.load(deps.storage, round_id)?.status;
    let in_flight = matches!(status, RoundStatus::Open | RoundStatus::Drawing);
    if in_flight
        && (args.randomness_mode.is_some()
            || args.verify_mode.is_some()
            || args.ticket_price.is_some()
            || args.split.is_some()
            || args.drand_pubkey.is_some()
            || args.drand_chain_hash.is_some())
    {
        return Err(ContractError::InvalidConfig {
            reason: "randomness/verify/price/split changes are only allowed between rounds"
                .to_string(),
        });
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
    if let Some(g) = args.drand_genesis_time {
        config.drand_genesis_time = g;
        changed.push(Attribute::new("drand_genesis_time", g.to_string()));
    }
    if let Some(p) = args.drand_period {
        config.drand_period = p;
        changed.push(Attribute::new("drand_period", p.to_string()));
    }
    if let Some(v) = args.min_claim_usaf {
        config.min_claim_usaf = v;
        changed.push(Attribute::new("min_claim_usaf", v));
    }
    if let Some(t) = args.reveal_timeout {
        config.reveal_timeout = t;
        changed.push(Attribute::new("reveal_timeout", t.to_string()));
    }
    if let Some(o) = args.open_code_registration {
        config.open_code_registration = o;
        changed.push(Attribute::new("open_code_registration", o.to_string()));
    }
    if let Some(mdr) = args.max_dry_rounds {
        config.max_dry_rounds = mdr;
        changed.push(Attribute::new("max_dry_rounds", mdr.to_string()));
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
    let dry_streak = DRY_STREAK.may_load(deps.storage)?.unwrap_or(0);
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
        dry_streak,
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
    // Idempotent version bump. The security-hardening upgrade added fields to
    // Config / Round / RandomnessRequest; all are `#[serde(default)]` so existing
    // persisted state deserializes without an explicit data migration (defaults:
    // reveal_timeout=0, open_code_registration=false, ticket_entropy=zero,
    // committer/commit_height/reveal_deadline=None). The "Must Be Won" rolldown
    // upgrade added `Config.max_dry_rounds` (serde default 5) and the
    // `DRY_STREAK` item (absent → treated as 0 via `.may_load()?.unwrap_or(0)`),
    // so both migrate without an explicit data step. The admin should `SetConfig`
    // a non-zero `reveal_timeout` post-migration. Add data migrations here on
    // future versions as needed.
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
        // The beacon round a round consumes is derived from `closes_at` using the
        // genesis/period, so both must be set for the future-round binding to work.
        if config.drand_period == 0 || config.drand_genesis_time == 0 {
            return Err(ContractError::InvalidConfig {
                reason: "drand mode requires non-zero drand_genesis_time and drand_period".to_string(),
            });
        }
        if matches!(config.verify_mode, VerifyMode::Bls)
            && config.drand_pubkey.len() != G2_LEN
        {
            return Err(ContractError::InvalidPubkey {
                reason: format!(
                    "drand mode with BLS verification requires a {G2_LEN}-byte G2 public key"
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

/// Fold one ticket into a round's ticket-entropy accumulator (CRITICAL #1a).
///
/// `new = sha256(prev || buyer_bytes || ticket_id_bytes || picks)`. Chaining the
/// previous accumulator makes the result depend on the full ordered ticket set,
/// which is not known when a commit-reveal submitter must post their commitment
/// during the `Open` phase — so it cannot be ground offline to steer the draw.
fn fold_ticket_entropy(prev: &[u8; 32], buyer: &Addr, ticket_id: &str, picks: &[u8]) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(32 + buyer.as_bytes().len() + ticket_id.len() + picks.len());
    buf.extend_from_slice(prev);
    buf.extend_from_slice(buyer.as_bytes());
    buf.extend_from_slice(ticket_id.as_bytes());
    buf.extend_from_slice(picks);
    sha256(&buf)
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

    /// Winner count for an exact tier (3/4/5/6); 0 for any other tier.
    fn for_tier(&self, tier: u8) -> u64 {
        match tier {
            3 => self.three,
            4 => self.four,
            5 => self.five,
            6 => self.six,
            _ => 0,
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

    /// Add `add` to the per-winner payout of an exact tier (3/4/5). Used by the
    /// "Must Be Won" forced rolldown to boost the best present lower tier with
    /// the jackpot allocation. Tier 6 (the jackpot itself) is never boosted here.
    fn boost_tier(&mut self, tier: u8, add: Uint128) {
        match tier {
            3 => self.tier_3 = self.tier_3.saturating_add(add),
            4 => self.tier_4 = self.tier_4.saturating_add(add),
            5 => self.tier_5 = self.tier_5.saturating_add(add),
            _ => {}
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
            drand_genesis_time: None,
            drand_period: None,
            authorized_submitters: vec![submitter.to_string()],
            min_claim_usaf: None,
            reveal_timeout: None,
            open_code_registration: None,
            max_dry_rounds: None,
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
            drand_genesis_time: None,
            drand_period: None,
            authorized_submitters: vec![],
            min_claim_usaf: None,
            reveal_timeout: None,
            open_code_registration: None,
            max_dry_rounds: None,
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
            drand_genesis_time: None,
            drand_period: None,
            authorized_submitters: vec![],
            min_claim_usaf: None,
            reveal_timeout: None,
            open_code_registration: None,
            max_dry_rounds: None,
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
            drand_genesis_time: None,
            drand_period: None,
            authorized_submitters: vec![],
            min_claim_usaf: None,
            reveal_timeout: None,
            open_code_registration: None,
            max_dry_rounds: None,
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
            drand_pubkey: Some(HexBinary::from(vec![1u8; G2_LEN])),
            drand_chain_hash: None,
            drand_genesis_time: None,
            drand_period: None,
            authorized_submitters: vec![],
            min_claim_usaf: None,
            reveal_timeout: None,
            open_code_registration: None,
            max_dry_rounds: None,
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
            drand_genesis_time: None,
            drand_period: None,
            authorized_submitters: vec![],
            min_claim_usaf: None,
            reveal_timeout: None,
            open_code_registration: None,
            max_dry_rounds: None,
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
        let (mut deps, api, env, admin, _sub) = setup();
        let buyer = mk(&api, "buyer");
        let referrer = mk(&api, "referrer");

        // Enable permissionless code registration so a non-admin referrer may
        // self-register (default is admin-only to prevent squatting, LOW #26).
        open_code_registration(&mut deps, &env, &admin);

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

        // buyer buys with the code (case-insensitive); should credit referrer.
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
                drand_genesis_time: None,
                drand_period: None,
                authorized_submitters: vec![submitter.to_string()],
                min_claim_usaf: None,
                reveal_timeout: None,
                open_code_registration: None,
                max_dry_rounds: None,
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

        // Reveal at the SAME block as the commit is rejected: the min-delay
        // window forces the reveal to a strictly later block (CRITICAL #1c).
        let err = execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&submitter, &[]),
            ExecuteMsg::RevealRandomness {
                round_id: 1,
                value: value.clone(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::RevealTooEarly { .. }));

        // Advance one block so the reveal window opens.
        let mut env3 = env2.clone();
        env3.block.height += 1;
        env3.block.time = Timestamp::from_seconds(env3.block.time.seconds() + 6);

        // Wrong reveal (bad pre-image) is rejected.
        let err = execute(
            deps.as_mut(),
            env3.clone(),
            message_info(&submitter, &[]),
            ExecuteMsg::RevealRandomness {
                round_id: 1,
                value: HexBinary::from(vec![0u8; 32]),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::RevealMismatch));

        // A different authorized submitter cannot reveal someone else's commit.
        let other = mk(&api, "other-op");
        execute(
            deps.as_mut(),
            env3.clone(),
            message_info(&admin, &[]),
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
                drand_genesis_time: None,
                drand_period: None,
                min_claim_usaf: None,
                reveal_timeout: None,
                open_code_registration: None,
                max_dry_rounds: None,
                add_submitters: Some(vec![other.to_string()]),
                remove_submitters: None,
            },
        )
        .unwrap();
        let err = execute(
            deps.as_mut(),
            env3.clone(),
            message_info(&other, &[]),
            ExecuteMsg::RevealRandomness {
                round_id: 1,
                value: value.clone(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::NotCommitter { .. }));

        // Correct reveal by the committer fulfils. The consumed seed is the
        // hardened derivation: sha256(value || ticket_entropy || time_be || height_be).
        execute(
            deps.as_mut(),
            env3.clone(),
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
        let mut preimage = value.to_vec();
        preimage.extend_from_slice(&[0u8; 32]); // no tickets bought => zero entropy
        preimage.extend_from_slice(&env3.block.time.seconds().to_be_bytes());
        preimage.extend_from_slice(&env3.block.height.to_be_bytes());
        assert_eq!(
            req.randomness.unwrap(),
            HexBinary::from(sha256(&preimage))
        );
        // The hardened seed differs from the naive sha256(value).
        assert_ne!(
            HexBinary::from(sha256(&preimage)),
            HexBinary::from(sha256(value.as_slice()))
        );

        // Draw succeeds.
        execute(
            deps.as_mut(),
            env3,
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
                drand_genesis_time: None,
                drand_period: None,
                authorized_submitters: vec![submitter.to_string()],
                min_claim_usaf: None,
                reveal_timeout: None,
                open_code_registration: None,
                max_dry_rounds: None,
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

    // --- "Must Be Won" forced rolldown --------------------------------------

    /// Instantiate with an explicit `max_dry_rounds` (mock randomness, dev
    /// verify, one submitter). Mirrors `setup()` but parameterizes the cap.
    fn setup_cap(max_dry_rounds: u64) -> (OD, MockApi, Env, Addr, Addr) {
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
            randomness_mode: None,
            verify_mode: None,
            drand_pubkey: None,
            drand_chain_hash: None,
            drand_genesis_time: None,
            drand_period: None,
            authorized_submitters: vec![submitter.to_string()],
            min_claim_usaf: None,
            reveal_timeout: None,
            open_code_registration: None,
            max_dry_rounds: Some(max_dry_rounds),
        };
        instantiate(deps.as_mut(), env.clone(), message_info(&admin, &[]), msg).unwrap();
        (deps, api, env, admin, submitter)
    }

    /// Build a valid 6-number pick (distinct, 1..=45) that matches EXACTLY `n`
    /// of `winning`: take `n` winning numbers, fill the rest from `1..=45`
    /// values NOT present in `winning`.
    fn picks_matching(winning: &[u8], n: usize) -> Vec<u8> {
        let mut picks: Vec<u8> = winning.iter().copied().take(n).collect();
        let mut v: u8 = 1;
        while picks.len() < 6 && v <= 45 {
            if !winning.contains(&v) && !picks.contains(&v) {
                picks.push(v);
            }
            v += 1;
        }
        picks.sort_unstable();
        picks
    }

    /// Close + submit mock randomness + draw an arbitrary `round_id`. Returns
    /// the derived winning numbers for that round.
    fn run_draw_round(
        deps: &mut OD,
        env: &mut Env,
        submitter: &Addr,
        round_id: u64,
        randomness: HexBinary,
    ) -> Vec<u8> {
        advance(env, DRAW_INTERVAL + 1);
        let keeper = mk(&deps.api, "keeper");
        execute(
            deps.as_mut(),
            env.clone(),
            message_info(&keeper, &[]),
            ExecuteMsg::CloseRound {},
        )
        .unwrap();
        execute(
            deps.as_mut(),
            env.clone(),
            message_info(submitter, &[]),
            ExecuteMsg::SubmitRandomness {
                round_id,
                randomness: randomness.clone(),
                signature: None,
            },
        )
        .unwrap();
        execute(
            deps.as_mut(),
            env.clone(),
            message_info(&keeper, &[]),
            ExecuteMsg::Draw { round_id },
        )
        .unwrap();
        derive_winning_numbers(randomness.as_slice(), 6, 45)
    }

    #[test]
    fn rolldown_forces_after_cap() {
        // max_dry_rounds = 3: rounds 1 & 2 roll over (streak 1, 2); round 3
        // FORCES the jackpot allocation down to the best present lower tier.
        let (mut deps, api, mut env, _admin, submitter) = setup_cap(3);
        let buyer = mk(&api, "buyer");

        // For each of 3 rounds: buy a ticket matching exactly 5 (never 6), so a
        // dry round always has a tier-5 winner to roll DOWN into.
        let rand_bytes: [u8; 3] = [0x11, 0x22, 0x33];
        let mut r1_pool_pre = Uint128::zero();
        for (i, b) in rand_bytes.iter().enumerate() {
            let round_id = (i + 1) as u64;
            let randomness = HexBinary::from(vec![*b; 32]);
            let winning = derive_winning_numbers(randomness.as_slice(), 6, 45);
            let picks = picks_matching(&winning, 5);
            buy(&mut deps, &env, &buyer, 1, Some(picks), None).unwrap();
            if round_id == 3 {
                r1_pool_pre = round(&deps, 3).pool; // pre-draw pool of round 3
            }
            run_draw_round(&mut deps, &mut env, &submitter, round_id, randomness.clone());
        }

        // Rounds 1 & 2 were dry with no forced rolldown: they rolled over.
        let r1 = round(&deps, 1);
        let r2 = round(&deps, 2);
        assert_eq!(r1.winning_tickets, 1); // the tier-5 winner
        assert_eq!(r2.winning_tickets, 1);
        assert_eq!(r2.rolled_over_from, Some(1)); // round 1 leftover rolled into 2

        // Round 3 is the forced round: tier-6 allocation rolled DOWN to tier 5.
        let r3 = round(&deps, 3);
        // Without the rolldown, tier_5 would be 20% of pool / 1 winner. With the
        // forced rolldown it also receives the 60% jackpot allocation.
        let tier5_base = r1_pool_pre.multiply_ratio(TIER5_BPS, 10_000u128);
        let tier6_alloc = r1_pool_pre.multiply_ratio(TIER6_BPS, 10_000u128);
        assert_eq!(r3.prize_tiers.tier_5, tier5_base + tier6_alloc);
        // No jackpot paid (tier_6 per-winner stays zero — no 6-match ticket).
        assert_eq!(r3.prize_tiers.tier_6, Uint128::zero());

        // dry_streak reset to 0 after the forced rolldown.
        assert_eq!(r3.dry_streak, 0);
        // The next round did NOT get the jackpot allocation rolled over (it was
        // distributed): its seeded pool is only the leftover dust, well under a
        // full jackpot allocation.
        let r4 = round(&deps, 4);
        assert!(r4.pool < tier6_alloc);

        // Pool accounting holds: distributed (= r3.pool retained) <= pre pool.
        assert!(r3.pool <= r1_pool_pre);
    }

    #[test]
    fn rolldown_streak_increments_then_resets() {
        // Observe dry_streak grow 1 -> 2 across two dry rounds under a high cap
        // (5) so no forced rolldown fires, then a jackpot win resets to 0.
        let (mut deps, api, mut env, _admin, submitter) = setup_cap(5);
        let buyer = mk(&api, "buyer");

        // Round 1: dry (match 4 only) -> streak 1.
        let rnd1 = HexBinary::from(vec![0x41; 32]);
        let w1 = derive_winning_numbers(rnd1.as_slice(), 6, 45);
        buy(&mut deps, &env, &buyer, 1, Some(picks_matching(&w1, 4)), None).unwrap();
        run_draw_round(&mut deps, &mut env, &submitter, 1, rnd1);
        assert_eq!(round(&deps, 1).dry_streak, 1);

        // Round 2: dry again -> streak 2.
        let rnd2 = HexBinary::from(vec![0x42; 32]);
        let w2 = derive_winning_numbers(rnd2.as_slice(), 6, 45);
        buy(&mut deps, &env, &buyer, 1, Some(picks_matching(&w2, 4)), None).unwrap();
        run_draw_round(&mut deps, &mut env, &submitter, 2, rnd2);
        assert_eq!(round(&deps, 2).dry_streak, 2);

        // Round 3: NATURAL jackpot win (match 6) -> resets streak to 0, no force.
        let rnd3 = HexBinary::from(vec![0x43; 32]);
        let w3 = derive_winning_numbers(rnd3.as_slice(), 6, 45);
        buy(&mut deps, &env, &buyer, 1, Some(w3.clone()), None).unwrap();
        run_draw_round(&mut deps, &mut env, &submitter, 3, rnd3);
        let r3 = round(&deps, 3);
        assert!(r3.prize_tiers.tier_6 > Uint128::zero()); // jackpot actually paid
        assert_eq!(r3.dry_streak, 0);
    }

    #[test]
    fn rolldown_cannot_fabricate_winner() {
        // Forced round with NO ticket matching >= 3: the guarantee can't create a
        // winner, so it rolls over and the streak persists (reaches the cap).
        let (mut deps, api, mut env, _admin, submitter) = setup_cap(2);
        let buyer = mk(&api, "buyer");

        // Round 1: dry, no lower-tier winner (match 0) -> streak 1.
        let rnd1 = HexBinary::from(vec![0x51; 32]);
        let w1 = derive_winning_numbers(rnd1.as_slice(), 6, 45);
        buy(&mut deps, &env, &buyer, 1, Some(picks_matching(&w1, 0)), None).unwrap();
        run_draw_round(&mut deps, &mut env, &submitter, 1, rnd1);
        assert_eq!(round(&deps, 1).dry_streak, 1);

        // Round 2: hits the cap and would force, but NO ticket matches >= 3.
        let rnd2 = HexBinary::from(vec![0x52; 32]);
        let w2 = derive_winning_numbers(rnd2.as_slice(), 6, 45);
        buy(&mut deps, &env, &buyer, 1, Some(picks_matching(&w2, 0)), None).unwrap();
        let pool_pre = round(&deps, 2).pool;
        run_draw_round(&mut deps, &mut env, &submitter, 2, rnd2);

        let r2 = round(&deps, 2);
        // Nothing distributed (no winner at any tier), streak persisted past cap.
        assert_eq!(r2.winning_tickets, 0);
        assert_eq!(r2.dry_streak, 2); // NOT reset — no forced payout possible
        assert_eq!(r2.pool, Uint128::zero()); // retained pool = distributed = 0
        // The full pool rolled over to round 3 (rollover enabled).
        assert_eq!(round(&deps, 3).pool, pool_pre);
        assert_eq!(round(&deps, 3).rolled_over_from, Some(2));
    }

    #[test]
    fn rolldown_pool_accounting_holds() {
        // Under a forced rolldown, distributed <= pool and every usaf is
        // accounted for (distributed retained + rollover seeds next round).
        let (mut deps, api, mut env, _admin, submitter) = setup_cap(1);
        let buyer = mk(&api, "buyer");

        // max_dry_rounds = 1: the very first dry round forces immediately.
        let rnd = HexBinary::from(vec![0x61; 32]);
        let w = derive_winning_numbers(rnd.as_slice(), 6, 45);
        // Two tier-3 winners so the jackpot alloc splits (exercises remainder).
        let buyer2 = mk(&api, "buyer2");
        buy(&mut deps, &env, &buyer, 1, Some(picks_matching(&w, 3)), None).unwrap();
        buy(&mut deps, &env, &buyer2, 1, Some(picks_matching(&w, 3)), None).unwrap();
        let pool_pre = round(&deps, 1).pool;
        run_draw_round(&mut deps, &mut env, &submitter, 1, rnd);

        let r1 = round(&deps, 1);
        let r2 = round(&deps, 2);
        // Forced rolldown to tier 3 fired: streak reset, jackpot boosted tier_3.
        assert_eq!(r1.dry_streak, 0);
        let tier3_base = pool_pre.multiply_ratio(TIER3_BPS, 10_000u128);
        let tier6_alloc = pool_pre.multiply_ratio(TIER6_BPS, 10_000u128);
        // Two winners share (tier-3 alloc + jackpot alloc); per-winner is the
        // floor of each split, so tier_3 >= base per-winner.
        let per_winner_base = tier3_base.multiply_ratio(1u128, 2u128);
        assert!(r1.prize_tiers.tier_3 >= per_winner_base);
        // distributed = retained pool never exceeds the pre-draw pool.
        assert!(r1.pool <= pool_pre);
        // Every usaf accounted: retained (distributed) + rolled-over == pool_pre.
        assert_eq!(r1.pool + r2.pool, pool_pre);
        // The boost really moved the jackpot allocation into tier 3 (not tier 6).
        assert_eq!(r1.prize_tiers.tier_6, Uint128::zero());
        assert!(tier6_alloc > Uint128::zero());
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
        let (mut deps, api, env, admin, _sub) = setup();
        open_code_registration(&mut deps, &env, &admin);
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

    /// Test helper: enable permissionless referral-code registration.
    fn open_code_registration(deps: &mut OD, env: &Env, admin: &Addr) {
        let mut msg = set_config_none();
        if let ExecuteMsg::SetConfig {
            open_code_registration,
            ..
        } = &mut msg
        {
            *open_code_registration = Some(true);
        }
        execute(deps.as_mut(), env.clone(), message_info(admin, &[]), msg).unwrap();
    }

    #[test]
    fn register_code_admin_only_by_default() {
        // Default (closed) registration: a non-admin cannot claim a new code,
        // but the admin can (anti-squatting, LOW #26).
        let (mut deps, api, _env, admin, _sub) = setup();
        let squatter = mk(&api, "squatter");
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&squatter, &[]),
            ExecuteMsg::RegisterCode {
                code: "brand".to_string(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Unauthorized { .. }));

        // Admin reserves it.
        execute(
            deps.as_mut(),
            mock_env(),
            message_info(&admin, &[]),
            ExecuteMsg::RegisterCode {
                code: "brand".to_string(),
            },
        )
        .unwrap();
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
                drand_genesis_time: None,
                drand_period: None,
                authorized_submitters: vec![],
                min_claim_usaf: Some(Uint128::new(10_000_000)), // high floor
                reveal_timeout: None,
                open_code_registration: None,
                max_dry_rounds: None,
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

        // Changing `split` while a round is Open (in-flight) is rejected by the
        // MEDIUM #16 guardrail before split validation even runs; economics may
        // only change between rounds.
        let mut msg = set_config_none();
        if let ExecuteMsg::SetConfig { split, .. } = &mut msg {
            *split = Some(FundSplitBps::new_unchecked(5000, 1000, 1500));
        }
        let err = execute(deps.as_mut(), mock_env(), message_info(&admin, &[]), msg)
            .unwrap_err();
        assert!(matches!(err, ContractError::InvalidConfig { .. }));

        // Valid mid-round update: draw_interval / rollover are always allowed
        // (draw_interval only affects the next round; closes_at is frozen at open).
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
            drand_genesis_time: None,
            drand_period: None,
            min_claim_usaf: None,
            reveal_timeout: None,
            open_code_registration: None,
            max_dry_rounds: None,
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

    // --- GrantBonusTicket (operator-sponsored bonus tickets) ---------------

    /// Grant `count` operator-sponsored bonus tickets to `owner`, attaching the
    /// (optionally overridden) funds. Mirrors the `buy` test helper.
    fn grant(
        deps: &mut OD,
        env: &Env,
        caller: &Addr,
        owner: &Addr,
        count: u32,
        numbers: Option<Vec<u8>>,
        funds: Option<Vec<Coin>>,
    ) -> Result<Response, ContractError> {
        let funds = funds.unwrap_or_else(|| coins(TICKET_PRICE * count as u128, DENOM));
        let info = message_info(caller, &funds);
        execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::GrantBonusTicket {
                owner: owner.to_string(),
                count,
                numbers,
            },
        )
    }

    /// Fetch all tickets in a round owned by `owner`.
    fn tickets_of(deps: &OD, round_id: u64, owner: &Addr) -> Vec<TicketInfo> {
        let res: TicketsResponse = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::Tickets {
                    round_id,
                    owner: Some(owner.to_string()),
                    start_after: None,
                    limit: None,
                },
            )
            .unwrap(),
        )
        .unwrap();
        res.tickets
    }

    #[test]
    fn grant_mints_free_tickets_owned_by_owner_and_funds_pool() {
        let (mut deps, api, env, admin, submitter) = setup();
        let owner = mk(&api, "xp_redeemer");

        // A submitter (not admin) grants 2 bonus tickets to `owner`.
        let pool_before = current(&deps).pool;
        grant(&mut deps, &env, &submitter, &owner, 2, None, None).unwrap();

        // Pool grew by count * ticket_price in full (no split).
        let r = current(&deps);
        assert_eq!(r.pool, pool_before + Uint128::new(2 * TICKET_PRICE));
        assert_eq!(r.ticket_count, 2);
        // `owner` is counted as a player.
        assert_eq!(r.player_count, 1);

        // The two tickets are owned by `owner` and flagged free with valid picks.
        let owned = tickets_of(&deps, 1, &owner);
        assert_eq!(owned.len(), 2);
        for t in &owned {
            assert!(t.ticket.free);
            assert_eq!(t.ticket.owner, owner);
            assert_eq!(t.ticket.numbers.len(), 6);
            assert!(t.ticket.numbers.iter().all(|n| (1..=45).contains(n)));
        }

        // Admin may also grant (auth = admin OR submitter).
        grant(&mut deps, &env, &admin, &owner, 1, None, None).unwrap();
        assert_eq!(current(&deps).ticket_count, 3);
    }

    #[test]
    fn grant_unauthorized_caller_rejected() {
        let (mut deps, api, env, _admin, _sub) = setup();
        let stranger = mk(&api, "stranger");
        let owner = mk(&api, "owner");
        let err = grant(&mut deps, &env, &stranger, &owner, 1, None, None).unwrap_err();
        assert!(matches!(err, ContractError::UnauthorizedSubmitter));
    }

    #[test]
    fn grant_wrong_or_missing_funds_rejected() {
        let (mut deps, api, env, _admin, submitter) = setup();
        let owner = mk(&api, "owner");

        // Too little for 2 tickets.
        let err = grant(
            &mut deps,
            &env,
            &submitter,
            &owner,
            2,
            None,
            Some(coins(TICKET_PRICE, DENOM)),
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Shared(_)));

        // No funds at all.
        let err = grant(&mut deps, &env, &submitter, &owner, 1, None, Some(vec![]))
            .unwrap_err();
        assert!(matches!(err, ContractError::Shared(_)));

        // Foreign denom.
        let err = grant(
            &mut deps,
            &env,
            &submitter,
            &owner,
            1,
            None,
            Some(coins(TICKET_PRICE, "uatom")),
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::Shared(_)));
    }

    #[test]
    fn grant_on_non_open_round_rejected() {
        let (mut deps, api, env, _admin, submitter) = setup();
        let owner = mk(&api, "owner");

        // Close the round → status Drawing, no longer accepts tickets.
        let mut env2 = env.clone();
        advance(&mut env2, DRAW_INTERVAL + 1);
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&submitter, &[]),
            ExecuteMsg::CloseRound {},
        )
        .unwrap();

        let err = grant(&mut deps, &env2, &submitter, &owner, 1, None, None).unwrap_err();
        assert!(matches!(err, ContractError::RoundNotOpen { .. }));
    }

    #[test]
    fn grant_out_of_domain_numbers_rejected_none_quickpicks() {
        let (mut deps, api, env, _admin, submitter) = setup();
        let owner = mk(&api, "owner");

        // Out-of-domain explicit picks are rejected (46 > number_max 45).
        let err = grant(
            &mut deps,
            &env,
            &submitter,
            &owner,
            1,
            Some(vec![1, 2, 3, 4, 5, 46]),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::InvalidNumbers { .. }));

        // Duplicate picks rejected too.
        let err = grant(
            &mut deps,
            &env,
            &submitter,
            &owner,
            1,
            Some(vec![1, 1, 3, 4, 5, 6]),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::InvalidNumbers { .. }));

        // `None` quick-picks valid in-range numbers.
        grant(&mut deps, &env, &submitter, &owner, 1, None, None).unwrap();
        let owned = tickets_of(&deps, 1, &owner);
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].ticket.numbers.len(), 6);
        assert!(owned[0].ticket.numbers.iter().all(|n| (1..=45).contains(n)));
    }

    #[test]
    fn granted_bonus_ticket_can_win_and_be_claimed() {
        // Full cycle: a paid buy + a granted bonus ticket that matches the drawn
        // numbers WINS and is claimable by `owner`.
        let (mut deps, api, env, _admin, submitter) = setup();
        let buyer = mk(&api, "buyer");
        let owner = mk(&api, "xp_redeemer");
        let randomness = HexBinary::from(vec![7u8; 32]);
        let winning = derive_winning_numbers(randomness.as_slice(), 6, 45);

        // A normal paid buy (non-winning quick-pick would be fine, but give it a
        // 3-match so the pool has multiple tiers) and a granted JACKPOT ticket.
        buy(&mut deps, &env, &buyer, 1, Some(picks_matching(&winning, 3)), None).unwrap();
        grant(
            &mut deps,
            &env,
            &submitter,
            &owner,
            1,
            Some(winning.clone()),
            None,
        )
        .unwrap();

        // The granted ticket is free and owned by `owner`.
        let owned = tickets_of(&deps, 1, &owner);
        assert_eq!(owned.len(), 1);
        assert!(owned[0].ticket.free);
        let bonus_ticket_id = owned[0].ticket_id.clone();

        // Close → submit randomness → draw.
        run_draw(&mut deps, &env, &submitter, randomness);
        assert_eq!(round(&deps, 1).status, RoundStatus::Settled);

        // The bonus ticket matched all 6 (jackpot) and carries a non-zero prize.
        let owned = tickets_of(&deps, 1, &owner);
        assert_eq!(owned[0].ticket.matches, 6);
        let prize = owned[0].ticket.prize;
        assert!(!prize.is_zero());
        assert!(owned[0].ticket.free); // still flagged free after the draw

        // `owner` claims the bonus ticket's prize.
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&owner, &[]),
            ExecuteMsg::ClaimReward {
                round_id: 1,
                ticket_id: bonus_ticket_id.clone(),
            },
        )
        .unwrap();
        assert!(res.messages.iter().any(|m| matches!(
            &m.msg,
            CosmosMsg::Bank(BankMsg::Send { to_address, amount })
                if to_address == &owner.to_string() && amount[0].amount == prize
        )));

        // Double-claim guarded.
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&owner, &[]),
            ExecuteMsg::ClaimReward {
                round_id: 1,
                ticket_id: bonus_ticket_id,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::AlreadyClaimed { .. }));
    }

    // --- CancelRound recovery (MEDIUM #15 / HIGH #7) ------------------------

    /// Instantiate a commit-reveal contract with one submitter, returning
    /// (deps, api, env, admin, submitter).
    fn setup_commit_reveal() -> (OD, MockApi, Env, Addr, Addr) {
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
                drand_genesis_time: None,
                drand_period: None,
                authorized_submitters: vec![submitter.to_string()],
                min_claim_usaf: None,
                reveal_timeout: Some(3600),
                open_code_registration: None,
                max_dry_rounds: None,
            },
        )
        .unwrap();
        (deps, api, env, admin, submitter)
    }

    #[test]
    fn cancel_stuck_round_refunds_and_advances_lifecycle() {
        // A round is closed, randomness never fulfilled; admin cancels it. Buyers
        // get pro-rata refunds and the next round opens so sales resume.
        let (mut deps, api, env, admin, _sub) = setup_commit_reveal();
        let buyer = mk(&api, "buyer");
        buy(&mut deps, &env, &buyer, 2, None, None).unwrap();

        let mut env2 = env.clone();
        advance(&mut env2, DRAW_INTERVAL + 1);
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&buyer, &[]),
            ExecuteMsg::CloseRound {},
        )
        .unwrap();
        assert_eq!(round(&deps, 1).status, RoundStatus::Drawing);

        // Non-admin cannot cancel before the recovery timeout.
        let stranger = mk(&api, "stranger");
        let err = execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&stranger, &[]),
            ExecuteMsg::CancelRound { round_id: 1 },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::CannotCancel { .. }));

        // Admin cancels immediately.
        let retained_pool = round(&deps, 1).pool;
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&admin, &[]),
            ExecuteMsg::CancelRound { round_id: 1 },
        )
        .unwrap();

        // Round 1 cancelled, next round open and current.
        assert_eq!(round(&deps, 1).status, RoundStatus::Cancelled);
        let r2 = current(&deps);
        assert_eq!(r2.id, 2);
        assert_eq!(r2.status, RoundStatus::Open);

        // New round accepts tickets.
        buy(&mut deps, &env2, &buyer, 1, None, None).unwrap();

        // Buyer pulls a refund on each cancelled-round ticket (pro-rata).
        let per_ticket = retained_pool / Uint128::from(2u128);
        for id in [ticket_id(0), ticket_id(1)] {
            let res = execute(
                deps.as_mut(),
                env2.clone(),
                message_info(&buyer, &[]),
                ExecuteMsg::ClaimReward {
                    round_id: 1,
                    ticket_id: id,
                },
            )
            .unwrap();
            assert!(res.messages.iter().any(|m| matches!(
                &m.msg,
                CosmosMsg::Bank(BankMsg::Send { to_address, amount })
                    if to_address == &buyer.to_string() && amount[0].amount == per_ticket
            )));
        }
        // Cancelled round's pool is fully drained by the two refunds.
        assert!(round(&deps, 1).pool <= retained_pool - per_ticket * Uint128::from(2u128));
    }

    #[test]
    fn cancel_permissionless_after_grace() {
        // After closes_at + CANCEL_GRACE_SECONDS anyone may cancel a stuck round.
        let (mut deps, api, env, _admin, _sub) = setup_commit_reveal();
        let buyer = mk(&api, "buyer");
        buy(&mut deps, &env, &buyer, 1, None, None).unwrap();

        let mut env2 = env.clone();
        advance(&mut env2, DRAW_INTERVAL + 1);
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&buyer, &[]),
            ExecuteMsg::CloseRound {},
        )
        .unwrap();

        // Warp past the grace window.
        let mut env3 = env2.clone();
        env3.block.time =
            Timestamp::from_seconds(round(&deps, 1).closes_at + CANCEL_GRACE_SECONDS + 1);
        let anyone = mk(&api, "anyone");
        execute(
            deps.as_mut(),
            env3,
            message_info(&anyone, &[]),
            ExecuteMsg::CancelRound { round_id: 1 },
        )
        .unwrap();
        assert_eq!(round(&deps, 1).status, RoundStatus::Cancelled);
        assert_eq!(current(&deps).id, 2);
    }

    #[test]
    fn cancel_rejected_when_randomness_fulfilled() {
        // A round whose randomness is fulfilled must be drawn, not cancelled.
        let (mut deps, _api, env, admin, submitter) = setup();
        let mut env2 = env.clone();
        advance(&mut env2, DRAW_INTERVAL + 1);
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&submitter, &[]),
            ExecuteMsg::CloseRound {},
        )
        .unwrap();
        execute(
            deps.as_mut(),
            env2.clone(),
            message_info(&submitter, &[]),
            ExecuteMsg::SubmitRandomness {
                round_id: 1,
                randomness: HexBinary::from(vec![1u8; 32]),
                signature: None,
            },
        )
        .unwrap();
        let err = execute(
            deps.as_mut(),
            env2,
            message_info(&admin, &[]),
            ExecuteMsg::CancelRound { round_id: 1 },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::CannotCancel { .. }));
    }

    #[test]
    fn cancel_rejected_on_open_round() {
        let (mut deps, _api, env, admin, _sub) = setup();
        let err = execute(
            deps.as_mut(),
            env,
            message_info(&admin, &[]),
            ExecuteMsg::CancelRound { round_id: 1 },
        )
        .unwrap_err();
        assert!(matches!(err, ContractError::CannotCancel { .. }));
    }

    // --- Randomness hardening (CRITICAL #1 / HIGH #7) -----------------------

    #[test]
    fn reveal_seed_depends_on_ticket_entropy() {
        // Two contracts with the SAME committed value but DIFFERENT ticket sets
        // must produce DIFFERENT consumed randomness, proving the seed mixes the
        // per-round ticket-entropy accumulator (CRITICAL #1a/#1b).
        fn run(with_extra_ticket: bool) -> HexBinary {
            let (mut deps, api, env, _admin, submitter) = setup_commit_reveal();
            let buyer = mk(&api, "buyer");
            buy(&mut deps, &env, &buyer, 1, Some(vec![1, 2, 3, 4, 5, 6]), None).unwrap();
            if with_extra_ticket {
                let buyer2 = mk(&api, "buyer2");
                buy(&mut deps, &env, &buyer2, 1, Some(vec![7, 8, 9, 10, 11, 12]), None).unwrap();
            }

            let mut env2 = env.clone();
            advance(&mut env2, DRAW_INTERVAL + 1);
            execute(
                deps.as_mut(),
                env2.clone(),
                message_info(&submitter, &[]),
                ExecuteMsg::CloseRound {},
            )
            .unwrap();

            let value = HexBinary::from(vec![0x5Au8; 32]);
            let commitment = HexBinary::from(sha256(value.as_slice()));
            execute(
                deps.as_mut(),
                env2.clone(),
                message_info(&submitter, &[]),
                ExecuteMsg::CommitRandomness {
                    round_id: 1,
                    commitment,
                },
            )
            .unwrap();

            // Reveal at a fixed later block so time/height are equal across runs;
            // only ticket_entropy differs.
            let mut env3 = env2.clone();
            env3.block.height += 1;
            execute(
                deps.as_mut(),
                env3,
                message_info(&submitter, &[]),
                ExecuteMsg::RevealRandomness {
                    round_id: 1,
                    value,
                },
            )
            .unwrap();
            round(&deps, 1).randomness.unwrap().randomness.unwrap()
        }

        let a = run(false);
        let b = run(true);
        assert_ne!(a, b, "ticket entropy must change the consumed seed");
    }

    #[test]
    fn set_config_rejects_mock_and_dev_in_production_build() {
        // In the shipped wasm (no `dev-randomness` feature) SetConfig cannot
        // switch into Mock randomness or Dev verify (MEDIUM #16). This test runs
        // under the default feature set, matching the deployable artifact.
        // (Skipped when the crate is compiled WITH the dev-randomness feature.)
        if cfg!(feature = "dev-randomness") {
            return;
        }
        // Use a Drand/Bls contract so we're not already in Mock/Dev, and there's
        // no in-flight economics guard collision for these specific fields.
        let mut deps = mock_dependencies();
        let api = deps.api;
        let admin = mk(&api, "admin");
        instantiate(
            deps.as_mut(),
            mock_env(),
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
                randomness_mode: Some(RandomnessMode::Drand),
                verify_mode: Some(VerifyMode::Bls),
                drand_pubkey: Some(HexBinary::from(vec![1u8; G2_LEN])),
                drand_chain_hash: Some("abcd".to_string()),
                drand_genesis_time: None,
                drand_period: None,
                authorized_submitters: vec![],
                min_claim_usaf: None,
                reveal_timeout: None,
                open_code_registration: None,
                max_dry_rounds: None,
            },
        )
        .unwrap();

        // Switch to Mock rejected.
        let mut msg = set_config_none();
        if let ExecuteMsg::SetConfig { randomness_mode, .. } = &mut msg {
            *randomness_mode = Some(RandomnessMode::Mock);
        }
        let err = execute(deps.as_mut(), mock_env(), message_info(&admin, &[]), msg)
            .unwrap_err();
        assert!(matches!(err, ContractError::InvalidConfig { .. }));

        // Switch to Dev verify rejected.
        let mut msg = set_config_none();
        if let ExecuteMsg::SetConfig { verify_mode, .. } = &mut msg {
            *verify_mode = Some(VerifyMode::Dev);
        }
        let err = execute(deps.as_mut(), mock_env(), message_info(&admin, &[]), msg)
            .unwrap_err();
        assert!(matches!(err, ContractError::InvalidConfig { .. }));
    }

    // --- Dust disposal (LOW #25) --------------------------------------------

    #[test]
    fn draw_jackpot_win_rolls_dust_to_next_round() {
        // On a jackpot win, tier allocations for empty tiers + rounding dust used
        // to strand in the settled round. They must now roll to the next round so
        // nothing leaks. (rollover enabled: setup() default.)
        let (mut deps, api, env, _admin, submitter) = setup();
        let buyer = mk(&api, "buyer");
        let randomness = HexBinary::from(vec![7u8; 32]);
        let winning = derive_winning_numbers(randomness.as_slice(), 6, 45);
        // Single jackpot ticket: tiers 3/4/5 have no winners, so ~40% of the pool
        // is unassigned leftover that must roll forward.
        buy(&mut deps, &env, &buyer, 1, Some(winning.clone()), None).unwrap();

        let pool_before = current(&deps).pool;
        run_draw(&mut deps, &env, &submitter, randomness);

        let r1 = round(&deps, 1);
        let r2 = round(&deps, 2);
        // Round 1 retains only the jackpot payout (distributed).
        assert_eq!(r1.pool, r1.prize_tiers.tier_6);
        // The remainder rolled into round 2; nothing stranded.
        assert_eq!(r1.pool + r2.pool, pool_before);
        assert!(r2.pool > Uint128::zero());
        assert_eq!(r2.rolled_over_from, Some(1));
    }

    #[test]
    fn draw_no_rollover_sweeps_dust_to_treasury() {
        // With rollover disabled, unassigned leftover is swept to the treasury
        // (not stranded, not rolled) so every usaf stays accounted (LOW #25).
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
                drand_genesis_time: None,
                drand_period: None,
                authorized_submitters: vec![submitter.to_string()],
                min_claim_usaf: None,
                reveal_timeout: None,
                open_code_registration: None,
                max_dry_rounds: None,
            },
        )
        .unwrap();
        let buyer = mk(&api, "buyer");
        buy(&mut deps, &env, &buyer, 1, Some(vec![1, 2, 3, 4, 5, 6]), None).unwrap();

        let treasury_before: TreasuryBalanceResponse =
            from_json(query(deps.as_ref(), mock_env(), QueryMsg::TreasuryBalance {}).unwrap())
                .unwrap();
        let pool_before = current(&deps).pool;

        run_draw(&mut deps, &env, &submitter, HexBinary::from(vec![0x22u8; 32]));

        let r1 = round(&deps, 1);
        let r2 = round(&deps, 2);
        // Nothing rolled forward.
        assert_eq!(r2.rolled_over_from, None);
        assert_eq!(r2.pool, Uint128::zero());
        // The leftover (pool minus any assigned lower-tier prizes) went to treasury.
        let treasury_after: TreasuryBalanceResponse =
            from_json(query(deps.as_ref(), mock_env(), QueryMsg::TreasuryBalance {}).unwrap())
                .unwrap();
        let swept = treasury_after.balance - treasury_before.balance;
        assert_eq!(r1.pool + swept, pool_before, "every usaf accounted");
    }
}
