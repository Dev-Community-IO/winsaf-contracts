# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| `0.1.x` (current) | Yes |
| `< 0.1.0` | No |

## Reporting a vulnerability

**Do not open public GitHub issues for exploitable bugs.**

1. Open a [private security advisory](https://github.com/Dev-Community-IO/winsaf-contracts/security/advisories/new)
2. Or email the maintainers listed in the GitHub org (if configured)

We aim to:

- Acknowledge within **72 hours**
- Provide a severity assessment within **7 days**
- Coordinate disclosure and patch release before public details

## Scope

**In scope**

- The `winsaf` CosmWasm contract and `winsaf-shared` crate in this repository
- Fund accounting, prize claims, referral ledger, randomness verification
- Admin / pause / migrate behavior

**Out of scope**

- The WinSaf Mini App, API, MPC service, or Telegram bot (private [`winsaf`](https://github.com/Dev-Community-IO/winsaf) repo)
- Social engineering, phishing, or compromised user devices
- Issues in Safrochain node / wasmvm itself (report to Safrochain)

## Threat model (summary)

### Non-custodial by design

Player funds sit in the contract’s round pools. The backend **cannot** move user wallets — only the ticket owner claims prizes.

### Admin powers (intentional)

The contract `admin` can:

- Pause new ticket sales (`Pause` / `Unpause`)
- Change economics via `SetConfig` (split must sum to 10_000 bps)
- Withdraw the **treasury** balance (`WithdrawTreasury`) — not player prize pools
- Migrate contract code (CosmWasm-level admin)

**Production requirement:** admin = **multisig + timelock**, never a single hot key.

### Randomness

Winning numbers derive only from **verified** submitted randomness:

- **Drand** — BLS12-381 pairing check on-chain (`VerifyMode::Bls`)
- **Commit-reveal** — `sha256(value) == commitment`
- **Mock** — dev/localnet only; never mainnet

Block hash and block time are **never** used as entropy.

### Upgrade policy

1. Build reproducible artifact: `./scripts/optimize.sh`
2. Compare `artifacts/checksums.txt` with on-chain code hash
3. Store new wasm → note `code_id`
4. Admin multisig executes `wasm migrate` to the verified `code_id`
5. Publish release notes + advisory if user action required

Rollback = migrate back to a previous **verified** `code_id`.

## Security checklist (operators)

- [ ] Contract `--admin` is a multisig
- [ ] Mainnet uses `RandomnessMode::Drand` + `VerifyMode::Bls` (not Mock/Dev)
- [ ] Deployer key has no ongoing admin role
- [ ] Keeper mnemonic is gas-only, low value
- [ ] GitHub branch protection enabled on `main`
- [ ] Dependabot + CI required on PRs

## Audit status

Independent audit: **pending** — track progress in release notes. Do not treat unaudited code as production-ready for mainnet with real funds.
