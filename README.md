<p align="center">
  <strong>WinSaf Contracts</strong><br/>
  Provably-fair on-chain lottery for Safrochain — CosmWasm, Apache-2.0
</p>

<p align="center">
  <a href="https://github.com/Dev-Community-IO/winsaf-contracts/actions/workflows/ci.yml"><img src="https://github.com/Dev-Community-IO/winsaf-contracts/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License" /></a>
  <img src="https://img.shields.io/badge/chain-Safrochain-3FB6FF" alt="Safrochain" />
  <img src="https://img.shields.io/badge/CosmWasm-2.2-35D8A0" alt="CosmWasm" />
</p>

---

**WinSaf** is a non-custodial Telegram lottery on [Safrochain](https://safrochain.com). This repository contains the **open-source CosmWasm smart contract** — lottery, treasury, referral, and verifiable randomness in **one consolidated contract**.

The product stack (Mini App, API, MPC wallet, bot) lives in the private [`winsaf`](https://github.com/Dev-Community-IO/winsaf) monorepo.

## Live deployment (testnet)

| Field | Value |
|-------|-------|
| Network | `safro-testnet-1` |
| Contract | [`addr_safro14c70k3s6uqnywq3jfrhcrdvl3cq4atse0cvwjxm65hy0khesnunq534cka`](https://explorer.testnet.safrochain.com/account/addr_safro14c70k3s6uqnywq3jfrhcrdvl3cq4atse0cvwjxm65hy0khesnunq534cka) |
| Code ID | `142` |
| Ticket price | 5 SAF (`5_000_000 usaf`) |
| Fund split | 75% prize · 10% referral · 15% treasury |

See [`deployment-testnet.json`](./deployment-testnet.json) for the canonical record in this repo.

## Why one contract?

Everything runs in a **single Wasm instance** — no inter-contract calls:

- **Lottery** — rounds, ticket sales, draws, pull-based prize claims
- **Treasury** — 15% ops cut accrues on-chain; admin withdraws via `WithdrawTreasury`
- **Referral** — immutable referrer binding + pull claims
- **Randomness** — drand BLS, commit-reveal, or mock (dev only); **never** block hash/time

## Quick start

```bash
git clone git@github.com:Dev-Community-IO/winsaf-contracts.git
cd winsaf-contracts
rustup target add wasm32-unknown-unknown

cargo test --all          # 88+ unit tests
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

Build optimized Wasm for Safrochain (requires [binaryen](https://github.com/WebAssembly/binaryen)):

```bash
./scripts/optimize.sh
# → artifacts/winsaf.wasm + artifacts/checksums.txt
```

Regenerate JSON schemas for integrators:

```bash
./scripts/schema.sh
```

## Repository layout

```
├── contracts/winsaf/       # Main CosmWasm contract (instantiate / execute / query / migrate)
├── packages/winsaf-shared/ # Shared types: FundSplitBps, RoundStatus, money helpers
├── scripts/
│   ├── optimize.sh         # Safrochain-compatible wasm build (bulk-memory lowering)
│   ├── schema.sh           # JSON schema generation
│   └── deploy.sh           # Testnet deploy helper (mainnet blocked by default)
├── deployment-testnet.json # Deployed address + code_id
└── .github/                # CI, issue templates, Dependabot
```

## Economics (on-chain defaults)

| Bucket | Bps | % |
|--------|-----|---|
| Prize pool | 7500 | 75% |
| Referral | 1000 | 10% |
| Treasury | 1500 | 15% |

Admin can update via `SetConfig` (must still sum to 10_000 bps). **On-chain config is the source of truth.**

## Security model

| Role | Powers |
|------|--------|
| **Players** | Buy tickets, claim own prizes |
| **Keeper / submitters** | Permissionless close/draw; authorized randomness delivery |
| **Admin** | Pause, config, treasury withdraw, wasm **migrate** (CosmWasm admin) |

- Funds are **integer `usaf`** only — overflow checks enabled in release builds
- Randomness is **cryptographically verified** before draws (drand BLS or commit-reveal)
- Upgrade path: `wasm migrate` to a **verified** `code_id` only — see [SECURITY.md](./SECURITY.md)

**Report vulnerabilities privately:** [Security advisories](https://github.com/Dev-Community-IO/winsaf-contracts/security/advisories/new)

## Chain facts

| | |
|-|-|
| VM | CosmWasm only (no EVM) |
| Runtime | wasmd 0.54.1 / wasmvm 2.2.4 |
| Chain ID (testnet) | `safro-testnet-1` |
| Address prefix | `addr_safro` |
| Denom | `usaf` (6 decimals) · display `SAF` |

## Documentation

| Doc | Purpose |
|-----|---------|
| [CONTRIBUTING.md](./CONTRIBUTING.md) | How to contribute, PR requirements |
| [SECURITY.md](./SECURITY.md) | Threat model, upgrade policy, reporting |
| [CHANGELOG.md](./CHANGELOG.md) | Release history |
| [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md) | Store, instantiate, migrate, verify checksums |
| [SETUP_GITHUB.md](./SETUP_GITHUB.md) | GitHub org credentials & branch protection |

## License

Apache-2.0 — see [LICENSE](./LICENSE).

## Links

- Product: [winsaf.xyz](https://winsaf.xyz)
- Safrochain explorer: [testnet](https://explorer.testnet.safrochain.com)
- Faucet: [faucet.testnet.safrochain.com](https://faucet.testnet.safrochain.com)
