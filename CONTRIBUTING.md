# Contributing to WinSaf Contracts

Thank you for improving the open-source WinSaf CosmWasm contract. This repo is **contracts only** — for Mini App / backend work, see the private `winsaf` monorepo.

## Before you start

Read [SECURITY.md](./SECURITY.md) and the invariants in `contracts/winsaf/src/lib.rs`.

**Non-negotiable:**

- CosmWasm / Rust only — **no Solidity, no EVM**
- Amounts are integer **`usaf`** (`Uint128`) — never floats
- Fund split must sum to **10_000 bps**
- Randomness must not use block hash or block time
- Never commit keys, mnemonics, or `.env` files

## Development setup

```bash
rustup target add wasm32-unknown-unknown
cargo test --all
```

Optional: `brew install binaryen` for `./scripts/optimize.sh`.

## Pull request workflow

1. Fork → branch from `main` (or `develop` if we use git-flow)
2. Make focused changes with tests
3. Run locally:
   ```bash
   cargo fmt --all
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test --all
   ```
4. If you changed `msg.rs`, run `./scripts/schema.sh` and commit schemas
5. Open a PR using the template — CI must pass

## Commit messages

Use clear, imperative subjects:

- `fix: reject buy when paused`
- `feat: add min_claim_usaf to SetConfig`
- `docs: update testnet deployment address`

## Governance for on-chain changes

Contract logic changes require:

1. Merged PR in this repo
2. Tagged release with reproducible wasm artifact
3. Admin multisig `migrate` on each deployed network

Config-only changes may use `SetConfig` without migration.

## Code of conduct

See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).

## License

By contributing, you agree your contributions are licensed under the Apache-2.0 license in [LICENSE](./LICENSE).
