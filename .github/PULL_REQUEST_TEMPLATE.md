## Summary

<!-- What does this PR change and why? Link issues with "Fixes #123" when applicable. -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature / execute message
- [ ] Breaking change (migration required)
- [ ] Docs / CI only

## Checklist

- [ ] `cargo fmt --all` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --all` passes
- [ ] Schemas regenerated if `msg.rs` changed (`./scripts/schema.sh`)
- [ ] Fund-split invariant preserved (sums to 10_000 bps) if economics touched
- [ ] Randomness changes avoid block hash / block time seeding
- [ ] No secrets, keys, or mnemonics in the diff

## On-chain impact

- [ ] Requires new `code_id` + admin `migrate` on deployed instances
- [ ] Config-only (`SetConfig`) — no migration
- [ ] Not applicable (docs/tests only)

## Test evidence

<!-- Paste relevant test names or describe manual verification on localnet/testnet. -->
