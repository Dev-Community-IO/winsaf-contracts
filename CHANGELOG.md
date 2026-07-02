# Changelog

All notable changes to the **winsaf** CosmWasm contract are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Open-source repository bootstrap (CI, issue templates, docs)
- Consolidated single-contract architecture (lottery + treasury + referral + randomness)

## [0.1.0] - 2026-07-02

### Added

- Initial public release of the `winsaf` contract
- Fund split: 7500 / 1000 / 1500 bps (prize / referral / treasury)
- Randomness modes: drand (BLS verify), commit-reveal, mock (dev)
- Permissionless `CloseRound` and `Draw`
- Pull-based `ClaimReward` and `ClaimReferral`
- Admin: `Pause`, `SetConfig`, `WithdrawTreasury`, `migrate`
- Testnet deployment on `safro-testnet-1` (code ID 142)

[Unreleased]: https://github.com/Dev-Community-IO/winsaf-contracts/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Dev-Community-IO/winsaf-contracts/releases/tag/v0.1.0
