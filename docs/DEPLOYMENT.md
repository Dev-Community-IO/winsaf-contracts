# Deployment guide

Deploy the `winsaf` contract to **Safrochain**. For chain endpoints and economics, see the README.

## Prerequisites

- `safrochaind` CLI + funded deployer key (testnet: [faucet](https://faucet.testnet.safrochain.com))
- Rust + `wasm32-unknown-unknown` + `binaryen` (`wasm-opt`)
- **Admin multisig address** ready (not the deployer hot key)

## 1. Build reproducible Wasm

```bash
./scripts/optimize.sh
ls -la artifacts/
cat artifacts/checksums.txt
```

Safrochain requires bulk-memory lowering — do not upload raw `cargo build` output without running this script.

## 2. Store code

```bash
safrochaind tx wasm store artifacts/winsaf.wasm \
  --from <deployer-key> \
  --chain-id safro-testnet-1 \
  --node https://rpc.testnet.safrochain.com \
  --gas auto --gas-adjustment 1.5 --gas-prices 0.025usaf \
  -y -b sync
```

Note the returned **`code_id`**.

## 3. Instantiate

```bash
safrochaind tx wasm instantiate <CODE_ID> \
  '{"admin":"<MULTISIG>","randomness_mode":"commit_reveal","verify_mode":"bls","authorized_submitters":["<KEEPER_ADDR>"]}' \
  --label "winsaf-v0.1.0" \
  --admin <MULTISIG> \
  --from <deployer-key> \
  --chain-id safro-testnet-1 \
  --node https://rpc.testnet.safrochain.com \
  --gas auto --gas-adjustment 1.5 --gas-prices 0.025usaf \
  -y -b sync
```

Or use the helper (testnet/localnet only):

```bash
./scripts/deploy.sh testnet mywallet os
```

## 4. Verify checksum

```bash
safrochaind q wasm code-info <CODE_ID> --node https://rpc.testnet.safrochain.com
# Compare hash with artifacts/checksums.txt
```

## 5. Record deployment

Update [`deployment-testnet.json`](../deployment-testnet.json) in this repo and tag a release.

## Upgrade (migrate)

Only the **CosmWasm contract admin** can upgrade:

```bash
# 1. Store new wasm → new CODE_ID
# 2. Migrate existing instance
safrochaind tx wasm migrate <CONTRACT_ADDR> <NEW_CODE_ID> '{}' \
  --from <admin-multisig> \
  --chain-id safro-testnet-1 \
  --node https://rpc.testnet.safrochain.com \
  --gas auto --gas-adjustment 1.5 --gas-prices 0.025usaf \
  -y -b sync
```

Always verify the new artifact checksum before migrating. Prefer timelock + multisig for production.

## Mainnet

`deploy.sh` **blocks mainnet** unless `WINSAF_ALLOW_MAINNET=iunderstand` is set. Complete audit + governance checklist before mainnet.
