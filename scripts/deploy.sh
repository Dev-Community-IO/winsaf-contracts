#!/usr/bin/env bash
# ============================================================================
# WinSaf — deploy the single `winsaf` CosmWasm contract to Safrochain.
#
#   ./scripts/deploy.sh [testnet|localnet] [key_name] [keyring_backend]
#
# Defaults: network=testnet, key=mywallet, keyring=os  (matches Safrimba).
#
# Stores artifacts/winsaf.wasm, instantiates it (mock/dev randomness for
# testnet, sender as authorized submitter), then writes the address + code id
# into ./deployment-<network>.json and (optionally) the main app monorepo
# config/chains/<network>.json when WINSAF_MONOREPO_ROOT is set.
#
# SAFETY: mainnet is refused unless WINSAF_ALLOW_MAINNET=iunderstand is set.
# ============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
say(){ echo -e "${BLUE}▸${NC} $*"; }; ok(){ echo -e "${GREEN}✓${NC} $*"; }
warn(){ echo -e "${YELLOW}!${NC} $*"; }; die(){ echo -e "${RED}✗ $*${NC}" >&2; exit 1; }

NETWORK="${1:-testnet}"
KEY_NAME="${2:-mywallet}"
KEYRING_BACKEND="${3:-${KEYRING_BACKEND:-os}}"

if [[ "$NETWORK" == "mainnet" ]]; then
  [[ "${WINSAF_ALLOW_MAINNET:-}" == "iunderstand" ]] || \
    die "Refusing to deploy to MAINNET (testnet-only by policy). Override: WINSAF_ALLOW_MAINNET=iunderstand"
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CW_ROOT="$(cd "$HERE/.." && pwd)"
MONOREPO_ROOT="${WINSAF_MONOREPO_ROOT:-}"
CHAIN_JSON="${WINSAF_CHAIN_JSON:-}"
if [[ -z "$CHAIN_JSON" && -n "$MONOREPO_ROOT" ]]; then
  CHAIN_JSON="$MONOREPO_ROOT/config/chains/$NETWORK.json"
fi
WASM="$CW_ROOT/artifacts/winsaf.wasm"
DEPLOY_OUT="$CW_ROOT/deployment-$NETWORK.json"

command -v safrochaind >/dev/null || die "safrochaind not found"
command -v jq >/dev/null || die "jq not found"
[[ -f "$WASM" ]] || die "optimized wasm not found: $WASM (run ./scripts/optimize.sh first)"

if [[ -n "$CHAIN_JSON" && ! -f "$CHAIN_JSON" ]]; then
  die "chain config not found: $CHAIN_JSON"
fi
if [[ -f "$CHAIN_JSON" ]]; then
  CHAIN_ID="$(jq -r '.chainId' "$CHAIN_JSON")"
  RPC="${CHAIN_RPC_URL:-$(jq -r '.endpoints.rpc' "$CHAIN_JSON")}"
else
  CHAIN_ID="${CHAIN_ID:-safro-testnet-1}"
  RPC="${CHAIN_RPC_URL:-https://rpc.testnet.safrochain.com}"
fi
DENOM="usaf"
GAS_PRICES="0.025${DENOM}"
KOPTS="--keyring-backend $KEYRING_BACKEND"
TXFLAGS="--chain-id $CHAIN_ID --node $RPC --gas auto --gas-adjustment 1.5 --gas-prices $GAS_PRICES --broadcast-mode sync -y --output json"

say "Network:  ${YELLOW}$NETWORK${NC} ($CHAIN_ID)"
say "RPC:      $RPC"
say "Key:      $KEY_NAME (keyring: $KEYRING_BACKEND)"
say "Wasm:     $WASM ($(du -h "$WASM" | cut -f1))"

SENDER="$(safrochaind keys show "$KEY_NAME" -a $KOPTS 2>/dev/null)" || die "key '$KEY_NAME' not in keyring '$KEYRING_BACKEND'"
[[ "$SENDER" =~ ^addr_safro ]] || die "resolved sender is not addr_safro: $SENDER"
ADMIN="${ADMIN_ADDRESS:-$SENDER}"
ok "Sender/admin: $SENDER"

BAL="$(safrochaind query bank balances "$SENDER" --node "$RPC" --output json 2>/dev/null | jq -r '.balances[]?|select(.denom=="'"$DENOM"'").amount' || echo 0)"
say "Balance: ${BAL:-0} $DENOM"
[[ "${BAL:-0}" -gt 2000000 ]] || die "insufficient $DENOM (need >2 SAF for gas). Fund $SENDER."

wait_tx(){ local h="$1" i out
  for i in $(seq 1 25); do
    out="$(safrochaind query tx "$h" --node "$RPC" --output json 2>/dev/null || true)"
    [[ -n "$out" && "$(echo "$out"|jq -r '.txhash // empty')" == "$h" ]] && { echo "$out"; return 0; }
    sleep 2
  done; die "tx $h not indexed after timeout"; }
attr(){ echo "$1" | jq -r --arg t "$2" --arg k "$3" '[.events[]?|select(.type==$t).attributes[]?|select(.key==$k).value][0] // empty'; }

ERRF="$(mktemp)"   # keep stderr (gas-estimate lines) OUT of the JSON we parse

# ---- store ----
say "── storing winsaf.wasm ──"
RES="$(safrochaind tx wasm store "$WASM" --from "$KEY_NAME" $KOPTS $TXFLAGS 2>"$ERRF")" || die "store failed:\n$(cat "$ERRF")"
RC="$(echo "$RES" | jq -r '.code // empty')"; [[ "$RC" == "0" ]] || die "store rejected (CheckTx code ${RC:-?}): $(echo "$RES" | jq -r '.raw_log // .')"
HASH="$(echo "$RES" | jq -r '.txhash // empty')"; [[ -n "$HASH" ]] || die "no txhash:\n$RES"
TX="$(wait_tx "$HASH")"; [[ "$(echo "$TX"|jq -r '.code')" == "0" ]] || die "store failed: $(echo "$TX"|jq -r '.raw_log')"
CODE_ID="$(attr "$TX" store_code code_id)"; [[ -n "$CODE_ID" ]] || die "no code_id"
ok "stored — code_id=$CODE_ID (tx $HASH)"

# ---- instantiate ----
# Randomness mode is REAL by default (commit-reveal) — no mock/dev on testnet.
# Override with RANDOMNESS_MODE=drand (requires DRAND_PUBKEY/DRAND_CHAIN_HASH) if a
# matching drand relayer is wired. RANDOMNESS_SUBMITTER defaults to the keeper/admin.
RMODE="${RANDOMNESS_MODE:-commit_reveal}"
VMODE="${VERIFY_MODE:-bls}"
SUBMITTER="${RANDOMNESS_SUBMITTER:-$SENDER}"
say "── instantiating winsaf (5 SAF · 6·45 · 24h · 75/10/15 · randomness=${RMODE}) ──"
INIT="$(jq -nc --arg a "$ADMIN" --arg s "$SUBMITTER" --arg m "$RMODE" --arg v "$VMODE" \
  --arg dpk "${DRAND_PUBKEY:-}" --arg dch "${DRAND_CHAIN_HASH:-}" \
  '{admin:$a, randomness_mode:$m, verify_mode:$v, authorized_submitters:[$s]}
   + (if $dpk != "" then {drand_pubkey:$dpk} else {} end)
   + (if $dch != "" then {drand_chain_hash:$dch} else {} end)')"
RES="$(safrochaind tx wasm instantiate "$CODE_ID" "$INIT" --label "winsaf" --admin "$ADMIN" --from "$KEY_NAME" $KOPTS $TXFLAGS 2>"$ERRF")" \
  || die "instantiate failed:\n$(cat "$ERRF")"
RC="$(echo "$RES" | jq -r '.code // empty')"; [[ "$RC" == "0" ]] || die "instantiate rejected (CheckTx code ${RC:-?}): $(echo "$RES" | jq -r '.raw_log // .')"
HASH="$(echo "$RES" | jq -r '.txhash // empty')"; TX="$(wait_tx "$HASH")"
[[ "$(echo "$TX"|jq -r '.code')" == "0" ]] || die "instantiate failed: $(echo "$TX"|jq -r '.raw_log')"
ADDR="$(attr "$TX" instantiate _contract_address)"; [[ -n "$ADDR" ]] || die "no _contract_address"
ok "instantiated — $ADDR (tx $HASH)"

# ---- write deployment record (+ optional monorepo chain config) ----
say "── writing $DEPLOY_OUT ──"
jq -n --arg net "$NETWORK" --arg cid "$CHAIN_ID" --arg admin "$ADMIN" --arg a "$ADDR" --argjson c "$CODE_ID" \
  '{network:$net, chainId:$cid, admin:$admin, contract:$a, codeId:$c,
    note:"Single winsaf contract with drand+BLS randomness and Must-Be-Won rolldown."}' > "$DEPLOY_OUT"

if [[ -f "$MONOREPO_ROOT/config/chains/$NETWORK.json" ]]; then
  CHAIN_JSON="$MONOREPO_ROOT/config/chains/$NETWORK.json"
  say "── updating $CHAIN_JSON ──"
  tmp="$(mktemp)"
  jq --arg a "$ADDR" --argjson c "$CODE_ID" \
    '.contracts.winsaf=$a | .contracts.lottery=$a | .contracts.treasury=$a | .contracts.referral=$a | .contracts.randomnessBeacon=$a
     | .codeIds.winsaf=$c' "$CHAIN_JSON" > "$tmp" && mv "$tmp" "$CHAIN_JSON"
  ok "updated monorepo chain config"
else
  warn "Set WINSAF_MONOREPO_ROOT to auto-update config/chains/$NETWORK.json in the winsaf app repo"
fi

EXPLORER="${WINSAF_EXPLORER_URL:-https://explorer.testnet.safrochain.com}"
if [[ -f "$CHAIN_JSON" ]]; then
  EXPLORER="$(jq -r '.endpoints.explorer // empty' "$CHAIN_JSON")"
fi

echo; ok "DEPLOYED winsaf to $CHAIN_ID"
echo -e "   contract  ${GREEN}$ADDR${NC}"
echo -e "   code_id   ${GREEN}$CODE_ID${NC}"
echo -e "   admin     $ADMIN"
echo -e "   explorer  ${EXPLORER}/account/$ADDR"
echo -e "   → written to $DEPLOY_OUT"
