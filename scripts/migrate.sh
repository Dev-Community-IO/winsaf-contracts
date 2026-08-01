#!/usr/bin/env bash
# ============================================================================
# WinSaf — in-place MIGRATE of the live `winsaf` contract to a new code id.
#
#   ./scripts/migrate.sh [testnet|localnet] [key_name] [keyring_backend]
#
# Defaults: network=testnet, key=mywallet, keyring=os.
#
# Stores the freshly-optimized artifacts/winsaf.wasm, then migrates the address
# already recorded in ../../config/chains/<network>.json (contracts.winsaf) to
# the new code id with an EMPTY MigrateMsg `{}` (pure code swap; the new
# GrantBonusTicketFromTreasury variant needs no state migration). Address, pool,
# treasury, claims and referral ledgers are preserved.
#
# The caller MUST be the contract admin (see `q wasm contract <addr>`).
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
    die "Refusing to migrate MAINNET (testnet-only by policy). Override: WINSAF_ALLOW_MAINNET=iunderstand"
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CW_ROOT="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$CW_ROOT/../.." && pwd)"
CHAIN_JSON="$REPO_ROOT/config/chains/$NETWORK.json"
WASM="$CW_ROOT/artifacts/winsaf.wasm"
DEPLOY_OUT="$CW_ROOT/deployment-$NETWORK.json"
MIGRATE_MSG="${MIGRATE_MSG:-{}}"

command -v safrochaind >/dev/null || die "safrochaind not found"
command -v jq >/dev/null || die "jq not found"
[[ -f "$CHAIN_JSON" ]] || die "chain config not found: $CHAIN_JSON"
[[ -f "$WASM" ]] || die "optimized wasm not found: $WASM (run ./scripts/optimize.sh first)"

CHAIN_ID="$(jq -r '.chainId' "$CHAIN_JSON")"
RPC="${CHAIN_RPC_URL:-$(jq -r '.endpoints.rpc' "$CHAIN_JSON")}"
CONTRACT="$(jq -r '.contracts.winsaf' "$CHAIN_JSON")"
[[ "$CONTRACT" =~ ^addr_safro ]] || die "no winsaf contract address in $CHAIN_JSON"
DENOM="usaf"
GAS_PRICES="0.025${DENOM}"
KOPTS="--keyring-backend $KEYRING_BACKEND"
TXFLAGS="--chain-id $CHAIN_ID --node $RPC --gas auto --gas-adjustment 1.5 --gas-prices $GAS_PRICES --broadcast-mode sync -y --output json"

say "Network:  ${YELLOW}$NETWORK${NC} ($CHAIN_ID)"
say "RPC:      $RPC"
say "Contract: $CONTRACT"
say "Wasm:     $WASM ($(du -h "$WASM" | cut -f1))"
say "Migrate:  $MIGRATE_MSG"

SENDER="$(safrochaind keys show "$KEY_NAME" -a $KOPTS 2>/dev/null)" || die "key '$KEY_NAME' not in keyring '$KEYRING_BACKEND'"
ok "Sender: $SENDER"

# Confirm the sender is the on-chain admin before attempting a migrate.
ADMIN_ONCHAIN="$(safrochaind query wasm contract "$CONTRACT" --node "$RPC" --output json 2>/dev/null | jq -r '.contract_info.admin // empty')"
[[ -n "$ADMIN_ONCHAIN" ]] || die "could not read contract admin"
[[ "$ADMIN_ONCHAIN" == "$SENDER" ]] || die "sender $SENDER is NOT the contract admin ($ADMIN_ONCHAIN) — cannot migrate"
ok "Sender is the contract admin"

wait_tx(){ local h="$1" i out
  for i in $(seq 1 25); do
    out="$(safrochaind query tx "$h" --node "$RPC" --output json 2>/dev/null || true)"
    [[ -n "$out" && "$(echo "$out"|jq -r '.txhash // empty')" == "$h" ]] && { echo "$out"; return 0; }
    sleep 2
  done; die "tx $h not indexed after timeout"; }
attr(){ echo "$1" | jq -r --arg t "$2" --arg k "$3" '[.events[]?|select(.type==$t).attributes[]?|select(.key==$k).value][0] // empty'; }

ERRF="$(mktemp)"

# ---- store new code ----
say "── storing new winsaf.wasm ──"
RES="$(safrochaind tx wasm store "$WASM" --from "$KEY_NAME" $KOPTS $TXFLAGS 2>"$ERRF")" || die "store failed:\n$(cat "$ERRF")"
RC="$(echo "$RES" | jq -r '.code // empty')"; [[ "$RC" == "0" ]] || die "store rejected (CheckTx code ${RC:-?}): $(echo "$RES" | jq -r '.raw_log // .')"
HASH="$(echo "$RES" | jq -r '.txhash // empty')"; [[ -n "$HASH" ]] || die "no txhash:\n$RES"
TX="$(wait_tx "$HASH")"; [[ "$(echo "$TX"|jq -r '.code')" == "0" ]] || die "store failed: $(echo "$TX"|jq -r '.raw_log')"
CODE_ID="$(attr "$TX" store_code code_id)"; [[ -n "$CODE_ID" ]] || die "no code_id"
ok "stored — code_id=$CODE_ID (tx $HASH)"

# ---- migrate ----
say "── migrating $CONTRACT → code_id=$CODE_ID ──"
RES="$(safrochaind tx wasm migrate "$CONTRACT" "$CODE_ID" "$MIGRATE_MSG" --from "$KEY_NAME" $KOPTS $TXFLAGS 2>"$ERRF")" \
  || die "migrate failed:\n$(cat "$ERRF")"
RC="$(echo "$RES" | jq -r '.code // empty')"; [[ "$RC" == "0" ]] || die "migrate rejected (CheckTx code ${RC:-?}): $(echo "$RES" | jq -r '.raw_log // .')"
HASH="$(echo "$RES" | jq -r '.txhash // empty')"; TX="$(wait_tx "$HASH")"
[[ "$(echo "$TX"|jq -r '.code')" == "0" ]] || die "migrate failed: $(echo "$TX"|jq -r '.raw_log')"
ok "migrated — $CONTRACT now runs code_id=$CODE_ID (tx $HASH)"

# ---- record the new code id ----
tmp="$(mktemp)"
jq --argjson c "$CODE_ID" '.codeIds.winsaf=$c' "$CHAIN_JSON" > "$tmp" && mv "$tmp" "$CHAIN_JSON"
jq --arg cid "$CHAIN_ID" --argjson c "$CODE_ID" \
  '.codeId=$c | .note="In-place MIGRATE to code \($c): adds GrantBonusTicketFromTreasury (treasury-funded XP redemption). Address/pool/treasury/claims preserved."' \
  "$DEPLOY_OUT" > "$tmp" && mv "$tmp" "$DEPLOY_OUT"

echo; ok "MIGRATED winsaf on $CHAIN_ID"
echo -e "   contract  ${GREEN}$CONTRACT${NC}"
echo -e "   code_id   ${GREEN}$CODE_ID${NC}"
echo -e "   explorer  $(jq -r '.endpoints.explorer' "$CHAIN_JSON")/account/$CONTRACT"
echo -e "   → code id written to $CHAIN_JSON and $DEPLOY_OUT"
