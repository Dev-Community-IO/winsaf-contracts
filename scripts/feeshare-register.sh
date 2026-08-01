#!/usr/bin/env bash
# ============================================================================
# WinSaf — register the `winsaf` contract with Safrochain's x/feeshare module so
# a share of every execution's gas fee (developer_shares, 50% on testnet) is paid
# to the admin/withdrawer. This is pure upside for the admin: no extra SAF from
# the admin is required, and it does not touch the contract's funds or logic.
#
#   ./scripts/feeshare-register.sh [testnet|localnet] [key_name] [keyring_backend]
#
# Defaults: network=testnet, key=mywallet, keyring=os.
#
# The deployer (sender) MUST be the contract creator or admin. The withdrawer
# defaults to the sender; override with WITHDRAWER=addr_safro1...
#
# Verify the module first:  safrochaind q feeshare params --node <rpc>
# SAFETY: mainnet is refused unless WINSAF_ALLOW_MAINNET=iunderstand is set.
# ============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
say(){ echo -e "${BLUE}▸${NC} $*"; }; ok(){ echo -e "${GREEN}✓${NC} $*"; }
die(){ echo -e "${RED}✗ $*${NC}" >&2; exit 1; }

NETWORK="${1:-testnet}"
KEY_NAME="${2:-mywallet}"
KEYRING_BACKEND="${3:-${KEYRING_BACKEND:-os}}"

if [[ "$NETWORK" == "mainnet" ]]; then
  [[ "${WINSAF_ALLOW_MAINNET:-}" == "iunderstand" ]] || \
    die "Refusing to act on MAINNET. Override: WINSAF_ALLOW_MAINNET=iunderstand"
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CW_ROOT="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$CW_ROOT/../.." && pwd)"
CHAIN_JSON="$REPO_ROOT/config/chains/$NETWORK.json"

command -v safrochaind >/dev/null || die "safrochaind not found"
command -v jq >/dev/null || die "jq not found"
[[ -f "$CHAIN_JSON" ]] || die "chain config not found: $CHAIN_JSON"

CHAIN_ID="$(jq -r '.chainId' "$CHAIN_JSON")"
RPC="${CHAIN_RPC_URL:-$(jq -r '.endpoints.rpc' "$CHAIN_JSON")}"
CONTRACT="$(jq -r '.contracts.winsaf' "$CHAIN_JSON")"
[[ "$CONTRACT" =~ ^addr_safro ]] || die "no winsaf contract address in $CHAIN_JSON"
GAS_PRICES="${CHAIN_GAS_PRICE:-$(jq -r '.gas.price // "0.025usaf"' "$CHAIN_JSON")}"
KOPTS="--keyring-backend $KEYRING_BACKEND"
TXFLAGS="--chain-id $CHAIN_ID --node $RPC --gas auto --gas-adjustment 1.5 --gas-prices $GAS_PRICES --broadcast-mode sync -y --output json"

SENDER="$(safrochaind keys show "$KEY_NAME" -a $KOPTS 2>/dev/null)" || die "key '$KEY_NAME' not in keyring '$KEYRING_BACKEND'"
WITHDRAWER="${WITHDRAWER:-$SENDER}"

say "Network:    $NETWORK ($CHAIN_ID)"
say "Contract:   $CONTRACT"
say "Deployer:   $SENDER"
say "Withdrawer: $WITHDRAWER"

# Show the module params (enable flag + developer share) so the operator sees the split.
PARAMS="$(safrochaind query feeshare params --node "$RPC" --output json 2>/dev/null || echo '{}')"
say "feeshare params: $(echo "$PARAMS" | jq -c '.params // .')"
# Some chains omit enable_fee_share and only expose developer_shares when the
# module is live (mainnet). Treat an explicit false as disabled; otherwise allow.
ENABLE="$(echo "$PARAMS" | jq -r '.params.enable_fee_share // empty')"
if [[ "$ENABLE" == "false" ]]; then
  die "feeshare is disabled on-chain (governance must enable it)"
fi
[[ -n "$(echo "$PARAMS" | jq -r '.params.developer_shares // empty')" ]] || \
  die "feeshare params missing developer_shares — module may be unavailable"
# Keep stderr (the CLI's "gas estimate: N" line) OUT of the JSON we parse.
ERRF="$(mktemp)"
if safrochaind query feeshare contract "$CONTRACT" --node "$RPC" --output json >/dev/null 2>&1; then
  ok "already registered — updating withdrawer to $WITHDRAWER"
  RES="$(safrochaind tx feeshare update "$CONTRACT" "$WITHDRAWER" --from "$KEY_NAME" $KOPTS $TXFLAGS 2>"$ERRF")" || die "update failed:\n$(cat "$ERRF")"
else
  say "── registering contract for feeshare ──"
  RES="$(safrochaind tx feeshare register "$CONTRACT" "$SENDER" "$WITHDRAWER" --from "$KEY_NAME" $KOPTS $TXFLAGS 2>"$ERRF")" || die "register failed:\n$(cat "$ERRF")"
fi
RC="$(echo "$RES" | jq -r '.code // empty' 2>/dev/null || echo '?')"
[[ "$RC" == "0" ]] || die "tx rejected (CheckTx code ${RC:-?}): $(echo "$RES" | jq -r '.raw_log // .' 2>/dev/null || echo "$RES")"
HASH="$(echo "$RES" | jq -r '.txhash // empty')"
ok "feeshare tx broadcast: $HASH"
echo -e "   verify: safrochaind query feeshare contract $CONTRACT --node $RPC --output json"
