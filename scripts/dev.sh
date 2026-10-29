#!/usr/bin/env bash
# Runs ThresholdVault locally: vaultd (REST API + relay) and three signerd
# nodes, each with its own data directory. Logs from all four are shown
# here, prefixed by process name. Press Ctrl+C to stop everything.
#
#   scripts/dev.sh            start (keeps wallets from earlier runs)
#   scripts/dev.sh --reset    wipe local dev data first
#
#   SEPOLIA_RPC_URL=https://...  scripts/dev.sh   enable Sepolia balances/transactions
#
# DEVELOPMENT ONLY: fixed tokens and passphrases. Signers run the real
# policies: the user signer signs only what was reviewed and confirmed on
# its approval API; server and backup require the user's approval token.
set -euo pipefail

cd "$(dirname "$0")/.."

DATA=${DATA:-./data/dev}
API_PORT=${API_PORT:-8080}
API_TOKEN=${API_TOKEN:-dev-api-token}
SIGNER_TOKEN=${SIGNER_TOKEN:-dev-signer-token}
APPROVAL_PORT=${APPROVAL_PORT:-7101}
APPROVAL_TOKEN=${APPROVAL_TOKEN:-dev-approval-token}
SEPOLIA_RPC_URL=${SEPOLIA_RPC_URL:-}
BSC_TESTNET_RPC_URL=${BSC_TESTNET_RPC_URL:-}

if [[ "${1:-}" == "--reset" ]]; then
  echo "Removing $DATA"
  rm -rf "$DATA"
fi
mkdir -p "$DATA"

if ! command -v go >/dev/null; then
  echo "error: 'go' not found on PATH. Install Go (https://go.dev/dl/) or open a new terminal." >&2
  exit 1
fi

echo "Building binaries into ./bin ..."
CGO_ENABLED=0 go build -o bin/ ./cmd/...

# Stop every process started by this script on exit or Ctrl+C.
trap 'trap - INT TERM EXIT; echo; echo "Stopping..."; kill 0 2>/dev/null; wait 2>/dev/null' INT TERM EXIT

prefix() { while IFS= read -r line; do printf '%-8s %s\n' "[$1]" "$line"; done; }

./bin/vaultd \
  --listen "127.0.0.1:$API_PORT" \
  --db "$DATA/vault.db" \
  --api-token "$API_TOKEN" \
  --signer-token "$SIGNER_TOKEN" \
  --signer-user http://127.0.0.1:7001 \
  --signer-server http://127.0.0.1:7002 \
  --signer-backup http://127.0.0.1:7003 \
  --sepolia-rpc "$SEPOLIA_RPC_URL" \
  --bsc-rpc "$BSC_TESTNET_RPC_URL" \
  2>&1 | prefix vaultd &

port=7001
for name in user server backup; do
  SIGNER_PASSPHRASE="dev-passphrase-$name" SIGNER_APPROVAL_TOKEN="$APPROVAL_TOKEN" ./bin/signerd \
    --name "$name" \
    --listen "127.0.0.1:$port" \
    --data-dir "$DATA/$name" \
    --peers-dir "$DATA/peers" \
    --relay-url "http://127.0.0.1:$API_PORT" \
    --api-token "$SIGNER_TOKEN" \
    --approval-listen "127.0.0.1:$APPROVAL_PORT" \
    2>&1 | prefix "$name" &
  port=$((port + 1))
done

sleep 1
RPC_STATUS="not set (balances/transactions disabled)"
[[ -n "$SEPOLIA_RPC_URL" ]] && RPC_STATUS="configured"
cat <<EOF

ThresholdVault is running
  REST API      http://127.0.0.1:$API_PORT      (Authorization: Bearer $API_TOKEN)
  user signer   http://127.0.0.1:7001     (Authorization: Bearer $SIGNER_TOKEN)
  server signer http://127.0.0.1:7002
  backup signer http://127.0.0.1:7003
  user approval http://127.0.0.1:$APPROVAL_PORT     (Authorization: Bearer $APPROVAL_TOKEN; user only)
  Sepolia RPC   $RPC_STATUS
  data          $DATA

Import docs/api/ThresholdVault.postman_collection.json into Postman.
Press Ctrl+C to stop.

EOF
wait
