#!/bin/bash
# Single Celestia validator for the chain-tlog e2e devnet.
#
# Adapted from eigerco/lumina ci/run-validator.sh (tag lumina-node-v1.3.0),
# Apache-2.0. Trimmed to one network, no Fibre, and no dasel so it runs on
# the stock celestia-app image without a docker build.

set -euxo pipefail

# Number of DA nodes to fund. The devnet runs one bridge (node-0).
NODE_COUNT="${NODE_COUNT:-1}"
P2P_NETWORK="${P2P_NETWORK:-private}"
CONFIG_DIR="${CELESTIA_APP_HOME:-$HOME/.celestia-app}"
NODE_NAME="validator-0"
NODE_COINS="200000000000000utia"
VALIDATOR_COINS="1000000000000000utia"
# Shared with the DA nodes
CREDENTIALS_DIR="/credentials"
GENESIS_DIR="/genesis"
GENESIS_HASH_FILE="$GENESIS_DIR/genesis-hash-$P2P_NETWORK"

node_address() {
  local bech="${2:-acc}"
  celestia-appd keys show "$1" --bech "$bech" -a --keyring-backend test
}

wait_for_block() {
  local block_hash=""
  while [[ -z "$block_hash" ]]; do
    block_hash="$(curl -sS "http://localhost:26657/block?height=$1" 2>/dev/null | jq -r '.result.block_id.hash // ""' || echo)"
    sleep 0.1
  done
  echo "$block_hash"
}

# Create a key and export it to the shared credentials volume.
create_key() {
  local node_name="$1"
  local key_file="$CREDENTIALS_DIR/$node_name.key"
  celestia-appd keys add "$node_name" --keyring-backend test
  echo "password" | celestia-appd keys export "$node_name" --keyring-backend test > "$key_file.lock"
  echo y | celestia-appd keys export "$node_name" --unsafe --unarmored-hex --keyring-backend test \
    > "$CREDENTIALS_DIR/$node_name.plaintext-key"
  # readers wait for the final name, so they never see a partial file
  mv "$key_file.lock" "$key_file"
  node_address "$node_name" > "$CREDENTIALS_DIR/$node_name.addr"
}

setup_validator() {
  rm -f "$CREDENTIALS_DIR"/*.key "$CREDENTIALS_DIR"/*.jwt "$GENESIS_HASH_FILE" || true

  celestia-appd init "$P2P_NETWORK" --chain-id "$P2P_NETWORK"
  create_key "$NODE_NAME"
  celestia-appd genesis add-genesis-account "$(node_address "$NODE_NAME")" "$VALIDATOR_COINS"
  for ((i = 0; i < NODE_COUNT; i++)); do
    create_key "node-$i"
    celestia-appd genesis add-genesis-account "$(node_address "node-$i")" "$NODE_COINS"
  done

  celestia-appd genesis gentx "$NODE_NAME" 5000000000utia \
    --fees 500utia --keyring-backend test --chain-id "$P2P_NETWORK"
  celestia-appd genesis collect-gentxs

  local cfg="$CONFIG_DIR/config/config.toml"
  sed -i 's#^laddr = "tcp://127.0.0.1:26657"#laddr = "tcp://0.0.0.0:26657"#' "$cfg"
  sed -i 's#^indexer = .*#indexer = "kv"#' "$cfg"
  grep -q '^laddr = "tcp://0.0.0.0:26657"' "$cfg"
}

main() {
  setup_validator
  (wait_for_block 1 > "$GENESIS_HASH_FILE.lock" && mv "$GENESIS_HASH_FILE.lock" "$GENESIS_HASH_FILE") &

  echo "Configuration finished. Running a validator node..."
  exec celestia-appd start \
    --api.enable \
    --api.address tcp://0.0.0.0:1317 \
    --grpc.enable \
    --grpc.address 0.0.0.0:9090 \
    --force-no-bbr \
    --delayed-precommit-timeout 500ms
}

main
