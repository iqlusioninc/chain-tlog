#!/bin/bash
# Healthy once the validator has produced a few blocks.
set -euo pipefail
celestia-appd status 2>/dev/null | jq -e '(.sync_info.latest_block_height | tonumber) >= 3' >/dev/null
