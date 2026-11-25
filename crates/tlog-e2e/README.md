# tlog-e2e

End-to-end tests for chain-tlog. They publish and revoke entries on a NEAR
sandbox and a local Celestia devnet, then verify them the way each kind of
log user would: NEAR only, Celestia only, or both.

| Test file | Needs | Covers |
|---|---|---|
| `tests/near.rs` | NEAR sandbox (downloaded by `near-workspaces`) | lifecycle, refused records |
| `tests/celestia.rs` | Celestia devnet + Lumina | lifecycle, squatter and invalid blobs skipped |
| `tests/both.rs` | both | mirrored publish/revoke, publish on one chain only (`AwaitingMirror` then `SplitPublication`), revocation on one chain only |

All chain tests are `#[ignore]`d so `cargo test --workspace` stays offline.

## Running locally

```sh
# Celestia: one validator and one bridge node (stock images, no build)
docker compose -f ci/celestia-devnet/docker-compose.yml up -d --wait

# Everything (the NEAR contract wasm is built on first use)
rustup target add wasm32-unknown-unknown
cargo test -p tlog-e2e -- --ignored --test-threads=1

docker compose -f ci/celestia-devnet/docker-compose.yml down -v
```

Run Celestia tests one at a time: they all submit from the bridge's single
funded key.

| Variable | Default | Use |
|---|---|---|
| `TLOG_NEAR_WASM` | built with `cargo build --target wasm32-unknown-unknown --release` | prebuilt contract wasm |
| `TLOG_CELESTIA_RPC` | `http://127.0.0.1:26658` | bridge node JSON-RPC |

The NEAR sandbox raises its open-file limit to 65535 and fails to start
where the hard limit is lower (some containers). GitHub's runners are fine.

## What each verifier trusts

- **Celestia**: observations come from an embedded Lumina light node.
  Headers, namespace completeness (NMT proofs) and data availability
  sampling are checked by Lumina; only heights the node has sampled are
  used. The bridge's RPC is used to submit blobs and to find its p2p
  address, not to read the log.
- **NEAR**: observations are view calls against the sandbox's RPC, which
  trusts that node. This is a placeholder until the NEAR light-client
  verifier exists.

## Plugging in new work

Every test goes through the `LogBackend` trait (`submit` a `Record`,
`observe` an entry), and `scenarios::single_backend_lifecycle` runs against
any implementation.

- **NEAR light client**: implement `observe` with a state proof of
  `tlog_near::entry_storage_key` checked against a verified header, either
  in `NearLog::observe` or as a wrapper type around `NearLog`, and the
  NEAR-only and both-chains tests exercise it unchanged.
- **New record shapes** (for example large NEAR payloads): build them with
  `Fixture`, submit with `LogBackend::submit` or call the contract directly
  through `NearLog::contract`.
- **Celestia hardening**: `CelestiaLog` keeps every `HeightReport` the
  follower produced (`reports`, `rejections()`), so tests can assert on
  what was skipped and why.
