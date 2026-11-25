# chain-tlog

A transparency log with two independent backends: a NEAR smart contract and a Celestia
namespace. Each one is a complete log on its own, covering publication, revocation and the
publisher registry. A log user picks one or both as authoritative, and verifiers check them
with light clients instead of trusting a log operator.

Read [docs/design/0001-independent-backends.md](docs/design/0001-independent-backends.md)
first.

## Layout

| Path | What |
|---|---|
| `crates/tlog-core` | Record format, ids, validation rules shared by both backends, in-memory log fold, verdict policy for one or both backends |
| `contracts/tlog-near` | NEAR contract: `submit(record)`, entry and payload views, NEP-297 events |
| `crates/tlog-celestia` | Namespace follower and sync loop; `lumina` feature: verified source on a Lumina light node; `rpc` feature: publisher over celestia-node RPC |
| `crates/tlog-e2e` | End-to-end tests on a NEAR sandbox and a local Celestia devnet, for NEAR-only, Celestia-only and both-chains users |
| `ci/celestia-devnet` | Docker Compose devnet: one celestia-app validator, one celestia-node bridge |

## Build and test

```sh
cargo test --workspace
cargo check -p tlog-celestia --features rpc,lumina

# Contract wasm (use cargo-near for deployable, reproducible builds)
rustup target add wasm32-unknown-unknown
cargo build -p tlog-near --target wasm32-unknown-unknown --release

# End-to-end, against a NEAR sandbox and a local Celestia devnet
docker compose -f ci/celestia-devnet/docker-compose.yml up -d --wait
cargo test -p tlog-e2e -- --ignored --test-threads=1
```

See [crates/tlog-e2e/README.md](crates/tlog-e2e/README.md) for what the end-to-end tests
cover and how to plug new verifiers into them.

## Status

Early scaffold. The NEAR light-client verifier and the CLIs are not written yet. See the design note's "Not done yet" section.
