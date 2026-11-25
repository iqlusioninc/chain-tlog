# chain-tlog

A transparency log with two independent backends: a NEAR smart contract and a Celestia
namespace. Each one is a complete log on its own, covering publication, revocation and the
publisher registry. A log user picks one or both as authoritative, and verifiers check them
with light clients instead of trusting a log operator.

Read [docs/spec.md](docs/spec.md) and [docs/threat-model.md](docs/threat-model.md) first.
Design decisions are in [docs/design/](docs/design/).

## Layout

| Path | What |
|---|---|
| `crates/tlog-core` | Record format, ids, validation rules shared by both backends, in-memory log fold, verdict policy for one or both backends |
| `contracts/tlog-near` | NEAR contract: `submit(record)`, entry and payload views, NEP-297 events |
| `crates/tlog-celestia` | Namespace follower and sync loop; `lumina` feature: verified source on a Lumina light node; `rpc` feature: publisher over celestia-node RPC |

## Build and test

```sh
cargo test --workspace
cargo check -p tlog-celestia --features rpc,lumina

# Contract wasm (use cargo-near for deployable, reproducible builds)
rustup target add wasm32-unknown-unknown
cargo build -p tlog-near --target wasm32-unknown-unknown --release
```

## Status

Early scaffold. The NEAR light-client verifier, the CLIs and end-to-end tests against live
networks are not written yet. See the design note's "Not done yet" section.
