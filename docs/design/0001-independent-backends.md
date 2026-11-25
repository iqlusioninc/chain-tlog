# 0001: Two independent backends, one log

Status: proposed. Changes the threat model and the proof format.

## Decision

A log is one logical object, identified by `log_id = H("chain-tlog/v1/log-id", borsh(LogConfig))`
where `LogConfig = { name, admin_key }`. It can be hosted on:

- **NEAR**: a contract (`contracts/tlog-near`) that stores entries and their status.
- **Celestia**: a namespace (`crates/tlog-celestia`), where the log is the fold of the namespace's blobs.

Each backend is a complete log on its own, covering publication, revocation and the publisher
registry. A log user picks NEAR, Celestia or both as authoritative. This replaces the earlier
split, where NEAR held state and Celestia held bodies.

## One record format, one rule set

Publishers sign a `Statement` (`Publish`, `Revoke` or `Registry`) once. The encoded `Record`
(`"TLG1" || borsh(Record)`) is byte-identical on both backends: it is the argument to the
contract's `submit` and the data of the Celestia blob. Both backends validate with the same
function, `tlog_core::rules::check`, so the same records in the same order give the same state.

- Authority comes from Ed25519 signatures inside the record, not from the NEAR caller or the
  Celestia blob signer. Anyone can relay.
- `entry_id = H("chain-tlog/v1/entry-id", borsh(Publish))`. It does not depend on the backend
  or the signature, so a verifier can line up the two backends without a mapping.
- The admin key signs registry updates. Updates carry a sequence number so an old
  `AddPublisher` cannot be replayed after a `RemovePublisher`.
- A publisher may revoke its own entries while still registered. The admin may revoke any
  entry. Removing a publisher does not revoke its entries.
- Both backends use ed25519-dalek's non-strict `verify`, because that is what NEAR's
  `ed25519_verify` host function runs. Different verification rules would let one record be
  valid on one chain only. The admin must not register small-order keys.

## How verifiers check each backend

**NEAR.** An entry lives at trie key `b"e" ++ entry_id`, with status in the same value. A
state proof of that key against a light-client-verified block proves inclusion and current
status in one step. A proof that the key is absent proves non-inclusion.

**Celestia.** The verifier runs a light node (Lumina) and folds the namespace height by
height, starting at the log's start height. For each height it fetches all of the namespace's
blobs with NMT proofs against the verified header. An empty namespace is proven empty, which
is what rules out a hidden revocation. Blobs that fail to decode or validate are skipped,
since anyone can post to a namespace. With sampling required, a height is used only after
data availability sampling has succeeded for it.

On both chains, chain consensus gives a single history. We do not use CT-style gossip or
consistency proofs.

## When both are authoritative

`tlog_core::policy::evaluate` combines the two results conjunctively and fails closed:

| NEAR | Celestia | Verdict |
|---|---|---|
| revoked (even if stale) | anything | **Revoked** |
| anything | revoked (even if stale) | **Revoked** |
| unavailable or stale | not revoked | **Unverifiable** |
| not revoked | unavailable or stale | **Unverifiable** |
| active | active | **Valid** |
| absent | absent | **NotFound** |
| active on one | absent on the other | **AwaitingMirror** within `mirror_grace`, then **SplitPublication** |

A stale head is one older than `max_head_age`. That limit is how long a revocation can go
unseen.

What this buys: forging an entry or hiding a revocation needs both chains, or both light
clients, to be compromised. Equivocation (different statements on each chain) can only make
entries invalid, never valid. The cost is liveness. Both chains must be reachable, and an
entry is only valid once both have it. Monitors should alert on `SplitPublication` and on a
revocation that appears on only one chain.

## Threat model changes

- Each backend's root of trust is its chain's consensus plus the log admin key. On NEAR,
  whoever can redeploy the contract can rewrite the log, so it must be deployed to an
  account with no full-access keys.
- On Celestia, anyone can post junk into the namespace. That costs followers bandwidth but
  cannot change the log.
- An online Celestia verifier pays one namespace query per block, including empty blocks.
  A cold start replays from the log's start height. Celestia nodes prune after the sampling
  window, so an old log needs an archival source for replay. Its data is still checked against
  verified headers, but blocks outside the sampling window can't be checked by sampling.

## Flagged: payload size on NEAR

The project assumes payloads are too large to store on NEAR. That assumption came from the
old split design, and it conflicts with a NEAR-only log:

- On Celestia the payload rides inline in the publish blob, so data availability comes with
  the log. The limit is the maximum blob size Celestia governance allows.
- On NEAR the contract stores an inline payload only up to `max_inline_payload`, which is set
  at deployment, and charges storage staking for it. Larger payloads get only a `content_hash`
  on NEAR. A NEAR-only log then gives no data availability for them.

Options: (a) keep payloads small enough to inline on NEAR, (b) accept that NEAR-only logs
prove integrity but not availability for large payloads, or (c) choose Celestia or both for
logs with large payloads. This needs a decision.

## Not done yet

- **NEAR light-client verifier.** This needs header sync and verification plus trie-proof
  checks for `b"e" ++ entry_id`. It is the largest open piece and the main implementation
  risk.
- Publisher and verifier CLIs, and a monitor that alerts on split publications.
- An integration test against a NEAR sandbox and a local Celestia devnet.
