# 0003: Hardening Celestia namespace verification

Status: proposed. Changes the proof format and the threat model of the Celestia backend.
Builds on [0001](0001-independent-backends.md).

## What changed

**We check the namespace proofs ourselves.** `tlog_celestia::proof::verify_namespace_data`
re-verifies a height's `NamespaceData` against the DAH of a light-client-verified header: one
row for every row root whose namespace range covers the log namespace, each with an NMT
presence or absence proof. Lumina checks the same proofs, but the follower's completeness
guarantee no longer depends on one light-client implementation. The same check lets an
untrusted source (an archival bridge node, a cache) serve namespace data. If the proofs check
out against a verified header, the source cannot have dropped, added or reordered a blob.

The proof a verifier relies on for "nothing changed at height h" is now stated precisely:

| DAH at h | What must be served | Meaning |
|---|---|---|
| no row range covers the namespace | zero rows | absent, by the row roots alone |
| some rows cover it, no shares in them | one absence proof per covering row | absent |
| some rows hold its shares | every covering row, all its shares, presence proofs | complete list |

Anything else is a `ProofError::Mismatch`, which is fatal for that source.

**One odd blob cannot stall the log.** Shares are split into share sequences and parsed one by
one (`items_from_shares`). A sequence that does not parse becomes a rejected position instead
of failing the whole height, as `Blob::reconstruct_all` would.

**Only share versions 0 and 1 count as records.** Version 2 (Fibre) blobs carry a commitment to
data held off the square, so they do not give the data availability a log record needs. They
are rejected with `Rejection::UnsupportedShareVersion`. Publishers must post plain blobs.

**Header times must strictly increase** across ingested heights. Staleness checks depend on it.

**Sync stalls instead of failing on transient errors.** Sources classify errors with
`SourceError::is_transient`. `sync_to_tip` stops at the first height that is not ready yet
(header not synced, sampling not done or failed, request timed out) and returns what it
ingested. The follower's head stays at the last good height, so the policy sees a stale head
and fails closed. Fatal errors (pruned header, proof mismatch) return the partial reports too.

## Lumina-specific findings

These come from reading lumina-node 1.3.0. None of them is a forgery risk. Each one could make
a verifier stall, or use a guarantee it did not have.

1. **Sampling metadata isn't proof of sampling.** Lumina writes `SamplingMetadata` before it
   samples, so `get_sampling_metadata` returning `Some` does not mean sampling succeeded. The
   only reliable signal is the `SamplingResult` event. `SamplingTracker` must subscribe before
   the node starts (`NodeBuilder::start_subscribed`), or heights sampled before it subscribed
   look unsampled.
2. **A failed sampling run isn't retried** until the node loses every peer and its sampler
   restarts. With sampling required, a verifier would stall at that height indefinitely.
   `LuminaSource` now samples such heights itself (16 random shares by default, each verified
   against the DAH by `request_sample`). If that also fails, the height is reported as
   `SamplingFailed`, which is transient. That is the correct behaviour for withheld data.
3. **In-memory stores prune immediately.** With `InMemoryStore`, Lumina's default pruning
   window is zero, so headers are pruned as soon as they are sampled, usually before the
   follower reads them. A follower that falls behind the pruning window gets `Pruned`, which is
   fatal. Set `pruning_window` to at least the longest time a verifier may be offline.
4. **Lumina only syncs headers inside its 7-day sampling window.** A cold start on an older log
   cannot get verified headers from Lumina at all. This is unchanged from 0001 and still needs
   an archival header source verified by hash chain back from a Lumina-verified header. That is
   follow-up work.

## Threat model

- A data source (light-node peer, bridge, archive) that lies about a namespace is detected
  whenever the header is verified, because of the table above. The only remaining way to hide a
  revocation is to compromise header verification itself (a validator-set supermajority, or an
  eclipsed light client during initial trust).
- Withholding is handled by DAS. A block producer that withholds the shares holding a revocation
  makes the verifier stall rather than see "no revocation". With `max_head_age` that becomes
  `Unverifiable`, not `Valid`.
- Squatters in the namespace can still cost bandwidth. They can no longer cause a stall by
  posting an unparseable sequence. Blob construction in celestia-app should prevent that
  anyway, so this guards against future share versions.

## Testing

`crates/tlog-celestia/src/verify_tests.rs` builds real extended data squares, DAHs and NMT
proofs (`testkit.rs`), with neighbouring namespaces so absence proofs are non-trivial. It
covers publish then revoke, absence proofs, a hidden revocation served three different ways, a
dropped row and a dropped share on a multi-row namespace, stall and resume, a fatal error with
partial reports, unparseable and share-version-1 blobs, and Fibre blobs.

A live run against a celestia-app + celestia-node devnet (Lumina's `ci/docker-compose.yml`) is
not in this change. The cloud container could not pull the images. See the PR for status.
