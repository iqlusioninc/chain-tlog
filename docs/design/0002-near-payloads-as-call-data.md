# 0002: Large payloads on NEAR travel as call data

Status: proposed. Changes the threat model (data availability on NEAR, payload stripping),
the record format (`Publish.payload_mode`) and the NEAR proof format (`StoredEntry.payload`).
Resolves "Flagged: payload size on NEAR" in 0001.

## Decision

On NEAR, a payload travels inside the function-call arguments of the `submit` transaction.
The contract checks it against the signed `content_hash` and `content_len`, then keeps only
the entry (hash, length, status, publication height). It stores the payload bytes in contract
state only when they fit under the deploy-time `max_inline_payload` cap.

The record bytes don't change. The arguments of the new `submit_raw` method are exactly the
encoded `Record` (`"TLG1" || borsh(Record)`), which is also the Celestia blob, with no JSON or
base64 wrapper. A payload up to one NEAR transaction can be logged this way, about 1.5 MiB.

## Options compared

Numbers are from nearcore `master` `core/parameters/res/runtime_configs/parameters.yaml`, the
NEAR docs, and nearcore's client config, as of 2026-11-25. Gas figures are estimates from
those parameters, not measurements.

| Option | Size limit | Cost for 1 MiB | Who can serve it later | What a light client proves |
|---|---|---|---|---|
| **Call data, one tx** | 1,572,864-byte tx (`max_transaction_size`, protocol 69+), so about 1.5 MiB of payload | Gas only, about 15 to 40 Tgas, so under 0.005 NEAR at the gas-price floor. Burned. | Any RPC node for about 36 h (5 epochs), then archival nodes or indexers only | State proof of the entry gives hash and status. Bytes from any source are checked against the hash. |
| Contract storage | Same tx limit per write. 4 MiB per value. | 10 NEAR locked (`storage_amount_per_byte` = 10^19 yN, so 1 NEAR per 100 KB). Refundable on delete. | Every node, forever | Direct state proof of the bytes, but see the 50 KB view limit below |
| Chunked storage | No hard limit. Many txs. | 10 NEAR per MiB locked, plus a tx per chunk | Every node, forever | State proofs per chunk, plus a commitment that binds the chunks |
| NEAR DA blob store | Same as call data. Larger blobs span several txs. | Same as call data | Same as call data: its README says the blob is "not stored in the blockchain state" and is pruned after "at least 3 NEAR epochs" | Commitment is a set of tx IDs, checked by tx outcome proofs |
| Off-chain, hash on NEAR | None | Hosting only | Whoever hosts it | Integrity only |

NEAR DA is call data under another name. It adds a second contract and a tx-ID commitment, and
it loses the atomic link between the payload and the log entry. Its reference repo has moved
to Nuffle-Labs. It offers nothing over sending the payload
to our own contract.

Global contract code is also kept by every node, but it costs 0.0001 NEAR per byte burned
(about 105 NEAR per MiB) and the payload would have to be wrapped as Wasm. Not worth it.

### Why call data wins for this project

Storage gives the best availability, but at 10 NEAR per MiB locked it fails the project
assumption that payloads are too large to keep on NEAR. Call data keeps that assumption, costs
almost nothing, and is the only option that is atomic with the log entry. Its weakness is
retention, covered below.

## How a verifier checks a payload

1. Prove the entry with a state proof of `b"e" ++ entry_id` against a light-client-verified
   block, as in 0001. The value now includes `payload: PayloadRef`.
2. If `PayloadRef::Inline`, the bytes are at `b"d" ++ entry_id` and can be proven the same way.
3. If `PayloadRef::CallData`, fetch the block at `published.height` from any source and find
   the action receipt to the log contract that created this entry. Its arguments take one of
   two shapes. `submit_raw` arguments are the encoded `Record` itself. `submit` arguments are
   JSON `{"record": "<base64 Record>"}`, used for payloads between `max_inline_payload` and
   about 1.1 MiB. Decode the `Record`, check it is for this `entry_id`, and check
   `sha256(payload) == content_hash` and `len == content_len`.
4. If `PayloadRef::Detached`, the publisher signed a hash-only publication. The payload was
   never on NEAR.

The hash check alone is enough for integrity, because the hash is in proven state. A verifier
does not need a transaction or receipt outcome proof. The source of the bytes doesn't need to
be trusted: archival RPC, an indexer, the publisher or a mirror all work.

The entry existing with `PayloadRef::CallData` also proves availability at publication time.
The contract only writes that value after reading the bytes from its own arguments. Those bytes
were in a chunk that validators had to hold to accept the block.

## Retention: what NEAR does and doesn't promise

- Regular nodes keep about 36 hours of history: `gc_num_epochs_to_keep` defaults to 5, and
  nodes can't go below 3. After that, a payload sent as call data is gone from every
  non-archival node.
- Archival nodes keep everything. They need about 3 TB hot SSD plus 115 TB cold disk, and the
  count is growing. Public archival access comes from a few providers, such as FastNear and
  neardata.xyz.
- NEAR Lake (S3) stopped indexing new blocks on 2026-03-24. It can't be relied on.

So a NEAR-only log with call-data payloads promises **integrity forever** and **availability at
publication**, but **retrievability after about 36 hours depends on someone keeping the
data**. NEAR's consensus does not guarantee it. Celestia has the same shape with a longer
window (its sampling window), which 0001 already notes.

Mitigations, in order of strength:

1. Inline storage for small payloads (`max_inline_payload`), which every node keeps forever.
2. The log operator, or the users who need the payloads, run or pay for an archival source.
3. Monitors and verifiers fetch and keep each payload within the 36-hour window. This depends
   on the "verifiers are online" assumption. An offline verifier that comes back later needs
   (2).
4. Pick Celestia or both for logs whose payloads must stay downloadable from the chain itself.

**Flag:** this does not break "payloads are too large to store on NEAR". It weakens what
"NEAR-only" means for availability, and it adds a duty to keep payloads that the project didn't
have before.

## Limits

- Payloads must fit, with the record and transaction overhead, in 1,572,864 bytes. The
  overhead is a few hundred bytes plus the subject. The chain rejects anything larger with
  `TransactionSizeExceeded`. The contract adds no cap of its own.
- The JSON `submit` method stays for small records. Base64 inside JSON cuts the usable size to
  about 1.1 MiB, so large payloads must use `submit_raw`.
- A log hosted on both chains needs each `Attached` payload to fit the smaller of the two
  limits: NEAR's transaction and Celestia's maximum blob size. A payload that fits only one
  lands on one chain and shows up as `SplitPublication`. Publishers should check this before
  signing, and pick `Detached` or a Celestia-only log for anything larger.
- `rules::check` has no size limit of its own, so `Reject::PayloadTooLarge` is gone. A size
  rule in `check` would make the two backends' rules differ. Each chain's own limit applies
  instead.
- Payloads larger than one transaction need chunked uploads. Chunked uploads need a content
  commitment that the contract can check one chunk at a time (for example a hash over
  fixed-size chunk hashes), which would change `content_hash` on both backends. Not done here.

## Payload stripping (threat T5)

Before this change, a record could carry a payload or not, and both were valid. Anyone who saw
a signed `Publish` (in a mempool, or on the other chain) could relay a copy with the payload
removed. The copy would land first and log the entry as hash-only. The real record would then
fail as `DuplicateEntry`, and the payload would never reach that backend. With call data this
matters more, because the payload is how NEAR gets data availability.

Fix: the signed `Publish` now commits to where its payload lives.

- `Publish.payload_mode: PayloadMode` is the last field, either `Attached` (0) or
  `Detached` (1).
- `Attached`: the record must carry the payload, matching `content_hash` and `content_len`.
- `Detached`: the record must not carry it. Only the hash is logged.
- `rules::check` rejects any other combination with `PayloadMismatch`, on both backends.

A stripped copy of an `Attached` publication is now invalid everywhere, so it can't front-run
the real one. A publisher that wants hash-only logging says so in the signed statement.

The field is part of `borsh(Publish)`, so it changes every `entry_id` and signature. That's
fine before v1 ships, but it's a format break for anything already signed.

## Availability when both backends are authoritative

The verdict table in 0001 covers status only. For availability under "both", a verifier
counts an `Attached` payload as available if **either** backend can serve bytes that match
`content_hash`. Integrity comes from the hash, which both chains agree on (the signed
`Publish` is byte-identical), so any copy is as good as another. Celestia's copy usually
lasts longer than NEAR's 36 hours. Requiring both copies would make the entry depend on
whichever retention runs out first, without adding any security.

A `Detached` publication is never available from either chain, under any mode.

## Proof format changes

- `Publish` gains `payload_mode`, as above. This changes the record on both chains.
- `StoredEntry` gains `payload: PayloadRef` as its last field: `Detached` (0), `Inline` (1)
  or `CallData` (2). The key `b"e" ++ entry_id` is unchanged.
- New contract method `submit_raw`, which takes the raw encoded `Record` as its arguments.
  `get_entry` gains `payload_location`.

## Effect on the NEAR verifier

nearcore's unpaginated `view_state`, the only form that returns proofs, refuses accounts whose
state is over `trie_viewer_state_size_limit` (default 50,000 bytes) with
`AccountStateTooLarge`. Paginated `view_state` refuses `include_proof`. A busy log contract
passes 50 KB quickly, whatever we do with payloads, so the verifier needs an RPC node with a
raised limit or its own node. Inline payloads make the state grow faster.
