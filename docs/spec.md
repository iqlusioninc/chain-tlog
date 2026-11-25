# chain-tlog specification, v1

Status: draft. This document is normative. Where it and the code disagree, one of them has a
bug; open an issue. Design rationale lives in `docs/design/`, and the threat model in
[threat-model.md](threat-model.md).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Model

A **log** is one logical transparency log. It holds **entries** (published statements about a
subject, such as a certificate for a domain or a release artifact), their **revocations**, and
the **publisher registry** that says who may publish.

A log can be hosted on one or two **backends**:

- **NEAR**: a contract account running `contracts/tlog-near`.
- **Celestia**: a namespace whose blobs, folded in order, are the log.

Each backend is a complete log on its own. A **verifier** picks which backends are
**authoritative** (NEAR, Celestia or both), checks each one through that chain's light client,
and combines the results with the policy in section 7. No log operator is trusted. Chain
consensus provides a single ordered history per backend, so v1 has no gossip protocol and no
consistency proofs.

Roles:

| Role | Holds | Can do |
|---|---|---|
| Admin | the admin Ed25519 key in `LogConfig` | add and remove publishers, revoke any entry |
| Publisher | a registered Ed25519 key | publish entries, revoke its own entries while registered |
| Relayer | a funded account on a chain | submit any record; has no authority of its own |
| Verifier | light clients for its authoritative backends | decide whether an entry is valid |
| Monitor | a follower of every backend that hosts the log | watch subjects and alert on anomalies (section 8) |

## 2. Log descriptor

A verifier needs a **log descriptor**, obtained out of band (for example, pinned in the
relying software). It is not signed by anything on chain; whoever distributes it decides
which log a verifier is checking.

```text
LogDescriptor {
    config:     LogConfig,          // name + admin key, hashes to log_id
    near:       Option<NearHost>,
    celestia:   Option<CelestiaHost>,
    authority:  Near | Celestia | Both,   // default policy for verifiers
    max_head_age, mirror_grace,           // default policy parameters (section 7)
}

NearHost {
    account_id:          AccountId,  // contract account
    code_hash:           [u8; 32],   // hash of the audited, reproducible wasm build
    max_inline_payload:  u64,        // must match the contract's init argument
}

CelestiaHost {
    network:       chain id (e.g. "celestia"),
    namespace:     Namespace,        // default: version 0, id = log_id[0..10]
    start_height:  u64,              // first height that belongs to the log
}
```

`LogDescriptor` is a v1 concept in this document only. There is no type for it in the code
yet; see section 10.

A verifier MAY override `authority`, `max_head_age` and `mirror_grace` locally. A log that
declares `authority = Both` obliges its publishers to submit every record to both backends.

## 3. Encoding and identifiers

All structured data is [borsh](https://borsh.io). All hashes are domain separated:

```text
H(tag, data) = SHA-256(tag || 0x00 || data)
```

| Tag | Used for |
|---|---|
| `chain-tlog/v1/log-id` | `log_id = H(tag, borsh(LogConfig))` |
| `chain-tlog/v1/entry-id` | `entry_id = H(tag, borsh(Publish))` |
| `chain-tlog/v1/statement` | signing input: `tag || 0x00 || borsh(Statement)` (not hashed; Ed25519 hashes internally) |

`content_hash` is plain `SHA-256(payload)` so that it matches hashes produced by other tools.

### 3.1 Types

```text
LogConfig       { name: String, admin: PublicKey }
Publish         { log_id, publisher: PublicKey, subject: String,
                  content_hash: [u8; 32], content_len: u64, serial: u64 }
Revoke          { log_id, entry_id, revoker: PublicKey, reason: RevocationReason }
RegistryUpdate  { log_id, seq: u64, op: RegistryOp }
RegistryOp      = AddPublisher { key, label: String } | RemovePublisher { key }
RevocationReason = Unspecified(0) | KeyCompromise(1) | Superseded(2) | Withdrawn(3)
Statement       = Publish | Revoke | Registry          // borsh enum, tags 0, 1, 2
SignedStatement { statement: Statement, signature: [u8; 64] }
Record          { signed: SignedStatement, payload: Option<Vec<u8>> }
```

`PublicKey` is a 32-byte Ed25519 key. `RevocationReason` is encoded as a single byte; any other
value fails to decode.

### 3.2 Record wire format

```text
encoded_record = "TLG1" || borsh(Record)
```

Decoding MUST reject a missing or different magic, malformed borsh, and trailing bytes. The
`1` in the magic is the format version. A future format uses a new magic and new hash tags.

### 3.3 What is identical across backends

The `SignedStatement` MUST be byte-identical on every backend: publishers sign once and submit
the same signed statement everywhere. `entry_id` covers only the `Publish` statement, not the
signature or the payload, so an entry has the same id on both backends and a verifier can line
them up without a mapping.

The `payload` field of the `Record` MAY differ between backends, because each backend has its
own inline payload limit. In particular, a record whose payload exceeds NEAR's
`max_inline_payload` is rejected by NEAR and must be submitted there without its payload (or
by the mechanism chosen in section 9). The earlier design note says the record is
byte-identical everywhere; that holds only when the payload fits both backends.

## 4. Validation rules

Every backend applies `tlog_core::rules::check` to each record, in backend order, against its
own current state. The function is pure and deterministic. A rejected record changes nothing.
On NEAR the call panics and the transaction fails. On Celestia the blob is skipped.

Checks, in order:

1. **Log**: `statement.log_id` MUST equal this log's `log_id`. Else `WrongLog`.
2. **Signature**: the signature MUST verify over the signing input (section 3) under the
   statement's signer: `publisher` for `Publish`, `revoker` for `Revoke`, `config.admin` for
   `Registry`. Else `BadSignature`.
3. **Payload**: if `payload` is present, the statement MUST be a `Publish`, and
   `len(payload) == content_len` and `SHA-256(payload) == content_hash`. Else
   `PayloadMismatch`. If the backend has an inline limit, `len(payload)` MUST NOT exceed it.
   Else `PayloadTooLarge`.
4. Per statement:
   - **Publish**: `publisher` MUST be registered (`UnknownPublisher`). `entry_id` MUST NOT
     already exist, revoked or not (`DuplicateEntry`). Effect: insert an active entry.
   - **Revoke**: the entry MUST exist (`UnknownEntry`) and MUST NOT be revoked
     (`AlreadyRevoked`). `revoker` MUST be the admin, or the entry's publisher while that
     publisher is still registered (`NotAuthorized`). Effect: mark revoked. Irreversible.
   - **Registry**: `seq` MUST equal the backend's next registry sequence number, starting at
     0 (`BadRegistrySeq`). `AddPublisher`: key MUST NOT be the admin (`AdminCannotPublish`) and
     MUST NOT already be registered (`AlreadyPublisher`). `RemovePublisher`: key MUST be
     registered (`NotPublisher`). Effect: change the registry and increment the sequence.

Consequences that the rest of the spec relies on:

- Removing a publisher does not revoke its entries. The admin revokes them explicitly.
- An entry id can never be reused, even after revocation. Publishers vary `serial` to publish
  the same content again.
- Every rejection is either permanent for that record (`WrongLog`, `BadSignature`,
  `PayloadMismatch`, `PayloadTooLarge`, `DuplicateEntry`, `AlreadyRevoked`,
  `AdminCannotPublish`, `AlreadyPublisher`, `NotPublisher`, and `BadRegistrySeq` with a lower
  `seq`) or may succeed on a later retry (`UnknownPublisher`, `UnknownEntry`, `NotAuthorized`,
  and `BadRegistrySeq` with a higher `seq`). Relayers retry the second kind (section 6.3).

### 4.1 Signature verification

Both backends MUST accept exactly the same signatures. NEAR's `ed25519_verify` host function
is the fixed point, and clients use ed25519-dalek's non-strict `verify` to match it. A shared
test-vector suite (non-canonical `s`, non-canonical `R`, small-order `A` and `R`) MUST pass
identically against the host function in a NEAR sandbox and against `Ed25519Dalek`. Until
that suite exists, this equivalence is an assumption.

The admin MUST NOT register small-order or non-canonical publisher keys. Section 10 proposes
enforcing this in `check` instead.

## 5. Backends

### 5.1 NEAR

The contract exposes `submit(record: base64)`. Anyone may call it; authority comes only from
the signature inside the record. The contract stores:

| Contract storage key | Value |
|---|---|
| `"e" || entry_id` | borsh `StoredEntry { publish, seq, published: ChainTime, revoked: Option<Revocation> }` |
| `"d" || entry_id` | borsh `Vec<u8>`, inline payload, if one was attached |
| `"p" || publisher_key` | borsh `String`, publisher label |
| `"STATE"` | borsh contract state (config, counters) |

This layout is part of the proof format and MUST NOT change within v1. In the NEAR state trie,
these are `ContractData { account_id, key }` entries under the log's account.

`ChainTime` for a NEAR record is the height and timestamp of the block in which the `submit`
receipt executed. `Position` is `(height, seq)`, where `seq` is a contract-wide counter of
published entries.

**Account lock.** Whoever can change the contract's code or call it with privileged methods can
rewrite the log. The contract has no owner methods and no upgrade path. It MUST be deployed to
an account with no access keys of any kind after deployment (all keys deleted), so the code and
storage can change only through `submit`.

### 5.2 Celestia

The log is the sequence of blobs in `namespace`, at heights `>= start_height`, ordered by
`(height, index of the blob within the namespace at that height)`. Each blob's data is an
`encoded_record`. Blobs use share version 0. The blob signer, if any, is ignored.

The fold is `tlog_core::state::LogState` with no inline payload limit beyond Celestia's own
blob size limit. Blobs that fail to decode or fail `check` are skipped and do not stop the fold.
`ChainTime` for a Celestia record is the height and time of the verified header containing it.

The default namespace is version 0 with id `log_id[0..10]`. Anyone can post to it. That is
harmless to correctness (section 4 rejects everything not signed by the right key) but costs
followers bandwidth (threat model, T8).

## 6. Proofs

An **observation** is a backend's light-client-verified answer for one entry:
`{ backend, status: Active | Revoked | Absent, head: ChainTime }`. `head` is the verified
block the status was proven against.

### 6.1 NEAR: inclusion, status and non-inclusion

One proof answers all three. To observe `entry_id` at a verified block `B`:

1. The light client verifies `B`'s header (section 6.4).
2. The verifier obtains a state proof for `ContractData { account_id, "e" || entry_id }` from
   any RPC node (`view_state` with `include_proof`), and checks it against `B`'s state root:
   trie proof to the shard's state root, then that shard root against the header's
   `prev_state_root`. The state proven is the state after the block preceding `B`.
3. If the key is present, its value decodes to `StoredEntry`, and `revoked` gives the status.
   If the proof shows the key absent, the status is `Absent`.
4. The verifier also checks, against the same state root, that the account's `code_hash`
   equals the descriptor's `code_hash`.

Checking the account lock (no access keys) needs a proof that the account's access-key subtree
is empty. Because a locked account cannot add keys, this only has to hold at one verified
height after deployment. Verifiers SHOULD check it once and record the height. How to produce
that proof from NEAR RPC is an open item for the NEAR light-client work.

Inline payloads are proven the same way, with the key `"d" || entry_id`.

Execution-outcome proofs (`light_client_proof` for the `submit` receipt) prove that a record
was accepted at some point, but not that the entry is unrevoked now. They are not sufficient
for status.

### 6.2 Celestia: inclusion, status and non-inclusion

Celestia has no state. Status is a function of the whole namespace history, so the verifier
folds it:

1. Start a `NamespaceFollower` at `start_height` with the descriptor's `LogConfig`.
2. For every height `h` from `start_height` to the light client's verified tip, with no gaps:
   - get the verified header for `h`;
   - get every blob in `namespace` at `h`, with NMT proofs against the header's data
     availability header showing the set is complete. An empty namespace MUST be proven empty
     (an absence proof), never assumed;
   - if sampling is required (section 6.4), use `h` only after data availability sampling for
     `h` has succeeded;
   - feed the blobs to the follower in namespace order.
3. The observation for `entry_id` is `LogState::status(entry_id)` with `head` = the last
   ingested header.

Inclusion and revocation are thus proven by the NMT proofs of the blobs that carried them.
Non-revocation and non-inclusion are proven by completeness: every height since
`start_height` was checked and no matching revocation or publication was found.

A verifier that is online keeps its follower running and pays one namespace query per block.
A cold start replays from `start_height`. Celestia nodes prune block data after the pruning
window, so replaying an old log needs an archival data source. Data from it is still checked
against verified headers, but blocks outside the sampling window cannot be sampled (threat
model, T6).

Snapshots of follower state are an optimisation a verifier MAY use for its own restarts. A
snapshot from anyone else is a trusted input and breaks the "no trusted operator" goal.

### 6.3 Relaying across backends

When a log has more than one backend, the publisher (or a relayer working for it) MUST submit
each record to every backend and MUST retry a record rejected for a retryable reason
(section 4) until it is accepted or becomes permanently rejected. In particular:

- registry updates MUST be applied to every backend, in `seq` order;
- a revocation MUST be resubmitted to a backend that returned `UnknownEntry` once the entry
  appears there.

The order of records can differ between backends. Section 7.2 lists the cases where that
makes backends disagree for good.

### 6.4 Light clients and what they are trusted for

| | NEAR | Celestia |
|---|---|---|
| Header validity | NEAR light-client protocol: each epoch's block producer set is committed by the previous epoch (`next_bp_hash`); a header is accepted when producers holding more than 2/3 of that epoch's stake sign the approval. The client must see at least one light-client block per epoch. | CometBFT-style header verification in Lumina: a header is accepted when validators with more than 2/3 of the voting power of a validator set the client already trusts sign it. |
| Bootstrapping | A trusted checkpoint block (weak subjectivity). | A trusted header recent enough that its validators are still bonded (weak subjectivity). |
| State or data | State proof against `prev_state_root`. | NMT proofs against the data availability header. |
| Data availability | Not sampled. Rests on validators (the same > 2/3) keeping state; any one honest RPC can serve the proof. | Data availability sampling inside the sampling window. Needs enough honest samplers and one honest full node for reconstruction and bad-encoding fraud proofs. |
| Implementation | Not written yet (largest open item). | `tlog-celestia` with `lumina` feature. |

The verifier's own clock is trusted to measure head age.

## 7. Verdicts

`tlog_core::policy::evaluate(policy, now, near, celestia)` turns observations into a verdict.
`Policy { authority, max_head_age, mirror_grace }`.

### 7.1 One authoritative backend

Observations from non-authoritative backends are ignored.

| Observation | Verdict |
|---|---|
| Revoked (even if the head is older than `max_head_age`) | `Revoked` |
| none, or head older than `max_head_age` | `Unverifiable` |
| Active | `Valid` |
| Absent | `NotFound` |

A stale revocation still counts because revocation is irreversible.

### 7.2 Both backends

Evaluated top to bottom; the first matching row wins.

| # | NEAR | Celestia | Verdict |
|---|---|---|---|
| 1 | Revoked (any age) | anything | `Revoked` |
| 2 | anything | Revoked (any age) | `Revoked` |
| 3 | none or stale | not revoked | `Unverifiable` (NEAR) |
| 4 | not revoked | none or stale | `Unverifiable` (Celestia) |
| 5 | Active | Active | `Valid` |
| 6 | Absent | Absent | `NotFound` |
| 7 | Active on one | Absent on the other | `AwaitingMirror` while `now - published <= mirror_grace`, else `SplitPublication` |

`published` in row 7 is the timestamp of the block that included the entry on the backend that
has it.

Properties:

- **Valid needs both.** An entry is valid only when it is active, with a fresh head, on both
  backends. Forging a valid entry needs both chains, or both light clients, to be broken.
- **Revocation needs one.** A revocation on either backend wins, so hiding a revocation also
  needs both broken. The cost is that one broken backend can falsely revoke (a denial of
  service, never a forgery).
- **Lagging chains fail closed.** A backend that is unreachable or behind `max_head_age` makes
  every non-revoked entry `Unverifiable`. Both chains must be live for anything to be valid.
- **Split publication is a publisher fault.** An entry on only one backend is never valid.

Ordering races that make backends disagree permanently, even with honest relaying:

| Race | Result | Effect under `Both` |
|---|---|---|
| `Publish` reaches backend A before a `RemovePublisher` of its key, and backend B after it | Active on A, rejected forever on B | `SplitPublication`. The admin SHOULD revoke it on A. |
| A publisher's own `Revoke` reaches A before a `RemovePublisher` of its key, and B after it | Revoked on A, Active on B | `Revoked`. Single-backend verifiers of B see it active until the admin revokes it on B. |

Every other ordering difference resolves once relayers retry. Registry state always converges,
because registry updates are totally ordered by `seq`.

### 7.3 Choosing the parameters

- `max_head_age` bounds how long a revocation can go unseen by an online verifier, on top of
  the time to get the revocation included. It must be longer than a chain's normal block time
  plus light-client sync lag, or verdicts flap to `Unverifiable`.
- `mirror_grace` must cover the slower backend's inclusion time plus relay retries. Too short
  and honest publications show `SplitPublication`; too long and a deliberate single-chain
  publication goes unflagged for longer (it is still never `Valid`).

## 8. Monitors

A monitor follows every backend that hosts the log, independent of any verifier's authority
choice, and SHOULD alert on:

- any new entry for a watched subject, on either backend;
- `SplitPublication`: an entry on one backend and not the other after `mirror_grace`;
- a revocation present on one backend and not the other after `mirror_grace`;
- any registry update, and any difference in registry state between backends lasting longer
  than `mirror_grace`;
- on NEAR, any change to the account's `code_hash` or access keys;
- a backend whose verified head stops advancing.

## 9. Large payloads (open)

Payloads are bound to an entry by `content_hash` and `content_len`. How a payload is made
available is still being decided in a separate piece of work, and this section will be filled
in from it. Facts the decision must respect:

- On Celestia the payload rides inline in the publish blob, so availability comes with the
  log, up to Celestia's maximum blob size.
- On NEAR, the contract stores inline payloads up to `max_inline_payload` and pays storage
  staking for them. The starting idea under research is to carry large payloads as call data
  in the NEAR transaction instead of contract storage, which changes what a NEAR light client
  can prove about availability (state proofs cover storage, not transaction arguments) and
  how long the data is retained.
- Whatever is chosen, verifiers MUST be able to check availability through light clients, and
  this spec MUST say which backends' availability is enough under `Both` (for example: any
  authoritative backend that serves bytes matching `content_hash`).
- The payload-stripping issue in threat model T5 has to be closed by the same change.

## 10. Open items in the code

These are differences between this spec and the code in PR #1, or gaps the spec depends on:

1. **No `LogDescriptor` type.** Verifiers have no single place for account id, code hash,
   namespace, start height and policy defaults.
2. **NEAR light-client verifier.** Header sync, state-proof verification, `code_hash` check and
   the one-time access-key check (section 6.1).
3. **Signature test vectors** across the NEAR host function and `Ed25519Dalek` (section 4.1).
4. **Weak keys.** Reject small-order and non-canonical keys in `check` for `AddPublisher` (and
   in `LogConfig` creation), rather than relying on the admin.
5. **Payload stripping** (threat model T5). `Publish` does not commit to whether the payload is
   inline, so anyone can relay a stripped copy first.
6. **Admin key rotation.** The admin key is part of `log_id`, so it cannot be rotated without
   starting a new log. Acceptable for v1; a compromise means migrating to a new log.
