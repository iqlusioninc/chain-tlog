# chain-tlog threat model, v1

Status: draft. Read with [spec.md](spec.md); section numbers like "spec 6.1" refer to it.

## 1. What the log promises

For a verifier using a given authority choice, with honest light-client roots of trust:

- **P1 Integrity.** An entry is `Valid` only if every authoritative backend includes it and it
  was signed by a publisher that was registered on that backend when the entry was included.
- **P2 Revocation visibility.** Once a revocation is included on an authoritative backend, an
  online verifier stops returning `Valid` for that entry within `max_head_age` plus its own
  sync lag.
- **P3 Non-equivocation.** Every verifier using the same backend sees the same history for it,
  because that history is the chain's consensus. There is no log operator who could show
  different views to different verifiers.
- **P4 Availability of payloads.** An `Attached` payload was available to the chain at
  publication, and stays retrievable from it for that backend's retention window (spec 9).
  Integrity of a payload from any source is checked against `content_hash`.
- **P5 Auditability.** Monitors can enumerate every entry, revocation and registry change on
  every backend.

The log does not promise that a payload is true or safe; it promises who vouched for it and
whether they still do.

## 2. Assumptions

These come from the project's standing assumptions and from spec section 6.4. Work that breaks
one of them must say so.

- **A1 Permissioned publishers.** Only keys the admin registered can publish. The admin key is
  kept offline or in an HSM.
- **A2 Online verifiers.** Verifiers keep their light clients synced. An offline verifier
  returns `Unverifiable` until it catches up; a Celestia verifier that was offline replays the
  heights it missed.
- **A3 Large payloads.** Payloads can be too large for NEAR contract storage. They travel as
  NEAR call data and are retained only for NEAR's garbage-collection window (spec 9).
  Long-term retrieval needs an archival source or verifiers that keep payloads.
- **A4 Chain consensus.** For each authoritative chain, more than 2/3 of stake (NEAR) or voting
  power (Celestia) is honest in every period the verifier relies on.
- **A5 Light-client bootstrap.** The verifier starts from a correct trusted checkpoint (weak
  subjectivity) and stays within each chain's trusting or epoch window.
- **A6 Celestia availability.** Enough honest light nodes sample, and the verifier is connected
  to at least one honest full node that can reconstruct blocks and send bad-encoding fraud
  proofs.
- **A7 Correct descriptor.** The verifier's log descriptor (spec 2) is authentic: right
  `LogConfig`, NEAR account and code hash, Celestia namespace and start height.
- **A8 Verifier clock.** The verifier's clock is roughly correct (it measures head age).
- **A9 Locked NEAR account.** The contract account has no access keys after deployment, and the
  deployed code is the audited build named by `code_hash`.

## 3. Adversaries

| Adversary | Capabilities |
|---|---|
| Outsider | Submits any bytes to either backend; reads everything; front-runs transactions it sees in a mempool. |
| Malicious relayer or RPC node | Drops, delays or reorders the records it relays; serves stale, wrong or partial data to verifiers. |
| Compromised publisher | Signs anything with one publisher key. |
| Compromised admin | Signs anything with the admin key. |
| Malicious chain majority | Controls > 2/3 of one chain's validators. Signs invalid headers or state, withholds data. |
| Eclipsing network attacker | Controls which peers a verifier's light client talks to. |

## 4. Threats

Each threat says which adversary, what it achieves, how the design stops it, and what is left.
"Single" means a verifier with one authoritative backend, "Both" means both.

### T1 Forged entry
Outsider or relayer submits a `Publish` not signed by a registered publisher.
*Stopped by* the signature and registry checks in `check`, applied by the contract and by every
Celestia follower. Records are bound to one log by `log_id` in the signed statement and to the
v1 format by the hash tags.
*Residual:* none, given A1 and that both backends accept identical signature sets (spec 4.1;
needs the shared test vectors).

### T2 Malicious RPC node or relayer
Serves the verifier wrong state, wrong blobs, an incomplete blob set, or an old head.
*Stopped by* light clients: NEAR state proofs against verified headers, Celestia NMT proofs and
namespace absence proofs against verified headers. An old head is caught by `max_head_age`.
Dropping records the verifier never asked about cannot change any proof.
*Residual:* denial of service. A relayer that will not submit a record delays it; the publisher
uses another relayer. A node that will not serve proofs makes the verdict `Unverifiable`.

### T3 Hidden revocation
An attacker wants a verifier to keep accepting a revoked entry.
*Stopped by:*
- NEAR: status and inclusion are the same storage value, so a proof of the entry shows its
  revocation.
- Celestia: the follower must ingest every height with a completeness proof, and refuses gaps,
  so a revocation blob cannot be left out. With sampling, data withheld by the producer stops
  the follower instead of reading as "empty".
- Both: a revocation on either backend wins, even if the other backend is stale or down.
- Freshness: a stale head is `Unverifiable` unless it already shows the revocation.
*Residual:* the window `max_head_age` plus inclusion latency. In Single, a malicious majority of
the authoritative chain can hide a revocation. In Both, it needs both chains.

### T4 Split view across backends
A compromised publisher publishes an entry on one backend only, or different entries on each.
*Stopped by:* in Both, an entry on one backend is never `Valid` (`AwaitingMirror`, then
`SplitPublication`). Entry ids are content-addressed, so "different entries" are simply two
split publications.
*Residual:* a Single verifier of the backend that has it accepts it. That is the cost of
choosing Single. Monitors alert on split publications (spec 8). Relaying is permissionless, so
anyone who sees the record can copy it to the other backend.

### T5 Payload stripping
An outsider who sees a signed `Publish` record with an inline payload (in a NEAR or Celestia
mempool, or on the other backend) submits the same signed statement with `payload = None`, and
gets it included first. The stripped copy is valid, so the original is then rejected as
`DuplicateEntry`. The entry is active but its payload is not on that backend.
*Impact:* breaks P4 on the affected backend. Integrity is unaffected: the payload, wherever it
comes from, still has to match `content_hash`.
*Stopped by* the signed `Publish.payload_mode` (design note 0002, PR #3). A stripped copy of an
`Attached` publication fails `check` with `PayloadMismatch` on both backends, so it cannot land
first.
*Residual:* none for stripping. Retention after publication is covered by spec 9.

### T6 Data withholding on Celestia
A block producer publishes a header but withholds the namespace data, hoping verifiers read the
namespace as empty.
*Stopped by* NMT completeness (the namespace rows must be served with proofs) and by data
availability sampling, which requires the follower to wait until sampling for that height
succeeded.
*Residual:* outside the sampling window (cold start on an old log via an archive), data is still
checked against headers, but its availability rests on A4 alone. The design note and
`lumina` module say this plainly; verifiers that care should not let their light client fall
out of the sampling window (A2).

### T7 NEAR contract or account takeover
Whoever controls the contract account can redeploy code or write storage directly, rewriting
the log.
*Stopped by* A9: no access keys, no upgrade method, and verifiers check `code_hash` in every
state proof and the empty access-key set once (spec 6.1).
*Residual:* NEAR protocol-level changes (a hard fork that edits state) are part of A4. Until
the light-client verifier implements the checks, A9 is unverified.

### T8 Namespace or contract spam
Anyone can post blobs into the namespace or call `submit`.
*Stopped by:* on NEAR, the caller pays gas and rejected calls change nothing; only registered
publishers can make the contract pay storage. On Celestia, rejected blobs are skipped.
*Residual:* Celestia followers must download and check every blob in the namespace, so a
spammer can raise every verifier's bandwidth and CPU at the price of Celestia blob fees. There
is no in-protocol filter, because skipping a blob without reading it would also allow skipping
a revocation. If this becomes a problem, options include a namespace per publisher or rate
limits enforced by fees; both need a design note.

### T9 Registry replay and divergence
An attacker replays an old `AddPublisher` after a `RemovePublisher`, or registry state differs
between backends.
*Stopped by* the registry sequence number. Registry updates are totally ordered by `seq`, so
every backend reaches the same registry once relayers deliver all updates.
*Residual:* a `RemovePublisher` delivered to one backend only leaves the key able to publish on
the other. In Both, those entries are never `Valid`; in Single on the lagging backend they are.
The admin MUST relay registry updates to every backend (spec 6.3); monitors alert on registry
differences. Ordering races near a removal can leave a permanent difference in one entry's
status (spec 7.2 table).

### T10 Compromised publisher key
*Impact:* the attacker can publish valid entries and revoke that publisher's entries until the
admin removes the key.
*Mitigation:* the admin removes the key and revokes the bad entries (removal alone does not
revoke them). Monitors watching subjects see the bad entries immediately. In Both mode, a
publication on one backend before the attacker reaches the other is flagged.

### T11 Compromised admin key
*Impact:* total. The attacker can register its own publishers and revoke every entry.
*Mitigation:* keep the key offline; monitors alert on every registry update. Because the admin
key is part of `log_id`, recovery means a new log and a new descriptor. Key rotation and
multi-signature admin are out of scope for v1.

### T12 Malicious chain majority
*Single:* the attacker can forge state or headers, hide revocations, and create entries on its
chain, as far as the verifier's light client accepts its signatures. Nothing in the log stops
this; it is the trust root.
*Both:* forging a valid entry or hiding a revocation needs both chains. One bad chain can only
cause false revocations or `Unverifiable` (denial of service).
*Long-range attacks:* old validator keys can sign an alternative history. Light clients with a
recent trusted checkpoint (A5) reject it.

### T13 Eclipse of the verifier's light client
An attacker controls the verifier's peers.
*Stopped by* header verification: the attacker cannot produce headers signed by the honest
validator set. It can withhold new headers, which shows up as a stale head (`Unverifiable`) and
not as a false verdict. On Celestia, an eclipsed light node can be fooled into thinking sampling
succeeded only if the attacker also serves the samples, which needs the data; withheld fraud
proofs are the remaining risk (A6).

### T14 Timestamp manipulation
NEAR block producers and Celestia proposers choose block timestamps within protocol limits.
Timestamps feed `max_head_age` and `mirror_grace`.
*Impact:* a producer can make a head look slightly fresher, or a publication slightly newer, by
the protocol's allowed drift. A majority could do more, but that is T12.
*Mitigation:* pick `max_head_age` and `mirror_grace` well above allowed drift.

### T15 Signature malleability and verifier differences
Different Ed25519 rules on the two backends could make a record valid on one only.
*Stopped by* using the same non-strict verification on both (spec 4.1). Malleability does not
matter for identity, because `entry_id` does not cover the signature.
*Residual:* unproven until the shared test vectors run; small-order keys rely on the admin until
`check` rejects them (spec 10).

### T16 Wrong descriptor
A verifier is given a descriptor pointing at the wrong account, namespace, start height or
config.
*Impact:* the verifier checks the wrong log. Pointing at an attacker-controlled NEAR account is
caught by the `code_hash` and access-key checks only if the descriptor's `code_hash` is right.
A start height that is too late makes the follower miss the registry, so every entry reads
`NotFound` (fails closed). A start height that is too early only costs time.
*Mitigation:* A7. The descriptor is distributed with the relying software, like a CT log list.

## 5. Out of scope for v1

- Gossip and consistency proofs. Each chain's consensus already gives one history (P3); no
  threat above needs them. Revisit if a backend without BFT finality is added.
- Privacy of subjects or payloads. Everything in the log is public.
- Offline verification (for example, stapled proofs checked without a light client). It would
  need a freshness source and breaks A2.
- Admin key rotation and threshold admin keys.
