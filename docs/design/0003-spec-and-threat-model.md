# 0003: Normative spec and threat model

Status: proposed. Changes the threat model and the proof format.

## Decision

`docs/spec.md` and `docs/threat-model.md` replace 0001 as the description of v1. 0001 stays as
the record of why there are two independent backends. Beyond writing down what 0001 and the
code already do, this note makes these changes:

- **Log descriptor.** Verifiers get a descriptor out of band with the NEAR account and its
  expected `code_hash`, the Celestia namespace and start height, and default policy values
  (spec 2). The descriptor is now an explicit trust input (A7).
- **NEAR proof format adds shard binding and an account check.** A NEAR proof must include the
  contract's `STATE` key with the expected `log_id`. Verifiers should also prove the account's
  `code_hash`, and once that it has no access keys, but stock RPC cannot serve those proofs
  yet, so they are SHOULD until a proof source exists (spec 6.1).
- **NEAR freshness.** A missing chunk makes a proof lag its block; this is threat T17. The 0001 rule "deploy with no full-access
  keys" becomes "no access keys at all", because a proof that the
  access-key subtree is empty is simpler to check than reading every key's permission.
- **Payload size in a two-backend log.** With `payload_mode` from 0002, records are
  byte-identical again, so an `Attached` payload must fit both chains' limits or it becomes a
  split publication (spec 3.3).
- **NEAR RPC requirement.** Proof-serving `view_state` has a 50 KB account-state limit by
  default, so NEAR verifiers need an RPC node with a raised limit (spec 6.1).
- **Relayer obligations.** Records go to every backend, and retryable rejections are retried
  (spec 6.3). Two ordering races near publisher removal can still leave backends permanently
  different for one entry; both are safe under `Both` (spec 7.2).
- **Monitors** alert on registry differences and NEAR account changes as well as split
  publications (spec 8).

## Found while writing

- **Payload stripping (T5).** Anyone could relay a copy of a `Publish` without its payload and
  get it included first. Fixed by `Publish.payload_mode` in 0002.
- **Weak keys.** `check` should reject small-order and non-canonical publisher keys instead of
  leaving it to the admin.
- **Signature equivalence** between NEAR's `ed25519_verify` and ed25519-dalek is assumed, not
  tested. A shared vector suite is needed.

## Not decided here

Chunked uploads for payloads larger than one NEAR transaction, admin key rotation, and anything that needs gossip or consistency
proofs.
