# 0002: Normative spec and threat model

Status: proposed. Changes the threat model and the proof format.

## Decision

`docs/spec.md` and `docs/threat-model.md` replace 0001 as the description of v1. 0001 stays as
the record of why there are two independent backends. Beyond writing down what 0001 and the
code already do, this note makes these changes:

- **Log descriptor.** Verifiers get a descriptor out of band with the NEAR account and its
  expected `code_hash`, the Celestia namespace and start height, and default policy values
  (spec 2). The descriptor is now an explicit trust input (A7).
- **NEAR proof format adds an account check.** A NEAR observation is only valid together with
  a state proof of the account's `code_hash`, and one proof, at some height after deployment,
  that the account has no access keys (spec 6.1). The 0001 rule "deploy with no full-access
  keys" becomes "no access keys at all", because a proof that the
  access-key subtree is empty is simpler to check than reading every key's permission.
- **Records are identical per signed statement, not per byte.** The inline payload may differ
  between backends because their limits differ (spec 3.3). 0001 said byte-identical.
- **Relayer obligations.** Records go to every backend, and retryable rejections are retried
  (spec 6.3). Two ordering races near publisher removal can still leave backends permanently
  different for one entry; both are safe under `Both` (spec 7.2).
- **Monitors** alert on registry differences and NEAR account changes as well as split
  publications (spec 8).

## Found while writing

- **Payload stripping (T5).** Anyone can relay a copy of a `Publish` without its payload and
  get it included first, which removes the payload from that backend for good. Fixing it
  means the signed `Publish` commits to the payload's location. It should land with the
  large-payload decision, which is still open (spec 9).
- **Weak keys.** `check` should reject small-order and non-canonical publisher keys instead of
  leaving it to the admin.
- **Signature equivalence** between NEAR's `ed25519_verify` and ed25519-dalek is assumed, not
  tested. A shared vector suite is needed.

## Not decided here

Large payloads (spec 9), admin key rotation, and anything that needs gossip or consistency
proofs.
