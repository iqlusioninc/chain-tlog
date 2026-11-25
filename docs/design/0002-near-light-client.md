# 0002: NEAR light-client verifier

Status: proposed. Changes the threat model and fixes the NEAR proof format.

Implements the NEAR side of 0001 in `crates/tlog-near-verifier`. Spec sections 6.1 and 6.4
describe what it must check; this note records how, and what it cannot yet check.

## Headers

The light client is the NEAR spec's `validate_and_update_head`. It holds a head and the block
producers of the head's epoch and the next. A `LightClientBlockView` is accepted when it is
higher than the head, is in the head's epoch or the next, and producers with more than 2/3 of
that epoch's stake signed `Endorsement(next_block_hash) || le(height + 2)`. A block entering the
next epoch must carry `next_bps`, checked against `next_bp_hash`; that is how the producer set
is followed across epochs. Block hashes are computed, never read from the RPC.

- **Bootstrap.** A checkpoint is a light-client block whose hash the user trusts. Its `next_bps`
  are checked against its header. Optionally, the producers of its own epoch are supplied too;
  those are trusted as part of the checkpoint.
- **Liveness.** The client must accept a block from every epoch (about 12 hours on mainnet).
  An offline verifier that misses an epoch needs a new checkpoint. This fits the
  "verifiers are online" assumption.
- Secp256k1 producer keys never verify. They count toward total stake but never toward
  approvals, so an unsupported key can only make the client refuse a block.

## Proof format

A NEAR observation of `entry_id` at verified head `H` is a `ContractStateProof`:

1. `H`'s hash.
2. The `prev_state_root` of every chunk header in `H`, in shard order. They must merklize
   (NEAR's `merklize`, leaves `sha256(root)`) to `H.inner_lite.prev_state_root`.
3. The index of the contract's shard.
4. Trie nodes and values (from `view_state` with `include_proof`, queried at `H`'s parent).

The verifier walks the trie from that shard root to
`0x09 ++ account ++ "," ++ "STATE"` and `0x09 ++ account ++ "," ++ "e" ++ entry_id`, hashing
every node it uses. A missing node is an error, never "absent". Absence is reported only when
the proven path diverges from the key.

The shard index is untrusted. A proof against the wrong shard would show the entry key absent,
so the verifier also requires the contract's `STATE` key in the same root and checks that it
holds the expected `log_id`. A wrong shard therefore fails instead of reporting `Absent`.
If the verifier pins a `code_hash`, the account record (`0x00 ++ account`) must also be in the
proof and match.

Values are decoded as borsh prefixes, so the contract may append fields to `StoredEntry` and
its root state (as the call-data payload work does) without breaking verifiers. Fields must
never be reordered or removed.

The observation's `head` is `H`'s height and timestamp. The proven state is the state after
`H`'s parent block.

## Gaps, flagged

1. **State proofs are refused for large accounts.** nearcore serves `view_state` with
   `include_proof` only when the account's storage is under `trie_viewer_state_size_limit`
   (50 kB by default). A real log is larger. Verifiers need an RPC node with the limit raised.
   That node is still untrusted, but someone has to run it. A custom proof endpoint is the
   alternative.
2. **Code hash and access-key lock can't be proven from stock RPC.** `view_state` proofs cover
   contract storage, and may not include the account record. No RPC method returns a proof
   for the account record or the access-key subtree. The verifier can check both
   (`VerifiedState::code_hash`, `VerifiedState::has_no_access_keys`) given the trie nodes, so
   this needs a proof source, not new verification code. The same custom endpoint as gap 1
   would solve both. Until then, `NearLogBinding::code_hash` should stay unset with stock RPC.
3. **Missing chunks make state lag.** When the contract shard's chunk is missing in `H`, `H`
   carries the previous chunk header, whose `prev_state_root` is the state before that chunk.
   A prover can then show state a few blocks older than `H`'s parent while the observation
   reports `H`'s time. The lag is bounded by the run of missing chunks on that shard. A
   revocation can be hidden for that long, beyond `max_head_age`. Fixing it means proving the
   chunk header is new (`height_included == H.height`) through `chunk_headers_root`, which is
   in the part of the header the light client sees only as `inner_rest_hash`. That needs the
   full header, whose layout changes across protocol versions. Left for a follow-up.
4. **Payload availability.** A NEAR-only log proves inline payloads with the key `"d" ++ id`
   (`VerifiedState::contract_data`). Call-data payloads (draft PR #3) need a check that the
   bytes were in the `submit` receipt at the published height; that is not done here.

## Threat model changes

- The NEAR backend's root of trust is the checkpoint plus more than 2/3 of stake in every
  epoch since it. Validators holding 2/3 of stake in any epoch can forge state.
- No RPC node is trusted. A node can only withhold (the verifier reports `Unavailable`) or
  serve state up to the missing-chunk lag in gap 3.
