//! End to end on synthetic state: run the real contract in near-sdk's mock
//! runtime, take the exact bytes it stores, put them in a trie with other
//! accounts' data, and prove entries against a head.

#[path = "common/trie_builder.rs"]
mod trie_builder;

use ed25519_dalek::{Signer, SigningKey};
use near_sdk::json_types::{Base64VecU8, U64};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{env, testing_env};
use tlog_core::hash::sha256;
use tlog_core::policy::{evaluate, Authority, BackendResult, Policy, Verdict};
use tlog_core::statement::{
    Publish, Record, RegistryOp, RegistryUpdate, RevocationReason, Revoke, SignedStatement, Statement,
};
use tlog_core::status::EntryStatus;
use tlog_core::{EntryId, LogId, PublicKey, Signature};
use tlog_near::TransparencyLog;
use tlog_near_verifier::entry::NearLogBinding;
use tlog_near_verifier::layout::{
    access_keys_trie_prefix, account_trie_key, contract_data_trie_key, decode_prefix, entry_key, StoredEntry,
    STATE_KEY,
};
use tlog_near_verifier::merkle::merkle_root;
use tlog_near_verifier::{
    observe_entry, BlockHeaderInnerLite, ContractStateProof, CryptoHash, EntryProofError, Head,
    StateProofError,
};

const ACCOUNT: &str = "tlog.near";

fn pk(k: &SigningKey) -> PublicKey {
    PublicKey(k.verifying_key().to_bytes())
}

fn rec(k: &SigningKey, statement: Statement) -> Base64VecU8 {
    let signature = Signature(k.sign(&statement.signing_bytes()).to_bytes());
    Base64VecU8(Record { signed: SignedStatement { statement, signature }, payload: None }.encode())
}

struct World {
    log_id: LogId,
    active: EntryId,
    revoked: EntryId,
    absent: EntryId,
    /// Contract storage, exactly as the contract wrote it.
    storage: Vec<(Vec<u8>, Vec<u8>)>,
}

fn run_contract() -> World {
    testing_env!(VMContextBuilder::new().block_height(100).block_timestamp(1_000).build());
    let admin = SigningKey::from_bytes(&[1; 32]);
    let publ = SigningKey::from_bytes(&[2; 32]);
    let mut c = TransparencyLog::new("test".into(), pk(&admin).to_hex(), U64(1024));
    let log_id: LogId = c.get_log_info().log_id.parse().unwrap();
    c.submit(rec(
        &admin,
        Statement::Registry(RegistryUpdate {
            log_id,
            seq: 0,
            op: RegistryOp::AddPublisher { key: pk(&publ), label: "p".into() },
        }),
    ));
    let publish = |serial| Publish {
        log_id,
        publisher: pk(&publ),
        subject: "example.com".into(),
        content_hash: sha256(b"cert"),
        content_len: 4,
        serial,
    };
    let (p1, p2, p3) = (publish(1), publish(2), publish(3));
    c.submit(rec(&publ, Statement::Publish(p1.clone())));
    c.submit(rec(&publ, Statement::Publish(p2.clone())));
    testing_env!(VMContextBuilder::new().block_height(150).block_timestamp(2_000).build());
    c.submit(rec(
        &publ,
        Statement::Revoke(Revoke {
            log_id,
            entry_id: p2.entry_id(),
            revoker: pk(&publ),
            reason: RevocationReason::Superseded,
        }),
    ));
    // Persist the root state and flush the maps, as the wasm wrapper would.
    env::state_write(&c);
    drop(c);

    let keys = [STATE_KEY.to_vec(), entry_key(&p1.entry_id()), entry_key(&p2.entry_id())];
    let storage = keys.iter().map(|k| (k.clone(), env::storage_read(k).expect("stored"))).collect();
    World { log_id, active: p1.entry_id(), revoked: p2.entry_id(), absent: p3.entry_id(), storage }
}

/// A shard trie with the contract's storage, its account record and an
/// access key, plus another account holding the same keys.
fn shard(world: &World, code_hash: [u8; 32], with_access_key: bool) -> ([u8; 32], Vec<Vec<u8>>) {
    let mut entries = Vec::new();
    for (k, v) in &world.storage {
        entries.push((contract_data_trie_key(ACCOUNT, k), v.clone()));
        entries.push((contract_data_trie_key("other.near", k), v.clone()));
    }
    let mut account = vec![0u8; 32]; // amount, locked
    account.extend_from_slice(&code_hash);
    account.extend_from_slice(&1000u64.to_le_bytes());
    entries.push((account_trie_key(ACCOUNT), account));
    if with_access_key {
        let mut k = access_keys_trie_prefix(ACCOUNT);
        k.extend_from_slice(&[0; 33]);
        entries.push((k, vec![1, 2, 3]));
    }
    let mut k = access_keys_trie_prefix("other.near");
    k.extend_from_slice(&[0; 33]);
    entries.push((k, vec![1, 2, 3]));
    trie_builder::build(&entries)
}

fn head_and_proof(world: &World, shard_index: usize) -> (Head, ContractStateProof) {
    let (root, items) = shard(world, [5; 32], false);
    let (other_root, other_items) = trie_builder::build(&[(b"\x09x.near,STATE".to_vec(), b"x".to_vec())]);
    let mut roots = vec![CryptoHash(other_root); 3];
    roots[1] = CryptoHash(root);
    let head = Head {
        hash: CryptoHash([9; 32]),
        prev_hash: CryptoHash([8; 32]),
        inner_lite: BlockHeaderInnerLite {
            height: 200,
            epoch_id: CryptoHash::default(),
            next_epoch_id: CryptoHash::default(),
            prev_state_root: merkle_root(&roots),
            outcome_root: CryptoHash::default(),
            timestamp: 3_000,
            next_bp_hash: CryptoHash::default(),
            block_merkle_root: CryptoHash::default(),
        },
    };
    let mut all = items;
    all.extend(other_items);
    let block_hash = head.hash;
    (head, ContractStateProof { block_hash, shard_state_roots: roots, shard_index, items: all })
}

fn binding(world: &World) -> NearLogBinding {
    NearLogBinding { account_id: ACCOUNT.into(), log_id: world.log_id, code_hash: Some(CryptoHash([5; 32])) }
}

#[test]
fn layout_mirror_matches_contract() {
    let w = run_contract();
    let raw = &w.storage[1].1;
    let mine: StoredEntry = decode_prefix(raw).unwrap();
    let theirs: tlog_near::StoredEntry = borsh::from_slice(raw).unwrap();
    assert_eq!(borsh::to_vec(&mine).unwrap(), borsh::to_vec(&theirs).unwrap());
}

#[test]
fn active_revoked_absent() {
    let w = run_contract();
    let (head, proof) = head_and_proof(&w, 1);
    let b = binding(&w);

    let o = observe_entry(&head, &b, &w.active, &proof).unwrap();
    assert!(matches!(o.status, EntryStatus::Active { published } if published.height == 100));
    assert_eq!(o.head.height, 200);

    let o = observe_entry(&head, &b, &w.revoked, &proof).unwrap();
    assert!(matches!(
        o.status,
        EntryStatus::Revoked { revoked, reason: RevocationReason::Superseded, .. } if revoked.height == 150
    ));

    let o = observe_entry(&head, &b, &w.absent, &proof).unwrap();
    assert_eq!(o.status, EntryStatus::Absent);

    // Into the verdict policy.
    let p = Policy { authority: Authority::Near, max_head_age_ns: 10_000, mirror_grace_ns: 0 };
    let obs = |id| BackendResult::Observed(observe_entry(&head, &b, id, &proof).unwrap());
    assert_eq!(evaluate(&p, 4_000, Some(&obs(&w.active)), None), Verdict::Valid);
    assert!(matches!(evaluate(&p, 4_000, Some(&obs(&w.revoked)), None), Verdict::Revoked { .. }));
    assert_eq!(evaluate(&p, 4_000, Some(&obs(&w.absent)), None), Verdict::NotFound);
}

#[test]
fn wrong_shard_cannot_hide_entries() {
    let w = run_contract();
    let (head, proof) = head_and_proof(&w, 0);
    assert_eq!(observe_entry(&head, &binding(&w), &w.active, &proof), Err(EntryProofError::NoContract));
}

#[test]
fn binds_head_log_and_code() {
    let w = run_contract();
    let (head, proof) = head_and_proof(&w, 1);
    let b = binding(&w);

    let mut other = head.clone();
    other.hash = CryptoHash([1; 32]);
    assert!(matches!(
        observe_entry(&other, &b, &w.active, &proof),
        Err(EntryProofError::State(StateProofError::WrongBlock { .. }))
    ));

    let mut other = head.clone();
    other.inner_lite.prev_state_root = CryptoHash([1; 32]);
    let mut p = proof.clone();
    p.block_hash = other.hash;
    assert_eq!(
        observe_entry(&other, &b, &w.active, &p),
        Err(EntryProofError::State(StateProofError::ShardRoots))
    );

    let mut wrong = b.clone();
    wrong.log_id = LogId([0; 32]);
    assert!(matches!(observe_entry(&head, &wrong, &w.active, &proof), Err(EntryProofError::WrongLog(_))));

    let mut wrong = b.clone();
    wrong.code_hash = Some(CryptoHash([6; 32]));
    assert!(matches!(observe_entry(&head, &wrong, &w.active, &proof), Err(EntryProofError::CodeHash { .. })));

    // Dropping proof nodes turns into an error, never into "absent".
    let mut p = proof.clone();
    p.items.retain(|b| b.first() != Some(&0));
    assert!(observe_entry(&head, &b, &w.active, &p).is_err());
}

#[test]
fn access_key_lock() {
    let w = run_contract();
    let (head, proof) = head_and_proof(&w, 1);
    let state = proof.verify(&head, ACCOUNT).unwrap();
    assert!(state.has_no_access_keys().unwrap());

    let (root, items) = shard(&w, [5; 32], true);
    let mut p = proof.clone();
    p.shard_state_roots[1] = CryptoHash(root);
    p.items = items;
    let mut h = head.clone();
    h.inner_lite.prev_state_root = merkle_root(&p.shard_state_roots);
    let state = p.verify(&h, ACCOUNT).unwrap();
    assert!(!state.has_no_access_keys().unwrap());
}
