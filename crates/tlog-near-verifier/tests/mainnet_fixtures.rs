//! Replays real NEAR mainnet RPC responses (captured with the
//! `fetch-fixtures` example) through the light client and state proofs.
//! This is what pins the hashing and encodings to nearcore's.

use std::path::{Path, PathBuf};

use serde_json::Value;
use tlog_near_verifier::merkle::merkle_root;
use tlog_near_verifier::views::{self, BlockView, LightClientBlockView, ValidatorStakeView, ViewStateResult};
use tlog_near_verifier::{ContractStateProof, CryptoHash, LightClient, LightClientBlock};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mainnet")
}

fn load<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let s = std::fs::read_to_string(dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn lcbs() -> Vec<LightClientBlock> {
    (0..)
        .map(|i| format!("lcb_{i}.json"))
        .take_while(|n| dir().join(n).exists())
        .map(|n| (&load::<LightClientBlockView>(&n)).try_into().unwrap())
        .collect()
}

#[test]
fn light_client_follows_mainnet() {
    let blocks = lcbs();
    assert!(blocks.len() >= 2, "fixtures missing; run the fetch-fixtures example");
    let bps = views::validators(&load::<Vec<ValidatorStakeView>>("bps_0.json")).unwrap();
    let mut lc = LightClient::from_checkpoint(blocks[0].hash(), &blocks[0], Some(bps)).unwrap();
    let mut epochs = std::collections::BTreeSet::from([blocks[0].inner_lite.epoch_id]);
    for b in &blocks[1..] {
        lc.update(b).unwrap_or_else(|e| panic!("height {}: {e}", b.inner_lite.height));
        epochs.insert(b.inner_lite.epoch_id);
    }
    assert!(epochs.len() >= 2, "fixtures should cross an epoch boundary");

    // A tampered block is refused.
    let mut lc = LightClient::from_checkpoint(blocks[0].hash(), &blocks[0], None).unwrap();
    let mut bad = blocks[1].clone();
    bad.inner_lite.prev_state_root = CryptoHash([0; 32]);
    assert!(lc.update(&bad).is_err());
}

#[test]
fn block_hash_and_shard_roots_match_mainnet() {
    let blocks = lcbs();
    let head = blocks.last().unwrap();
    let block: BlockView = load("head_block.json");
    assert_eq!(block.header.hash, head.hash(), "computed block hash");
    let roots: Vec<CryptoHash> = block.chunks.iter().map(|c| c.prev_state_root).collect();
    assert_eq!(merkle_root(&roots), head.inner_lite.prev_state_root);
}

#[test]
fn state_proofs_match_mainnet() {
    let blocks = lcbs();
    let head_block = blocks.last().unwrap();
    let bps = views::validators(&load::<Vec<ValidatorStakeView>>("bps_0.json")).unwrap();
    let mut lc = LightClient::from_checkpoint(blocks[0].hash(), &blocks[0], Some(bps)).unwrap();
    for b in &blocks[1..] {
        lc.update(b).unwrap();
    }
    let head = lc.head();
    assert_eq!(head.hash, head_block.hash());

    let block: BlockView = load("head_block.json");
    let roots: Vec<CryptoHash> = block.chunks.iter().map(|c| c.prev_state_root).collect();
    let present: ViewStateResult = load("view_state_present.json");
    let absent: ViewStateResult = load("view_state_absent.json");
    let account: Value = load("view_account.json");
    let account_id = account["account_id"].as_str().unwrap();

    let mut items = present.proof_items().unwrap();
    items.extend(absent.proof_items().unwrap());
    let hashes: Vec<CryptoHash> = items.iter().map(|b| CryptoHash::hash(b)).collect();
    let shard_index = roots.iter().position(|r| hashes.contains(r)).expect("proof root is a shard root");
    let proof = ContractStateProof { block_hash: head.hash, shard_state_roots: roots, shard_index, items };
    let state = proof.verify(head, account_id).unwrap();

    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    for v in &present.values {
        let key = b64.decode(&v.key).unwrap();
        let value = b64.decode(&v.value).unwrap();
        assert_eq!(state.contract_data(&key).unwrap(), Some(value), "key {key:?}");
    }
    assert!(!present.values.is_empty());
    assert_eq!(state.contract_data(b"tlog-absent-key").unwrap(), None);

    // Whether a view_state proof also carries the account record depends on
    // how nearcore records the read. If it does, the code hash must match.
    let rpc_code_hash: CryptoHash = account["result"]["code_hash"].as_str().unwrap().parse().unwrap();
    match state.code_hash() {
        Ok(Some(h)) => assert_eq!(h, rpc_code_hash),
        Ok(None) => panic!("account proven absent"),
        Err(e) => println!("account record not in proof: {e}"),
    }
}
