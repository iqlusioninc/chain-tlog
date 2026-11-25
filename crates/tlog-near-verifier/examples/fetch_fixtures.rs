//! Fetch real NEAR light-client blocks and state proofs as test fixtures.
//!
//! ```sh
//! cargo run -p tlog-near-verifier --features rpc --example fetch-fixtures -- \
//!     https://rpc.mainnet.near.org crates/tlog-near-verifier/tests/fixtures/mainnet
//! ```
//!
//! Saves raw RPC responses. The `mainnet_fixtures` test replays them through
//! the light client and the state-proof checks.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use tlog_near_verifier::rpc::NearRpc;
use tlog_near_verifier::views::LightClientBlockView;
use tlog_near_verifier::{CryptoHash, LightClientBlock};

// Accounts tried, in order, for a state proof. They must have small storage
// (under the RPC's 50 kB view_state limit) and a contract STATE key.
const CANDIDATES: &[&str] =
    &["lockup-whitelist.near", "near", "linkdrop.near", "registrar", "system", "tlog-fixture.near"];

fn save(dir: &Path, name: &str, v: &Value) {
    std::fs::write(dir.join(name), serde_json::to_string_pretty(v).unwrap()).unwrap();
    println!("saved {name}");
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let url = args.next().unwrap_or_else(|| "https://rpc.mainnet.near.org".into());
    let dir = PathBuf::from(
        args.next().unwrap_or_else(|| "crates/tlog-near-verifier/tests/fixtures/mainnet".into()),
    );
    std::fs::create_dir_all(&dir).unwrap();
    let rpc = NearRpc::new(url);

    let status = rpc.call_raw("status", json!([])).await.unwrap();
    let latest: u64 = status["sync_info"]["latest_block_height"].as_u64().unwrap();
    println!("latest height {latest}");

    // A block about one and a half epochs back (mainnet epochs are 43,200
    // blocks), so the chain of light-client blocks crosses an epoch boundary.
    let mut start = None;
    for h in (latest - 65_000)..(latest - 64_900) {
        if let Ok(b) = rpc.call_raw("block", json!({ "block_id": h })).await {
            start = Some(b["header"]["hash"].as_str().unwrap().to_owned());
            break;
        }
    }
    let mut last: CryptoHash = start.expect("no start block").parse().unwrap();
    println!("start block {last}");

    let mut n = 0;
    while n < 8 {
        let v = rpc.call_raw("next_light_client_block", json!({ "last_block_hash": last })).await.unwrap();
        if v.is_null() || v.as_object().is_some_and(|o| o.is_empty()) {
            break;
        }
        let view: LightClientBlockView = serde_json::from_value(v.clone()).unwrap();
        let block: LightClientBlock = (&view).try_into().unwrap();
        let ours = block.hash();
        let theirs = rpc.call_raw("block", json!({ "block_id": block.inner_lite.height })).await.unwrap();
        println!(
            "lcb {n}: height {} epoch {} hash {} matches rpc: {}",
            block.inner_lite.height,
            block.inner_lite.epoch_id,
            ours,
            theirs["header"]["hash"].as_str() == Some(&ours.to_string())
        );
        if n == 0 {
            let bps =
                rpc.call_raw("EXPERIMENTAL_validators_ordered", json!({ "block_id": ours })).await.unwrap();
            save(&dir, "bps_0.json", &bps);
        }
        save(&dir, &format!("lcb_{n}.json"), &v);
        if ours == last {
            break;
        }
        last = ours;
        n += 1;
    }

    let head: LightClientBlock = {
        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join(format!("lcb_{}.json", n - 1))).unwrap())
                .unwrap();
        (&serde_json::from_value::<LightClientBlockView>(v).unwrap()).try_into().unwrap()
    };
    let head_hash = head.hash();
    save(&dir, "head_block.json", &rpc.call_raw("block", json!({ "block_id": head_hash })).await.unwrap());

    for account in CANDIDATES {
        let q = |prefix: &str| {
            let rpc = rpc.clone();
            let prefix = base64_encode(prefix.as_bytes());
            let account = account.to_string();
            async move {
                rpc.call_raw(
                    "query",
                    json!({
                        "request_type": "view_state",
                        "block_id": head.prev_block_hash,
                        "account_id": account,
                        "prefix_base64": prefix,
                        "include_proof": true,
                    }),
                )
                .await
            }
        };
        match (q("STATE").await, q("tlog-absent-key").await) {
            (Ok(present), Ok(absent)) => {
                let has_state = present["values"].as_array().is_some_and(|a| !a.is_empty());
                println!(
                    "{account}: STATE present: {has_state}, proof nodes {}",
                    present["proof"].as_array().map_or(0, Vec::len)
                );
                save(&dir, "view_state_present.json", &present);
                save(&dir, "view_state_absent.json", &absent);
                let acct = rpc
                    .call_raw(
                        "query",
                        json!({ "request_type": "view_account", "block_id": head.prev_block_hash, "account_id": account }),
                    )
                    .await
                    .unwrap();
                save(&dir, "view_account.json", &json!({ "account_id": account, "result": acct }));
                if has_state {
                    break;
                }
            }
            (a, b) => println!("{account}: {:?} {:?}", a.err(), b.err()),
        }
    }
}

fn base64_encode(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}
