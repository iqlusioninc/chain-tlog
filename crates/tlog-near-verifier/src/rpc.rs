//! Minimal NEAR JSON-RPC client.
//!
//! The node is untrusted. This module only fetches; checking is done by
//! [`crate::LightClient`] and [`crate::ContractStateProof::verify`].
//!
//! Proofs come from `view_state` with `include_proof`. nearcore refuses that
//! call for accounts whose storage exceeds the node's
//! `trie_viewer_state_size_limit` (50 kB by default), so a log of any size
//! needs an RPC node with that limit raised. That node is still untrusted.

use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::hash::CryptoHash;
use crate::light_client::Head;
use crate::state_proof::ContractStateProof;
use crate::types::{LightClientBlock, ValidatorStake};
use crate::views::{self, BlockView, LightClientBlockView, ValidatorStakeView, ViewError, ViewStateResult};

/// RPC errors.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// Transport.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    /// The node returned an error object.
    #[error("rpc error: {0}")]
    Rpc(Value),
    /// The response did not parse.
    #[error("decode: {0}")]
    Decode(String),
    /// A view did not convert.
    #[error(transparent)]
    View(#[from] ViewError),
    /// No shard root matched the proof.
    #[error("no shard state root in block {0} matches the proof")]
    NoShard(CryptoHash),
}

/// A NEAR JSON-RPC endpoint.
#[derive(Clone, Debug)]
pub struct NearRpc {
    url: String,
    http: reqwest::Client,
}

impl NearRpc {
    /// Client for `url`, e.g. `https://rpc.mainnet.near.org`.
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into(), http: reqwest::Client::new() }
    }

    /// Raw call. Returns the `result` field.
    pub async fn call_raw(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let body = json!({ "jsonrpc": "2.0", "id": "tlog", "method": method, "params": params });
        let mut resp: Value = self.http.post(&self.url).json(&body).send().await?.json().await?;
        if let Some(e) = resp.get("error") {
            return Err(RpcError::Rpc(e.clone()));
        }
        Ok(resp.get_mut("result").map(Value::take).unwrap_or(Value::Null))
    }

    async fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T, RpcError> {
        let v = self.call_raw(method, params).await?;
        serde_json::from_value(v).map_err(|e| RpcError::Decode(e.to_string()))
    }

    /// `next_light_client_block` after `last`. `None` if the node has
    /// nothing newer.
    pub async fn next_light_client_block(
        &self,
        last: &CryptoHash,
    ) -> Result<Option<LightClientBlock>, RpcError> {
        let v = self.call_raw("next_light_client_block", json!({ "last_block_hash": last })).await?;
        if v.is_null() || v.as_object().is_some_and(|o| o.is_empty()) {
            return Ok(None);
        }
        let view: LightClientBlockView =
            serde_json::from_value(v).map_err(|e| RpcError::Decode(e.to_string()))?;
        Ok(Some((&view).try_into()?))
    }

    /// `block` by hash.
    pub async fn block(&self, hash: &CryptoHash) -> Result<BlockView, RpcError> {
        self.call("block", json!({ "block_id": hash })).await
    }

    /// Block producers of the epoch containing `block`, in the order
    /// approvals use (`EXPERIMENTAL_validators_ordered`). Untrusted: only
    /// useful as a checkpoint's `current_bps`.
    pub async fn validators_ordered(&self, block: &CryptoHash) -> Result<Vec<ValidatorStake>, RpcError> {
        let v: Vec<ValidatorStakeView> =
            self.call("EXPERIMENTAL_validators_ordered", json!({ "block_id": block })).await?;
        Ok(views::validators(&v)?)
    }

    /// `view_state` with proof for keys under `prefix` in `account`'s
    /// storage, at the state after `block`.
    pub async fn view_state_proof(
        &self,
        block: &CryptoHash,
        account: &str,
        prefix: &[u8],
    ) -> Result<ViewStateResult, RpcError> {
        let prefix_base64 = base64::engine::general_purpose::STANDARD.encode(prefix);
        self.call(
            "query",
            json!({
                "request_type": "view_state",
                "block_id": block,
                "account_id": account,
                "prefix_base64": prefix_base64,
                "include_proof": true,
            }),
        )
        .await
    }

    /// Fetch a proof for `keys` of `account`'s storage against `head`.
    ///
    /// The state committed in `head` is the state after `head`'s parent, so
    /// the query goes to the parent. The shard is the one whose root is
    /// among the proof's nodes.
    pub async fn contract_state_proof(
        &self,
        head: &Head,
        account: &str,
        keys: &[&[u8]],
    ) -> Result<ContractStateProof, RpcError> {
        let block = self.block(&head.hash).await?;
        let shard_state_roots: Vec<CryptoHash> = block.chunks.iter().map(|c| c.prev_state_root).collect();
        let mut items = Vec::new();
        for key in keys {
            items.extend(self.view_state_proof(&head.prev_hash, account, key).await?.proof_items()?);
        }
        let hashes: std::collections::HashSet<CryptoHash> =
            items.iter().map(|b| CryptoHash::hash(b)).collect();
        let shard_index =
            shard_state_roots.iter().position(|r| hashes.contains(r)).ok_or(RpcError::NoShard(head.hash))?;
        Ok(ContractStateProof { block_hash: head.hash, shard_state_roots, shard_index, items })
    }
}
