//! NEAR JSON-RPC views, and conversion into the types this crate checks.
//!
//! Parsing a view proves nothing. Hashes the RPC reports (a block's `hash`
//! field, for example) are ignored; the verifier computes its own.

use base64::Engine as _;
use serde::Deserialize;

use crate::hash::CryptoHash;
use crate::types::{BlockHeaderInnerLite, LightClientBlock, NearPublicKey, NearSignature, ValidatorStake};

/// A view could not be converted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("malformed RPC view: {0}")]
pub struct ViewError(pub String);

fn err(s: impl Into<String>) -> ViewError {
    ViewError(s.into())
}

fn split_key(s: &str) -> Result<(&str, Vec<u8>), ViewError> {
    let (ty, data) = s.split_once(':').ok_or_else(|| err(format!("key without type: {s}")))?;
    let bytes = bs58::decode(data).into_vec().map_err(|_| err(format!("bad base58: {s}")))?;
    Ok((ty, bytes))
}

/// Parse `"ed25519:<base58>"` or `"secp256k1:<base58>"`.
pub fn parse_public_key(s: &str) -> Result<NearPublicKey, ViewError> {
    match split_key(s)? {
        ("ed25519", b) => Ok(NearPublicKey::Ed25519(b.try_into().map_err(|_| err("ed25519 key length"))?)),
        ("secp256k1", b) => {
            Ok(NearPublicKey::Secp256k1(b.try_into().map_err(|_| err("secp256k1 key length"))?))
        }
        (t, _) => Err(err(format!("unknown key type {t}"))),
    }
}

/// Parse `"ed25519:<base58>"` or `"secp256k1:<base58>"`.
pub fn parse_signature(s: &str) -> Result<NearSignature, ViewError> {
    match split_key(s)? {
        ("ed25519", b) => Ok(NearSignature::Ed25519(b.try_into().map_err(|_| err("ed25519 sig length"))?)),
        ("secp256k1", b) => {
            Ok(NearSignature::Secp256k1(b.try_into().map_err(|_| err("secp256k1 sig length"))?))
        }
        (t, _) => Err(err(format!("unknown signature type {t}"))),
    }
}

/// `BlockHeaderInnerLiteView`.
#[derive(Clone, Debug, Deserialize)]
#[allow(missing_docs)]
pub struct InnerLiteView {
    pub height: u64,
    pub epoch_id: CryptoHash,
    pub next_epoch_id: CryptoHash,
    pub prev_state_root: CryptoHash,
    pub outcome_root: CryptoHash,
    pub timestamp_nanosec: String,
    pub next_bp_hash: CryptoHash,
    pub block_merkle_root: CryptoHash,
}

impl TryFrom<&InnerLiteView> for BlockHeaderInnerLite {
    type Error = ViewError;
    fn try_from(v: &InnerLiteView) -> Result<Self, ViewError> {
        Ok(Self {
            height: v.height,
            epoch_id: v.epoch_id,
            next_epoch_id: v.next_epoch_id,
            prev_state_root: v.prev_state_root,
            outcome_root: v.outcome_root,
            timestamp: v.timestamp_nanosec.parse().map_err(|_| err("timestamp_nanosec"))?,
            next_bp_hash: v.next_bp_hash,
            block_merkle_root: v.block_merkle_root,
        })
    }
}

/// `ValidatorStakeView`.
#[derive(Clone, Debug, Deserialize)]
#[allow(missing_docs)]
pub struct ValidatorStakeView {
    pub account_id: String,
    pub public_key: String,
    pub stake: String,
    #[serde(default)]
    pub validator_stake_struct_version: Option<String>,
}

impl TryFrom<&ValidatorStakeView> for ValidatorStake {
    type Error = ViewError;
    fn try_from(v: &ValidatorStakeView) -> Result<Self, ViewError> {
        match v.validator_stake_struct_version.as_deref() {
            None | Some("V1") => {}
            Some(other) => return Err(err(format!("validator stake version {other}"))),
        }
        Ok(ValidatorStake::V1 {
            account_id: v.account_id.clone(),
            public_key: parse_public_key(&v.public_key)?,
            stake: v.stake.parse().map_err(|_| err("stake"))?,
        })
    }
}

/// Convert a list of validator views.
pub fn validators(v: &[ValidatorStakeView]) -> Result<Vec<ValidatorStake>, ViewError> {
    v.iter().map(ValidatorStake::try_from).collect()
}

/// `LightClientBlockView`.
#[derive(Clone, Debug, Deserialize)]
#[allow(missing_docs)]
pub struct LightClientBlockView {
    pub prev_block_hash: CryptoHash,
    pub next_block_inner_hash: CryptoHash,
    pub inner_lite: InnerLiteView,
    pub inner_rest_hash: CryptoHash,
    pub next_bps: Option<Vec<ValidatorStakeView>>,
    pub approvals_after_next: Vec<Option<String>>,
}

impl TryFrom<&LightClientBlockView> for LightClientBlock {
    type Error = ViewError;
    fn try_from(v: &LightClientBlockView) -> Result<Self, ViewError> {
        Ok(Self {
            prev_block_hash: v.prev_block_hash,
            next_block_inner_hash: v.next_block_inner_hash,
            inner_lite: (&v.inner_lite).try_into()?,
            inner_rest_hash: v.inner_rest_hash,
            next_bps: v.next_bps.as_deref().map(validators).transpose()?,
            approvals_after_next: v
                .approvals_after_next
                .iter()
                .map(|a| a.as_deref().map(parse_signature).transpose())
                .collect::<Result<_, _>>()?,
        })
    }
}

/// The parts of a `BlockView` a state proof needs.
#[derive(Clone, Debug, Deserialize)]
#[allow(missing_docs)]
pub struct BlockView {
    pub header: BlockHeaderView,
    pub chunks: Vec<ChunkHeaderView>,
}

/// The parts of a `BlockHeaderView` this crate reads.
#[derive(Clone, Debug, Deserialize)]
#[allow(missing_docs)]
pub struct BlockHeaderView {
    pub height: u64,
    pub hash: CryptoHash,
    pub prev_hash: CryptoHash,
    pub epoch_id: CryptoHash,
}

/// The parts of a `ChunkHeaderView` this crate reads.
#[derive(Clone, Debug, Deserialize)]
#[allow(missing_docs)]
pub struct ChunkHeaderView {
    pub shard_id: u64,
    pub prev_state_root: CryptoHash,
    pub height_created: u64,
    pub height_included: u64,
}

/// One value in a `view_state` result.
#[derive(Clone, Debug, Deserialize)]
#[allow(missing_docs)]
pub struct StateItemView {
    pub key: String,
    pub value: String,
}

/// `view_state` result.
#[derive(Clone, Debug, Deserialize)]
#[allow(missing_docs)]
pub struct ViewStateResult {
    #[serde(default)]
    pub values: Vec<StateItemView>,
    #[serde(default)]
    pub proof: Vec<String>,
    pub block_hash: CryptoHash,
    pub block_height: u64,
}

impl ViewStateResult {
    /// Decoded proof items plus the returned values. Values are added
    /// to the proof map by hash, so they only fill in what the trie nodes
    /// already commit to; nothing here is trusted.
    pub fn proof_items(&self) -> Result<Vec<Vec<u8>>, ViewError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        self.proof
            .iter()
            .chain(self.values.iter().map(|v| &v.value))
            .map(|p| b64.decode(p).map_err(|_| err("proof base64")))
            .collect()
    }
}
