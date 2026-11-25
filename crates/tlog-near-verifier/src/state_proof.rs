//! Contract state proofs against a verified head.
//!
//! A verified head `H` commits, in `inner_lite.prev_state_root`, to the
//! merkle root ([`crate::merkle`]) of the `prev_state_root` of every chunk
//! header in `H`, in shard order. For a shard whose chunk in `H` is new,
//! that is the shard's state after `H`'s parent block. A proof is then:
//!
//! 1. every shard's `prev_state_root` from `H`'s chunk headers, which must
//!    merklize to `H.inner_lite.prev_state_root`;
//! 2. which shard holds the log contract;
//! 3. trie nodes for the keys being proven, against that shard's root.
//!
//! The shard index is not trusted. A wrong shard cannot make the log look
//! empty, because [`crate::entry::observe_entry`] requires the contract's
//! root state (and, if configured, its account record) to be present in the
//! same root.

use crate::hash::CryptoHash;
use crate::layout::{access_keys_trie_prefix, account_trie_key, contract_data_trie_key, decode_account};
use crate::light_client::Head;
use crate::merkle::merkle_root;
use crate::trie::{TrieError, TrieProof};

/// An unverified state proof, as fetched from an RPC node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContractStateProof {
    /// The head this proof is against.
    pub block_hash: CryptoHash,
    /// `prev_state_root` of each chunk header in the head block, in shard order.
    pub shard_state_roots: Vec<CryptoHash>,
    /// Index into `shard_state_roots` of the contract's shard.
    pub shard_index: usize,
    /// Trie nodes and values.
    pub items: Vec<Vec<u8>>,
}

/// Why a state proof was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateProofError {
    /// The proof is for a different block than the verified head.
    #[error("proof is for block {proof}, head is {head}")]
    WrongBlock {
        /// Block in the proof.
        proof: CryptoHash,
        /// Verified head.
        head: CryptoHash,
    },
    /// The shard roots do not merklize to the head's `prev_state_root`.
    #[error("shard state roots do not match the head's prev_state_root")]
    ShardRoots,
    /// Shard index out of range.
    #[error("shard index {0} out of range")]
    ShardIndex(usize),
    /// The trie walk failed.
    #[error("trie proof: {0}")]
    Trie(#[from] TrieError),
    /// The account record is in a format this verifier does not know.
    #[error("unsupported or malformed account record")]
    Account,
}

/// A state proof checked against a head: lookups are answered against the
/// contract shard's verified state root.
#[derive(Clone, Debug)]
pub struct VerifiedState {
    root: CryptoHash,
    proof: TrieProof,
    account_id: String,
}

impl ContractStateProof {
    /// Check the shard root against `head` and return a view for
    /// `account_id`'s state.
    pub fn verify(&self, head: &Head, account_id: &str) -> Result<VerifiedState, StateProofError> {
        if self.block_hash != head.hash {
            return Err(StateProofError::WrongBlock { proof: self.block_hash, head: head.hash });
        }
        if merkle_root(&self.shard_state_roots) != head.inner_lite.prev_state_root {
            return Err(StateProofError::ShardRoots);
        }
        let root = *self
            .shard_state_roots
            .get(self.shard_index)
            .ok_or(StateProofError::ShardIndex(self.shard_index))?;
        Ok(VerifiedState {
            root,
            proof: TrieProof::new(self.items.iter().cloned()),
            account_id: account_id.to_owned(),
        })
    }
}

impl VerifiedState {
    /// The shard state root lookups are checked against.
    pub fn root(&self) -> &CryptoHash {
        &self.root
    }

    /// Contract storage value at `key`, or `None` if proven absent.
    pub fn contract_data(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateProofError> {
        Ok(self.proof.get(&self.root, &contract_data_trie_key(&self.account_id, key))?)
    }

    /// The account's code hash, or `None` if the account is proven absent.
    pub fn code_hash(&self) -> Result<Option<CryptoHash>, StateProofError> {
        match self.proof.get(&self.root, &account_trie_key(&self.account_id))? {
            None => Ok(None),
            Some(v) => Ok(Some(decode_account(&v).ok_or(StateProofError::Account)?.code_hash)),
        }
    }

    /// True if the account has no access keys at all (the contract is
    /// locked). Stock RPC does not serve proofs for access keys; see the
    /// design note.
    pub fn has_no_access_keys(&self) -> Result<bool, StateProofError> {
        Ok(self.proof.prefix_is_empty(&self.root, &access_keys_trie_prefix(&self.account_id))?)
    }
}
