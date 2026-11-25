//! NEAR consensus types the light client hashes and checks.
//!
//! The borsh layouts here must match nearcore byte for byte, because block
//! hashes and the block producer hash are computed over them.

use borsh::{BorshDeserialize, BorshSerialize};

use crate::hash::CryptoHash;

/// Epoch identifier. In NEAR it is the hash of a block in the epoch before
/// the previous one.
pub type EpochId = CryptoHash;

/// `BlockHeaderInnerLite`: the part of a header the light client sees in
/// full. Field order is the borsh layout.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BlockHeaderInnerLite {
    /// Block height.
    pub height: u64,
    /// Epoch this block is in.
    pub epoch_id: EpochId,
    /// Epoch after this one.
    pub next_epoch_id: EpochId,
    /// Merkle root over the shards' `prev_state_root`s in this block's chunk
    /// headers. See [`crate::state_proof`].
    pub prev_state_root: CryptoHash,
    /// Root of execution outcomes.
    pub outcome_root: CryptoHash,
    /// Block timestamp, Unix nanoseconds.
    pub timestamp: u64,
    /// `SHA-256(borsh(next epoch's block producers))`.
    pub next_bp_hash: CryptoHash,
    /// Root of the merkle tree of all previous block hashes.
    pub block_merkle_root: CryptoHash,
}

/// A validator public key.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum NearPublicKey {
    /// Ed25519.
    Ed25519([u8; 32]),
    /// Secp256k1, uncompressed without the 0x04 prefix.
    Secp256k1([u8; 64]),
}

/// A validator signature.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum NearSignature {
    /// Ed25519.
    Ed25519([u8; 64]),
    /// Secp256k1 recoverable signature.
    Secp256k1([u8; 65]),
}

impl NearSignature {
    /// Verify over `msg`. Secp256k1 validator keys are not supported and
    /// never verify; a producer with such a key counts toward total stake
    /// but never toward approvals, so the error is on the safe side.
    pub fn verify(&self, msg: &[u8], key: &NearPublicKey) -> bool {
        match (self, key) {
            (NearSignature::Ed25519(sig), NearPublicKey::Ed25519(pk)) => {
                let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pk) else {
                    return false;
                };
                let sig = ed25519_dalek::Signature::from_bytes(sig);
                ed25519_dalek::Verifier::verify(&vk, msg, &sig).is_ok()
            }
            _ => false,
        }
    }
}

/// `ValidatorStake`, a versioned enum. Only V1 exists. The version tag is
/// part of the borsh encoding, and so of `next_bp_hash`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ValidatorStake {
    /// Version 1.
    V1 {
        /// Validator account.
        account_id: String,
        /// Block-signing key.
        public_key: NearPublicKey,
        /// Stake, yoctoNEAR.
        stake: u128,
    },
}

impl ValidatorStake {
    /// Signing key.
    pub fn public_key(&self) -> &NearPublicKey {
        match self {
            ValidatorStake::V1 { public_key, .. } => public_key,
        }
    }

    /// Stake, yoctoNEAR.
    pub fn stake(&self) -> u128 {
        match self {
            ValidatorStake::V1 { stake, .. } => *stake,
        }
    }

    /// Account id.
    pub fn account_id(&self) -> &str {
        match self {
            ValidatorStake::V1 { account_id, .. } => account_id,
        }
    }
}

/// `SHA-256(borsh(bps))`, which a header commits to as `next_bp_hash`.
pub fn bp_hash(bps: &[ValidatorStake]) -> CryptoHash {
    CryptoHash::hash_borsh(&bps.to_vec())
}

/// `ApprovalInner`. Producers sign `borsh(ApprovalInner) || le_u64(target height)`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ApprovalInner {
    /// Endorse the block with this hash.
    Endorsement(CryptoHash),
    /// Skip to a height.
    Skip(u64),
}

/// `LightClientBlockView`, as returned by `next_light_client_block`.
///
/// The fields are untrusted until [`crate::LightClient::update`] accepts the
/// block. The block hash is computed from them, never read from the RPC.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct LightClientBlock {
    /// Parent block hash.
    pub prev_block_hash: CryptoHash,
    /// `combine(hash(borsh(inner_lite)), inner_rest_hash)` of the next block.
    pub next_block_inner_hash: CryptoHash,
    /// Header fields.
    pub inner_lite: BlockHeaderInnerLite,
    /// Hash of the rest of the header.
    pub inner_rest_hash: CryptoHash,
    /// Block producers of the next epoch. Required when this block starts
    /// tracking a new epoch.
    pub next_bps: Option<Vec<ValidatorStake>>,
    /// Signatures on the block after the next one, in block producer order.
    pub approvals_after_next: Vec<Option<NearSignature>>,
}

impl LightClientBlock {
    /// This block's hash:
    /// `combine(combine(hash(borsh(inner_lite)), inner_rest_hash), prev_block_hash)`.
    pub fn hash(&self) -> CryptoHash {
        let inner = CryptoHash::combine(&CryptoHash::hash_borsh(&self.inner_lite), &self.inner_rest_hash);
        CryptoHash::combine(&inner, &self.prev_block_hash)
    }

    /// The next block's hash.
    pub fn next_block_hash(&self) -> CryptoHash {
        CryptoHash::combine(&self.next_block_inner_hash, &self.hash())
    }

    /// Bytes the block producers signed in `approvals_after_next`: an
    /// endorsement of the next block, at this block's height plus two.
    pub fn approval_message(&self) -> Vec<u8> {
        let mut msg = borsh::to_vec(&ApprovalInner::Endorsement(self.next_block_hash())).expect("borsh");
        msg.extend_from_slice(&(self.inner_lite.height + 2).to_le_bytes());
        msg
    }
}
