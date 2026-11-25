//! NEAR light client: follows block producers across epochs and verifies
//! headers.
//!
//! This is `validate_and_update_head` from the NEAR spec's light client
//! section. A block is accepted when:
//!
//! 1. it is higher than the current head;
//! 2. its epoch is the head's epoch or the next one, and the block
//!    producers of that epoch are known;
//! 3. producers holding more than 2/3 of that epoch's stake signed an
//!    endorsement of the block after it ([`LightClientBlock::approval_message`]);
//! 4. if it carries `next_bps`, they hash to its `next_bp_hash`. A block
//!    that moves the head into the next epoch must carry them, which is how
//!    the client learns the producers of the epoch after.
//!
//! The light client needs a block from every epoch, because a block is only
//! accepted from the head's epoch or the one after. An online verifier
//! (a project assumption) syncs well within an epoch (about 12 hours on
//! mainnet). One that falls further behind needs a fresh checkpoint.

use std::collections::BTreeMap;

use crate::hash::CryptoHash;
use crate::types::{bp_hash, BlockHeaderInnerLite, EpochId, LightClientBlock, ValidatorStake};

/// The latest verified block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    /// Block hash, computed from the verified fields.
    pub hash: CryptoHash,
    /// Parent block hash.
    pub prev_hash: CryptoHash,
    /// Verified header fields.
    pub inner_lite: BlockHeaderInnerLite,
}

/// Why a block was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LightClientError {
    /// The checkpoint block does not hash to the trusted hash.
    #[error("checkpoint hash mismatch: expected {expected}, got {got}")]
    CheckpointHash {
        /// Trusted hash.
        expected: CryptoHash,
        /// Computed hash.
        got: CryptoHash,
    },
    /// Not higher than the head.
    #[error("block height {height} is not above head height {head}")]
    NotNewer {
        /// Block height.
        height: u64,
        /// Head height.
        head: u64,
    },
    /// Epoch is neither the head's nor the next.
    #[error("block epoch {0} is neither the head's epoch nor the next")]
    UnknownEpoch(EpochId),
    /// Block producers for the block's epoch are not known.
    #[error("block producers for epoch {0} are not known")]
    MissingBlockProducers(EpochId),
    /// A block that enters the next epoch did not carry `next_bps`.
    #[error("block enters a new epoch but carries no next_bps")]
    MissingNextBps,
    /// `next_bps` does not hash to `next_bp_hash`.
    #[error("next_bps does not match next_bp_hash")]
    NextBpsHash,
    /// An approval signature failed.
    #[error("invalid approval signature from {0}")]
    BadSignature(String),
    /// Not enough stake approved.
    #[error("approved stake {approved} of {total} is not above 2/3")]
    InsufficientStake {
        /// Stake that signed.
        approved: u128,
        /// Total epoch stake.
        total: u128,
    },
}

/// Light client state: the head and the block producers of the head's epoch
/// and the next.
#[derive(Clone, Debug)]
pub struct LightClient {
    head: Head,
    block_producers: BTreeMap<EpochId, Vec<ValidatorStake>>,
}

impl LightClient {
    /// Start from a checkpoint: a light-client block whose hash the user
    /// trusts (obtained out of band, like any light client's trust root).
    ///
    /// The block must carry `next_bps`, which are checked against its
    /// `next_bp_hash`. That lets the client accept blocks from the next
    /// epoch on. To also accept later blocks from the checkpoint's own
    /// epoch, pass that epoch's producers as `current_bps`. They are taken
    /// on trust, so they are part of the checkpoint.
    pub fn from_checkpoint(
        trusted_hash: CryptoHash,
        block: &LightClientBlock,
        current_bps: Option<Vec<ValidatorStake>>,
    ) -> Result<Self, LightClientError> {
        let got = block.hash();
        if got != trusted_hash {
            return Err(LightClientError::CheckpointHash { expected: trusted_hash, got });
        }
        let next_bps = block.next_bps.as_ref().ok_or(LightClientError::MissingNextBps)?;
        if bp_hash(next_bps) != block.inner_lite.next_bp_hash {
            return Err(LightClientError::NextBpsHash);
        }
        let mut block_producers = BTreeMap::new();
        block_producers.insert(block.inner_lite.next_epoch_id, next_bps.clone());
        if let Some(bps) = current_bps {
            block_producers.insert(block.inner_lite.epoch_id, bps);
        }
        Ok(Self {
            head: Head { hash: got, prev_hash: block.prev_block_hash, inner_lite: block.inner_lite.clone() },
            block_producers,
        })
    }

    /// The latest verified block.
    pub fn head(&self) -> &Head {
        &self.head
    }

    /// Block producers known for `epoch`.
    pub fn block_producers(&self, epoch: &EpochId) -> Option<&[ValidatorStake]> {
        self.block_producers.get(epoch).map(Vec::as_slice)
    }

    /// Check `block` and, if it passes, make it the head.
    pub fn update(&mut self, block: &LightClientBlock) -> Result<(), LightClientError> {
        let lite = &block.inner_lite;
        let head = &self.head.inner_lite;
        if lite.height <= head.height {
            return Err(LightClientError::NotNewer { height: lite.height, head: head.height });
        }
        if lite.epoch_id != head.epoch_id && lite.epoch_id != head.next_epoch_id {
            return Err(LightClientError::UnknownEpoch(lite.epoch_id));
        }
        if lite.epoch_id == head.next_epoch_id && block.next_bps.is_none() {
            return Err(LightClientError::MissingNextBps);
        }
        let bps = self
            .block_producers
            .get(&lite.epoch_id)
            .ok_or(LightClientError::MissingBlockProducers(lite.epoch_id))?;

        let msg = block.approval_message();
        let mut total: u128 = 0;
        let mut approved: u128 = 0;
        for (approval, bp) in block.approvals_after_next.iter().zip(bps.iter()) {
            total = total.saturating_add(bp.stake());
            let Some(sig) = approval else { continue };
            if !sig.verify(&msg, bp.public_key()) {
                return Err(LightClientError::BadSignature(bp.account_id().to_owned()));
            }
            approved = approved.saturating_add(bp.stake());
        }
        // Producers without an approval slot still count toward the total.
        for bp in bps.iter().skip(block.approvals_after_next.len()) {
            total = total.saturating_add(bp.stake());
        }
        // Spec: approved > floor(total * 2 / 3). u128 holds 2x NEAR's supply.
        if approved <= total.saturating_mul(2) / 3 {
            return Err(LightClientError::InsufficientStake { approved, total });
        }

        if let Some(next_bps) = &block.next_bps {
            if bp_hash(next_bps) != lite.next_bp_hash {
                return Err(LightClientError::NextBpsHash);
            }
        }

        self.head = Head { hash: block.hash(), prev_hash: block.prev_block_hash, inner_lite: lite.clone() };
        if let Some(next_bps) = &block.next_bps {
            self.block_producers.insert(lite.next_epoch_id, next_bps.clone());
        }
        let (cur, next) = (self.head.inner_lite.epoch_id, self.head.inner_lite.next_epoch_id);
        self.block_producers.retain(|e, _| *e == cur || *e == next);
        Ok(())
    }
}
