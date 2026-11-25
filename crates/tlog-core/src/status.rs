//! What a verifier learns about an entry from one backend.

use borsh::{BorshDeserialize, BorshSerialize};

use crate::statement::RevocationReason;

/// A backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum Backend {
    /// The NEAR contract.
    Near,
    /// The Celestia namespace.
    Celestia,
}

/// A point on a backend's chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub struct ChainTime {
    /// Block height.
    pub height: u64,
    /// Block timestamp, Unix nanoseconds, from the light-client-verified header.
    pub unix_ns: u64,
}

/// Total order of records within one backend.
///
/// On Celestia this is `(block height, index of the blob within the
/// namespace)`. On NEAR it is `(block height, contract-wide sequence number)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub struct Position {
    /// Block height.
    pub height: u64,
    /// Tie-breaker within the block.
    pub index: u64,
}

/// Status of an entry on one backend, as of that backend's verified head.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum EntryStatus {
    /// Published and not revoked.
    Active {
        /// When it was published.
        published: ChainTime,
    },
    /// Revoked. Revocation is irreversible.
    Revoked {
        /// When it was published.
        published: ChainTime,
        /// When it was revoked.
        revoked: ChainTime,
        /// Reason code.
        reason: RevocationReason,
    },
    /// Not in this backend's log as of the head.
    Absent,
}

/// A light-client-verified status of one entry on one backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    /// Which backend.
    pub backend: Backend,
    /// Entry status as of `head`.
    pub status: EntryStatus,
    /// The verified head the status was proven against.
    pub head: ChainTime,
}
