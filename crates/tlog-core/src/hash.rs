//! Domain-separated hashing.
//!
//! Every hash in the protocol is `SHA-256(tag || 0x00 || data)`, where `tag`
//! is one of the constants below. Tags carry the protocol version so that a
//! future format change cannot collide with v1 identifiers or signatures.

use sha2::{Digest, Sha256};

/// Tag for [`crate::LogId`] derivation.
pub const TAG_LOG_ID: &str = "chain-tlog/v1/log-id";
/// Tag for [`crate::EntryId`] derivation.
pub const TAG_ENTRY_ID: &str = "chain-tlog/v1/entry-id";
/// Tag prefixed to every signed statement.
pub const TAG_STATEMENT: &str = "chain-tlog/v1/statement";

/// `SHA-256(tag || 0x00 || data)`.
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag.as_bytes());
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

/// Plain SHA-256, used for payload content hashes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
