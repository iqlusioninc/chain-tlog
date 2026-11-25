//! chain-tlog Celestia backend.
//!
//! The log lives in one Celestia namespace. Every blob in the namespace is
//! a candidate [`Record`], encoded exactly as for the NEAR contract. The log
//! is the deterministic fold of those blobs, in order, through the shared
//! [`tlog_core::rules`]. Because anyone can post to a namespace, invalid or
//! undecodable blobs are skipped rather than trusted: authority comes only
//! from signatures checked against the admin-managed publisher registry,
//! which itself lives in the namespace as admin-signed records.
//!
//! A log on Celestia is identified by `(LogConfig, namespace, start_height)`.
//! Blobs below `start_height` are ignored.
//!
//! - [`follower`]: the namespace fold and per-entry observations.
//! - [`proof`]: checking namespace completeness and absence proofs against
//!   a verified header, and parsing the shares into blobs.
//! - [`source`]: what a verifier needs from a Celestia light client, and a
//!   sync loop over it.
//! - `lumina` (feature `lumina`): that source backed by an embedded Lumina node.
//! - `publisher` (feature `rpc`): posting records through celestia-node RPC.

#![forbid(unsafe_code)]

pub mod follower;
pub mod proof;
pub mod source;

#[cfg(test)]
mod testkit;
#[cfg(test)]
mod verify_tests;

#[cfg(feature = "lumina")]
pub mod lumina;

#[cfg(feature = "rpc")]
pub mod publisher;

use celestia_types::nmt::Namespace;
use celestia_types::Blob;
use tlog_core::statement::Record;
use tlog_core::LogId;

pub use follower::{FollowError, HeightReport, NamespaceFollower, Rejection};
pub use proof::{items_from_namespace_data, verify_namespace_data, NamespaceItem, ProofError};
pub use source::{sync_to_tip, SourceError, Stalled, SyncError, SyncOutcome, VerifiedNamespaceSource};

/// Length of a version-0 namespace id.
pub const NAMESPACE_V0_LEN: usize = 10;

/// Default namespace for a log: version 0, id = first 10 bytes of the log id.
///
/// Deriving it from the log id means a verifier only needs the log config to
/// find the namespace. A squatter can still post into it, which costs them
/// fees and costs followers bandwidth but cannot change the log.
pub fn default_namespace(log_id: &LogId) -> Namespace {
    Namespace::new_v0(&log_id.as_bytes()[..NAMESPACE_V0_LEN]).expect("10-byte v0 namespace id is valid")
}

/// Wrap an encoded record as a blob in `namespace`. Uses share version 0
/// (no signer field): authority comes from the record's own signature.
pub fn record_blob(namespace: Namespace, record: &Record) -> Result<Blob, celestia_types::Error> {
    Blob::new(namespace, record.encode(), None)
}
