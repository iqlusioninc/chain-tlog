//! Validation rules every backend applies before accepting a record.
//!
//! [`check`] is pure: it reads backend state through [`LogView`] and returns
//! the [`Effect`] the backend must apply, or why the record is rejected. The
//! NEAR contract implements `LogView` over contract storage and panics on
//! rejection. The Celestia follower implements it over [`crate::LogState`]
//! and skips rejected blobs, since anyone can post to a namespace.
//!
//! Keeping one implementation of the rules is what makes the two backends
//! the same log: given the same sequence of records, they reach the same
//! state.

use crate::sig::SignatureVerifier;
use crate::statement::{LogConfig, Publish, Record, RegistryOp, RevocationReason, Statement};
use crate::{EntryId, LogId, PublicKey};

/// What a backend must know about an existing entry to validate a revocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryMeta {
    /// Publisher of the entry.
    pub publisher: PublicKey,
    /// Whether it is already revoked.
    pub revoked: bool,
}

/// Read access to backend state.
pub trait LogView {
    /// Whether `key` is currently a registered publisher.
    fn is_publisher(&self, key: &PublicKey) -> bool;
    /// Existing entry, if any.
    fn entry(&self, id: &EntryId) -> Option<EntryMeta>;
    /// Sequence number the next registry update must carry.
    fn next_registry_seq(&self) -> u64;
}

/// State change to apply for an accepted record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Insert a new active entry.
    Published {
        /// Its id.
        entry_id: EntryId,
        /// The statement. The payload, if attached, has been checked against
        /// it and is still in the record; it isn't copied here, because
        /// copying a 1.5 MiB payload costs real gas on NEAR.
        publish: Publish,
    },
    /// Mark an entry revoked.
    Revoked {
        /// Entry id.
        entry_id: EntryId,
        /// Reason code.
        reason: RevocationReason,
        /// Who revoked it.
        revoker: PublicKey,
    },
    /// Add a publisher and bump the registry sequence.
    PublisherAdded {
        /// Key.
        key: PublicKey,
        /// Label.
        label: String,
    },
    /// Remove a publisher and bump the registry sequence.
    PublisherRemoved {
        /// Key.
        key: PublicKey,
    },
}

/// Why a record was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Statement is for a different log.
    WrongLog {
        /// This backend's log.
        expected: LogId,
        /// The statement's log.
        got: LogId,
    },
    /// Signature does not verify against the required signer.
    BadSignature,
    /// Publisher is not registered.
    UnknownPublisher,
    /// An entry with this id already exists.
    DuplicateEntry,
    /// Revocation targets an entry this backend does not have.
    UnknownEntry,
    /// Entry already revoked.
    AlreadyRevoked,
    /// Revoker is neither the entry's (still registered) publisher nor the admin.
    NotAuthorized,
    /// Registry update out of sequence.
    BadRegistrySeq {
        /// Sequence the backend expects.
        expected: u64,
        /// Sequence in the update.
        got: u64,
    },
    /// Adding a key that is already a publisher.
    AlreadyPublisher,
    /// Removing a key that is not a publisher.
    NotPublisher,
    /// The admin key cannot also be a publisher.
    AdminCannotPublish,
    /// Payload attached to a non-publish statement, or it does not match
    /// the statement's hash and length.
    PayloadMismatch,
}

/// Validate `record` against backend state.
///
/// There is no payload size limit here. Each chain enforces its own
/// (NEAR's transaction size, Celestia's blob size), and a backend that
/// stores payloads decides separately what to keep. Rejecting on size here
/// would make the rules differ between backends.
pub fn check(
    config: &LogConfig,
    log_id: &LogId,
    view: &impl LogView,
    sigv: &impl SignatureVerifier,
    record: &Record,
) -> Result<Effect, Reject> {
    let st = &record.signed.statement;

    if st.log_id() != log_id {
        return Err(Reject::WrongLog { expected: *log_id, got: *st.log_id() });
    }

    if !sigv.verify(st.signer(config), &st.signing_bytes(), &record.signed.signature) {
        return Err(Reject::BadSignature);
    }

    if !record.payload_matches_with(|d| sigv.sha256(d)) {
        return Err(Reject::PayloadMismatch);
    }

    match st {
        Statement::Publish(p) => {
            if !view.is_publisher(&p.publisher) {
                return Err(Reject::UnknownPublisher);
            }
            let entry_id = p.entry_id();
            if view.entry(&entry_id).is_some() {
                return Err(Reject::DuplicateEntry);
            }
            Ok(Effect::Published { entry_id, publish: p.clone() })
        }
        Statement::Revoke(r) => {
            let meta = view.entry(&r.entry_id).ok_or(Reject::UnknownEntry)?;
            if meta.revoked {
                return Err(Reject::AlreadyRevoked);
            }
            let by_admin = r.revoker == config.admin;
            let by_publisher = r.revoker == meta.publisher && view.is_publisher(&r.revoker);
            if !(by_admin || by_publisher) {
                return Err(Reject::NotAuthorized);
            }
            Ok(Effect::Revoked { entry_id: r.entry_id, reason: r.reason, revoker: r.revoker })
        }
        Statement::Registry(u) => {
            let expected = view.next_registry_seq();
            if u.seq != expected {
                return Err(Reject::BadRegistrySeq { expected, got: u.seq });
            }
            match &u.op {
                RegistryOp::AddPublisher { key, label } => {
                    if *key == config.admin {
                        return Err(Reject::AdminCannotPublish);
                    }
                    if view.is_publisher(key) {
                        return Err(Reject::AlreadyPublisher);
                    }
                    Ok(Effect::PublisherAdded { key: *key, label: label.clone() })
                }
                RegistryOp::RemovePublisher { key } => {
                    if !view.is_publisher(key) {
                        return Err(Reject::NotPublisher);
                    }
                    Ok(Effect::PublisherRemoved { key: *key })
                }
            }
        }
    }
}
