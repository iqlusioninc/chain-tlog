//! In-memory log fold.
//!
//! Applies records in backend order and answers status queries. The Celestia
//! verifier uses this to follow a namespace; tests use it as the reference
//! model the NEAR contract must agree with.

use std::collections::BTreeMap;

use crate::rules::{check, Effect, EntryMeta, LogView, Reject};
use crate::sig::SignatureVerifier;
use crate::statement::{LogConfig, Publish, Record, RevocationReason};
use crate::status::{ChainTime, EntryStatus, Position};
use crate::{EntryId, LogId, PublicKey};

/// One entry in the fold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEntry {
    /// The publish statement.
    pub publish: Publish,
    /// Where it sits in the backend order.
    pub position: Position,
    /// When it was published.
    pub published: ChainTime,
    /// Revocation, if any.
    pub revoked: Option<(ChainTime, RevocationReason)>,
}

/// Errors applying a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyError {
    /// The record failed validation; backend state is unchanged.
    Rejected(Reject),
    /// Records were fed out of order. This is a caller bug.
    OutOfOrder {
        /// Last applied position.
        last: Position,
        /// Position given.
        got: Position,
    },
}

/// Deterministic fold over one backend's records.
#[derive(Clone, Debug)]
pub struct LogState {
    config: LogConfig,
    log_id: LogId,
    publishers: BTreeMap<PublicKey, String>,
    registry_seq: u64,
    entries: BTreeMap<EntryId, StoredEntry>,
    last: Option<Position>,
}

impl LogState {
    /// Empty log. No publishers until the admin adds some.
    pub fn new(config: LogConfig) -> Self {
        let log_id = config.log_id();
        Self {
            config,
            log_id,
            publishers: BTreeMap::new(),
            registry_seq: 0,
            entries: BTreeMap::new(),
            last: None,
        }
    }

    /// The log's config.
    pub fn config(&self) -> &LogConfig {
        &self.config
    }

    /// The log's id.
    pub fn log_id(&self) -> &LogId {
        &self.log_id
    }

    /// Last applied position (accepted or rejected).
    pub fn last_position(&self) -> Option<Position> {
        self.last
    }

    /// Entry by id.
    pub fn entry(&self, id: &EntryId) -> Option<&StoredEntry> {
        self.entries.get(id)
    }

    /// Number of entries ever published.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if nothing has been published.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Status of an entry as of everything applied so far.
    pub fn status(&self, id: &EntryId) -> EntryStatus {
        match self.entries.get(id) {
            None => EntryStatus::Absent,
            Some(e) => match e.revoked {
                None => EntryStatus::Active { published: e.published },
                Some((revoked, reason)) => EntryStatus::Revoked { published: e.published, revoked, reason },
            },
        }
    }

    /// Validate and apply one record at `position`.
    ///
    /// Positions must strictly increase. A rejected record still advances
    /// the position, because the backend did order it.
    pub fn apply(
        &mut self,
        position: Position,
        time: ChainTime,
        record: &Record,
        sigv: &impl SignatureVerifier,
    ) -> Result<Effect, ApplyError> {
        if let Some(last) = self.last {
            if position <= last {
                return Err(ApplyError::OutOfOrder { last, got: position });
            }
        }
        self.last = Some(position);

        let effect = check(&self.config, &self.log_id, self, sigv, record).map_err(ApplyError::Rejected)?;

        match &effect {
            Effect::Published { entry_id, publish, .. } => {
                self.entries.insert(
                    *entry_id,
                    StoredEntry { publish: publish.clone(), position, published: time, revoked: None },
                );
            }
            Effect::Revoked { entry_id, reason, .. } => {
                let e = self.entries.get_mut(entry_id).expect("checked by rules");
                e.revoked = Some((time, *reason));
            }
            Effect::PublisherAdded { key, label } => {
                self.publishers.insert(*key, label.clone());
                self.registry_seq += 1;
            }
            Effect::PublisherRemoved { key } => {
                self.publishers.remove(key);
                self.registry_seq += 1;
            }
        }
        Ok(effect)
    }
}

impl LogView for LogState {
    fn is_publisher(&self, key: &PublicKey) -> bool {
        self.publishers.contains_key(key)
    }

    fn entry(&self, id: &EntryId) -> Option<EntryMeta> {
        self.entries
            .get(id)
            .map(|e| EntryMeta { publisher: e.publish.publisher, revoked: e.revoked.is_some() })
    }

    fn next_registry_seq(&self) -> u64 {
        self.registry_seq
    }
}

#[cfg(all(test, feature = "dalek"))]
mod tests {
    use super::*;
    use crate::sig::Ed25519Dalek;
    use crate::statement::test_support::*;
    use crate::statement::{RegistryOp, RegistryUpdate, Revoke, Statement};

    struct Fixture {
        st: LogState,
        admin: ed25519_dalek::SigningKey,
        publ: ed25519_dalek::SigningKey,
        h: u64,
    }

    impl Fixture {
        fn new() -> Self {
            let admin = key(1);
            let cfg = LogConfig { name: "test".into(), admin: pk(&admin) };
            Self { st: LogState::new(cfg), admin, publ: key(2), h: 0 }
        }

        fn id(&self) -> LogId {
            *self.st.log_id()
        }

        fn apply(&mut self, r: &Record) -> Result<Effect, ApplyError> {
            self.h += 1;
            let t = ChainTime { height: self.h, unix_ns: self.h * 1_000_000_000 };
            self.st.apply(Position { height: self.h, index: 0 }, t, r, &Ed25519Dalek)
        }

        fn registry(&mut self, seq: u64, op: RegistryOp) -> Result<Effect, ApplyError> {
            let r =
                record(&self.admin, Statement::Registry(RegistryUpdate { log_id: self.id(), seq, op }), None);
            self.apply(&r)
        }

        fn add_publisher(&mut self) {
            let key = pk(&self.publ);
            self.registry(0, RegistryOp::AddPublisher { key, label: "p".into() }).unwrap();
        }
    }

    fn rejected(r: Result<Effect, ApplyError>) -> Reject {
        match r {
            Err(ApplyError::Rejected(e)) => e,
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn publish_then_revoke_by_publisher() {
        let mut f = Fixture::new();
        f.add_publisher();
        let p = publish(f.id(), &f.publ, "example.com", b"cert", 1);
        let id = p.entry_id();
        f.apply(&record(&f.publ.clone(), Statement::Publish(p), Some(b"cert".to_vec()))).unwrap();
        assert!(matches!(f.st.status(&id), EntryStatus::Active { .. }));

        let rv = Revoke {
            log_id: f.id(),
            entry_id: id,
            revoker: pk(&f.publ),
            reason: RevocationReason::KeyCompromise,
        };
        f.apply(&record(&f.publ.clone(), Statement::Revoke(rv.clone()), None)).unwrap();
        assert!(matches!(
            f.st.status(&id),
            EntryStatus::Revoked { reason: RevocationReason::KeyCompromise, .. }
        ));

        assert_eq!(
            rejected(f.apply(&record(&f.publ.clone(), Statement::Revoke(rv), None))),
            Reject::AlreadyRevoked
        );
    }

    #[test]
    fn unregistered_publisher_rejected() {
        let mut f = Fixture::new();
        let p = publish_detached(f.id(), &f.publ, "s", b"x", 1);
        assert_eq!(
            rejected(f.apply(&record(&f.publ.clone(), Statement::Publish(p), None))),
            Reject::UnknownPublisher
        );
    }

    #[test]
    fn bad_signature_rejected() {
        let mut f = Fixture::new();
        f.add_publisher();
        let p = publish(f.id(), &f.publ, "s", b"x", 1);
        // Signed by the wrong key.
        let r = record(&key(9), Statement::Publish(p), None);
        assert_eq!(rejected(f.apply(&r)), Reject::BadSignature);
    }

    #[test]
    fn wrong_log_rejected() {
        let mut f = Fixture::new();
        f.add_publisher();
        let other = LogId([7; 32]);
        let p = publish(other, &f.publ, "s", b"x", 1);
        assert!(matches!(
            rejected(f.apply(&record(&f.publ.clone(), Statement::Publish(p), None))),
            Reject::WrongLog { .. }
        ));
    }

    #[test]
    fn duplicate_and_payload_checks() {
        let mut f = Fixture::new();
        f.add_publisher();
        let p = publish_detached(f.id(), &f.publ, "s", b"x", 1);
        let publ = f.publ.clone();
        f.apply(&record(&publ, Statement::Publish(p.clone()), None)).unwrap();
        assert_eq!(rejected(f.apply(&record(&publ, Statement::Publish(p), None))), Reject::DuplicateEntry);

        // Threat T5: a stripped copy of an attached publication is rejected,
        // so it cannot be logged ahead of the real record.
        let att = publish(f.id(), &publ, "s", b"x", 9);
        assert_eq!(
            rejected(f.apply(&record(&publ, Statement::Publish(att.clone()), None))),
            Reject::PayloadMismatch
        );
        f.apply(&record(&publ, Statement::Publish(att), Some(b"x".to_vec()))).unwrap();

        let p2 = publish(f.id(), &publ, "s", b"x", 2);
        assert_eq!(
            rejected(f.apply(&record(&publ, Statement::Publish(p2), Some(b"y".to_vec())))),
            Reject::PayloadMismatch
        );
    }

    #[test]
    fn registry_replay_is_rejected() {
        let mut f = Fixture::new();
        f.add_publisher();
        let key = pk(&f.publ);
        f.registry(1, RegistryOp::RemovePublisher { key }).unwrap();
        // Replaying the original seq-0 add must fail.
        assert_eq!(
            rejected(f.registry(0, RegistryOp::AddPublisher { key, label: "p".into() })),
            Reject::BadRegistrySeq { expected: 2, got: 0 }
        );
    }

    #[test]
    fn removed_publisher_cannot_revoke_but_admin_can() {
        let mut f = Fixture::new();
        f.add_publisher();
        let publ = f.publ.clone();
        let p = publish_detached(f.id(), &publ, "s", b"x", 1);
        let id = p.entry_id();
        f.apply(&record(&publ, Statement::Publish(p), None)).unwrap();
        f.registry(1, RegistryOp::RemovePublisher { key: pk(&publ) }).unwrap();

        let rv =
            Revoke { log_id: f.id(), entry_id: id, revoker: pk(&publ), reason: RevocationReason::Withdrawn };
        assert_eq!(rejected(f.apply(&record(&publ, Statement::Revoke(rv), None))), Reject::NotAuthorized);

        let admin = f.admin.clone();
        let rv = Revoke {
            log_id: f.id(),
            entry_id: id,
            revoker: pk(&admin),
            reason: RevocationReason::KeyCompromise,
        };
        f.apply(&record(&admin, Statement::Revoke(rv), None)).unwrap();
        assert!(matches!(f.st.status(&id), EntryStatus::Revoked { .. }));
    }

    #[test]
    fn out_of_order_is_an_error() {
        let mut f = Fixture::new();
        f.add_publisher();
        let publ = f.publ.clone();
        let p = publish(f.id(), &publ, "s", b"x", 1);
        let r = record(&publ, Statement::Publish(p), None);
        let t = ChainTime { height: 1, unix_ns: 0 };
        assert!(matches!(
            f.st.apply(Position { height: 1, index: 0 }, t, &r, &Ed25519Dalek),
            Err(ApplyError::OutOfOrder { .. })
        ));
    }
}
