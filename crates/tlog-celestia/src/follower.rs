//! Folding a namespace into log state.

use celestia_types::nmt::Namespace;
use celestia_types::Blob;
use tlog_core::sig::Ed25519Dalek;
use tlog_core::state::ApplyError;
use tlog_core::statement::{DecodeError, LogConfig, Record};
use tlog_core::status::{Backend, ChainTime, Observation, Position};
use tlog_core::{Effect, EntryId, LogState, Reject};

/// Why a blob in the namespace did not change the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// Not a record.
    Decode(DecodeError),
    /// A record that failed validation.
    Rule(Reject),
}

/// Outcome of ingesting one height.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeightReport {
    /// Height ingested.
    pub height: u64,
    /// Records that changed the log.
    pub accepted: Vec<(Position, Effect)>,
    /// Blobs that did not.
    pub rejected: Vec<(Position, Rejection)>,
}

/// Errors from [`NamespaceFollower::ingest`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FollowError {
    /// Heights must be ingested one by one with no gaps. Skipping a height
    /// could skip a revocation.
    #[error("expected height {expected}, got {got}")]
    Gap {
        /// Next height the follower needs.
        expected: u64,
        /// Height given.
        got: u64,
    },
    /// A blob from another namespace was passed in.
    #[error("blob from a different namespace")]
    WrongNamespace,
}

/// Follows one log namespace from its start height.
///
/// The follower trusts its caller to hand it, for each height, the complete
/// and correct list of blobs in the namespace, verified against a
/// light-client-verified header. [`crate::source`] is where that comes from.
#[derive(Clone, Debug)]
pub struct NamespaceFollower {
    state: LogState,
    namespace: Namespace,
    next_height: u64,
    head: Option<ChainTime>,
}

impl NamespaceFollower {
    /// New follower for the log defined by `config`, in `namespace`,
    /// starting at `start_height`.
    pub fn new(config: LogConfig, namespace: Namespace, start_height: u64) -> Self {
        Self { state: LogState::new(config, None), namespace, next_height: start_height, head: None }
    }

    /// The namespace followed.
    pub fn namespace(&self) -> Namespace {
        self.namespace
    }

    /// Next height to ingest.
    pub fn next_height(&self) -> u64 {
        self.next_height
    }

    /// Last ingested height and its header time.
    pub fn head(&self) -> Option<ChainTime> {
        self.head
    }

    /// Log state as of [`Self::head`].
    pub fn state(&self) -> &LogState {
        &self.state
    }

    /// Ingest every blob of the namespace at `time.height`, in namespace order.
    pub fn ingest(&mut self, time: ChainTime, blobs: &[Blob]) -> Result<HeightReport, FollowError> {
        if time.height != self.next_height {
            return Err(FollowError::Gap { expected: self.next_height, got: time.height });
        }
        if blobs.iter().any(|b| b.namespace != self.namespace) {
            return Err(FollowError::WrongNamespace);
        }

        let mut report = HeightReport { height: time.height, ..Default::default() };
        for (i, blob) in blobs.iter().enumerate() {
            let pos = Position { height: time.height, index: i as u64 };
            let record = match Record::decode(&blob.data) {
                Ok(r) => r,
                Err(e) => {
                    report.rejected.push((pos, Rejection::Decode(e)));
                    continue;
                }
            };
            match self.state.apply(pos, time, &record, &Ed25519Dalek) {
                Ok(effect) => report.accepted.push((pos, effect)),
                Err(ApplyError::Rejected(r)) => report.rejected.push((pos, Rejection::Rule(r))),
                Err(ApplyError::OutOfOrder { .. }) => unreachable!("positions increase within a height"),
            }
        }

        self.head = Some(time);
        self.next_height += 1;
        Ok(report)
    }

    /// Status of `entry_id` as of the follower's head, for
    /// [`tlog_core::policy::evaluate`]. `None` until a height is ingested.
    pub fn observe(&self, entry_id: &EntryId) -> Option<Observation> {
        Some(Observation {
            backend: Backend::Celestia,
            status: self.state.status(entry_id),
            head: self.head?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{default_namespace, record_blob};
    use ed25519_dalek::{Signer, SigningKey};
    use tlog_core::hash::sha256;
    use tlog_core::statement::{
        PayloadMode, Publish, RegistryOp, RegistryUpdate, RevocationReason, Revoke, SignedStatement,
        Statement,
    };
    use tlog_core::{EntryStatus, PublicKey, Signature};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pk(k: &SigningKey) -> PublicKey {
        PublicKey(k.verifying_key().to_bytes())
    }

    fn rec(k: &SigningKey, statement: Statement, payload: Option<Vec<u8>>) -> Record {
        let signature = Signature(k.sign(&statement.signing_bytes()).to_bytes());
        Record { signed: SignedStatement { statement, signature }, payload }
    }

    fn t(h: u64) -> ChainTime {
        ChainTime { height: h, unix_ns: h * 6_000_000_000 }
    }

    #[test]
    fn follows_publish_and_revoke_and_skips_junk() {
        let admin = key(1);
        let publ = key(2);
        let cfg = LogConfig { name: "test".into(), admin: pk(&admin) };
        let log_id = cfg.log_id();
        let ns = default_namespace(&log_id);
        let mut f = NamespaceFollower::new(cfg, ns, 10);

        let add = rec(
            &admin,
            Statement::Registry(RegistryUpdate {
                log_id,
                seq: 0,
                op: RegistryOp::AddPublisher { key: pk(&publ), label: "p".into() },
            }),
            None,
        );
        let body = b"release-manifest".to_vec();
        let p = Publish {
            log_id,
            publisher: pk(&publ),
            subject: "pkg:foo".into(),
            content_hash: sha256(&body),
            content_len: body.len() as u64,
            serial: 1,
            payload_mode: PayloadMode::Attached,
        };
        let id = p.entry_id();
        let publish = rec(&publ, Statement::Publish(p), Some(body));
        let junk = Blob::new(ns, b"squatter".to_vec(), None).unwrap();
        // Same publish signed by an unregistered key.
        let forged = {
            let mut r = publish.clone();
            r.signed.signature = Signature(key(9).sign(&r.signed.statement.signing_bytes()).to_bytes());
            r
        };

        let blobs = vec![
            record_blob(ns, &add).unwrap(),
            junk,
            record_blob(ns, &forged).unwrap(),
            record_blob(ns, &publish).unwrap(),
        ];
        let rep = f.ingest(t(10), &blobs).unwrap();
        assert_eq!(rep.accepted.len(), 2);
        assert_eq!(rep.rejected.len(), 2);
        assert!(matches!(rep.rejected[0].1, Rejection::Decode(_)));
        assert_eq!(rep.rejected[1].1, Rejection::Rule(Reject::BadSignature));

        let obs = f.observe(&id).unwrap();
        assert!(matches!(obs.status, EntryStatus::Active { .. }));
        assert_eq!(obs.head, t(10));

        // Empty height still advances the head.
        f.ingest(t(11), &[]).unwrap();
        assert_eq!(f.observe(&id).unwrap().head, t(11));

        let rv = rec(
            &publ,
            Statement::Revoke(Revoke {
                log_id,
                entry_id: id,
                revoker: pk(&publ),
                reason: RevocationReason::Withdrawn,
            }),
            None,
        );
        f.ingest(t(12), &[record_blob(ns, &rv).unwrap()]).unwrap();
        assert!(
            matches!(f.observe(&id).unwrap().status, EntryStatus::Revoked { revoked, .. } if revoked == t(12))
        );
    }

    #[test]
    fn gaps_and_foreign_namespaces_are_errors() {
        let cfg = LogConfig { name: "t".into(), admin: pk(&key(1)) };
        let ns = default_namespace(&cfg.log_id());
        let mut f = NamespaceFollower::new(cfg, ns, 5);
        assert_eq!(f.ingest(t(6), &[]), Err(FollowError::Gap { expected: 5, got: 6 }));

        let other = Namespace::new_v0(&[1; 10]).unwrap();
        let b = Blob::new(other, b"x".to_vec(), None).unwrap();
        assert_eq!(f.ingest(t(5), &[b]), Err(FollowError::WrongNamespace));
        assert!(f.observe(&EntryId([0; 32])).is_none());
    }
}
