//! Verifier hardening tests over real data squares and NMT proofs.
//!
//! Each block is laid out, erasure-coded and committed to a DAH like a real
//! Celestia block. The verifier only accepts namespace data whose proofs
//! check against that DAH, so these tests exercise the same completeness
//! and absence checks a light node relies on.

use std::collections::BTreeMap;

use celestia_types::consts::appconsts::SHARE_SIZE;
use celestia_types::namespace_data::NamespaceData;
use celestia_types::nmt::{Namespace, NS_SIZE};
use celestia_types::state::AccAddress;
use celestia_types::{Blob, InfoByte, Share};
use ed25519_dalek::{Signer, SigningKey};
use tlog_core::hash::sha256;
use tlog_core::statement::{
    LogConfig, Publish, Record, RegistryOp, RegistryUpdate, RevocationReason, Revoke, SignedStatement,
    Statement,
};
use tlog_core::{EntryId, EntryStatus, PublicKey, Signature};

use crate::proof::{items_from_shares, verify_namespace_data, NamespaceItem, ProofError};
use crate::source::{sync_to_tip, SyncError};
use crate::testkit::{block, block_from_raw, raw_shares, time, ChainSource, ChainSourceError, Fault};
use crate::{default_namespace, record_blob, NamespaceFollower, Rejection};

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

/// A log with one registered publisher and one entry, plus a revocation of
/// that entry, ready to place into blocks.
struct Fixture {
    cfg: LogConfig,
    ns: Namespace,
    /// Namespaces sorting just below and above `ns`, so rows hold other
    /// data around the log's namespace and absence proofs are non-trivial.
    lo: Namespace,
    hi: Namespace,
    add: Record,
    publish: Record,
    revoke: Record,
    id: EntryId,
}

fn fixture(payload_len: usize) -> Fixture {
    let admin = key(1);
    let publ = key(2);
    let cfg = LogConfig { name: "hardening".into(), admin: pk(&admin) };
    let log_id = cfg.log_id();
    let ns = default_namespace(&log_id);
    let lo = Namespace::new_v0(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 0]).unwrap();
    let hi = Namespace::new_v0(&[0xff; 10]).unwrap();
    assert!(lo < ns && ns < hi);

    let add = rec(
        &admin,
        Statement::Registry(RegistryUpdate {
            log_id,
            seq: 0,
            op: RegistryOp::AddPublisher { key: pk(&publ), label: "p".into() },
        }),
        None,
    );
    let body: Vec<u8> = (0..payload_len).map(|i| i as u8).collect();
    let p = Publish {
        log_id,
        publisher: pk(&publ),
        subject: "pkg:foo".into(),
        content_hash: sha256(&body),
        content_len: body.len() as u64,
        serial: 1,
    };
    let id = p.entry_id();
    let publish = rec(&publ, Statement::Publish(p), Some(body));
    let revoke = rec(
        &publ,
        Statement::Revoke(Revoke {
            log_id,
            entry_id: id,
            revoker: pk(&publ),
            reason: RevocationReason::KeyCompromise,
        }),
        None,
    );
    Fixture { cfg, ns, lo, hi, add, publish, revoke, id }
}

impl Fixture {
    fn blob(&self, r: &Record) -> Blob {
        record_blob(self.ns, r).unwrap()
    }
    fn noise(&self, h: u64) -> Vec<Blob> {
        vec![
            Blob::new(self.lo, vec![h as u8; 300], None).unwrap(),
            Blob::new(self.hi, vec![h as u8; 300], None).unwrap(),
        ]
    }
    /// h10: registry + publish, h11: other namespaces only, h12: revoke.
    fn chain(&self) -> ChainSource {
        let mut b10 = self.noise(10);
        b10.extend([self.blob(&self.add), self.blob(&self.publish)]);
        let mut b12 = self.noise(12);
        b12.push(self.blob(&self.revoke));
        let blocks =
            BTreeMap::from([(10, block(&b10, 4)), (11, block(&self.noise(11), 4)), (12, block(&b12, 4))]);
        ChainSource::new(10, 12, blocks)
    }
    fn follower(&self) -> NamespaceFollower {
        NamespaceFollower::new(self.cfg.clone(), self.ns, 10)
    }
}

#[tokio::test]
async fn publish_and_revoke_through_proofs() {
    let fx = fixture(64);
    let src = fx.chain();
    let mut f = fx.follower();

    let out = sync_to_tip(&mut f, &src).await.unwrap();
    assert!(out.stalled.is_none());
    assert_eq!(out.reports.iter().map(|r| r.height).collect::<Vec<_>>(), vec![10, 12]);
    assert!(out.reports.iter().all(|r| r.rejected.is_empty()));

    let obs = f.observe(&fx.id).unwrap();
    assert_eq!(obs.head, time(12));
    assert!(matches!(
        obs.status,
        EntryStatus::Revoked { published, revoked, reason: RevocationReason::KeyCompromise }
            if published == time(10) && revoked == time(12)
    ));
}

#[test]
fn empty_height_is_proven_by_absence_proof() {
    let fx = fixture(64);
    let src = fx.chain();
    let b11 = &src.blocks[&11];
    let data = b11.namespace_data(fx.ns, 11);

    // The log namespace sorts between lo and hi, which share a row, so the
    // row's range covers it and the node must prove it absent there.
    assert_eq!(data.rows().len(), 1);
    assert!(data.rows()[0].shares.is_empty());
    assert!(data.rows()[0].proof.is_of_absence());
    verify_namespace_data(fx.ns, 11, &b11.dah, &data).unwrap();

    // Claiming "no rows at all" for a namespace the DAH says a row covers
    // is not accepted as absence.
    let none = NamespaceData::new(vec![]);
    assert!(matches!(verify_namespace_data(fx.ns, 11, &b11.dah, &none), Err(ProofError::Mismatch(_))));
}

#[test]
fn namespace_outside_every_row_needs_no_rows() {
    // A block with no data near the namespace: no row covers it, so zero
    // rows is the complete answer and verifies.
    let fx = fixture(64);
    let only_hi = block(&[Blob::new(fx.hi, vec![1; 10], None).unwrap()], 2);
    let ns_below = Namespace::new_v0(&[0, 0, 0, 0, 0, 0, 0, 0, 2, 0]).unwrap();
    let data = only_hi.namespace_data(ns_below, 5);
    assert!(data.rows().is_empty());
    verify_namespace_data(ns_below, 5, &only_hi.dah, &data).unwrap();
}

#[tokio::test]
async fn hidden_revocation_is_rejected() {
    let fx = fixture(64);

    // 1. Serve the absence proof from height 11 as height 12's answer.
    let mut src = fx.chain();
    let forged = src.blocks[&11].namespace_data(fx.ns, 12);
    src.faults.insert(12, Fault::Serve(forged));
    let mut f = fx.follower();
    let err = sync_to_tip(&mut f, &src).await.unwrap_err();
    match err {
        SyncError::Source {
            height: 12,
            error: ChainSourceError::Proof(ProofError::Mismatch(_)),
            reports,
        } => {
            assert_eq!(reports.len(), 1, "height 10's report is kept");
        }
        other => panic!("unexpected: {other:?}"),
    }
    // The follower stopped before 12: the entry still looks active, but its
    // head is 11, so a freshness check sees the head is not current.
    assert_eq!(f.head(), Some(time(11)));
    assert!(matches!(f.observe(&fx.id).unwrap().status, EntryStatus::Active { .. }));

    // 2. Serve no rows at all.
    let mut src = fx.chain();
    src.faults.insert(12, Fault::Serve(NamespaceData::new(vec![])));
    let mut f = fx.follower();
    assert!(sync_to_tip(&mut f, &src).await.is_err());

    // 3. Serve the right row with the revoke's shares swapped for the
    //    publish's (same namespace, valid shares, wrong content).
    let mut src = fx.chain();
    let mut data = src.blocks[&12].namespace_data(fx.ns, 12);
    let other = src.blocks[&10].namespace_data(fx.ns, 10);
    let mut rows = data.rows().to_vec();
    rows[0].shares = other.rows()[0].shares.clone();
    data = NamespaceData::new(rows);
    src.faults.insert(12, Fault::Serve(data));
    let mut f = fx.follower();
    assert!(sync_to_tip(&mut f, &src).await.is_err());
}

#[tokio::test]
async fn dropping_one_row_of_a_multi_row_namespace_is_rejected() {
    // A payload big enough that the publish blob spans several rows.
    let fx = fixture(4 * SHARE_SIZE);
    let mut b = fx.noise(10);
    b.extend([fx.blob(&fx.add), fx.blob(&fx.publish)]);
    let blk = block(&b, 4);
    let data = blk.namespace_data(fx.ns, 10);
    assert!(data.rows().len() >= 2, "namespace spans {} rows", data.rows().len());
    verify_namespace_data(fx.ns, 10, &blk.dah, &data).unwrap();

    let mut rows = data.rows().to_vec();
    rows.pop();
    let short = NamespaceData::new(rows);
    assert!(matches!(verify_namespace_data(fx.ns, 10, &blk.dah, &short), Err(ProofError::Mismatch(_))));

    // Dropping a share from inside a row breaks that row's proof.
    let mut rows = data.rows().to_vec();
    rows[0].shares.pop();
    let trimmed = NamespaceData::new(rows);
    assert!(verify_namespace_data(fx.ns, 10, &blk.dah, &trimmed).is_err());
}

#[tokio::test]
async fn not_ready_height_stalls_then_resumes() {
    let fx = fixture(64);
    let mut src = fx.chain();
    src.faults.insert(12, Fault::NotReady);
    let mut f = fx.follower();

    let out = sync_to_tip(&mut f, &src).await.unwrap();
    let stalled = out.stalled.expect("stalled at 12");
    assert_eq!(stalled.height, 12);
    assert_eq!(f.head(), Some(time(11)));
    assert_eq!(f.next_height(), 12);

    src.faults.clear();
    let out = sync_to_tip(&mut f, &src).await.unwrap();
    assert!(out.stalled.is_none());
    assert!(matches!(f.observe(&fx.id).unwrap().status, EntryStatus::Revoked { .. }));
}

#[tokio::test]
async fn unparseable_and_foreign_version_blobs_do_not_stall_the_log() {
    let fx = fixture(64);

    // Height 10 holds, in order: the registry update, a share sequence with
    // a share version nobody defines, a record posted with share version 1
    // (a signer, which the log ignores), and the publish.
    let odd = {
        let mut shares = Blob::new(fx.ns, vec![7; 100], None).unwrap().to_shares().unwrap();
        let mut raw = shares[0].to_vec();
        raw[NS_SIZE] = InfoByte::new(42, true).unwrap().as_u8();
        shares[0] = Share::from_raw(&raw).unwrap();
        shares
    };
    let with_signer = Blob::new(fx.ns, fx.add.encode(), Some(AccAddress::from([9u8; 20]))).unwrap();
    assert_eq!(with_signer.share_version, 1);

    let mut raw = raw_shares(&[Blob::new(fx.lo, vec![1; 10], None).unwrap()]);
    raw.extend(fx.blob(&fx.add).to_shares().unwrap().iter().map(|s| s.to_vec()));
    raw.extend(odd.iter().map(|s| s.to_vec()));
    raw.extend(with_signer.to_shares().unwrap().iter().map(|s| s.to_vec()));
    raw.extend(fx.blob(&fx.publish).to_shares().unwrap().iter().map(|s| s.to_vec()));
    let blk = block_from_raw(raw, 4);

    let mut src = ChainSource::new(10, 10, BTreeMap::from([(10, blk)]));
    src.tip = 10;
    let mut f = fx.follower();
    let out = sync_to_tip(&mut f, &src).await.unwrap();
    let rep = &out.reports[0];

    assert_eq!(rep.accepted.len(), 2, "{rep:?}");
    assert_eq!(rep.rejected.len(), 2, "{rep:?}");
    assert_eq!(rep.rejected[0].0.index, 1);
    assert!(matches!(rep.rejected[0].1, Rejection::Unparseable(_)));
    // The share-version-1 copy of the registry update is a replay of seq 0.
    assert_eq!(rep.rejected[1].0.index, 2);
    assert!(matches!(rep.rejected[1].1, Rejection::Rule(tlog_core::Reject::BadRegistrySeq { .. })));
    assert!(matches!(f.observe(&fx.id).unwrap().status, EntryStatus::Active { .. }));
}

#[test]
fn truncated_sequence_is_one_unparseable_item() {
    let ns = Namespace::new_v0(&[5; 10]).unwrap();
    let big = Blob::new(ns, vec![3; 3 * SHARE_SIZE], None).unwrap();
    let small = Blob::new(ns, vec![4; 10], None).unwrap();
    let mut shares = big.to_shares().unwrap();
    shares.pop();
    shares.extend(small.to_shares().unwrap());
    let refs: Vec<&Share> = shares.iter().collect();

    let items = items_from_shares(&refs);
    assert_eq!(items.len(), 2);
    assert!(matches!(items[0], NamespaceItem::Unparseable { .. }));
    assert_eq!(items[1], NamespaceItem::Blob(small));
}

#[test]
fn fibre_share_version_is_rejected() {
    let fx = fixture(64);
    let mut f = fx.follower();
    let mut b = fx.blob(&fx.add);
    b.share_version = 2;
    let rep = f.ingest(time(10), &[b]).unwrap();
    assert_eq!(rep.rejected[0].1, Rejection::UnsupportedShareVersion(2));
}

#[test]
fn header_time_must_increase() {
    let fx = fixture(64);
    let mut f = fx.follower();
    f.ingest(time(10), &[]).unwrap();
    let mut t = time(11);
    t.unix_ns = time(10).unix_ns;
    assert!(matches!(f.ingest(t, &[]), Err(crate::FollowError::TimeNotIncreasing { .. })));
}

#[tokio::test]
async fn unservable_height_is_an_error_with_partial_reports() {
    let fx = fixture(64);
    let mut src = fx.chain();
    src.faults.insert(12, Fault::Gone);
    let mut f = fx.follower();
    match sync_to_tip(&mut f, &src).await {
        Err(SyncError::Source { height: 12, error: ChainSourceError::Gone(12), reports }) => {
            assert_eq!(reports.len(), 1);
            assert_eq!(reports[0].height, 10);
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert_eq!(f.next_height(), 12);
}
