//! What the verifier needs from a Celestia light client.

use celestia_types::nmt::Namespace;
use celestia_types::Blob;
use tlog_core::status::ChainTime;

use crate::follower::{FollowError, HeightReport, NamespaceFollower};

/// A Celestia light client the verifier trusts for three things:
///
/// 1. Headers: [`Self::verified_tip`] and [`Self::header_time`] return only
///    headers the client verified against the validator set.
/// 2. Namespace completeness: [`Self::namespace_blobs`] returns every blob
///    in the namespace at a height, checked with NMT proofs against that
///    header's data availability header. An absent namespace is proven
///    absent, not assumed.
/// 3. Availability: the client has done data availability sampling for the
///    height, or the implementation says plainly that it has not (see the
///    `lumina` module).
#[allow(async_fn_in_trait)]
pub trait VerifiedNamespaceSource {
    /// Error type.
    type Error: std::error::Error + 'static;

    /// Highest height the client has verified and is willing to serve.
    async fn verified_tip(&self) -> Result<u64, Self::Error>;

    /// Verified header time at `height`.
    async fn header_time(&self, height: u64) -> Result<ChainTime, Self::Error>;

    /// All blobs in `namespace` at `height`, completeness verified.
    async fn namespace_blobs(&self, namespace: Namespace, height: u64) -> Result<Vec<Blob>, Self::Error>;
}

/// Errors from [`sync_to_tip`].
#[derive(Debug, thiserror::Error)]
pub enum SyncError<E: std::error::Error + 'static> {
    /// The light client failed.
    #[error("light client: {0}")]
    Source(#[source] E),
    /// The follower refused the data.
    #[error("follower: {0}")]
    Follow(#[from] FollowError),
}

/// Ingest every height from the follower's next height to the source's
/// verified tip. Returns reports for heights where the namespace had blobs.
///
/// Cost is one namespace query per height, including empty ones, because an
/// empty height must be proven empty to rule out a hidden revocation. An
/// online verifier pays this incrementally; a cold start pays it from the
/// log's start height (see the design note on Celestia pruning).
pub async fn sync_to_tip<S: VerifiedNamespaceSource>(
    follower: &mut NamespaceFollower,
    source: &S,
) -> Result<Vec<HeightReport>, SyncError<S::Error>> {
    let tip = source.verified_tip().await.map_err(SyncError::Source)?;
    let ns = follower.namespace();
    let mut reports = Vec::new();
    while follower.next_height() <= tip {
        let h = follower.next_height();
        let time = source.header_time(h).await.map_err(SyncError::Source)?;
        let blobs = source.namespace_blobs(ns, h).await.map_err(SyncError::Source)?;
        let rep = follower.ingest(time, &blobs)?;
        if !rep.accepted.is_empty() || !rep.rejected.is_empty() {
            reports.push(rep);
        }
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tlog_core::statement::LogConfig;
    use tlog_core::PublicKey;

    #[derive(Debug, thiserror::Error)]
    #[error("mock")]
    struct MockErr;

    struct Mock {
        tip: u64,
        blobs: BTreeMap<u64, Vec<Blob>>,
    }

    impl VerifiedNamespaceSource for Mock {
        type Error = MockErr;
        async fn verified_tip(&self) -> Result<u64, MockErr> {
            Ok(self.tip)
        }
        async fn header_time(&self, height: u64) -> Result<ChainTime, MockErr> {
            Ok(ChainTime { height, unix_ns: height })
        }
        async fn namespace_blobs(&self, _: Namespace, height: u64) -> Result<Vec<Blob>, MockErr> {
            Ok(self.blobs.get(&height).cloned().unwrap_or_default())
        }
    }

    #[tokio::test]
    async fn syncs_every_height_to_tip() {
        let cfg = LogConfig { name: "t".into(), admin: PublicKey([3; 32]) };
        let ns = crate::default_namespace(&cfg.log_id());
        let mut f = NamespaceFollower::new(cfg, ns, 100);
        let junk = Blob::new(ns, b"junk".to_vec(), None).unwrap();
        let src = Mock { tip: 104, blobs: BTreeMap::from([(102, vec![junk])]) };

        let reps = sync_to_tip(&mut f, &src).await.unwrap();
        assert_eq!(reps.len(), 1);
        assert_eq!(reps[0].height, 102);
        assert_eq!(f.next_height(), 105);
        assert_eq!(f.head().unwrap().height, 104);
    }
}
