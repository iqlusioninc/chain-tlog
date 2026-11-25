//! What the verifier needs from a Celestia light client.

use celestia_types::nmt::Namespace;
use tlog_core::status::ChainTime;

use crate::follower::{FollowError, HeightReport, NamespaceFollower};
use crate::proof::NamespaceItem;

/// Errors a [`VerifiedNamespaceSource`] can return.
pub trait SourceError: std::error::Error + 'static {
    /// True if the height is not ready yet (header not synced, sampling not
    /// done, request timed out) and asking again later may succeed. False if
    /// the source cannot serve the height (pruned, outside the sampling
    /// window, proof mismatch) and the caller must change something.
    fn is_transient(&self) -> bool;
}

/// A Celestia light client the verifier trusts for three things:
///
/// 1. Headers: [`Self::verified_tip`] and [`Self::header_time`] return only
///    headers the client verified against the validator set.
/// 2. Namespace completeness: [`Self::namespace_items`] returns every share
///    sequence in the namespace at a height, in order, checked with NMT
///    proofs against that header's data availability header (see
///    [`crate::proof`]). An absent namespace is proven absent, not assumed.
/// 3. Availability: the client has done data availability sampling for the
///    height, or the implementation says plainly that it has not (see the
///    `lumina` module).
///
/// A height the source cannot vouch for yet must be an error, never an empty
/// list: an empty list is read as proof that nothing was posted.
#[allow(async_fn_in_trait)]
pub trait VerifiedNamespaceSource {
    /// Error type.
    type Error: SourceError;

    /// Highest height the client has verified and is willing to serve.
    async fn verified_tip(&self) -> Result<u64, Self::Error>;

    /// Verified header time at `height`.
    async fn header_time(&self, height: u64) -> Result<ChainTime, Self::Error>;

    /// Every share sequence in `namespace` at `height`, completeness and
    /// availability verified.
    async fn namespace_items(
        &self,
        namespace: Namespace,
        height: u64,
    ) -> Result<Vec<NamespaceItem>, Self::Error>;
}

/// Why [`sync_to_tip`] stopped before the tip.
#[derive(Debug)]
pub struct Stalled<E> {
    /// The height it could not ingest. The follower's head is the height
    /// before it.
    pub height: u64,
    /// What the source said.
    pub error: E,
}

/// Result of [`sync_to_tip`].
#[derive(Debug)]
pub struct SyncOutcome<E> {
    /// Reports for heights where the namespace had blobs.
    pub reports: Vec<HeightReport>,
    /// The source's tip when the sync started.
    pub tip: u64,
    /// Set if the sync stopped early on a transient source error. The
    /// follower keeps everything ingested so far; call again later.
    pub stalled: Option<Stalled<E>>,
}

/// Errors from [`sync_to_tip`].
#[derive(Debug, thiserror::Error)]
pub enum SyncError<E: std::error::Error + 'static> {
    /// The light client failed and retrying will not help.
    #[error("light client at height {height}: {error}")]
    Source {
        /// Height being ingested.
        height: u64,
        /// The error.
        #[source]
        error: E,
        /// Reports for heights ingested before the failure.
        reports: Vec<HeightReport>,
    },
    /// The light client could not report its tip.
    #[error("light client tip: {0}")]
    Tip(#[source] E),
    /// The follower refused the data.
    #[error("follower: {0}")]
    Follow(#[from] FollowError),
}

/// Ingest every height from the follower's next height to the source's
/// verified tip.
///
/// Cost is one namespace query per height, including empty ones, because an
/// empty height must be proven empty to rule out a hidden revocation. An
/// online verifier pays this incrementally; a cold start pays it from the
/// log's start height (see the design note on Celestia pruning).
///
/// A transient source error stops the sync at that height without error
/// (see [`SyncOutcome::stalled`]). The follower's head stays at the last
/// ingested height, so a stall shows up as a stale head and the policy
/// fails closed.
pub async fn sync_to_tip<S: VerifiedNamespaceSource>(
    follower: &mut NamespaceFollower,
    source: &S,
) -> Result<SyncOutcome<S::Error>, SyncError<S::Error>> {
    let tip = source.verified_tip().await.map_err(SyncError::Tip)?;
    let ns = follower.namespace();
    let mut reports = Vec::new();
    while follower.next_height() <= tip {
        let h = follower.next_height();
        let fetched = match source.header_time(h).await {
            Ok(time) => source.namespace_items(ns, h).await.map(|items| (time, items)),
            Err(e) => Err(e),
        };
        let (time, items) = match fetched {
            Ok(v) => v,
            Err(error) if error.is_transient() => {
                return Ok(SyncOutcome { reports, tip, stalled: Some(Stalled { height: h, error }) })
            }
            Err(error) => return Err(SyncError::Source { height: h, error, reports }),
        };
        let rep = follower.ingest_items(time, &items)?;
        if !rep.accepted.is_empty() || !rep.rejected.is_empty() {
            reports.push(rep);
        }
    }
    Ok(SyncOutcome { reports, tip, stalled: None })
}
