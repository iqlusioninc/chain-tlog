//! [`VerifiedNamespaceSource`] backed by an embedded Lumina light node.
//!
//! What Lumina gives us, and what we check again ourselves:
//!
//! - **Headers.** Lumina's syncer verifies headers against the validator
//!   set, so anything in its store is light-client-verified. We read time
//!   and the data availability header (DAH) only from that store.
//! - **Completeness.** We fetch the namespace with `request_namespace_data`
//!   and re-verify every row's NMT proof against the stored header's DAH
//!   with [`crate::proof::verify_namespace_data`]. Lumina checks the same
//!   proofs; checking them here keeps the guarantee independent of the node
//!   implementation, and catches a node that returns data for the wrong
//!   height.
//! - **Availability.** With [`Availability::Sampled`], a height is served
//!   only once data availability sampling (DAS) for it has succeeded, so a
//!   block whose data was withheld is never read as an empty namespace.
//!
//! ## Sampling
//!
//! Lumina 1.3 does not expose which heights it sampled successfully. Its
//! stored "sampling metadata" is written *before* sampling starts, so it
//! cannot be used. [`SamplingTracker`] rebuilds the set from the node's
//! `SamplingResult` events, which needs the subscription to exist before
//! the node starts sampling: start the node with
//! [`NodeBuilder::start_subscribed`](lumina_node::NodeBuilder::start_subscribed)
//! and pass its subscriber to [`SamplingTracker::run`].
//!
//! Lumina does not retry a height whose sampling failed until the node
//! loses all peers and restarts its sampler. To avoid stalling on such a
//! height, or on one sampled before the tracker subscribed, the source can
//! sample the height itself (`own_samples`), with the same per-share proofs
//! Lumina uses. A height whose own sampling also fails is reported as
//! [`LuminaSourceError::SamplingFailed`], a transient error: the verifier
//! stops there and its head goes stale, which the policy treats as
//! unverifiable. That is the right outcome for withheld data.
//!
//! Lumina samples only inside its sampling window ([`lumina_node::node::SAMPLING_WINDOW`],
//! 7 days). For older heights (a cold start on an old log), use
//! [`Availability::Unchecked`]: data is still checked against verified
//! headers, but availability of the rest of those blocks rests on the
//! validator-set honesty assumption.
//!
//! ## Pruning
//!
//! Lumina prunes headers once they leave its pruning window, and with
//! in-memory stores the default pruning window is **zero**: headers are
//! pruned as soon as they are sampled, usually before the follower reads
//! them. A follower that falls behind the pruning window cannot continue
//! (it gets [`LuminaSourceError::Pruned`]). Set
//! [`NodeBuilder::pruning_window`](lumina_node::NodeBuilder::pruning_window)
//! to at least the longest time the follower may be offline, or use a
//! persistent store with the default 7-day window.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use blockstore::Blockstore;
use celestia_types::nmt::Namespace;
use celestia_types::ExtendedHeader;
use lumina_node::block_ranges::BlockRanges;
use lumina_node::events::{EventSubscriber, NodeEvent};
use lumina_node::node::P2pError;
use lumina_node::store::{Store, StoreError};
use lumina_node::{Node, NodeError};
use rand::Rng;
use tlog_core::status::ChainTime;

use crate::proof::{items_from_namespace_data, verify_namespace_data, NamespaceItem, ProofError};
use crate::source::{SourceError, VerifiedNamespaceSource};

/// Shares sampled per height when the source samples by itself. Same as
/// Lumina's sampler.
pub const DEFAULT_OWN_SAMPLES: usize = 16;

/// Errors from [`LuminaSource`].
#[derive(Debug, thiserror::Error)]
pub enum LuminaSourceError {
    /// The node failed.
    #[error(transparent)]
    Node(#[from] NodeError),
    /// The header is not in the store yet. Retry later.
    #[error("header {0} not synced yet")]
    NotSynced(u64),
    /// The header was pruned or is older than the node will ever sync.
    /// The follower needs another source for this height.
    #[error("header {0} pruned or outside the node's window")]
    Pruned(u64),
    /// Sampling for this height has not succeeded yet, and the source does
    /// not sample by itself. Retry later.
    #[error("height {0} not sampled")]
    NotSampled(u64),
    /// The source's own sampling could not get every share it asked for.
    /// Either the network is struggling or the block's data is withheld.
    #[error("sampling height {height} failed for {failed} of {of} shares")]
    SamplingFailed {
        /// Height.
        height: u64,
        /// Shares not retrieved.
        failed: usize,
        /// Shares asked for.
        of: usize,
    },
    /// The namespace data did not verify against the header.
    #[error(transparent)]
    Proof(#[from] ProofError),
    /// Header time before the Unix epoch or beyond u64 nanoseconds.
    #[error("header time out of range at height {0}")]
    TimeOutOfRange(u64),
}

impl SourceError for LuminaSourceError {
    fn is_transient(&self) -> bool {
        match self {
            LuminaSourceError::NotSynced(_)
            | LuminaSourceError::NotSampled(_)
            | LuminaSourceError::SamplingFailed { .. } => true,
            LuminaSourceError::Node(NodeError::P2p(e)) => matches!(
                e,
                P2pError::RequestTimedOut
                    | P2pError::HeaderNotSynced(_)
                    | P2pError::ShrEx(_)
                    | P2pError::HeaderEx(_)
                    | P2pError::Shwap(_)
            ),
            LuminaSourceError::Node(_)
            | LuminaSourceError::Pruned(_)
            | LuminaSourceError::Proof(_)
            | LuminaSourceError::TimeOutOfRange(_) => false,
        }
    }
}

#[derive(Debug, Default)]
struct Sampled {
    ok: BlockRanges,
    failed: HashSet<u64>,
}

/// Heights the node has sampled, built from node events.
#[derive(Clone, Debug, Default)]
pub struct SamplingTracker {
    inner: Arc<Mutex<Sampled>>,
}

impl SamplingTracker {
    /// Whether DAS succeeded for `height`.
    pub fn is_sampled(&self, height: u64) -> bool {
        self.inner.lock().expect("lock").ok.contains(height)
    }

    /// Whether the node's last sampling attempt for `height` failed.
    pub fn sampling_failed(&self, height: u64) -> bool {
        self.inner.lock().expect("lock").failed.contains(&height)
    }

    fn record(&self, height: u64, failed: bool) {
        let mut s = self.inner.lock().expect("lock");
        if failed {
            if !s.ok.contains(height) {
                s.failed.insert(height);
            }
        } else {
            let _ = s.ok.insert_relaxed(height..=height);
            s.failed.remove(&height);
        }
    }

    /// Consume node events until the node stops. Spawn this on your runtime
    /// with the subscriber from `NodeBuilder::start_subscribed`.
    pub async fn run(self, mut events: EventSubscriber) {
        while let Ok(info) = events.recv().await {
            if let NodeEvent::SamplingResult { height, failed, .. } = info.event {
                self.record(height, failed);
            }
        }
    }
}

/// How [`LuminaSource`] establishes that a height's data is available.
#[derive(Clone, Debug)]
pub enum Availability {
    /// Serve a height only after DAS succeeded for it: the node's own
    /// sampling as seen by `tracker`, or failing that, `own_samples` random
    /// shares fetched and verified by this source. `own_samples = 0` turns
    /// own sampling off.
    Sampled {
        /// Tracker fed from the node's events.
        tracker: SamplingTracker,
        /// Shares to sample when the tracker has no success for a height.
        own_samples: usize,
    },
    /// Do not check availability by sampling. Data is still verified
    /// against headers. Use only for heights outside the sampling window.
    Unchecked,
}

impl Availability {
    /// Sampling with the default own-sampling fallback.
    pub fn sampled(tracker: SamplingTracker) -> Self {
        Availability::Sampled { tracker, own_samples: DEFAULT_OWN_SAMPLES }
    }
}

/// Lumina-backed source.
pub struct LuminaSource<'a, B: Blockstore + 'static, S: Store + 'static> {
    node: &'a Node<B, S>,
    availability: Availability,
    /// Timeout for each namespace request.
    pub request_timeout: Option<Duration>,
    /// Timeout for each share the source samples itself.
    pub sample_timeout: Option<Duration>,
}

impl<'a, B: Blockstore + 'static, S: Store + 'static> LuminaSource<'a, B, S> {
    /// Wrap a running node.
    pub fn new(node: &'a Node<B, S>, availability: Availability) -> Self {
        Self {
            node,
            availability,
            request_timeout: Some(Duration::from_secs(30)),
            sample_timeout: Some(Duration::from_secs(10)),
        }
    }

    async fn header(&self, height: u64) -> Result<ExtendedHeader, LuminaSourceError> {
        match self.node.get_header_by_height(height).await {
            Ok(h) => Ok(h),
            Err(NodeError::Store(StoreError::NotFound)) => Err(self.classify_missing(height).await),
            Err(e) => Err(e.into()),
        }
    }

    /// A header is missing from the store. Above the lowest stored header,
    /// the syncer will get to it. Below it, it is gone if the lowest stored
    /// header is already at the edge of the sampling window, since the
    /// syncer never goes past that edge; otherwise the syncer is still
    /// backfilling.
    async fn classify_missing(&self, height: u64) -> LuminaSourceError {
        let Ok(info) = self.node.syncer_info().await else {
            return LuminaSourceError::NotSynced(height);
        };
        let Some(tail) = info.stored_headers.tail() else {
            return LuminaSourceError::NotSynced(height);
        };
        if height > tail {
            return LuminaSourceError::NotSynced(height);
        }
        let window = lumina_node::node::SAMPLING_WINDOW;
        match self.node.get_header_by_height(tail).await {
            Ok(h) => {
                let now_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as i128)
                    .unwrap_or(0);
                let age_ns = (now_ns - h.time().unix_timestamp_nanos()).max(0);
                let age = Duration::from_nanos(u64::try_from(age_ns).unwrap_or(u64::MAX));
                // Allow an hour of slack: the syncer stops a little inside the window.
                if age + Duration::from_secs(3600) >= window {
                    LuminaSourceError::Pruned(height)
                } else {
                    LuminaSourceError::NotSynced(height)
                }
            }
            Err(_) => LuminaSourceError::NotSynced(height),
        }
    }

    async fn ensure_available(&self, header: &ExtendedHeader) -> Result<(), LuminaSourceError> {
        let Availability::Sampled { tracker, own_samples } = &self.availability else {
            return Ok(());
        };
        let height = header.height();
        if tracker.is_sampled(height) {
            return Ok(());
        }
        if *own_samples == 0 {
            return Err(LuminaSourceError::NotSampled(height));
        }

        let width = header.dah.square_width();
        let coords = random_coords(width, *own_samples);
        let mut failed = 0;
        for &(row, col) in &coords {
            // `request_sample` verifies the share's proof against this
            // height's DAH before returning it.
            if let Err(e) = self.node.request_sample(row, col, height, self.sample_timeout).await {
                match e {
                    NodeError::P2p(P2pError::HeaderPruned(_)) => {
                        return Err(LuminaSourceError::Pruned(height))
                    }
                    NodeError::P2p(_) => failed += 1,
                    other => return Err(other.into()),
                }
            }
        }
        if failed > 0 {
            return Err(LuminaSourceError::SamplingFailed { height, failed, of: coords.len() });
        }
        tracker.record(height, false);
        Ok(())
    }
}

/// Up to `n` distinct random coordinates in a `width` x `width` extended
/// square; the whole square if it has no more than `n` shares.
fn random_coords(width: u16, n: usize) -> Vec<(u16, u16)> {
    let total = usize::from(width).pow(2);
    if total <= n {
        return (0..width).flat_map(|r| (0..width).map(move |c| (r, c))).collect();
    }
    let mut rng = rand::thread_rng();
    let mut set = HashSet::with_capacity(n);
    while set.len() < n {
        set.insert((rng.gen_range(0..width), rng.gen_range(0..width)));
    }
    set.into_iter().collect()
}

fn chain_time(h: &ExtendedHeader) -> Result<ChainTime, LuminaSourceError> {
    let height = h.height();
    let ns = h.time().unix_timestamp_nanos();
    let unix_ns = u64::try_from(ns).map_err(|_| LuminaSourceError::TimeOutOfRange(height))?;
    Ok(ChainTime { height, unix_ns })
}

impl<B: Blockstore + 'static, S: Store + 'static> VerifiedNamespaceSource for LuminaSource<'_, B, S> {
    type Error = LuminaSourceError;

    async fn verified_tip(&self) -> Result<u64, Self::Error> {
        Ok(self.node.get_local_head_header().await?.height())
    }

    async fn header_time(&self, height: u64) -> Result<ChainTime, Self::Error> {
        chain_time(&self.header(height).await?)
    }

    async fn namespace_items(
        &self,
        namespace: Namespace,
        height: u64,
    ) -> Result<Vec<NamespaceItem>, Self::Error> {
        let header = self.header(height).await?;
        self.ensure_available(&header).await?;
        let data = self.node.request_namespace_data(namespace, height, self.request_timeout).await?;
        verify_namespace_data(namespace, height, &header.dah, &data)?;
        Ok(items_from_namespace_data(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_coords_are_distinct_and_in_range() {
        let c = random_coords(8, 16);
        assert_eq!(c.len(), 16);
        assert_eq!(c.iter().collect::<HashSet<_>>().len(), 16);
        assert!(c.iter().all(|&(r, col)| r < 8 && col < 8));
        assert_eq!(random_coords(2, 16).len(), 4);
    }

    #[test]
    fn tracker_success_overrides_failure() {
        let t = SamplingTracker::default();
        t.record(5, true);
        assert!(t.sampling_failed(5) && !t.is_sampled(5));
        t.record(5, false);
        assert!(t.is_sampled(5) && !t.sampling_failed(5));
        t.record(5, true);
        assert!(t.is_sampled(5), "a later failed retry does not undo a success");
    }

    #[test]
    fn transient_classification() {
        assert!(LuminaSourceError::NotSynced(1).is_transient());
        assert!(LuminaSourceError::SamplingFailed { height: 1, failed: 1, of: 16 }.is_transient());
        assert!(LuminaSourceError::Node(NodeError::P2p(P2pError::RequestTimedOut)).is_transient());
        assert!(!LuminaSourceError::Pruned(1).is_transient());
        assert!(!LuminaSourceError::Node(NodeError::P2p(P2pError::HeaderPruned(1))).is_transient());
        assert!(!LuminaSourceError::Proof(ProofError::NotUserNamespace).is_transient());
    }
}
