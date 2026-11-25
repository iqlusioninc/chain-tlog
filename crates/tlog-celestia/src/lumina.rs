//! [`VerifiedNamespaceSource`] backed by an embedded Lumina light node.
//!
//! What Lumina gives us:
//!
//! - Headers are synced and verified by Lumina's syncer, so anything from
//!   its local store is light-client-verified.
//! - `request_all_blobs` fetches the namespace's rows over shrex and checks
//!   them against the header's data availability header, including that
//!   every row containing the namespace is present. That is the
//!   completeness proof the follower relies on.
//! - The DASer samples recent heights. With sampling required, a height is
//!   only served once sampling for it succeeded, so a block whose data was
//!   withheld is never mistaken for an empty namespace.
//!
//! Lumina 1.3 does not expose its sampled ranges outside test builds, so
//! [`SamplingTracker`] rebuilds them from the node's `SamplingResult`
//! events. Subscribe right after starting the node. Heights sampled before
//! the subscription show as not sampled.
//!
//! Lumina samples only inside its sampling window. For heights older than
//! that (a cold start on an old log), pass `None` as the tracker: data is
//! still checked against verified headers, but availability of the rest of
//! those blocks rests on the validator-set honesty assumption.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use blockstore::Blockstore;
use celestia_types::nmt::Namespace;
use celestia_types::Blob;
use lumina_node::block_ranges::BlockRanges;
use lumina_node::events::{EventSubscriber, NodeEvent};
use lumina_node::store::Store;
use lumina_node::{Node, NodeError};
use tlog_core::status::ChainTime;

use crate::source::VerifiedNamespaceSource;

/// Errors from [`LuminaSource`].
#[derive(Debug, thiserror::Error)]
pub enum LuminaSourceError {
    /// The node failed.
    #[error(transparent)]
    Node(#[from] NodeError),
    /// Sampling for this height has not succeeded (yet). Retry later.
    #[error("height {0} not sampled")]
    NotSampled(u64),
    /// Header time before the Unix epoch or beyond u64 nanoseconds.
    #[error("header time out of range at height {0}")]
    TimeOutOfRange(u64),
}

/// Heights the node has successfully sampled, built from node events.
#[derive(Clone, Debug, Default)]
pub struct SamplingTracker {
    sampled: Arc<Mutex<BlockRanges>>,
}

impl SamplingTracker {
    /// Whether DAS succeeded for `height`.
    pub fn is_sampled(&self, height: u64) -> bool {
        self.sampled.lock().expect("lock").contains(height)
    }

    /// Consume node events until the node stops. Spawn this on your runtime.
    pub async fn run(self, mut events: EventSubscriber) {
        while let Ok(info) = events.recv().await {
            if let NodeEvent::SamplingResult { height, failed: false, .. } = info.event {
                let _ = self.sampled.lock().expect("lock").insert_relaxed(height..=height);
            }
        }
    }
}

/// Lumina-backed source.
pub struct LuminaSource<'a, B: Blockstore + 'static, S: Store + 'static> {
    node: &'a Node<B, S>,
    sampling: Option<SamplingTracker>,
    /// Timeout for each namespace request.
    pub request_timeout: Option<Duration>,
}

impl<'a, B: Blockstore + 'static, S: Store + 'static> LuminaSource<'a, B, S> {
    /// Wrap a running node. With `sampling` set, only sampled heights are
    /// served; with `None`, availability is not checked by sampling.
    pub fn new(node: &'a Node<B, S>, sampling: Option<SamplingTracker>) -> Self {
        Self { node, sampling, request_timeout: Some(Duration::from_secs(30)) }
    }
}

impl<B: Blockstore + 'static, S: Store + 'static> VerifiedNamespaceSource for LuminaSource<'_, B, S> {
    type Error = LuminaSourceError;

    async fn verified_tip(&self) -> Result<u64, Self::Error> {
        Ok(self.node.get_local_head_header().await?.height())
    }

    async fn header_time(&self, height: u64) -> Result<ChainTime, Self::Error> {
        let h = self.node.get_header_by_height(height).await?;
        let ns = h.time().unix_timestamp_nanos();
        let unix_ns = u64::try_from(ns).map_err(|_| LuminaSourceError::TimeOutOfRange(height))?;
        Ok(ChainTime { height, unix_ns })
    }

    async fn namespace_blobs(&self, namespace: Namespace, height: u64) -> Result<Vec<Blob>, Self::Error> {
        if let Some(t) = &self.sampling {
            if !t.is_sampled(height) {
                return Err(LuminaSourceError::NotSampled(height));
            }
        }
        Ok(self.node.request_all_blobs(namespace, height, self.request_timeout).await?)
    }
}
