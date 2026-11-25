//! Celestia backend on the local devnet, verified through a Lumina light node.

use std::time::Duration;

use anyhow::{bail, Context};
use celestia_rpc::{BlobClient, Client, HeaderClient, P2PClient, TxConfig};
use celestia_types::nmt::Namespace;
use celestia_types::Blob;
use lumina_node::blockstore::InMemoryBlockstore;
use lumina_node::network::Network;
use lumina_node::store::InMemoryStore;
use lumina_node::{Node, NodeBuilder};
use multiaddr::{Multiaddr, Protocol};
use tlog_celestia::lumina::{LuminaSource, SamplingTracker};
use tlog_celestia::publisher::CelestiaPublisher;
use tlog_celestia::{default_namespace, sync_to_tip, HeightReport, NamespaceFollower, Rejection, SyncError};
use tlog_core::statement::Record;
use tlog_core::status::Backend;
use tlog_core::{BackendResult, EntryId, LogConfig};

use crate::LogBackend;

/// Bridge node JSON-RPC of `ci/celestia-devnet`. Override with
/// `TLOG_CELESTIA_RPC`.
pub const DEFAULT_RPC: &str = "http://127.0.0.1:26658";

/// p2p network id of the devnet.
pub const NETWORK_ID: &str = "private";

/// How long to wait for the light node to verify and sample a height.
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(120);

/// Bridge RPC URL from the environment or the default.
pub fn rpc_url() -> String {
    std::env::var("TLOG_CELESTIA_RPC").unwrap_or_else(|_| DEFAULT_RPC.into())
}

/// A log namespace on the devnet: a publisher that posts through the
/// bridge's RPC, and a Lumina light node plus [`NamespaceFollower`] that
/// read it back without trusting the bridge.
pub struct CelestiaLog {
    /// Bridge RPC, for submitting and for finding the bridge's p2p address.
    pub rpc: Client,
    /// Posts records to the log namespace.
    pub publisher: CelestiaPublisher,
    /// Embedded light node.
    pub node: Node<InMemoryBlockstore, InMemoryStore>,
    /// Heights the light node has sampled.
    pub sampling: SamplingTracker,
    /// Fold of the namespace as verified so far.
    pub follower: NamespaceFollower,
    /// Every non-empty height the follower has ingested, with what it
    /// accepted and rejected.
    pub reports: Vec<HeightReport>,
    /// The observation head must reach this height.
    target_height: u64,
}

impl CelestiaLog {
    /// Connect to the devnet at [`rpc_url`] and start following `config`'s
    /// default namespace from the next block.
    pub async fn connect(config: &LogConfig) -> anyhow::Result<Self> {
        let url = rpc_url();
        let rpc =
            Client::new(&url, None, None, None).await.with_context(|| format!("connecting to {url}"))?;
        let ns = default_namespace(&config.log_id());
        let start_height = rpc.header_network_head().await?.height() + 1;
        let publisher = CelestiaPublisher::connect(&url, None, ns).await?;

        let info = rpc.p2p_info().await.context("bridge p2p.Info")?;
        let bootnodes: Vec<Multiaddr> = info
            .addrs
            .into_iter()
            .filter(|a| !a.iter().any(|p| matches!(p, Protocol::Ip4(ip) if ip.is_loopback())))
            .filter(|a| !a.iter().any(|p| matches!(p, Protocol::Ip6(_))))
            .map(|a| a.with(Protocol::P2p(info.id.0)))
            .collect();
        if bootnodes.is_empty() {
            bail!("bridge reported no reachable p2p addresses");
        }

        let (node, events) = NodeBuilder::new()
            .network(Network::custom(NETWORK_ID)?)
            .bootnodes(bootnodes)
            // In-memory stores prune right after sampling by default, which
            // would drop the headers the follower still needs.
            .pruning_window(Duration::from_secs(3600))
            .start_subscribed()
            .await
            .context("starting Lumina")?;
        let sampling = SamplingTracker::default();
        tokio::spawn(sampling.clone().run(events));

        Ok(Self {
            rpc,
            publisher,
            node,
            sampling,
            follower: NamespaceFollower::new(config.clone(), ns, start_height),
            reports: Vec::new(),
            target_height: start_height,
        })
    }

    /// The log namespace.
    pub fn namespace(&self) -> Namespace {
        self.follower.namespace()
    }

    /// Post arbitrary bytes to the log namespace, as a squatter could.
    pub async fn submit_raw(&mut self, data: Vec<u8>) -> anyhow::Result<u64> {
        let blob = Blob::new(self.namespace(), data, None)?;
        let height = self.rpc.blob_submit(&[blob], TxConfig::default()).await?;
        self.target_height = self.target_height.max(height);
        Ok(height)
    }

    /// All rejections seen so far, in log order.
    pub fn rejections(&self) -> Vec<Rejection> {
        self.reports.iter().flat_map(|r| r.rejected.iter().map(|(_, why)| why.clone())).collect()
    }

    /// Sync the follower through the light node until it has ingested
    /// `height`. Heights the node has not sampled yet are retried.
    pub async fn sync_through(&mut self, height: u64) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + SYNC_TIMEOUT;
        loop {
            let source = LuminaSource::new(&self.node, Some(self.sampling.clone()));
            let last_err = match sync_to_tip(&mut self.follower, &source).await {
                Ok(reps) => {
                    self.reports.extend(reps);
                    None
                }
                // Not synced or not sampled yet: try again.
                Err(SyncError::Source(e)) => Some(e),
                Err(e) => return Err(e.into()),
            };
            if self.follower.head().is_some_and(|h| h.height >= height) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                let at = self.follower.next_height();
                return Err(match last_err {
                    Some(e) => anyhow::Error::new(e),
                    None => anyhow::anyhow!("light node tip below {height}"),
                }
                .context(format!("Lumina did not verify height {height} (follower at {at})")));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

impl LogBackend for CelestiaLog {
    fn backend(&self) -> Backend {
        Backend::Celestia
    }

    async fn submit(&mut self, record: &Record) -> anyhow::Result<()> {
        let s = self.publisher.submit(record).await?;
        self.target_height = self.target_height.max(s.height);
        Ok(())
    }

    /// Celestia accepts any blob, so a bad record is not refused at submit
    /// time; it shows up as a rejection when the follower folds the
    /// namespace. See [`NamespaceFollower::ingest`].
    async fn observe(&mut self, entry_id: &EntryId) -> anyhow::Result<BackendResult> {
        self.sync_through(self.target_height).await?;
        Ok(self.follower.observe(entry_id).map_or(BackendResult::Unavailable, BackendResult::Observed))
    }
}
