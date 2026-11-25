//! Live run of the Celestia backend against a local devnet.
//!
//! Needs Lumina's CI devnet (`ci/` at tag `lumina-node-v1.3.0`): the
//! `validator` and the `node-0` bridge with `SKIP_AUTH=true`, RPC on
//! `localhost:26658` and p2p TCP on `localhost:2121`. Run with
//!
//! ```text
//! cargo test -p tlog-celestia --features rpc,lumina --test devnet -- --ignored --nocapture
//! ```
//!
//! Environment overrides: `TLOG_DEVNET_RPC` (default `ws://localhost:26658`)
//! and `TLOG_DEVNET_P2P` (default `/ip4/127.0.0.1/tcp/2121`), the address
//! the bridge's p2p port is reachable at from here. The bridge advertises its
//! container address for TCP, which is not reachable from the host.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use celestia_rpc::{Client, HeaderClient, P2PClient};
use celestia_types::nmt::Namespace;
use ed25519_dalek::{Signer, SigningKey};
use lumina_node::network::Network;
use lumina_node::NodeBuilder;
use tlog_celestia::lumina::{Availability, LuminaSource, LuminaSourceError, SamplingTracker};
use tlog_celestia::publisher::CelestiaPublisher;
use tlog_celestia::{
    default_namespace, sync_to_tip, HeightReport, NamespaceFollower, NamespaceItem, SourceError,
    VerifiedNamespaceSource,
};
use tlog_core::hash::sha256;
use tlog_core::statement::{
    LogConfig, Publish, Record, RegistryOp, RegistryUpdate, RevocationReason, Revoke, SignedStatement,
    Statement,
};
use tlog_core::status::ChainTime;
use tlog_core::{Effect, EntryId, EntryStatus, PublicKey, Signature};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn pk(k: &SigningKey) -> PublicKey {
    PublicKey(k.verifying_key().to_bytes())
}

fn rec(k: &SigningKey, statement: Statement, payload: Option<Vec<u8>>) -> Record {
    let signature = Signature(k.sign(&statement.signing_bytes()).to_bytes());
    Record { signed: SignedStatement { statement, signature }, payload }
}

/// Parse `s` as the same type as `like`. Lets the test build a multiaddr
/// without naming the multiaddr crate, which is not a dependency here.
fn parse_like<T: FromStr>(_like: &T, s: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    s.parse().expect("multiaddr")
}

/// What the source was asked, and what it said, per height.
#[derive(Default, Debug)]
struct Seen {
    /// Height -> was the tracker already showing a success when the source
    /// was asked for this height's data (true) or did own-sampling run (false).
    tracker_hit: BTreeMap<u64, bool>,
    /// Height -> errors returned for it, in order.
    errors: BTreeMap<u64, Vec<String>>,
}

/// Wraps [`LuminaSource`] to record whether the node's own sampling was
/// visible to the tracker when each height was read.
struct Recording<'a, S> {
    inner: S,
    tracker: SamplingTracker,
    seen: &'a Mutex<Seen>,
}

impl<S: VerifiedNamespaceSource<Error = LuminaSourceError>> VerifiedNamespaceSource for Recording<'_, S> {
    type Error = LuminaSourceError;

    async fn verified_tip(&self) -> Result<u64, Self::Error> {
        self.inner.verified_tip().await
    }

    async fn header_time(&self, height: u64) -> Result<ChainTime, Self::Error> {
        let r = self.inner.header_time(height).await;
        if let Err(e) = &r {
            self.seen.lock().unwrap().errors.entry(height).or_default().push(format!("header_time: {e}"));
        }
        r
    }

    async fn namespace_items(&self, ns: Namespace, height: u64) -> Result<Vec<NamespaceItem>, Self::Error> {
        let hit = self.tracker.is_sampled(height);
        let r = self.inner.namespace_items(ns, height).await;
        let mut seen = self.seen.lock().unwrap();
        match &r {
            Ok(_) => {
                seen.tracker_hit.insert(height, hit);
            }
            Err(e) => seen.errors.entry(height).or_default().push(format!("namespace_items: {e}")),
        }
        r
    }
}

/// Tests share the bridge's signing account, so they must not submit
/// concurrently. Held for a whole test.
static DEVNET: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

type LuminaNode =
    lumina_node::Node<lumina_node::blockstore::InMemoryBlockstore, lumina_node::store::InMemoryStore>;

fn rpc_url() -> String {
    env_or("TLOG_DEVNET_RPC", "ws://localhost:26658")
}

/// Start a Lumina node bootstrapped from the bridge, with a tracker fed from
/// its events. `pruning_window: None` keeps Lumina's in-memory default (0).
async fn start_node(pruning_window: Option<Duration>) -> (LuminaNode, SamplingTracker, Client) {
    let p2p_addr = env_or("TLOG_DEVNET_P2P", "/ip4/127.0.0.1/tcp/2121");
    let rpc = Client::new(&rpc_url(), None, None, None).await.expect("rpc connect");
    let info = rpc.p2p_info().await.expect("p2p.Info");
    let tcp =
        info.addrs.iter().find(|a| a.to_string().contains("/tcp/")).expect("bridge listens on tcp").clone();
    println!("bridge {} advertises tcp {tcp}", info.id.0);
    let bootnode = parse_like(&tcp, &format!("{p2p_addr}/p2p/{}", info.id.0));
    println!("dialing {bootnode}");

    let mut builder = NodeBuilder::new().network(Network::custom("private").unwrap()).bootnodes([bootnode]);
    if let Some(w) = pruning_window {
        builder = builder.pruning_window(w);
    }
    let (node, events) = builder.start_subscribed().await.expect("start lumina");
    let tracker = SamplingTracker::default();
    tokio::spawn(tracker.clone().run(events));
    tokio::time::timeout(Duration::from_secs(60), node.wait_connected_trusted())
        .await
        .expect("lumina connected to the bridge within 60s")
        .expect("wait_connected_trusted");
    (node, tracker, rpc)
}

/// A fresh log per test run, so runs on one devnet stay apart.
struct TestLog {
    cfg: LogConfig,
    admin: SigningKey,
    publ: SigningKey,
    ns: Namespace,
}

impl TestLog {
    fn new(tag: &str) -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let admin = SigningKey::from_bytes(&sha256(format!("admin-{tag}-{nonce}").as_bytes()));
        let publ = SigningKey::from_bytes(&sha256(format!("publisher-{tag}-{nonce}").as_bytes()));
        let cfg = LogConfig { name: format!("devnet-{tag}-{nonce}"), admin: pk(&admin) };
        let ns = default_namespace(&cfg.log_id());
        println!("log {} namespace {:?}", cfg.name, ns);
        Self { cfg, admin, publ, ns }
    }

    fn add_publisher(&self) -> Record {
        rec(
            &self.admin,
            Statement::Registry(RegistryUpdate {
                log_id: self.cfg.log_id(),
                seq: 0,
                op: RegistryOp::AddPublisher { key: pk(&self.publ), label: "devnet".into() },
            }),
            None,
        )
    }

    fn publish(&self, body: &[u8]) -> (EntryId, Record) {
        let p = Publish {
            log_id: self.cfg.log_id(),
            publisher: pk(&self.publ),
            subject: "pkg:devnet".into(),
            content_hash: sha256(body),
            content_len: body.len() as u64,
            serial: 1,
        };
        (p.entry_id(), rec(&self.publ, Statement::Publish(p), Some(body.to_vec())))
    }

    fn revoke(&self, entry_id: EntryId) -> Record {
        rec(
            &self.publ,
            Statement::Revoke(Revoke {
                log_id: self.cfg.log_id(),
                entry_id,
                revoker: pk(&self.publ),
                reason: RevocationReason::Withdrawn,
            }),
            None,
        )
    }
}

async fn wait_network_height(rpc: &Client, height: u64) {
    while rpc.header_network_head().await.expect("network head").height() < height {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Sync until the follower has ingested `until`, retrying on stalls.
async fn follow_until<S>(
    follower: &mut NamespaceFollower,
    source: &S,
    until: u64,
    limit: Duration,
) -> Result<(Vec<HeightReport>, Vec<String>), String>
where
    S: VerifiedNamespaceSource<Error = LuminaSourceError>,
{
    let mut reports = Vec::new();
    let mut stalls: Vec<String> = Vec::new();
    let deadline = Instant::now() + limit;
    while follower.next_height() <= until {
        if Instant::now() >= deadline {
            return Err(format!(
                "follower stuck at {}; last stall: {:?}",
                follower.next_height(),
                stalls.last()
            ));
        }
        let out = sync_to_tip(follower, source).await.map_err(|e| format!("{e}"))?;
        reports.extend(out.reports);
        if let Some(s) = out.stalled {
            assert!(s.error.is_transient());
            let msg = format!("stalled at {} (tip {}): {}", s.height, out.tip, s.error);
            if stalls.last() != Some(&msg) {
                println!("{msg}");
            }
            stalls.push(msg);
            tokio::time::sleep(Duration::from_secs(1)).await;
        } else if follower.next_height() <= until {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    Ok((reports, stalls))
}

fn print_reports(reports: &[HeightReport]) {
    for r in reports {
        for (pos, eff) in &r.accepted {
            println!("height {}: accepted #{} {}", r.height, pos.index, effect_name(eff));
        }
        for (pos, why) in &r.rejected {
            println!("height {}: REJECTED #{}: {why:?}", r.height, pos.index);
        }
    }
}

fn effect_name(e: &Effect) -> &'static str {
    match e {
        Effect::PublisherAdded { .. } => "PublisherAdded",
        Effect::Published { .. } => "Published",
        Effect::Revoked { .. } => "Revoked",
        _ => "other",
    }
}

/// Publish, let empty heights go by, revoke; follow it all through Lumina
/// with DAS required.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a local Celestia devnet (see module docs)"]
async fn publish_and_revoke_on_devnet() {
    let _devnet = DEVNET.lock().await;
    let (node, tracker, rpc) = start_node(Some(Duration::from_secs(3600))).await;
    let log = TestLog::new("revoke");
    let publisher = CelestiaPublisher::connect(&rpc_url(), None, log.ns).await.expect("publisher connect");

    let (entry, publish) = log.publish(b"release-manifest");
    let add_at = publisher.submit(&log.add_publisher()).await.expect("submit add-publisher");
    println!("AddPublisher at {}", add_at.height);
    let pub_at = publisher.submit(&publish).await.expect("submit publish");
    println!("Publish at {}", pub_at.height);
    // Let a few empty heights go by so the follower has to prove absence.
    wait_network_height(&rpc, pub_at.height + 3).await;
    let rev_at = publisher.submit(&log.revoke(entry)).await.expect("submit revoke");
    println!("Revoke at {}", rev_at.height);
    assert!(add_at.height <= pub_at.height && pub_at.height < rev_at.height);

    // Follow from the first record: the registry update has to be in the log
    // for the publish to count.
    let mut follower = NamespaceFollower::new(log.cfg.clone(), log.ns, add_at.height);
    let seen = Mutex::new(Seen::default());
    let source = Recording {
        inner: LuminaSource::new(&node, Availability::sampled(tracker.clone())),
        tracker: tracker.clone(),
        seen: &seen,
    };
    let (reports, stalls) = follow_until(&mut follower, &source, rev_at.height, Duration::from_secs(300))
        .await
        .unwrap_or_else(|e| {
            panic!("{e}\nseen: {:#?}", seen.lock().unwrap());
        });

    print_reports(&reports);
    let seen = seen.into_inner().unwrap();
    let own_sampled: Vec<u64> = seen.tracker_hit.iter().filter(|(_, hit)| !**hit).map(|(h, _)| *h).collect();
    println!(
        "heights read {}..={}: tracker had a success for {}, own-sampling ran for {:?}",
        add_at.height,
        follower.head().unwrap().height,
        seen.tracker_hit.len() - own_sampled.len(),
        own_sampled
    );
    for (h, errs) in &seen.errors {
        println!("errors at {h}: {errs:?}");
    }
    println!("{} stall(s) in total", stalls.len());

    let ingested: Vec<u64> = seen.tracker_hit.keys().copied().collect();
    let expected: Vec<u64> = (add_at.height..follower.next_height()).collect();
    assert_eq!(ingested, expected, "every height from the start was read and proven");
    let with_blobs: Vec<u64> = reports.iter().map(|r| r.height).collect();
    let empty = expected.iter().filter(|h| !with_blobs.contains(h)).count();
    assert!(empty >= 3, "at least the gap heights were ingested as proven-empty: {empty}");
    assert!(reports.iter().all(|r| r.rejected.is_empty()), "no rejections expected in a fresh namespace");
    let accepted: usize = reports.iter().map(|r| r.accepted.len()).sum();
    assert_eq!(accepted, 3, "registry, publish and revoke accepted");

    let obs = follower.observe(&entry).expect("observation");
    match obs.status {
        EntryStatus::Revoked { published, revoked, .. } => {
            assert_eq!(published.height, pub_at.height);
            assert_eq!(revoked.height, rev_at.height);
        }
        other => panic!("expected Revoked, got {other:?}"),
    }
    assert!(obs.head.height >= rev_at.height);
    node.stop().await;
}

/// The source's own sampling (`request_sample` against the bridge), with a
/// tracker that never hears from the node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a local Celestia devnet (see module docs)"]
async fn own_sampling_on_devnet() {
    let _devnet = DEVNET.lock().await;
    let (node, _fed, _rpc) = start_node(Some(Duration::from_secs(3600))).await;
    let log = TestLog::new("own");
    let publisher = CelestiaPublisher::connect(&rpc_url(), None, log.ns).await.expect("publisher connect");
    let (entry, publish) = log.publish(b"own-sampling");
    let add_at = publisher.submit(&log.add_publisher()).await.expect("submit add-publisher");
    let pub_at = publisher.submit(&publish).await.expect("submit publish");
    println!("AddPublisher at {}, Publish at {}", add_at.height, pub_at.height);

    let unfed = SamplingTracker::default();
    let mut follower = NamespaceFollower::new(log.cfg.clone(), log.ns, add_at.height);
    let seen = Mutex::new(Seen::default());
    let source = Recording {
        inner: LuminaSource::new(&node, Availability::Sampled { tracker: unfed.clone(), own_samples: 16 }),
        tracker: unfed.clone(),
        seen: &seen,
    };
    let (reports, stalls) = follow_until(&mut follower, &source, pub_at.height, Duration::from_secs(120))
        .await
        .unwrap_or_else(|e| panic!("{e}\nseen: {:#?}", seen.lock().unwrap()));
    print_reports(&reports);
    println!("{} stall(s)", stalls.len());
    let seen = seen.into_inner().unwrap();
    assert!(seen.tracker_hit.values().all(|hit| !hit), "every height was sampled by the source itself");
    assert!(
        (add_at.height..=pub_at.height).all(|h| unfed.is_sampled(h)),
        "own sampling recorded its successes"
    );
    assert!(matches!(follower.observe(&entry).unwrap().status, EntryStatus::Active { .. }));
    node.stop().await;
}

/// With Lumina's in-memory default pruning window (zero), headers are pruned
/// right after sampling. A follower that asks for a pruned height must be told
/// `Pruned` (fatal: it needs another source), not stall forever on a
/// transient `NotSynced`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a local Celestia devnet (see module docs)"]
async fn pruned_header_is_fatal_not_a_stall() {
    let _devnet = DEVNET.lock().await;
    let (node, tracker, rpc) = start_node(None).await;
    let log = TestLog::new("pruned");
    let publisher = CelestiaPublisher::connect(&rpc_url(), None, log.ns).await.expect("publisher connect");
    let add_at = publisher.submit(&log.add_publisher()).await.expect("submit add-publisher");
    println!("AddPublisher at {}", add_at.height);
    wait_network_height(&rpc, add_at.height + 3).await;

    // Wait for Lumina to sample and then prune the height.
    let deadline = Instant::now() + Duration::from_secs(120);
    while node.get_header_by_height(add_at.height).await.is_ok() {
        assert!(Instant::now() < deadline, "height {} was never pruned", add_at.height);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let info = node.syncer_info().await.unwrap();
    println!("height {} gone from the store; stored headers {:?}", add_at.height, info.stored_headers);

    let mut follower = NamespaceFollower::new(log.cfg.clone(), log.ns, add_at.height);
    let source = LuminaSource::new(&node, Availability::sampled(tracker.clone()));
    let outcome = follow_until(&mut follower, &source, add_at.height, Duration::from_secs(30)).await;
    println!("outcome: {outcome:?}");
    let err = outcome.expect_err("a pruned height cannot be ingested");
    assert!(err.contains("pruned"), "expected a fatal Pruned error, got: {err}");
    node.stop().await;
}
