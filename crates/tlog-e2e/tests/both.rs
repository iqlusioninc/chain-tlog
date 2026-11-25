//! Log users who treat both NEAR and Celestia as authoritative, and what
//! each kind of user sees when the two logs disagree.
//!
//! ```sh
//! docker compose -f ci/celestia-devnet/docker-compose.yml up -d --wait
//! cargo test -p tlog-e2e --test both -- --ignored --test-threads=1
//! ```

use std::time::Duration;

use tlog_core::statement::RevocationReason;
use tlog_core::status::Backend;
use tlog_core::{Authority, EntryId, Verdict};
use tlog_e2e::celestia::CelestiaLog;
use tlog_e2e::near::{NearLog, DEFAULT_MAX_INLINE_PAYLOAD};
use tlog_e2e::{policy, verify, Fixture, LogBackend};

const GRACE: Duration = Duration::from_secs(600);

struct Both {
    fx: Fixture,
    near: NearLog,
    celestia: CelestiaLog,
}

impl Both {
    async fn new(name: &str) -> anyhow::Result<Self> {
        let mut fx = Fixture::unique(name);
        let mut near = NearLog::deploy(&fx.config, DEFAULT_MAX_INLINE_PAYLOAD).await?;
        let mut celestia = CelestiaLog::connect(&fx.config).await?;
        // One signed registry record, mirrored to both.
        let add = fx.add_publisher();
        near.submit(&add).await?;
        celestia.submit(&add).await?;
        Ok(Self { fx, near, celestia })
    }

    /// Verdict for each kind of log user: NEAR-only, Celestia-only, both.
    async fn verdicts(&mut self, id: &EntryId, grace: Duration) -> anyhow::Result<[Verdict; 3]> {
        let n = verify(&policy(Authority::Near, grace), Some(&mut self.near), None::<&mut CelestiaLog>, id)
            .await?;
        let c =
            verify(&policy(Authority::Celestia, grace), None::<&mut NearLog>, Some(&mut self.celestia), id)
                .await?;
        let b = verify(&policy(Authority::Both, grace), Some(&mut self.near), Some(&mut self.celestia), id)
            .await?;
        Ok([n, c, b])
    }
}

/// The normal path: the publisher submits the same bytes to both chains.
#[tokio::test]
#[ignore = "needs the NEAR sandbox and the Celestia devnet; run with --ignored"]
async fn mirrored_publish_and_revoke() -> anyhow::Result<()> {
    let mut t = Both::new("e2e-both").await?;
    let (id, rec) = t.fx.publish("example.com", b"cert", 1, true);
    t.near.submit(&rec).await?;
    t.celestia.submit(&rec).await?;
    assert_eq!(t.verdicts(&id, GRACE).await?, [Verdict::Valid; 3]);

    let rv = t.fx.revoke(id, RevocationReason::KeyCompromise);
    t.near.submit(&rv).await?;
    t.celestia.submit(&rv).await?;
    let [n, c, b] = t.verdicts(&id, GRACE).await?;
    let reason = RevocationReason::KeyCompromise;
    assert_eq!(n, Verdict::Revoked { backend: Backend::Near, reason });
    assert_eq!(c, Verdict::Revoked { backend: Backend::Celestia, reason });
    assert!(matches!(b, Verdict::Revoked { reason: r, .. } if r == reason), "{b:?}");
    Ok(())
}

/// Published on NEAR, never mirrored to Celestia. A NEAR-only user accepts
/// it; a both-chains user waits out the grace period, then reports a split.
#[tokio::test]
#[ignore = "needs the NEAR sandbox and the Celestia devnet; run with --ignored"]
async fn publish_missing_on_one_chain() -> anyhow::Result<()> {
    let mut t = Both::new("e2e-both-split").await?;
    let (id, rec) = t.fx.publish("example.com", b"near only", 1, false);
    t.near.submit(&rec).await?;

    let [n, c, b] = t.verdicts(&id, GRACE).await?;
    assert_eq!(n, Verdict::Valid);
    assert_eq!(c, Verdict::NotFound);
    assert_eq!(b, Verdict::AwaitingMirror { present_on: Backend::Near });

    let [_, _, b] = t.verdicts(&id, Duration::ZERO).await?;
    assert_eq!(b, Verdict::SplitPublication { present_on: Backend::Near });

    // Mirroring late heals it.
    t.celestia.submit(&rec).await?;
    assert_eq!(t.verdicts(&id, Duration::ZERO).await?, [Verdict::Valid; 3]);
    Ok(())
}

/// Revoked on Celestia only. A both-chains user treats it as revoked; a
/// NEAR-only user still sees it valid until the revocation is mirrored.
#[tokio::test]
#[ignore = "needs the NEAR sandbox and the Celestia devnet; run with --ignored"]
async fn revocation_on_one_chain_wins() -> anyhow::Result<()> {
    let mut t = Both::new("e2e-both-revoke").await?;
    let (id, rec) = t.fx.publish("example.com", b"cert", 1, false);
    t.near.submit(&rec).await?;
    t.celestia.submit(&rec).await?;

    let reason = RevocationReason::Withdrawn;
    let rv = t.fx.revoke_by(&t.fx.admin, id, reason);
    t.celestia.submit(&rv).await?;

    let [n, c, b] = t.verdicts(&id, GRACE).await?;
    assert_eq!(n, Verdict::Valid);
    assert_eq!(c, Verdict::Revoked { backend: Backend::Celestia, reason });
    assert_eq!(b, Verdict::Revoked { backend: Backend::Celestia, reason });

    // Same signed revocation, mirrored to NEAR.
    t.near.submit(&rv).await?;
    let [n, _, _] = t.verdicts(&id, GRACE).await?;
    assert_eq!(n, Verdict::Revoked { backend: Backend::Near, reason });
    Ok(())
}
