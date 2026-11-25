//! Celestia-only log users, against `ci/celestia-devnet` and a Lumina light node.
//!
//! ```sh
//! docker compose -f ci/celestia-devnet/docker-compose.yml up -d --wait
//! cargo test -p tlog-e2e --test celestia -- --ignored --test-threads=1
//! ```

use tlog_celestia::Rejection;
use tlog_core::statement::DecodeError;
use tlog_core::status::EntryStatus;
use tlog_core::Reject;
use tlog_e2e::celestia::CelestiaLog;
use tlog_e2e::{scenarios, Fixture, LogBackend};

#[tokio::test]
#[ignore = "needs the Celestia devnet; run with --ignored"]
async fn celestia_only_lifecycle() -> anyhow::Result<()> {
    let mut fx = Fixture::unique("e2e-celestia");
    let mut celestia = CelestiaLog::connect(&fx.config).await?;
    scenarios::single_backend_lifecycle(&mut fx, &mut celestia).await
}

/// Anyone can post to the namespace. Squatter blobs and invalid records
/// show up as rejections in the follower and never change the log.
#[tokio::test]
#[ignore = "needs the Celestia devnet; run with --ignored"]
async fn celestia_skips_squatters_and_invalid_records() -> anyhow::Result<()> {
    let mut fx = Fixture::unique("e2e-celestia-junk");
    let mut celestia = CelestiaLog::connect(&fx.config).await?;

    celestia.submit_raw(b"not a record".to_vec()).await?;
    // Publish before the publisher is registered: rejected.
    let (id, rec) = fx.publish("s", b"payload", 1, false);
    celestia.submit(&rec).await?;
    scenarios::register_publisher(&mut fx, &mut celestia).await?;
    // The same bytes after registration: accepted.
    celestia.submit(&rec).await?;
    // Once more: duplicate.
    celestia.submit(&rec).await?;

    celestia.observe(&id).await?;
    let status = celestia.follower.observe(&id).map(|o| o.status);
    assert!(matches!(status, Some(EntryStatus::Active { .. })), "{status:?}");
    assert_eq!(
        celestia.rejections(),
        vec![
            Rejection::Decode(DecodeError::BadMagic),
            Rejection::Rule(Reject::UnknownPublisher),
            Rejection::Rule(Reject::DuplicateEntry),
        ]
    );
    Ok(())
}
