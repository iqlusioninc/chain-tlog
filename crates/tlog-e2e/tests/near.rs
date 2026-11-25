//! NEAR-only log users, against a `near-workspaces` sandbox.
//!
//! `cargo test -p tlog-e2e --test near -- --ignored`

use tlog_core::statement::RevocationReason;
use tlog_e2e::near::{NearLog, DEFAULT_MAX_INLINE_PAYLOAD};
use tlog_e2e::{scenarios, Fixture, LogBackend};

#[tokio::test]
#[ignore = "needs the NEAR sandbox; run with --ignored"]
async fn near_only_lifecycle() -> anyhow::Result<()> {
    let mut fx = Fixture::unique("e2e-near");
    let mut near = NearLog::deploy(&fx.config, DEFAULT_MAX_INLINE_PAYLOAD).await?;
    scenarios::single_backend_lifecycle(&mut fx, &mut near).await
}

#[tokio::test]
#[ignore = "needs the NEAR sandbox; run with --ignored"]
async fn near_refuses_invalid_records() -> anyhow::Result<()> {
    let mut fx = Fixture::unique("e2e-near-invalid");
    let mut near = NearLog::deploy(&fx.config, 1024).await?;
    scenarios::register_publisher(&mut fx, &mut near).await?;

    // Replayed registry update (stale sequence number).
    let mut replay_fx = Fixture::new(&fx.config.name);
    let stale = replay_fx.add_publisher();
    assert!(near.submit(&stale).await.is_err(), "replayed registry update accepted");

    // Inline payload over the contract's limit.
    let big = vec![7u8; 2048];
    let (_, too_big) = fx.publish("big", &big, 1, true);
    assert!(near.submit(&too_big).await.is_err(), "oversized inline payload accepted");

    // Duplicate publish.
    let (id, rec) = fx.publish("dup", b"x", 1, false);
    near.submit(&rec).await?;
    assert!(near.submit(&rec).await.is_err(), "duplicate publish accepted");

    // Record for another log.
    let other = Fixture::unique("e2e-near-other");
    let (_, foreign) = other.publish("x", b"x", 1, false);
    assert!(near.submit(&foreign).await.is_err(), "record for another log accepted");

    // Revoking twice.
    near.submit(&fx.revoke(id, RevocationReason::Superseded)).await?;
    assert!(
        near.submit(&fx.revoke(id, RevocationReason::Superseded)).await.is_err(),
        "double revoke accepted"
    );
    Ok(())
}
