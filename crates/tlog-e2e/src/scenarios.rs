//! Scenarios that run against any [`LogBackend`].
//!
//! A new verifier or backend implementation gets coverage by calling these
//! from a test with its own `LogBackend`.

use std::time::Duration;

use anyhow::ensure;
use tlog_core::statement::RevocationReason;
use tlog_core::status::Backend;
use tlog_core::{Authority, EntryId, Policy, Verdict};

use crate::fixture::{pk, Fixture};
use crate::{policy, verify, LogBackend, NoBackend};

/// The single-backend authority for `b`.
pub fn authority_of(b: Backend) -> Authority {
    match b {
        Backend::Near => Authority::Near,
        Backend::Celestia => Authority::Celestia,
    }
}

/// Verify `entry_id` with `backend` as the only authoritative backend.
pub async fn verify_one<B: LogBackend>(
    policy: &Policy,
    backend: &mut B,
    entry_id: &EntryId,
) -> anyhow::Result<Verdict> {
    match backend.backend() {
        Backend::Near => verify::<B, NoBackend>(policy, Some(backend), None, entry_id).await,
        Backend::Celestia => verify::<NoBackend, B>(policy, None, Some(backend), entry_id).await,
    }
}

/// Register the fixture's publisher on `backend`.
pub async fn register_publisher<B: LogBackend>(fx: &mut Fixture, backend: &mut B) -> anyhow::Result<()> {
    let add = fx.add_publisher();
    backend.submit(&add).await
}

/// Publish, verify, revoke, verify, on one backend that a log user treats
/// as the only authority.
///
/// Covers: inline payload publish, an unknown entry, publisher revocation,
/// admin revocation, and that a record signed by an unregistered key never
/// becomes an entry (refused at submit on NEAR, skipped by the follower on
/// Celestia).
pub async fn single_backend_lifecycle<B: LogBackend>(
    fx: &mut Fixture,
    backend: &mut B,
) -> anyhow::Result<()> {
    let which = backend.backend();
    let p = policy(authority_of(which), Duration::from_secs(600));
    register_publisher(fx, backend).await?;

    // Publish two entries, one with its payload inline.
    let (a, rec_a) = fx.publish("example.com", b"certificate A", 1, true);
    let (b, rec_b) = fx.publish("example.com", b"certificate B", 2, false);
    backend.submit(&rec_a).await?;
    backend.submit(&rec_b).await?;

    // A record signed by a key that is not registered.
    let mut rogue = Fixture::new(&format!("{}-rogue", fx.config.name));
    rogue.config = fx.config.clone();
    let (forged_id, forged) = rogue.publish("example.com", b"forged", 1, true);
    ensure!(pk(&rogue.publisher) != pk(&fx.publisher), "rogue key must differ from the registered publisher");
    let _ = backend.submit(&forged).await; // NEAR refuses it; Celestia accepts the blob.

    let unknown = fx.publish_statement("example.com", b"never published", 99).entry_id();

    assert_eq!(verify_one(&p, backend, &a).await?, Verdict::Valid, "{which:?}: A after publish");
    assert_eq!(verify_one(&p, backend, &b).await?, Verdict::Valid, "{which:?}: B after publish");
    assert_eq!(verify_one(&p, backend, &unknown).await?, Verdict::NotFound, "{which:?}: unknown");
    assert_eq!(verify_one(&p, backend, &forged_id).await?, Verdict::NotFound, "{which:?}: forged");

    // Publisher revokes A; admin revokes B.
    backend.submit(&fx.revoke(a, RevocationReason::KeyCompromise)).await?;
    let admin_revoke = fx.revoke_by(&fx.admin, b, RevocationReason::Withdrawn);
    backend.submit(&admin_revoke).await?;

    assert_eq!(
        verify_one(&p, backend, &a).await?,
        Verdict::Revoked { backend: which, reason: RevocationReason::KeyCompromise },
        "{which:?}: A after revoke"
    );
    assert_eq!(
        verify_one(&p, backend, &b).await?,
        Verdict::Revoked { backend: which, reason: RevocationReason::Withdrawn },
        "{which:?}: B after admin revoke"
    );
    Ok(())
}
