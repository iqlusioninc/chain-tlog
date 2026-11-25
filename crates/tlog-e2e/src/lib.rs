//! End-to-end harness for chain-tlog.
//!
//! The tests in `tests/` publish and revoke entries on real chains and then
//! verify them the way a log user would, for each [`Authority`] choice:
//!
//! - NEAR: a `near-workspaces` sandbox with the `tlog-near` contract deployed.
//! - Celestia: the local devnet in `ci/celestia-devnet` (one validator, one
//!   bridge node), read back through an embedded Lumina light node.
//!
//! # Plugging in
//!
//! Everything a test touches goes through [`LogBackend`]: `submit` puts the
//! same encoded [`Record`] on a chain, `observe` returns a [`BackendResult`]
//! for [`tlog_core::evaluate`]. To test a new verifier (for example the NEAR
//! light client), implement `observe` with it and reuse the scenarios in
//! [`scenarios`]. To test a new record shape (for example large NEAR
//! payloads), build it with [`Fixture`] and submit it through the same trait.
//!
//! # What is trusted here
//!
//! - [`celestia::CelestiaLog`] observes through Lumina: headers, namespace
//!   completeness and sampling are checked by the light node, not taken from
//!   the bridge's RPC. The RPC is only used to submit blobs and to find the
//!   bridge's p2p address.
//! - [`near::NearLog`] observes with a view call against the sandbox's RPC.
//!   That trusts the RPC node. It is a stand-in until the NEAR light-client
//!   verifier lands; swap it in by replacing [`near::NearLog::observe`].
//!
//! # Running
//!
//! The chain tests are `#[ignore]`d so `cargo test --workspace` stays
//! offline. See `crates/tlog-e2e/README.md`.

#![forbid(unsafe_code)]

pub mod celestia;
pub mod fixture;
pub mod near;
pub mod scenarios;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tlog_core::statement::Record;
use tlog_core::status::Backend;
use tlog_core::{evaluate, BackendResult, EntryId, Policy, Verdict};

pub use fixture::Fixture;

/// One backend of a log under test.
#[allow(async_fn_in_trait)]
pub trait LogBackend {
    /// Which backend this is.
    fn backend(&self) -> Backend;

    /// Put an encoded record on the chain and wait until it is included.
    /// Returns an error if the backend rejected it.
    async fn submit(&mut self, record: &Record) -> anyhow::Result<()>;

    /// Status of `entry_id` as of a head that includes everything this
    /// handle has submitted so far.
    async fn observe(&mut self, entry_id: &EntryId) -> anyhow::Result<BackendResult>;
}

/// Current wall-clock time in Unix nanoseconds, the `now` a verifier passes
/// to [`evaluate`].
pub fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock after epoch").as_nanos() as u64
}

/// A policy with a one-minute freshness bound and the given mirror grace.
pub fn policy(authority: tlog_core::Authority, mirror_grace: Duration) -> Policy {
    Policy { authority, max_head_age_ns: 60_000_000_000, mirror_grace_ns: mirror_grace.as_nanos() as u64 }
}

/// Observe on whichever backends are given and evaluate.
pub async fn verify<N: LogBackend, C: LogBackend>(
    policy: &Policy,
    near: Option<&mut N>,
    celestia: Option<&mut C>,
    entry_id: &EntryId,
) -> anyhow::Result<Verdict> {
    let n = match near {
        Some(b) => Some(b.observe(entry_id).await?),
        None => None,
    };
    let c = match celestia {
        Some(b) => Some(b.observe(entry_id).await?),
        None => None,
    };
    Ok(evaluate(policy, now_ns(), n.as_ref(), c.as_ref()))
}

/// Placeholder backend for "not authoritative" in [`verify`] calls.
pub enum NoBackend {}

impl LogBackend for NoBackend {
    fn backend(&self) -> Backend {
        match *self {}
    }
    async fn submit(&mut self, _: &Record) -> anyhow::Result<()> {
        match *self {}
    }
    async fn observe(&mut self, _: &EntryId) -> anyhow::Result<BackendResult> {
        match *self {}
    }
}
