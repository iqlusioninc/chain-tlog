//! Shared core for chain-tlog.
//!
//! A chain-tlog *log* is one logical transparency log, identified by a
//! [`LogId`] derived from its [`LogConfig`]. It can be hosted on a NEAR
//! contract, a Celestia namespace, or both. Each host (a *backend*) is a
//! complete log on its own: it orders the same signed [`Record`]s and applies
//! the same validation [`rules`]. Verifiers pick which backends are
//! authoritative and combine what they observe with [`policy::evaluate`].
//!
//! This crate holds everything that must be identical across backends:
//!
//! - the wire format of statements and records ([`statement`]),
//! - identifiers and their hash derivations ([`ids`]),
//! - the validation rules a backend applies before accepting a record ([`rules`]),
//! - an in-memory log fold used by followers such as the Celestia verifier ([`state`]),
//! - the status and verdict types verifiers report ([`status`], [`policy`]).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod hash;
pub mod ids;
pub mod policy;
pub mod rules;
pub mod sig;
pub mod state;
pub mod statement;
pub mod status;

pub use ids::{EntryId, LogId, PublicKey, Signature};
pub use policy::{evaluate, Authority, BackendResult, Policy, Verdict};
pub use rules::{check, Effect, EntryMeta, LogView, Reject};
pub use sig::SignatureVerifier;
pub use state::LogState;
pub use statement::{
    LogConfig, Publish, Record, RegistryOp, RegistryUpdate, RevocationReason, Revoke, SignedStatement,
    Statement,
};
pub use status::{Backend, ChainTime, EntryStatus, Observation, Position};
