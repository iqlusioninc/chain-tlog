//! chain-tlog NEAR verifier.
//!
//! Checks the NEAR backend of a log without trusting an RPC node or the log
//! operator. It has three layers:
//!
//! 1. [`light_client`]: follows NEAR's block producer set across epochs and
//!    accepts a block only when producers holding more than 2/3 of the
//!    epoch's stake signed an approval for it. This is the light client
//!    protocol from the NEAR spec (nomicon, "Light Client").
//! 2. [`state_proof`]: checks a trie proof for keys in the log contract's
//!    storage against the shard state roots committed in a verified head.
//! 3. [`entry`]: reads an entry's stored value (or proves it absent) and
//!    turns it into a [`tlog_core::Observation`], which goes into
//!    [`tlog_core::policy::evaluate`].
//!
//! The `rpc` feature adds a JSON-RPC client and [`backend::NearBackend`],
//! which ties the layers together. RPC nodes are untrusted; every byte they
//! return is checked.
//!
//! See `docs/design/0004-near-light-client.md` for the trust model and the
//! proof format.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod entry;
pub mod hash;
pub mod layout;
pub mod light_client;
pub mod merkle;
pub mod state_proof;
pub mod trie;
pub mod types;
pub mod views;

#[cfg(feature = "rpc")]
pub mod backend;
#[cfg(feature = "rpc")]
pub mod rpc;

pub use entry::{observe_entry, EntryProofError, NearLogBinding};
pub use hash::CryptoHash;
pub use light_client::{Head, LightClient, LightClientError};
pub use state_proof::{ContractStateProof, StateProofError, VerifiedState};
pub use types::{BlockHeaderInnerLite, LightClientBlock, NearPublicKey, NearSignature, ValidatorStake};
