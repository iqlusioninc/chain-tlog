//! Entry observations: inclusion, status and non-inclusion from one proof.

use tlog_core::status::{Backend, ChainTime, EntryStatus, Observation};
use tlog_core::{EntryId, LogId};

use crate::hash::CryptoHash;
use crate::layout::{decode_prefix, entry_key, StateHeader, StoredEntry, STATE_KEY};
use crate::light_client::Head;
use crate::state_proof::{ContractStateProof, StateProofError, VerifiedState};

/// What a verifier pins about a log's NEAR deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NearLogBinding {
    /// Contract account.
    pub account_id: String,
    /// Log id the contract must hold.
    pub log_id: LogId,
    /// If set, the account's code hash must equal this.
    pub code_hash: Option<CryptoHash>,
}

/// Why an entry observation could not be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EntryProofError {
    /// The state proof was refused.
    #[error(transparent)]
    State(#[from] StateProofError),
    /// The contract's root state is not in the proven shard. Either the
    /// proof names the wrong shard or the contract is not deployed.
    #[error("contract state not found in the proven shard")]
    NoContract,
    /// The contract holds a different log.
    #[error("contract holds log {0}, expected another")]
    WrongLog(LogId),
    /// The account's code hash differs from the pinned one.
    #[error("code hash {got} does not match pinned {expected}")]
    CodeHash {
        /// Pinned.
        expected: CryptoHash,
        /// Proven.
        got: CryptoHash,
    },
    /// The account record is proven absent.
    #[error("account is absent")]
    NoAccount,
    /// The stored value does not decode, or belongs to another entry.
    #[error("stored entry is malformed")]
    MalformedEntry,
}

/// Check the contract's identity in `state`.
pub fn check_binding(state: &VerifiedState, binding: &NearLogBinding) -> Result<(), EntryProofError> {
    let raw = state.contract_data(STATE_KEY)?.ok_or(EntryProofError::NoContract)?;
    let header: StateHeader = decode_prefix(&raw).ok_or(EntryProofError::NoContract)?;
    if header.log_id != binding.log_id || header.config.log_id() != binding.log_id {
        return Err(EntryProofError::WrongLog(header.log_id));
    }
    if let Some(expected) = binding.code_hash {
        let got = state.code_hash()?.ok_or(EntryProofError::NoAccount)?;
        if got != expected {
            return Err(EntryProofError::CodeHash { expected, got });
        }
    }
    Ok(())
}

/// Observe `entry_id` on NEAR at `head`.
///
/// `head` must come from [`crate::LightClient`]. The proof must contain the
/// contract's `STATE` key and the entry key (present or absent), and the
/// account record if `binding.code_hash` is set.
pub fn observe_entry(
    head: &Head,
    binding: &NearLogBinding,
    entry_id: &EntryId,
    proof: &ContractStateProof,
) -> Result<Observation, EntryProofError> {
    let state = proof.verify(head, &binding.account_id)?;
    check_binding(&state, binding)?;
    let status = match state.contract_data(&entry_key(entry_id))? {
        None => EntryStatus::Absent,
        Some(raw) => {
            let e: StoredEntry = decode_prefix(&raw).ok_or(EntryProofError::MalformedEntry)?;
            if e.publish.entry_id() != *entry_id || e.publish.log_id != binding.log_id {
                return Err(EntryProofError::MalformedEntry);
            }
            match e.revoked {
                None => EntryStatus::Active { published: e.published },
                Some(r) => EntryStatus::Revoked { published: e.published, revoked: r.at, reason: r.reason },
            }
        }
    };
    Ok(Observation {
        backend: Backend::Near,
        status,
        head: ChainTime { height: head.inner_lite.height, unix_ns: head.inner_lite.timestamp },
    })
}
