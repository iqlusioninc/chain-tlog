//! Where the log lives in NEAR state, and how its values decode.
//!
//! The contract's storage layout is part of the proof format (see
//! `contracts/tlog-near`). The types here mirror the contract's borsh
//! layout without depending on `near-sdk`; a test in this crate checks the
//! encodings match byte for byte.
//!
//! Values are decoded as a prefix: trailing bytes are ignored, so the
//! contract may append fields to `StoredEntry` and the contract state
//! without breaking verifiers. Fields must never be reordered or removed.

use borsh::{BorshDeserialize, BorshSerialize};
use tlog_core::statement::{LogConfig, Publish, RevocationReason};
use tlog_core::status::ChainTime;
use tlog_core::{EntryId, LogId, PublicKey};

use crate::hash::CryptoHash;

/// Contract key of the entry value: `b"e" ++ entry_id`.
pub fn entry_key(entry_id: &EntryId) -> Vec<u8> {
    let mut k = b"e".to_vec();
    k.extend_from_slice(entry_id.as_bytes());
    k
}

/// Contract key of an inline payload: `b"d" ++ entry_id`.
pub fn payload_key(entry_id: &EntryId) -> Vec<u8> {
    let mut k = b"d".to_vec();
    k.extend_from_slice(entry_id.as_bytes());
    k
}

/// Contract key of the contract's root state.
pub const STATE_KEY: &[u8] = b"STATE";

/// nearcore trie column for accounts.
const COL_ACCOUNT: u8 = 0;
/// nearcore trie column for access keys.
const COL_ACCESS_KEY: u8 = 2;
/// nearcore trie column for contract storage.
const COL_CONTRACT_DATA: u8 = 9;
/// Separator between account id and contract key. Not a valid account-id
/// character, so keys of different accounts cannot collide.
const ACCOUNT_DATA_SEPARATOR: u8 = b',';

/// Trie key of a contract storage key: `0x09 ++ account ++ b',' ++ key`.
pub fn contract_data_trie_key(account_id: &str, key: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + account_id.len() + key.len());
    k.push(COL_CONTRACT_DATA);
    k.extend_from_slice(account_id.as_bytes());
    k.push(ACCOUNT_DATA_SEPARATOR);
    k.extend_from_slice(key);
    k
}

/// Trie key of an account record: `0x00 ++ account`.
pub fn account_trie_key(account_id: &str) -> Vec<u8> {
    let mut k = vec![COL_ACCOUNT];
    k.extend_from_slice(account_id.as_bytes());
    k
}

/// Trie prefix of all of an account's access keys: `0x02 ++ account ++ 0x02`.
pub fn access_keys_trie_prefix(account_id: &str) -> Vec<u8> {
    let mut k = vec![COL_ACCESS_KEY];
    k.extend_from_slice(account_id.as_bytes());
    k.push(COL_ACCESS_KEY);
    k
}

/// Mirror of the contract's `Revocation`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Revocation {
    /// Block it was revoked in.
    pub at: ChainTime,
    /// Reason code.
    pub reason: RevocationReason,
    /// Who revoked it.
    pub revoker: PublicKey,
}

/// Mirror of the contract's `StoredEntry`, the value at [`entry_key`].
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StoredEntry {
    /// The publish statement.
    pub publish: Publish,
    /// Contract-wide sequence number.
    pub seq: u64,
    /// Block it was published in.
    pub published: ChainTime,
    /// Revocation, if any.
    pub revoked: Option<Revocation>,
}

/// The first two fields of the contract's root state at [`STATE_KEY`].
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StateHeader {
    /// Log configuration.
    pub config: LogConfig,
    /// Log id, `config.log_id()`.
    pub log_id: LogId,
}

/// The fields of a NEAR account record the verifier uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountInfo {
    /// Hash of the deployed contract code.
    pub code_hash: CryptoHash,
}

/// Decode a borsh prefix, ignoring trailing bytes.
pub fn decode_prefix<T: BorshDeserialize>(bytes: &[u8]) -> Option<T> {
    T::deserialize(&mut &bytes[..]).ok()
}

/// Decode a NEAR account record.
///
/// Supports the V1 layout `{ amount: u128, locked: u128, code_hash, storage_usage: u64 }`.
/// Later versions start with a `u128::MAX` sentinel and are refused, so a
/// verifier fails closed rather than misreading them.
pub fn decode_account(bytes: &[u8]) -> Option<AccountInfo> {
    if bytes.len() != 72 || bytes[..16] == [0xff; 16] {
        return None;
    }
    Some(AccountInfo { code_hash: CryptoHash(bytes[32..64].try_into().ok()?) })
}
