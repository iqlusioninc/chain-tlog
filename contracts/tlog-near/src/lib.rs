//! chain-tlog NEAR backend.
//!
//! The contract is a complete log on its own. It accepts the same encoded
//! [`Record`] bytes a publisher posts to Celestia, validates them with
//! [`tlog_core::rules::check`], and stores the result.
//!
//! # Storage layout (part of the proof format)
//!
//! Verifiers prove an entry's status with a NEAR state proof of one trie key,
//! so the layout is fixed:
//!
//! | Trie key                     | Value                         |
//! |------------------------------|-------------------------------|
//! | `b"e" ++ entry_id` (32 bytes)| borsh [`StoredEntry`]         |
//! | `b"p" ++ publisher_key`      | borsh `String` label          |
//! | `b"d" ++ entry_id`           | borsh `Vec<u8>` inline payload|
//! | `b"STATE"`                   | borsh [`TransparencyLog`]     |
//!
//! Status and inclusion are in the same value, so one proof of `b"e" ++ id`
//! against a light-client-verified block answers "is this entry in the log
//! and unrevoked as of that block". A proof that the key is absent answers
//! "not in the log".
//!
//! # Authorisation
//!
//! Anyone may call [`TransparencyLog::submit`]: authority comes from the
//! signature inside the record, not from the NEAR caller. This keeps the
//! record bytes identical across backends and lets a relayer pay gas. The
//! contract pays storage staking, which only registered publishers can
//! consume.
//!
//! Deploy to an account with no full-access keys. Whoever can redeploy the
//! contract can rewrite the log.

use near_sdk::json_types::{Base64VecU8, U64};
use near_sdk::store::LookupMap;
use near_sdk::{env, near, PanicOnDefault};

use tlog_core::rules::{check, EntryMeta, LogView};
use tlog_core::sig::SignatureVerifier;
use tlog_core::statement::{LogConfig, Publish, Record, RevocationReason};
use tlog_core::status::ChainTime;
use tlog_core::{Effect, EntryId, LogId, PublicKey, Signature};

/// Trie key prefix for entries.
pub const PREFIX_ENTRIES: &[u8] = b"e";
/// Trie key prefix for publishers.
pub const PREFIX_PUBLISHERS: &[u8] = b"p";
/// Trie key prefix for inline payloads.
pub const PREFIX_PAYLOADS: &[u8] = b"d";

/// Trie key holding the record for `entry_id`. Verifiers request a state
/// proof for this key.
pub fn entry_storage_key(entry_id: &EntryId) -> Vec<u8> {
    let mut k = PREFIX_ENTRIES.to_vec();
    k.extend_from_slice(entry_id.as_bytes());
    k
}

/// Revocation details.
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revocation {
    /// Block it was revoked in.
    pub at: ChainTime,
    /// Reason code.
    pub reason: RevocationReason,
    /// Who revoked it.
    pub revoker: PublicKey,
}

/// Value stored under `b"e" ++ entry_id`.
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEntry {
    /// The publish statement.
    pub publish: Publish,
    /// Contract-wide sequence number, the tie-breaker within a block.
    pub seq: u64,
    /// Block it was published in.
    pub published: ChainTime,
    /// Revocation, if any.
    pub revoked: Option<Revocation>,
}

/// Contract state.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct TransparencyLog {
    config: LogConfig,
    log_id: LogId,
    max_inline_payload: u64,
    registry_seq: u64,
    next_seq: u64,
    publishers: LookupMap<PublicKey, String>,
    entries: LookupMap<EntryId, StoredEntry>,
    payloads: LookupMap<EntryId, Vec<u8>>,
}

/// JSON view of an entry.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryView {
    /// Hex entry id.
    pub entry_id: String,
    /// Hex publisher key.
    pub publisher: String,
    /// Subject.
    pub subject: String,
    /// Hex SHA-256 of the payload.
    pub content_hash: String,
    /// Payload length.
    pub content_len: U64,
    /// Publisher serial.
    pub serial: U64,
    /// Contract sequence number.
    pub seq: U64,
    /// Block height of publication.
    pub published_height: U64,
    /// Block timestamp of publication, ns.
    pub published_ns: U64,
    /// `"active"` or `"revoked"`.
    pub status: String,
    /// Block height of revocation.
    pub revoked_height: Option<U64>,
    /// Revocation reason code.
    pub revocation_reason: Option<u8>,
    /// Whether the payload is stored inline.
    pub has_payload: bool,
}

/// JSON view of the log's identity.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogInfo {
    /// Log name.
    pub name: String,
    /// Hex admin key.
    pub admin: String,
    /// Hex log id.
    pub log_id: String,
    /// Inline payload limit in bytes.
    pub max_inline_payload: U64,
    /// Next registry sequence number.
    pub registry_seq: U64,
    /// Number of records accepted that created entries.
    pub entries: U64,
}

struct HostVerifier;

impl SignatureVerifier for HostVerifier {
    fn verify(&self, key: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
        env::ed25519_verify(&sig.0, msg, &key.0)
    }
}

struct View<'a>(&'a TransparencyLog);

impl LogView for View<'_> {
    fn is_publisher(&self, key: &PublicKey) -> bool {
        self.0.publishers.contains_key(key)
    }

    fn entry(&self, id: &EntryId) -> Option<EntryMeta> {
        self.0
            .entries
            .get(id)
            .map(|e| EntryMeta { publisher: e.publish.publisher, revoked: e.revoked.is_some() })
    }

    fn next_registry_seq(&self) -> u64 {
        self.0.registry_seq
    }
}

fn parse_hex<T: core::str::FromStr>(what: &str, s: &str) -> T {
    s.parse().unwrap_or_else(|_| env::panic_str(&format!("invalid hex {what}")))
}

fn now() -> ChainTime {
    ChainTime { height: env::block_height(), unix_ns: env::block_timestamp() }
}

fn emit(event: &str, data: String) {
    env::log_str(&format!(
        r#"EVENT_JSON:{{"standard":"chain-tlog","version":"1.0.0","event":"{event}","data":[{data}]}}"#
    ));
}

#[near]
impl TransparencyLog {
    /// Initialise the log. `admin` is a hex Ed25519 key.
    #[init]
    pub fn new(name: String, admin: String, max_inline_payload: U64) -> Self {
        let config = LogConfig { name, admin: parse_hex("admin key", &admin) };
        let log_id = config.log_id();
        Self {
            config,
            log_id,
            max_inline_payload: max_inline_payload.0,
            registry_seq: 0,
            next_seq: 0,
            publishers: LookupMap::new(PREFIX_PUBLISHERS),
            entries: LookupMap::new(PREFIX_ENTRIES),
            payloads: LookupMap::new(PREFIX_PAYLOADS),
        }
    }

    /// Submit an encoded [`Record`]. Panics if it fails validation.
    /// Returns the hex entry id for publications and revocations.
    pub fn submit(&mut self, record: Base64VecU8) -> Option<String> {
        let record =
            Record::decode(&record.0).unwrap_or_else(|e| env::panic_str(&format!("malformed record: {e:?}")));
        let effect = check(
            &self.config,
            &self.log_id,
            &View(self),
            &HostVerifier,
            &record,
            Some(self.max_inline_payload),
        )
        .unwrap_or_else(|e| env::panic_str(&format!("rejected: {e:?}")));
        let t = now();

        match effect {
            Effect::Published { entry_id, publish, payload } => {
                let seq = self.next_seq;
                self.next_seq += 1;
                emit(
                    "publish",
                    format!(
                        r#"{{"entry_id":"{entry_id}","subject":{},"publisher":"{}","seq":{seq}}}"#,
                        near_sdk::serde_json::to_string(&publish.subject).unwrap(),
                        publish.publisher
                    ),
                );
                if let Some(p) = payload {
                    self.payloads.insert(entry_id, p);
                }
                self.entries.insert(entry_id, StoredEntry { publish, seq, published: t, revoked: None });
                Some(entry_id.to_hex())
            }
            Effect::Revoked { entry_id, reason, revoker } => {
                let e = self.entries.get_mut(&entry_id).expect("checked by rules");
                e.revoked = Some(Revocation { at: t, reason, revoker });
                emit(
                    "revoke",
                    format!(r#"{{"entry_id":"{entry_id}","reason":{},"revoker":"{revoker}"}}"#, reason as u8),
                );
                Some(entry_id.to_hex())
            }
            Effect::PublisherAdded { key, label } => {
                self.publishers.insert(key, label);
                self.registry_seq += 1;
                emit("publisher_added", format!(r#"{{"key":"{key}"}}"#));
                None
            }
            Effect::PublisherRemoved { key } => {
                self.publishers.remove(&key);
                self.registry_seq += 1;
                emit("publisher_removed", format!(r#"{{"key":"{key}"}}"#));
                None
            }
        }
    }

    /// Entry by hex id.
    pub fn get_entry(&self, entry_id: String) -> Option<EntryView> {
        let id: EntryId = parse_hex("entry id", &entry_id);
        let e = self.entries.get(&id)?;
        Some(EntryView {
            entry_id: id.to_hex(),
            publisher: e.publish.publisher.to_hex(),
            subject: e.publish.subject.clone(),
            content_hash: hex::encode(e.publish.content_hash),
            content_len: U64(e.publish.content_len),
            serial: U64(e.publish.serial),
            seq: U64(e.seq),
            published_height: U64(e.published.height),
            published_ns: U64(e.published.unix_ns),
            status: if e.revoked.is_some() { "revoked" } else { "active" }.into(),
            revoked_height: e.revoked.as_ref().map(|r| U64(r.at.height)),
            revocation_reason: e.revoked.as_ref().map(|r| r.reason as u8),
            has_payload: self.payloads.contains_key(&id),
        })
    }

    /// Inline payload by hex entry id.
    pub fn get_payload(&self, entry_id: String) -> Option<Base64VecU8> {
        let id: EntryId = parse_hex("entry id", &entry_id);
        self.payloads.get(&id).cloned().map(Base64VecU8)
    }

    /// Whether a hex key is a registered publisher.
    pub fn is_publisher(&self, key: String) -> bool {
        self.publishers.contains_key(&parse_hex::<PublicKey>("key", &key))
    }

    /// Log identity and counters.
    pub fn get_log_info(&self) -> LogInfo {
        LogInfo {
            name: self.config.name.clone(),
            admin: self.config.admin.to_hex(),
            log_id: self.log_id.to_hex(),
            max_inline_payload: U64(self.max_inline_payload),
            registry_seq: U64(self.registry_seq),
            entries: U64(self.next_seq),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;
    use tlog_core::hash::sha256;
    use tlog_core::statement::{RegistryOp, RegistryUpdate, Revoke, SignedStatement, Statement};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pk(k: &SigningKey) -> PublicKey {
        PublicKey(k.verifying_key().to_bytes())
    }

    fn rec(k: &SigningKey, statement: Statement, payload: Option<Vec<u8>>) -> Base64VecU8 {
        let signature = Signature(k.sign(&statement.signing_bytes()).to_bytes());
        Base64VecU8(Record { signed: SignedStatement { statement, signature }, payload }.encode())
    }

    fn setup() -> (TransparencyLog, SigningKey, SigningKey) {
        testing_env!(VMContextBuilder::new().block_height(100).block_timestamp(1_000).build());
        let admin = key(1);
        let publ = key(2);
        let mut c = TransparencyLog::new("test".into(), pk(&admin).to_hex(), U64(1024));
        let log_id = c.log_id;
        c.submit(rec(
            &admin,
            Statement::Registry(RegistryUpdate {
                log_id,
                seq: 0,
                op: RegistryOp::AddPublisher { key: pk(&publ), label: "p".into() },
            }),
            None,
        ));
        (c, admin, publ)
    }

    fn publish_stmt(c: &TransparencyLog, k: &SigningKey, payload: &[u8], serial: u64) -> Publish {
        Publish {
            log_id: c.log_id,
            publisher: pk(k),
            subject: "example.com".into(),
            content_hash: sha256(payload),
            content_len: payload.len() as u64,
            serial,
        }
    }

    #[test]
    fn publish_and_revoke() {
        let (mut c, _admin, publ) = setup();
        assert!(c.is_publisher(pk(&publ).to_hex()));

        let p = publish_stmt(&c, &publ, b"cert", 1);
        let id = c.submit(rec(&publ, Statement::Publish(p.clone()), Some(b"cert".to_vec()))).unwrap();
        assert_eq!(id, p.entry_id().to_hex());

        let v = c.get_entry(id.clone()).unwrap();
        assert_eq!(v.status, "active");
        assert_eq!(v.published_height, U64(100));
        assert!(v.has_payload);
        assert_eq!(c.get_payload(id.clone()).unwrap().0, b"cert");

        testing_env!(VMContextBuilder::new().block_height(150).block_timestamp(2_000).build());
        let rv = Revoke {
            log_id: c.log_id,
            entry_id: p.entry_id(),
            revoker: pk(&publ),
            reason: RevocationReason::Superseded,
        };
        c.submit(rec(&publ, Statement::Revoke(rv), None));
        let v = c.get_entry(id).unwrap();
        assert_eq!(v.status, "revoked");
        assert_eq!(v.revoked_height, Some(U64(150)));
        assert_eq!(v.revocation_reason, Some(2));
    }

    #[test]
    #[should_panic(expected = "BadSignature")]
    fn wrong_signer_rejected() {
        let (mut c, _admin, publ) = setup();
        let p = publish_stmt(&c, &publ, b"x", 1);
        c.submit(rec(&key(9), Statement::Publish(p), None));
    }

    #[test]
    #[should_panic(expected = "DuplicateEntry")]
    fn duplicate_rejected() {
        let (mut c, _admin, publ) = setup();
        let p = publish_stmt(&c, &publ, b"x", 1);
        c.submit(rec(&publ, Statement::Publish(p.clone()), None));
        c.submit(rec(&publ, Statement::Publish(p), None));
    }

    #[test]
    #[should_panic(expected = "PayloadTooLarge")]
    fn payload_limit_enforced() {
        let (mut c, _admin, publ) = setup();
        let big = vec![7u8; 2048];
        let p = publish_stmt(&c, &publ, &big, 1);
        c.submit(rec(&publ, Statement::Publish(p), Some(big)));
    }

    #[test]
    fn storage_key_matches_layout() {
        let (mut c, _admin, publ) = setup();
        let p = publish_stmt(&c, &publ, b"x", 1);
        c.submit(rec(&publ, Statement::Publish(p.clone()), None));
        c.entries.flush();
        let raw = env::storage_read(&entry_storage_key(&p.entry_id())).expect("entry at documented key");
        let stored: StoredEntry = near_sdk::borsh::from_slice(&raw).unwrap();
        assert_eq!(stored.publish, p);
    }
}
