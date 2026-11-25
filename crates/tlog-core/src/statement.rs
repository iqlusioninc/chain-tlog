//! Statements, signed statements and the record wire format.
//!
//! A [`Record`] is the unit a backend orders. Its encoding is
//! `RECORD_MAGIC || borsh(Record)` and is byte-for-byte the same whether it
//! is passed to the NEAR contract's `submit` method or posted as a Celestia
//! blob. Publishers sign once and submit the same bytes to every backend.

use borsh::{BorshDeserialize, BorshSerialize};

use crate::hash::{sha256, tagged_hash, TAG_ENTRY_ID, TAG_LOG_ID, TAG_STATEMENT};
use crate::{EntryId, LogId, PublicKey, Signature};

/// Magic prefix of an encoded [`Record`]. The trailing `1` is the format version.
pub const RECORD_MAGIC: [u8; 4] = *b"TLG1";

/// Static configuration that defines a log. Hashing it gives the [`LogId`].
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct LogConfig {
    /// Human-readable name, for example `"iqlusion-release-signing"`.
    pub name: String,
    /// Key that signs publisher registry updates and may revoke any entry.
    pub admin: PublicKey,
}

impl LogConfig {
    /// `H(TAG_LOG_ID, borsh(self))`.
    pub fn log_id(&self) -> LogId {
        LogId(tagged_hash(TAG_LOG_ID, &borsh::to_vec(self).expect("borsh to vec")))
    }
}

/// Publish a new entry.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Publish {
    /// Log this statement belongs to.
    pub log_id: LogId,
    /// Registered publisher key that signs this statement.
    pub publisher: PublicKey,
    /// What monitors watch, like a domain name in CT.
    pub subject: String,
    /// SHA-256 of the payload.
    pub content_hash: [u8; 32],
    /// Payload length in bytes.
    pub content_len: u64,
    /// Publisher-chosen value that makes otherwise identical publications
    /// distinct, for example a sequence number or timestamp.
    pub serial: u64,
    /// Whether the payload rides in the record. Signed, so a relayer cannot
    /// strip the payload from an `Attached` publication and get the
    /// hash-only copy logged first (threat T5). See design note 0002.
    pub payload_mode: PayloadMode,
}

/// Where a publication's payload lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum PayloadMode {
    /// The record must carry the payload. On Celestia it is in the blob; on
    /// NEAR it is in the call data of the `submit` transaction.
    Attached = 0,
    /// The record must not carry the payload. Only the hash is logged and
    /// the payload is distributed some other way.
    Detached = 1,
}

impl Publish {
    /// `H(TAG_ENTRY_ID, borsh(self))`.
    pub fn entry_id(&self) -> EntryId {
        EntryId(tagged_hash(TAG_ENTRY_ID, &borsh::to_vec(self).expect("borsh to vec")))
    }
}

/// Why an entry was revoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum RevocationReason {
    /// No reason given.
    Unspecified = 0,
    /// The key or material the entry vouches for is compromised.
    KeyCompromise = 1,
    /// A newer entry replaces this one.
    Superseded = 2,
    /// Published in error, or no longer endorsed.
    Withdrawn = 3,
}

/// Revoke an existing entry. Irreversible.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Revoke {
    /// Log this statement belongs to.
    pub log_id: LogId,
    /// Entry being revoked.
    pub entry_id: EntryId,
    /// Key that signs this statement: the entry's publisher or the log admin.
    pub revoker: PublicKey,
    /// Reason code.
    pub reason: RevocationReason,
}

/// A change to the publisher registry.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum RegistryOp {
    /// Authorise a publisher key.
    AddPublisher {
        /// Publisher key.
        key: PublicKey,
        /// Free-form label for monitors.
        label: String,
    },
    /// Deauthorise a publisher key. Existing entries stay as they are; revoke
    /// them explicitly if they should stop being valid.
    RemovePublisher {
        /// Publisher key.
        key: PublicKey,
    },
}

/// Admin-signed registry update.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RegistryUpdate {
    /// Log this statement belongs to.
    pub log_id: LogId,
    /// Must equal the backend's next registry sequence number. Prevents an
    /// old `AddPublisher` from being replayed after a `RemovePublisher`.
    pub seq: u64,
    /// The change.
    pub op: RegistryOp,
}

/// Any statement a backend can order.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Statement {
    /// See [`Publish`].
    Publish(Publish),
    /// See [`Revoke`].
    Revoke(Revoke),
    /// See [`RegistryUpdate`].
    Registry(RegistryUpdate),
}

impl Statement {
    /// Log this statement belongs to.
    pub fn log_id(&self) -> &LogId {
        match self {
            Statement::Publish(p) => &p.log_id,
            Statement::Revoke(r) => &r.log_id,
            Statement::Registry(u) => &u.log_id,
        }
    }

    /// Key that must have signed this statement.
    pub fn signer<'a>(&'a self, config: &'a LogConfig) -> &'a PublicKey {
        match self {
            Statement::Publish(p) => &p.publisher,
            Statement::Revoke(r) => &r.revoker,
            Statement::Registry(_) => &config.admin,
        }
    }

    /// Bytes covered by the signature: `TAG_STATEMENT || 0x00 || borsh(self)`.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let body = borsh::to_vec(self).expect("borsh to vec");
        let mut out = Vec::with_capacity(TAG_STATEMENT.len() + 1 + body.len());
        out.extend_from_slice(TAG_STATEMENT.as_bytes());
        out.push(0);
        out.extend_from_slice(&body);
        out
    }
}

/// A statement and its signature.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SignedStatement {
    /// The statement.
    pub statement: Statement,
    /// Signature over [`Statement::signing_bytes`] by [`Statement::signer`].
    pub signature: Signature,
}

/// The unit a backend orders: a signed statement plus, for publications, an
/// optional inline payload.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Record {
    /// The signed statement.
    pub signed: SignedStatement,
    /// Payload. Required on a [`PayloadMode::Attached`] publish, where it
    /// must match `content_hash` and `content_len`, and forbidden everywhere
    /// else.
    pub payload: Option<Vec<u8>>,
}

/// Errors decoding a [`Record`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Missing or wrong [`RECORD_MAGIC`].
    BadMagic,
    /// Body is not a valid borsh `Record`, or has trailing bytes.
    Malformed,
}

impl Record {
    /// `RECORD_MAGIC || borsh(self)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = RECORD_MAGIC.to_vec();
        borsh::to_writer(&mut out, self).expect("borsh to vec");
        out
    }

    /// Inverse of [`Record::encode`]. Rejects trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let body = bytes.strip_prefix(&RECORD_MAGIC[..]).ok_or(DecodeError::BadMagic)?;
        borsh::from_slice(body).map_err(|_| DecodeError::Malformed)
    }

    /// True if the attached payload agrees with the statement: present and
    /// matching `content_hash`/`content_len` for an [`PayloadMode::Attached`]
    /// publication, absent otherwise.
    pub fn payload_matches(&self) -> bool {
        self.payload_matches_with(sha256)
    }

    /// [`Self::payload_matches`] with a caller-supplied SHA-256, so a
    /// backend can use a cheaper implementation.
    pub fn payload_matches_with(&self, sha256: impl Fn(&[u8]) -> [u8; 32]) -> bool {
        match (&self.signed.statement, &self.payload) {
            (Statement::Publish(p), Some(data)) => {
                p.payload_mode == PayloadMode::Attached
                    && data.len() as u64 == p.content_len
                    && sha256(data) == p.content_hash
            }
            (Statement::Publish(p), None) => p.payload_mode == PayloadMode::Detached,
            (_, None) => true,
            (_, Some(_)) => false,
        }
    }
}

#[cfg(all(test, feature = "dalek"))]
pub(crate) mod test_support {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    pub fn pk(k: &SigningKey) -> PublicKey {
        PublicKey(k.verifying_key().to_bytes())
    }

    pub fn sign(k: &SigningKey, statement: Statement) -> SignedStatement {
        let sig = k.sign(&statement.signing_bytes());
        SignedStatement { statement, signature: Signature(sig.to_bytes()) }
    }

    pub fn record(k: &SigningKey, statement: Statement, payload: Option<Vec<u8>>) -> Record {
        Record { signed: sign(k, statement), payload }
    }

    pub fn publish(log_id: LogId, k: &SigningKey, subject: &str, payload: &[u8], serial: u64) -> Publish {
        Publish {
            log_id,
            publisher: pk(k),
            subject: subject.into(),
            content_hash: sha256(payload),
            content_len: payload.len() as u64,
            serial,
            payload_mode: PayloadMode::Attached,
        }
    }

    pub fn publish_detached(
        log_id: LogId,
        k: &SigningKey,
        subject: &str,
        payload: &[u8],
        serial: u64,
    ) -> Publish {
        Publish { payload_mode: PayloadMode::Detached, ..publish(log_id, k, subject, payload, serial) }
    }
}

#[cfg(all(test, feature = "dalek"))]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn record_roundtrip_and_magic() {
        let admin = key(1);
        let cfg = LogConfig { name: "t".into(), admin: pk(&admin) };
        let p = publish(cfg.log_id(), &key(2), "example.com", b"hello", 1);
        let r = record(&key(2), Statement::Publish(p), Some(b"hello".to_vec()));
        let bytes = r.encode();
        assert_eq!(&bytes[..4], b"TLG1");
        assert_eq!(Record::decode(&bytes).unwrap(), r);
        assert!(r.payload_matches());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(Record::decode(&trailing), Err(DecodeError::Malformed));
        assert_eq!(Record::decode(&bytes[1..]), Err(DecodeError::BadMagic));
    }

    #[test]
    fn payload_mode_is_enforced() {
        let cfg = LogConfig { name: "t".into(), admin: pk(&key(1)) };
        let att = publish(cfg.log_id(), &key(2), "s", b"x", 1);
        // Stripping the payload from an attached publication is detectable.
        assert!(!record(&key(2), Statement::Publish(att.clone()), None).payload_matches());
        assert!(record(&key(2), Statement::Publish(att), Some(b"x".to_vec())).payload_matches());
        let det = publish_detached(cfg.log_id(), &key(2), "s", b"x", 1);
        assert!(record(&key(2), Statement::Publish(det.clone()), None).payload_matches());
        assert!(!record(&key(2), Statement::Publish(det), Some(b"x".to_vec())).payload_matches());
    }

    #[test]
    fn entry_id_is_content_addressed() {
        let cfg = LogConfig { name: "t".into(), admin: pk(&key(1)) };
        let a = publish(cfg.log_id(), &key(2), "s", b"x", 1);
        let mut b = a.clone();
        assert_eq!(a.entry_id(), b.entry_id());
        b.serial = 2;
        assert_ne!(a.entry_id(), b.entry_id());
    }

    #[test]
    fn log_id_binds_name_and_admin() {
        let a = LogConfig { name: "a".into(), admin: pk(&key(1)) };
        let b = LogConfig { name: "b".into(), admin: pk(&key(1)) };
        let c = LogConfig { name: "a".into(), admin: pk(&key(2)) };
        assert_ne!(a.log_id(), b.log_id());
        assert_ne!(a.log_id(), c.log_id());
    }
}
