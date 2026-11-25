//! Keys, log config and signed records for tests.

use ed25519_dalek::{Signer, SigningKey};
use tlog_core::hash::sha256;
use tlog_core::statement::{
    LogConfig, Publish, Record, RegistryOp, RegistryUpdate, RevocationReason, Revoke, SignedStatement,
    Statement,
};
use tlog_core::{EntryId, LogId, PublicKey, Signature};

/// A log with an admin key and one publisher key.
pub struct Fixture {
    /// Log config. Its id is what both backends are bound to.
    pub config: LogConfig,
    /// Admin key: signs registry updates, may revoke anything.
    pub admin: SigningKey,
    /// Publisher key the tests register.
    pub publisher: SigningKey,
    next_registry_seq: u64,
}

/// Public key of a signing key.
pub fn pk(k: &SigningKey) -> PublicKey {
    PublicKey(k.verifying_key().to_bytes())
}

/// Sign a statement into a record.
pub fn sign(k: &SigningKey, statement: Statement, payload: Option<Vec<u8>>) -> Record {
    let signature = Signature(k.sign(&statement.signing_bytes()).to_bytes());
    Record { signed: SignedStatement { statement, signature }, payload }
}

impl Fixture {
    /// New log. `name` should be unique per test run so Celestia namespaces
    /// (derived from the log id) don't collide across tests on one devnet.
    pub fn new(name: &str) -> Self {
        let seed = sha256(name.as_bytes());
        let admin = SigningKey::from_bytes(&sha256(&[&seed[..], b"admin"].concat()));
        let publisher = SigningKey::from_bytes(&sha256(&[&seed[..], b"publisher"].concat()));
        let config = LogConfig { name: name.into(), admin: pk(&admin) };
        Self { config, admin, publisher, next_registry_seq: 0 }
    }

    /// A fixture whose name carries the current time, so reruns against a
    /// long-lived devnet start from an empty namespace.
    pub fn unique(prefix: &str) -> Self {
        Self::new(&format!("{prefix}-{}", crate::now_ns()))
    }

    /// The log id.
    pub fn log_id(&self) -> LogId {
        self.config.log_id()
    }

    /// Admin-signed `AddPublisher` for [`Self::publisher`], with the next
    /// registry sequence number.
    pub fn add_publisher(&mut self) -> Record {
        let key = pk(&self.publisher);
        self.registry(RegistryOp::AddPublisher { key, label: "e2e".into() })
    }

    /// Admin-signed registry update with the next sequence number.
    pub fn registry(&mut self, op: RegistryOp) -> Record {
        let seq = self.next_registry_seq;
        self.next_registry_seq += 1;
        sign(&self.admin, Statement::Registry(RegistryUpdate { log_id: self.log_id(), seq, op }), None)
    }

    /// The publish statement for `payload`, unsigned.
    pub fn publish_statement(&self, subject: &str, payload: &[u8], serial: u64) -> Publish {
        Publish {
            log_id: self.log_id(),
            publisher: pk(&self.publisher),
            subject: subject.into(),
            content_hash: sha256(payload),
            content_len: payload.len() as u64,
            serial,
        }
    }

    /// Publisher-signed publish. With `inline`, the payload rides in the record.
    pub fn publish(&self, subject: &str, payload: &[u8], serial: u64, inline: bool) -> (EntryId, Record) {
        let p = self.publish_statement(subject, payload, serial);
        let id = p.entry_id();
        (id, sign(&self.publisher, Statement::Publish(p), inline.then(|| payload.to_vec())))
    }

    /// Publisher-signed revocation.
    pub fn revoke(&self, entry_id: EntryId, reason: RevocationReason) -> Record {
        self.revoke_by(&self.publisher, entry_id, reason)
    }

    /// Revocation signed by `key` (the publisher or the admin).
    pub fn revoke_by(&self, key: &SigningKey, entry_id: EntryId, reason: RevocationReason) -> Record {
        sign(
            key,
            Statement::Revoke(Revoke { log_id: self.log_id(), entry_id, revoker: pk(key), reason }),
            None,
        )
    }
}
