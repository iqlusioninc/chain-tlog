//! Signature verification, abstracted so the NEAR contract can use the host
//! function and clients can use ed25519-dalek.

use crate::{PublicKey, Signature};

/// Verifies an Ed25519 signature over `msg`.
pub trait SignatureVerifier {
    /// Returns true if `sig` is a valid signature by `key` over `msg`.
    fn verify(&self, key: &PublicKey, msg: &[u8], sig: &Signature) -> bool;

    /// Plain SHA-256, used to check payloads against `content_hash`. The
    /// NEAR contract overrides this with the host function, which costs
    /// several times less gas than hashing in Wasm.
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        crate::hash::sha256(data)
    }
}

/// ed25519-dalek verifier.
///
/// Uses ed25519-dalek's (non-strict) `verify`, which is exactly what the
/// NEAR host function `ed25519_verify` runs. Both backends must accept the
/// same signatures, or the same record could be valid on one chain and not
/// the other. Signature malleability does not matter here because entry ids
/// do not cover the signature. Weak (small-order) keys must be kept out at
/// registration by the admin; see the design note.
#[cfg(feature = "dalek")]
#[derive(Clone, Copy, Debug, Default)]
pub struct Ed25519Dalek;

#[cfg(feature = "dalek")]
impl SignatureVerifier for Ed25519Dalek {
    fn verify(&self, key: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&key.0) else {
            return false;
        };
        let sig = ed25519_dalek::Signature::from_bytes(&sig.0);
        ed25519_dalek::Verifier::verify(&vk, msg, &sig).is_ok()
    }
}
