//! NEAR's `CryptoHash`: SHA-256, shown as base58.

use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;
use core::str::FromStr;
use sha2::{Digest, Sha256};

/// A 32-byte SHA-256 digest, as NEAR uses for block hashes, state roots and
/// trie node hashes.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
pub struct CryptoHash(pub [u8; 32]);

impl CryptoHash {
    /// SHA-256 of `data`.
    pub fn hash(data: &[u8]) -> Self {
        Self(Sha256::digest(data).into())
    }

    /// SHA-256 of the borsh encoding of `value`.
    pub fn hash_borsh<T: BorshSerialize>(value: &T) -> Self {
        Self::hash(&borsh::to_vec(value).expect("borsh to vec"))
    }

    /// `SHA-256(a || b)`, NEAR's `combine_hash`.
    pub fn combine(a: &CryptoHash, b: &CryptoHash) -> Self {
        let mut h = Sha256::new();
        h.update(a.0);
        h.update(b.0);
        Self(h.finalize().into())
    }

    /// True for the all-zero hash, which NEAR uses for an empty trie.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Display for CryptoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&bs58::encode(self.0).into_string())
    }
}

impl fmt::Debug for CryptoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CryptoHash({self})")
    }
}

/// Error parsing a base58 hash.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid base58 CryptoHash")]
pub struct ParseHashError;

impl FromStr for CryptoHash {
    type Err = ParseHashError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = bs58::decode(s).into_vec().map_err(|_| ParseHashError)?;
        Ok(Self(v.try_into().map_err(|_| ParseHashError)?))
    }
}

impl serde::Serialize for CryptoHash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for CryptoHash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str> as serde::Deserialize>::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}
