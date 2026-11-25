//! NEAR state trie proofs.
//!
//! A NEAR shard's state is a hexary Patricia trie. Each node is stored as
//! `borsh(RawTrieNodeWithSize)` and addressed by the SHA-256 of those bytes;
//! values are stored separately and addressed by their own SHA-256. A proof
//! (`view_state` with `include_proof`) is the set of node encodings on the
//! path to a key. Given a trusted root, [`TrieProof::get`] walks the path,
//! hashing every node it uses, so an untrusted prover can neither change a
//! value nor hide one: a key is reported absent only if the proven path
//! diverges from it.
//!
//! Node encoding, from nearcore `core/store/src/trie/raw_node.rs`:
//!
//! ```text
//! RawTrieNodeWithSize { node: RawTrieNode, memory_usage: u64 }
//! RawTrieNode =
//!   0 Leaf(Vec<u8> key, ValueRef)
//!   1 BranchNoValue(Children)
//!   2 BranchWithValue(ValueRef, Children)
//!   3 Extension(Vec<u8> key, CryptoHash child)
//! ValueRef { length: u32, hash: CryptoHash }
//! Children = u16 bitmap (bit i = child i present), then each present child hash in order
//! ```
//!
//! Leaf and extension keys are nibble strings: the first byte holds the
//! odd-length flag (`0x10`) and, if odd, the first nibble in its low four
//! bits; `0x20` marks a leaf. The remaining bytes hold two nibbles each,
//! high nibble first.

use std::collections::HashMap;

use crate::hash::CryptoHash;

/// Errors walking a trie proof.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrieError {
    /// The proof lacks a node or value the walk needs.
    #[error("proof is missing node {0}")]
    MissingNode(CryptoHash),
    /// A node does not decode.
    #[error("malformed trie node {0}")]
    MalformedNode(CryptoHash),
    /// A value's length does not match its reference.
    #[error("value length mismatch for {0}")]
    ValueLength(CryptoHash),
}

#[derive(Clone, Copy)]
struct ValueRef {
    length: u32,
    hash: CryptoHash,
}

enum Node {
    Leaf(Vec<u8>, ValueRef),
    Branch(Option<ValueRef>, Box<[Option<CryptoHash>; 16]>),
    Extension(Vec<u8>, CryptoHash),
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }
    fn hash(&mut self) -> Option<CryptoHash> {
        self.take(32).map(|b| CryptoHash(b.try_into().unwrap()))
    }
    fn bytes(&mut self) -> Option<Vec<u8>> {
        let n = self.u32()? as usize;
        self.take(n).map(<[u8]>::to_vec)
    }
    fn value_ref(&mut self) -> Option<ValueRef> {
        Some(ValueRef { length: self.u32()?, hash: self.hash()? })
    }
    fn children(&mut self) -> Option<Box<[Option<CryptoHash>; 16]>> {
        let bitmap = self.u16()?;
        let mut out = Box::new([None; 16]);
        for (i, slot) in out.iter_mut().enumerate() {
            if bitmap & (1 << i) != 0 {
                *slot = Some(self.hash()?);
            }
        }
        Some(out)
    }
}

fn decode_node(bytes: &[u8]) -> Option<Node> {
    let mut r = Reader(bytes);
    let node = match r.u8()? {
        0 => Node::Leaf(r.bytes()?, r.value_ref()?),
        1 => Node::Branch(None, r.children()?),
        2 => {
            let v = r.value_ref()?;
            Node::Branch(Some(v), r.children()?)
        }
        3 => Node::Extension(r.bytes()?, r.hash()?),
        _ => return None,
    };
    let _memory_usage = r.take(8)?;
    r.0.is_empty().then_some(node)
}

/// Decode a nibble-encoded leaf or extension key into nibbles.
fn decode_nibbles(encoded: &[u8]) -> Option<Vec<u8>> {
    let (&first, rest) = encoded.split_first()?;
    let mut out = Vec::with_capacity(rest.len() * 2 + 1);
    if first & 0x10 != 0 {
        out.push(first & 0x0f);
    }
    for b in rest {
        out.push(b >> 4);
        out.push(b & 0x0f);
    }
    Some(out)
}

/// Split bytes into nibbles, high nibble first.
pub fn to_nibbles(key: &[u8]) -> Vec<u8> {
    key.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect()
}

/// A set of trie nodes and values, indexed by hash. Entries the walk does
/// not reach are ignored, so a proof may mix nodes for several keys.
#[derive(Clone, Debug, Default)]
pub struct TrieProof {
    items: HashMap<CryptoHash, Vec<u8>>,
}

/// Result of a prefix walk.
enum Walk {
    /// The path diverges from the key: nothing under it.
    Diverged,
    /// The key ends exactly at a branch, with this value (if any).
    AtBranch(Option<ValueRef>),
    /// The key ends exactly at a leaf.
    AtLeaf(ValueRef),
    /// The key ends inside a leaf or extension key, or at a branch, so
    /// something is stored under it.
    NonEmptyBelow,
}

impl TrieProof {
    /// Build from raw proof items (node encodings and values).
    pub fn new<I: IntoIterator<Item = Vec<u8>>>(items: I) -> Self {
        Self { items: items.into_iter().map(|b| (CryptoHash::hash(&b), b)).collect() }
    }

    /// Add items.
    pub fn extend<I: IntoIterator<Item = Vec<u8>>>(&mut self, items: I) {
        self.items.extend(items.into_iter().map(|b| (CryptoHash::hash(&b), b)));
    }

    fn node(&self, h: &CryptoHash) -> Result<Node, TrieError> {
        let bytes = self.items.get(h).ok_or(TrieError::MissingNode(*h))?;
        decode_node(bytes).ok_or(TrieError::MalformedNode(*h))
    }

    fn walk(&self, root: &CryptoHash, key: &[u8]) -> Result<Walk, TrieError> {
        if root.is_zero() {
            return Ok(Walk::Diverged);
        }
        let mut rest: &[u8] = key;
        let mut at = *root;
        loop {
            match self.node(&at)? {
                Node::Leaf(enc, value) => {
                    let path = decode_nibbles(&enc).ok_or(TrieError::MalformedNode(at))?;
                    return Ok(if path == rest {
                        Walk::AtLeaf(value)
                    } else if path.starts_with(rest) {
                        Walk::NonEmptyBelow
                    } else {
                        Walk::Diverged
                    });
                }
                Node::Extension(enc, child) => {
                    let path = decode_nibbles(&enc).ok_or(TrieError::MalformedNode(at))?;
                    if rest.starts_with(&path) {
                        rest = &rest[path.len()..];
                        at = child;
                    } else if path.starts_with(rest) {
                        return Ok(Walk::NonEmptyBelow);
                    } else {
                        return Ok(Walk::Diverged);
                    }
                }
                Node::Branch(value, children) => {
                    let Some((&nib, tail)) = rest.split_first() else {
                        return Ok(Walk::AtBranch(value));
                    };
                    match children.get(nib as usize).copied().flatten() {
                        Some(child) => {
                            rest = tail;
                            at = child;
                        }
                        None => return Ok(Walk::Diverged),
                    }
                }
            }
        }
    }

    fn value(&self, v: ValueRef) -> Result<Vec<u8>, TrieError> {
        let bytes = self.items.get(&v.hash).ok_or(TrieError::MissingNode(v.hash))?;
        if bytes.len() != v.length as usize {
            return Err(TrieError::ValueLength(v.hash));
        }
        Ok(bytes.clone())
    }

    /// Value stored at `key` under `root`, or `None` if the proof shows it
    /// absent. Errors if the proof is incomplete or malformed; an error
    /// never means "absent".
    pub fn get(&self, root: &CryptoHash, key: &[u8]) -> Result<Option<Vec<u8>>, TrieError> {
        match self.walk(root, &to_nibbles(key))? {
            Walk::AtLeaf(v) | Walk::AtBranch(Some(v)) => self.value(v).map(Some),
            Walk::AtBranch(None) | Walk::Diverged | Walk::NonEmptyBelow => Ok(None),
        }
    }

    /// True if no key starting with `prefix` exists under `root`.
    pub fn prefix_is_empty(&self, root: &CryptoHash, prefix: &[u8]) -> Result<bool, TrieError> {
        // NEAR's trie never stores empty subtrees, so reaching any node at or
        // below the prefix means something is stored there.
        Ok(matches!(self.walk(root, &to_nibbles(prefix))?, Walk::Diverged))
    }
}

#[cfg(test)]
#[path = "../tests/common/trie_builder.rs"]
mod test_trie;

#[cfg(test)]
mod tests {
    use super::*;

    fn kv(k: &[u8], v: &[u8]) -> (Vec<u8>, Vec<u8>) {
        (k.to_vec(), v.to_vec())
    }

    fn build(entries: &[(Vec<u8>, Vec<u8>)]) -> (CryptoHash, Vec<Vec<u8>>) {
        let (root, items) = super::test_trie::build(entries);
        (CryptoHash(root), items)
    }

    #[test]
    fn present_absent_and_prefix() {
        let entries = vec![kv(b"abc", b"1"), kv(b"abd", b"2"), kv(b"ab", b"3"), kv(b"x", b"4")];
        let (root, items) = build(&entries);
        let p = TrieProof::new(items);
        for (k, v) in &entries {
            assert_eq!(p.get(&root, k).unwrap().as_deref(), Some(&v[..]), "{k:?}");
        }
        assert_eq!(p.get(&root, b"a").unwrap(), None);
        assert_eq!(p.get(&root, b"abe").unwrap(), None);
        assert_eq!(p.get(&root, b"abcd").unwrap(), None);
        assert_eq!(p.get(&root, b"y").unwrap(), None);
        assert!(!p.prefix_is_empty(&root, b"a").unwrap());
        assert!(!p.prefix_is_empty(&root, b"ab").unwrap());
        assert!(p.prefix_is_empty(&root, b"abz").unwrap());
        assert!(p.prefix_is_empty(&root, b"q").unwrap());
        assert!(p.prefix_is_empty(&CryptoHash::default(), b"q").unwrap());
    }

    #[test]
    fn missing_node_is_an_error_not_absence() {
        let (root, items) = build(&[kv(b"abc", b"1"), kv(b"abd", b"2")]);
        // Drop the leaves: looking a key up must error, not say absent.
        let pruned: Vec<_> = items.into_iter().filter(|b| b.first() != Some(&0)).collect();
        let p = TrieProof::new(pruned);
        assert!(matches!(p.get(&root, b"abd"), Err(TrieError::MissingNode(_))));
        assert!(matches!(TrieProof::default().get(&root, b"abc"), Err(TrieError::MissingNode(_))));
    }

    #[test]
    fn wrong_value_is_rejected() {
        let (root, mut items) = build(&[kv(b"k", b"value")]);
        // Replace the value with one of the same length: hash lookup fails.
        items.retain(|b| b != b"value");
        items.push(b"VALUE".to_vec());
        let p = TrieProof::new(items);
        assert!(matches!(p.get(&root, b"k"), Err(TrieError::MissingNode(_))));
    }
}
