//! NEAR's binary merkle tree (`near_primitives::merkle::merklize`).
//!
//! Leaves are `SHA-256(borsh(item))`. Each level pairs neighbours with
//! [`CryptoHash::combine`]; an unpaired last node moves up unchanged. An
//! empty list has the zero root.

use crate::hash::CryptoHash;

/// Root of `items`, each hashed as `SHA-256(borsh(item))`. For a list of
/// hashes, borsh is the 32 raw bytes.
pub fn merkle_root(items: &[CryptoHash]) -> CryptoHash {
    if items.is_empty() {
        return CryptoHash::default();
    }
    let mut level: Vec<CryptoHash> = items.iter().map(|h| CryptoHash::hash(&h.0)).collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [a, b] => CryptoHash::combine(a, b),
                [a] => *a,
                _ => unreachable!(),
            })
            .collect();
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> CryptoHash {
        CryptoHash([b; 32])
    }

    #[test]
    fn shapes() {
        let l = |b| CryptoHash::hash(&[b; 32]);
        assert_eq!(merkle_root(&[]), CryptoHash::default());
        assert_eq!(merkle_root(&[h(1)]), l(1));
        assert_eq!(merkle_root(&[h(1), h(2)]), CryptoHash::combine(&l(1), &l(2)));
        // Odd node is promoted, not duplicated.
        let left = CryptoHash::combine(&l(1), &l(2));
        assert_eq!(merkle_root(&[h(1), h(2), h(3)]), CryptoHash::combine(&left, &l(3)));
    }
}
