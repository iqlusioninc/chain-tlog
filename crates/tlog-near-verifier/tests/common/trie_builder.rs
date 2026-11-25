//! A minimal NEAR state trie builder, in nearcore's node encoding, for
//! tests. Self-contained so both unit and integration tests can include it.

#![allow(dead_code)]

use sha2::{Digest, Sha256};

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn nibbles(key: &[u8]) -> Vec<u8> {
    key.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect()
}

fn encode_nibbles(nibs: &[u8], is_leaf: bool) -> Vec<u8> {
    let flag = if is_leaf { 0x20 } else { 0 };
    let mut out = Vec::new();
    let rest = if nibs.len() % 2 == 1 {
        out.push(flag | 0x10 | nibs[0]);
        &nibs[1..]
    } else {
        out.push(flag);
        nibs
    };
    for pair in rest.chunks(2) {
        out.push((pair[0] << 4) | pair[1]);
    }
    out
}

fn value_ref(out: &mut Vec<u8>, v: &[u8]) {
    out.extend_from_slice(&(v.len() as u32).to_le_bytes());
    out.extend_from_slice(&sha(v));
}

/// Builds a trie over `entries`; returns `(root, every node and value)`.
pub fn build(entries: &[(Vec<u8>, Vec<u8>)]) -> ([u8; 32], Vec<Vec<u8>>) {
    let mut items = Vec::new();
    let mut list: Vec<(Vec<u8>, Vec<u8>)> = entries.iter().map(|(k, v)| (nibbles(k), v.clone())).collect();
    list.sort();
    if list.is_empty() {
        return ([0; 32], items);
    }
    let root = node(&list, &mut items);
    (root, items)
}

fn push(items: &mut Vec<Vec<u8>>, mut body: Vec<u8>) -> [u8; 32] {
    body.extend_from_slice(&0u64.to_le_bytes()); // memory_usage
    let h = sha(&body);
    items.push(body);
    h
}

fn node(list: &[(Vec<u8>, Vec<u8>)], items: &mut Vec<Vec<u8>>) -> [u8; 32] {
    if list.len() == 1 {
        let (k, v) = &list[0];
        items.push(v.clone());
        let mut body = vec![0u8];
        let enc = encode_nibbles(k, true);
        body.extend_from_slice(&(enc.len() as u32).to_le_bytes());
        body.extend_from_slice(&enc);
        value_ref(&mut body, v);
        return push(items, body);
    }
    let first = &list[0].0;
    let common =
        (0..first.len()).take_while(|&i| list.iter().all(|(k, _)| k.get(i) == Some(&first[i]))).count();
    if common > 0 {
        let rest: Vec<_> = list.iter().map(|(k, v)| (k[common..].to_vec(), v.clone())).collect();
        let child = node(&rest, items);
        let mut body = vec![3u8];
        let enc = encode_nibbles(&first[..common], false);
        body.extend_from_slice(&(enc.len() as u32).to_le_bytes());
        body.extend_from_slice(&enc);
        body.extend_from_slice(&child);
        return push(items, body);
    }
    let value = list.iter().find(|(k, _)| k.is_empty()).map(|(_, v)| v.clone());
    let mut children = Vec::new();
    let mut bitmap = 0u16;
    for nib in 0..16u8 {
        let sub: Vec<_> = list
            .iter()
            .filter(|(k, _)| k.first() == Some(&nib))
            .map(|(k, v)| (k[1..].to_vec(), v.clone()))
            .collect();
        if !sub.is_empty() {
            bitmap |= 1 << nib;
            children.push(node(&sub, items));
        }
    }
    let mut body = Vec::new();
    match &value {
        Some(v) => {
            items.push(v.clone());
            body.push(2);
            value_ref(&mut body, v);
        }
        None => body.push(1),
    }
    body.extend_from_slice(&bitmap.to_le_bytes());
    for c in children {
        body.extend_from_slice(&c);
    }
    push(items, body)
}
