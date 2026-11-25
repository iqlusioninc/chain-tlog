//! Namespace completeness and absence proofs, checked by us.
//!
//! A light client hands us a [`NamespaceData`]: for every row of the
//! extended square whose namespace range covers the log namespace, the
//! namespace's shares in that row plus an NMT proof against the row root in
//! the header's [`DataAvailabilityHeader`]. Rows that cover the namespace but
//! hold none of its shares carry an absence proof.
//!
//! [`verify_namespace_data`] re-checks all of that against a DAH from a
//! light-client-verified header, so the completeness guarantee the follower
//! depends on does not rest on any one light-client implementation. It also
//! lets an untrusted source (an archival bridge node, a cache) serve the
//! data: if the proofs check out against a verified header, the source
//! cannot have dropped, added or reordered a blob.
//!
//! [`items_from_shares`] turns the verified shares into blobs. Unlike
//! [`Blob::reconstruct_all`], it never fails as a whole: a share sequence
//! that cannot be parsed (for example a share version this crate does not
//! know) becomes one [`NamespaceItem::Unparseable`] and the rest of the
//! height still folds. Otherwise a single odd blob in the namespace would
//! stall every verifier of the log at that height.

use celestia_types::consts::appconsts;
use celestia_types::namespace_data::{NamespaceData, NamespaceDataId};
use celestia_types::nmt::Namespace;
use celestia_types::{Blob, DataAvailabilityHeader, Share};

/// One share sequence in the namespace, in namespace order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamespaceItem {
    /// A blob that parsed.
    Blob(Blob),
    /// A share sequence that did not parse as a blob. It still takes a
    /// position in the namespace order.
    Unparseable {
        /// Why it did not parse.
        reason: String,
    },
}

impl From<Blob> for NamespaceItem {
    fn from(b: Blob) -> Self {
        NamespaceItem::Blob(b)
    }
}

/// Why namespace data was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProofError {
    /// The namespace is not a user namespace. Logs live in version-0 user
    /// namespaces only; reserved namespaces have different share rules.
    #[error("namespace is not a version-0 user namespace")]
    NotUserNamespace,
    /// The rows or proofs do not match the DAH: a row is missing, extra, or
    /// its proof does not verify. The source is lying or broken.
    #[error("namespace data does not match the header: {0}")]
    Mismatch(String),
}

/// Check that `data` is the complete content of `namespace` at `height`,
/// against `dah` from a verified header.
///
/// On success the shares in `data` are exactly the namespace's shares in
/// that block, in order. An empty result is a proof of absence.
pub fn verify_namespace_data(
    namespace: Namespace,
    height: u64,
    dah: &DataAvailabilityHeader,
    data: &NamespaceData,
) -> Result<(), ProofError> {
    if namespace.version() != appconsts::SHARE_VERSION_ZERO || namespace.is_reserved() {
        return Err(ProofError::NotUserNamespace);
    }
    let id = NamespaceDataId::new(namespace, height).map_err(|e| ProofError::Mismatch(e.to_string()))?;
    data.verify(id, dah).map_err(|e| ProofError::Mismatch(e.to_string()))?;
    // `verify` checks each row's proof against the namespace, which already
    // implies every share is in it. Check anyway: it is cheap, and the
    // follower must never see a foreign share.
    if data.rows().iter().flat_map(|r| r.shares.iter()).any(|s| s.namespace() != namespace) {
        return Err(ProofError::Mismatch("share from another namespace".into()));
    }
    Ok(())
}

/// Verified namespace data to items, in namespace order.
pub fn items_from_namespace_data(data: &NamespaceData) -> Vec<NamespaceItem> {
    let shares: Vec<&Share> = data.rows().iter().flat_map(|r| r.shares.iter()).collect();
    items_from_shares(&shares)
}

/// Split one namespace's shares into share sequences and parse each.
///
/// A sequence starts at a share with the sequence-start bit set and runs up
/// to the next one. Namespace padding (a sequence start with length 0) ends
/// a sequence and is not an item.
pub fn items_from_shares(shares: &[&Share]) -> Vec<NamespaceItem> {
    let starts: Vec<usize> =
        shares.iter().enumerate().filter(|(_, s)| s.sequence_length().is_some()).map(|(i, _)| i).collect();

    let mut items = Vec::new();
    // Shares before the first sequence start belong to no blob. A verified
    // namespace never has them, but say so rather than drop them.
    if starts.first().is_some_and(|&s| s > 0) || (starts.is_empty() && !shares.is_empty()) {
        items.push(NamespaceItem::Unparseable {
            reason: "continuation share without a sequence start".into(),
        });
    }
    for (k, &start) in starts.iter().enumerate() {
        if shares[start].sequence_length() == Some(0) {
            continue; // namespace padding
        }
        let end = starts.get(k + 1).copied().unwrap_or(shares.len());
        let seq = &shares[start..end];
        let item = match Blob::reconstruct(seq.iter().copied()) {
            Ok(blob) if blob.shares_len() == seq.len() => NamespaceItem::Blob(blob),
            Ok(blob) => NamespaceItem::Unparseable {
                reason: format!("sequence has {} shares, blob needs {}", seq.len(), blob.shares_len()),
            },
            Err(e) => NamespaceItem::Unparseable { reason: e.to_string() },
        };
        items.push(item);
    }
    items
}
