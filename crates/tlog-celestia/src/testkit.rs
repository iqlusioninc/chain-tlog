//! Test helpers: real extended data squares, DAHs and namespace proofs.
//!
//! Lays blobs out in namespace order the way a block producer does, pads
//! the square, erasure-codes it, and serves namespace data with NMT proofs
//! generated from that square. Tests can then tamper with what is served
//! and check the verifier notices.

use std::collections::BTreeMap;

use celestia_types::consts::appconsts::SHARE_SIZE;
use celestia_types::namespace_data::NamespaceData;
use celestia_types::nmt::{Namespace, NS_SIZE};
use celestia_types::{Blob, DataAvailabilityHeader, ExtendedDataSquare, InfoByte};
use tlog_core::status::ChainTime;

use crate::proof::{items_from_namespace_data, verify_namespace_data, NamespaceItem, ProofError};
use crate::source::{SourceError, VerifiedNamespaceSource};

/// One block: its square and DAH.
#[derive(Clone, Debug)]
pub struct Block {
    pub eds: ExtendedDataSquare,
    pub dah: DataAvailabilityHeader,
}

fn tail_padding() -> Vec<u8> {
    let mut s = vec![0u8; SHARE_SIZE];
    s[..NS_SIZE].copy_from_slice(Namespace::TAIL_PADDING.as_bytes());
    s[NS_SIZE] = InfoByte::new(0, true).unwrap().as_u8();
    s
}

/// Raw shares for `blobs`, sorted by namespace (stable), each blob's
/// shares contiguous.
pub fn raw_shares(blobs: &[Blob]) -> Vec<Vec<u8>> {
    let mut sorted: Vec<&Blob> = blobs.iter().collect();
    sorted.sort_by_key(|b| b.namespace);
    sorted.iter().flat_map(|b| b.to_shares().unwrap()).map(|s| s.to_vec()).collect()
}

/// Build a block from raw original-square shares (already in namespace
/// order), padded to the smallest square of width >= `min_width`.
pub fn block_from_raw(mut shares: Vec<Vec<u8>>, min_width: usize) -> Block {
    let mut w = min_width.max(1).next_power_of_two();
    while w * w < shares.len() {
        w *= 2;
    }
    shares.resize(w * w, tail_padding());
    let eds = ExtendedDataSquare::from_ods(shares).unwrap();
    let dah = DataAvailabilityHeader::from_eds(&eds);
    Block { eds, dah }
}

/// Build a block holding `blobs`.
pub fn block(blobs: &[Blob], min_width: usize) -> Block {
    block_from_raw(raw_shares(blobs), min_width)
}

impl Block {
    /// What an honest node serves for `namespace`.
    pub fn namespace_data(&self, namespace: Namespace, height: u64) -> NamespaceData {
        let rows = self.eds.get_namespace_data(namespace, &self.dah, height).unwrap();
        NamespaceData::new(rows.into_iter().map(|(_, r)| r).collect())
    }
}

/// How a [`ChainSource`] misbehaves at a height.
#[derive(Clone, Debug)]
pub enum Fault {
    /// Not ready yet; transient.
    NotReady,
    /// Cannot serve; fatal.
    Gone,
    /// Serve this data instead of the honest data.
    Serve(NamespaceData),
}

/// Errors from [`ChainSource`].
#[derive(Debug, thiserror::Error)]
pub enum ChainSourceError {
    #[error("height {0} not ready")]
    NotReady(u64),
    #[error("height {0} gone")]
    Gone(u64),
    #[error(transparent)]
    Proof(#[from] ProofError),
}

impl SourceError for ChainSourceError {
    fn is_transient(&self) -> bool {
        matches!(self, ChainSourceError::NotReady(_))
    }
}

/// A chain of blocks with verified headers and an untrusted data server.
///
/// Headers (time, DAH) stand in for light-client-verified headers. Namespace
/// data goes through [`verify_namespace_data`] like real data would, so a
/// [`Fault::Serve`] that lies is caught.
#[derive(Default)]
pub struct ChainSource {
    pub blocks: BTreeMap<u64, Block>,
    pub faults: BTreeMap<u64, Fault>,
    pub tip: u64,
}

/// Header time used for every height in tests.
pub fn time(height: u64) -> ChainTime {
    ChainTime { height, unix_ns: 1_700_000_000_000_000_000 + height * 6_000_000_000 }
}

impl ChainSource {
    /// Chain from `start` to `tip`. Heights not in `blocks` get a block with
    /// only an unrelated namespace in it.
    pub fn new(start: u64, tip: u64, mut blocks: BTreeMap<u64, Block>) -> Self {
        let filler = Namespace::new_v0(&[0xee; 10]).unwrap();
        for h in start..=tip {
            blocks
                .entry(h)
                .or_insert_with(|| block(&[Blob::new(filler, vec![h as u8; 8], None).unwrap()], 1));
        }
        Self { blocks, faults: BTreeMap::new(), tip }
    }
}

impl VerifiedNamespaceSource for ChainSource {
    type Error = ChainSourceError;

    async fn verified_tip(&self) -> Result<u64, Self::Error> {
        Ok(self.tip)
    }

    async fn header_time(&self, height: u64) -> Result<ChainTime, Self::Error> {
        Ok(time(height))
    }

    async fn namespace_items(
        &self,
        namespace: Namespace,
        height: u64,
    ) -> Result<Vec<NamespaceItem>, Self::Error> {
        let block = &self.blocks[&height];
        let data = match self.faults.get(&height) {
            None => block.namespace_data(namespace, height),
            Some(Fault::NotReady) => return Err(ChainSourceError::NotReady(height)),
            Some(Fault::Gone) => return Err(ChainSourceError::Gone(height)),
            Some(Fault::Serve(d)) => d.clone(),
        };
        verify_namespace_data(namespace, height, &block.dah, &data)?;
        Ok(items_from_namespace_data(&data))
    }
}
