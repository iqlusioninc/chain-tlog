//! Light client against a synthetic chain with real signatures.

use ed25519_dalek::{Signer, SigningKey};
use tlog_near_verifier::types::bp_hash;
use tlog_near_verifier::{
    BlockHeaderInnerLite, CryptoHash, LightClient, LightClientBlock, LightClientError, NearPublicKey,
    NearSignature, ValidatorStake,
};

struct Epoch {
    id: CryptoHash,
    keys: Vec<SigningKey>,
    stakes: Vec<u128>,
}

impl Epoch {
    fn new(tag: u8, stakes: &[u128]) -> Self {
        let keys = (0..stakes.len())
            .map(|i| SigningKey::from_bytes(&[tag.wrapping_mul(31) ^ i as u8; 32]))
            .collect();
        Self { id: CryptoHash([tag; 32]), keys, stakes: stakes.to_vec() }
    }
    fn bps(&self) -> Vec<ValidatorStake> {
        self.keys
            .iter()
            .zip(&self.stakes)
            .enumerate()
            .map(|(i, (k, s))| ValidatorStake::V1 {
                account_id: format!("bp{i}.near"),
                public_key: NearPublicKey::Ed25519(k.verifying_key().to_bytes()),
                stake: *s,
            })
            .collect()
    }
}

/// Block at `height` in `epoch`, with `next` as the next epoch, signed by
/// the producers flagged in `signers`.
fn block(
    height: u64,
    prev: CryptoHash,
    epoch: &Epoch,
    next: &Epoch,
    signers: &[bool],
    with_bps: bool,
) -> LightClientBlock {
    let mut b = LightClientBlock {
        prev_block_hash: prev,
        next_block_inner_hash: CryptoHash([height as u8; 32]),
        inner_lite: BlockHeaderInnerLite {
            height,
            epoch_id: epoch.id,
            next_epoch_id: next.id,
            prev_state_root: CryptoHash::default(),
            outcome_root: CryptoHash::default(),
            timestamp: height * 1_000_000_000,
            next_bp_hash: bp_hash(&next.bps()),
            block_merkle_root: CryptoHash::default(),
        },
        inner_rest_hash: CryptoHash([7; 32]),
        next_bps: with_bps.then(|| next.bps()),
        approvals_after_next: vec![],
    };
    let msg = b.approval_message();
    b.approvals_after_next = epoch
        .keys
        .iter()
        .zip(signers)
        .map(|(k, &s)| s.then(|| NearSignature::Ed25519(k.sign(&msg).to_bytes())))
        .collect();
    b
}

fn setup() -> (Epoch, Epoch, Epoch, LightClient) {
    let e1 = Epoch::new(1, &[10, 10, 10, 10]);
    let e2 = Epoch::new(2, &[40, 30, 20, 10]);
    let e3 = Epoch::new(3, &[25, 25, 25, 25]);
    // Checkpoint: last block of epoch 0, whose next epoch is e1.
    let e0 = Epoch::new(0, &[1]);
    let cp = block(100, CryptoHash::default(), &e0, &e1, &[true], true);
    let lc = LightClient::from_checkpoint(cp.hash(), &cp, None).unwrap();
    (e1, e2, e3, lc)
}

#[test]
fn follows_epochs() {
    let (e1, e2, e3, mut lc) = setup();
    let all = [true; 4];

    // Entering e1 requires next_bps for e2.
    let b = block(101, lc.head().hash, &e1, &e2, &all, false);
    assert_eq!(lc.update(&b), Err(LightClientError::MissingNextBps));
    let b = block(101, lc.head().hash, &e1, &e2, &all, true);
    lc.update(&b).unwrap();
    assert_eq!(lc.head().hash, b.hash());

    // Within e1, next_bps is optional.
    let b = block(150, lc.head().hash, &e1, &e2, &all, false);
    lc.update(&b).unwrap();

    // Can't skip to e3: its producers are not known yet.
    let skip = block(300, lc.head().hash, &e3, &e3, &all, true);
    assert_eq!(lc.update(&skip), Err(LightClientError::UnknownEpoch(e3.id)));

    // Into e2. Producers 0 and 1 hold 70 of 100: enough.
    let b = block(201, lc.head().hash, &e2, &e3, &[true, true, false, false], true);
    lc.update(&b).unwrap();
    assert!(lc.block_producers(&e1.id).is_none(), "old epoch pruned");
    assert!(lc.block_producers(&e3.id).is_some());
}

#[test]
fn needs_more_than_two_thirds() {
    let (e1, e2, _, mut lc) = setup();
    // 2 of 4 equal stakes: 20 of 40, not enough.
    let b = block(101, lc.head().hash, &e1, &e2, &[true, true, false, false], true);
    assert_eq!(lc.update(&b), Err(LightClientError::InsufficientStake { approved: 20, total: 40 }));
    // Exactly 2/3 is not enough either: e2 has 40/30/20/10.
    lc.update(&block(101, lc.head().hash, &e1, &e2, &[true; 4], true)).unwrap();
    let e3 = Epoch::new(3, &[1]);
    let b = block(201, lc.head().hash, &e2, &e3, &[true, false, true, false], true); // 60 of 100
    assert!(matches!(lc.update(&b), Err(LightClientError::InsufficientStake { .. })));
    // 3 of 4: 30 of 40.
    let (e1, e2, _, mut lc) = setup();
    lc.update(&block(101, lc.head().hash, &e1, &e2, &[true, true, true, false], true)).unwrap();
}

#[test]
fn rejects_tampering() {
    let (e1, e2, _, mut lc) = setup();
    let all = [true; 4];

    // Changing any hashed field invalidates the approvals.
    let mut b = block(101, lc.head().hash, &e1, &e2, &all, true);
    b.inner_lite.timestamp += 1;
    assert!(matches!(lc.update(&b), Err(LightClientError::BadSignature(_))));

    // Swapping in a different next epoch's producers.
    let mut b = block(101, lc.head().hash, &e1, &e2, &all, true);
    b.next_bps = Some(Epoch::new(9, &[1000]).bps());
    assert_eq!(lc.update(&b), Err(LightClientError::NextBpsHash));

    // Old block.
    let b = block(100, lc.head().hash, &e1, &e2, &all, true);
    assert!(matches!(lc.update(&b), Err(LightClientError::NotNewer { .. })));

    // Signature by a key that isn't the producer's.
    let mut b = block(101, lc.head().hash, &e1, &e2, &all, true);
    let msg = b.approval_message();
    b.approvals_after_next[0] =
        Some(NearSignature::Ed25519(SigningKey::from_bytes(&[99; 32]).sign(&msg).to_bytes()));
    assert!(matches!(lc.update(&b), Err(LightClientError::BadSignature(_))));

    // Wrong checkpoint hash.
    let cp = block(100, CryptoHash::default(), &e1, &e2, &all, true);
    assert!(matches!(
        LightClient::from_checkpoint(CryptoHash([1; 32]), &cp, None),
        Err(LightClientError::CheckpointHash { .. })
    ));
}
