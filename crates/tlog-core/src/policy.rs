//! Turning per-backend observations into one verdict.
//!
//! A log user picks which backends are authoritative ([`Authority`]). The
//! verifier asks each authoritative backend's light client for an
//! [`Observation`] and calls [`evaluate`].
//!
//! With [`Authority::Both`] the rule is conjunctive and fails closed:
//!
//! 1. Revoked on either backend means revoked. Revocation is irreversible,
//!    so even a stale observation of a revocation counts.
//! 2. Otherwise, if either backend is unavailable or its head is too old,
//!    the entry cannot be verified.
//! 3. Active on both means valid.
//! 4. Absent on both means not found.
//! 5. Active on one and absent on the other is never valid. Within the
//!    mirror grace period it is [`Verdict::AwaitingMirror`]; after it, the
//!    publisher failed to mirror and it is [`Verdict::SplitPublication`],
//!    which monitors should alert on.
//!
//! The effect is that forging an entry or hiding a revocation requires
//! breaking both chains (or both light clients), at the cost of needing
//! both to be live.

use crate::statement::RevocationReason;
use crate::status::{Backend, EntryStatus, Observation};

/// Which backends a log user treats as authoritative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authority {
    /// Only the NEAR contract.
    Near,
    /// Only the Celestia namespace.
    Celestia,
    /// Both, combined conjunctively.
    Both,
}

/// Verifier policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Authoritative backends.
    pub authority: Authority,
    /// Maximum age of a backend's verified head, in nanoseconds, before its
    /// observation is treated as stale. This bounds how long a revocation
    /// can go unseen.
    pub max_head_age_ns: u64,
    /// With [`Authority::Both`], how long after publication on one backend
    /// the entry may be missing from the other before it counts as a split
    /// publication.
    pub mirror_grace_ns: u64,
}

/// One backend's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendResult {
    /// Light-client-verified observation.
    Observed(Observation),
    /// The light client could not produce a verified observation.
    Unavailable,
}

/// Why a backend's answer could not be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unusable {
    /// No verified observation.
    Unavailable,
    /// Head older than `max_head_age_ns`.
    Stale,
}

/// Final answer for an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Published and not revoked on every authoritative backend.
    Valid,
    /// Revoked on an authoritative backend.
    Revoked {
        /// Backend that showed the revocation.
        backend: Backend,
        /// Reason code.
        reason: RevocationReason,
    },
    /// Absent from every authoritative backend.
    NotFound,
    /// Present on one backend, not yet on the other, within the grace period.
    AwaitingMirror {
        /// Backend that has it.
        present_on: Backend,
    },
    /// Present on one backend and still missing from the other after the
    /// grace period. A publisher fault.
    SplitPublication {
        /// Backend that has it.
        present_on: Backend,
    },
    /// A required backend could not be checked.
    Unverifiable {
        /// Which backend.
        backend: Backend,
        /// Why.
        why: Unusable,
    },
}

enum Class {
    Revoked(RevocationReason),
    Active { published_ns: u64 },
    Absent,
    Unusable(Unusable),
}

fn classify(policy: &Policy, now_ns: u64, r: Option<&BackendResult>) -> Class {
    let obs = match r {
        Some(BackendResult::Observed(o)) => o,
        Some(BackendResult::Unavailable) | None => return Class::Unusable(Unusable::Unavailable),
    };
    // A revocation is final, so it holds even if the head is old.
    if let EntryStatus::Revoked { reason, .. } = obs.status {
        return Class::Revoked(reason);
    }
    if now_ns.saturating_sub(obs.head.unix_ns) > policy.max_head_age_ns {
        return Class::Unusable(Unusable::Stale);
    }
    match obs.status {
        EntryStatus::Active { published } => Class::Active { published_ns: published.unix_ns },
        EntryStatus::Absent => Class::Absent,
        EntryStatus::Revoked { .. } => unreachable!(),
    }
}

fn single(backend: Backend, c: Class) -> Verdict {
    match c {
        Class::Revoked(reason) => Verdict::Revoked { backend, reason },
        Class::Unusable(why) => Verdict::Unverifiable { backend, why },
        Class::Active { .. } => Verdict::Valid,
        Class::Absent => Verdict::NotFound,
    }
}

/// Combine backend results into a verdict. Results for backends that are
/// not authoritative under `policy` are ignored.
pub fn evaluate(
    policy: &Policy,
    now_ns: u64,
    near: Option<&BackendResult>,
    celestia: Option<&BackendResult>,
) -> Verdict {
    match policy.authority {
        Authority::Near => single(Backend::Near, classify(policy, now_ns, near)),
        Authority::Celestia => single(Backend::Celestia, classify(policy, now_ns, celestia)),
        Authority::Both => {
            let n = classify(policy, now_ns, near);
            let c = classify(policy, now_ns, celestia);
            use Class::*;
            match (n, c) {
                (Revoked(reason), _) => Verdict::Revoked { backend: Backend::Near, reason },
                (_, Revoked(reason)) => Verdict::Revoked { backend: Backend::Celestia, reason },
                (Unusable(why), _) => Verdict::Unverifiable { backend: Backend::Near, why },
                (_, Unusable(why)) => Verdict::Unverifiable { backend: Backend::Celestia, why },
                (Active { .. }, Active { .. }) => Verdict::Valid,
                (Absent, Absent) => Verdict::NotFound,
                (Active { published_ns }, Absent) => mirror(policy, now_ns, Backend::Near, published_ns),
                (Absent, Active { published_ns }) => mirror(policy, now_ns, Backend::Celestia, published_ns),
            }
        }
    }
}

fn mirror(policy: &Policy, now_ns: u64, present_on: Backend, published_ns: u64) -> Verdict {
    if now_ns.saturating_sub(published_ns) <= policy.mirror_grace_ns {
        Verdict::AwaitingMirror { present_on }
    } else {
        Verdict::SplitPublication { present_on }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::ChainTime;

    const S: u64 = 1_000_000_000;
    const NOW: u64 = 10_000 * S;

    fn policy(authority: Authority) -> Policy {
        Policy { authority, max_head_age_ns: 60 * S, mirror_grace_ns: 600 * S }
    }

    fn at(secs_ago: u64) -> ChainTime {
        ChainTime { height: 1, unix_ns: NOW - secs_ago * S }
    }

    fn obs(backend: Backend, status: EntryStatus, head_age: u64) -> BackendResult {
        BackendResult::Observed(Observation { backend, status, head: at(head_age) })
    }

    fn active(published_ago: u64) -> EntryStatus {
        EntryStatus::Active { published: at(published_ago) }
    }

    fn revoked() -> EntryStatus {
        EntryStatus::Revoked {
            published: at(5000),
            revoked: at(4000),
            reason: RevocationReason::KeyCompromise,
        }
    }

    #[test]
    fn single_backend() {
        let p = policy(Authority::Near);
        let n = obs(Backend::Near, active(100), 5);
        assert_eq!(evaluate(&p, NOW, Some(&n), None), Verdict::Valid);

        let stale = obs(Backend::Near, active(100), 120);
        assert_eq!(
            evaluate(&p, NOW, Some(&stale), None),
            Verdict::Unverifiable { backend: Backend::Near, why: Unusable::Stale }
        );

        // Celestia is ignored when only NEAR is authoritative.
        let c = obs(Backend::Celestia, revoked(), 5);
        assert_eq!(evaluate(&p, NOW, Some(&n), Some(&c)), Verdict::Valid);
    }

    #[test]
    fn stale_revocation_still_counts() {
        let p = policy(Authority::Celestia);
        let c = obs(Backend::Celestia, revoked(), 9000);
        assert!(matches!(evaluate(&p, NOW, None, Some(&c)), Verdict::Revoked { .. }));
    }

    #[test]
    fn both_requires_both() {
        let p = policy(Authority::Both);
        let n = obs(Backend::Near, active(100), 5);
        let c = obs(Backend::Celestia, active(90), 5);
        assert_eq!(evaluate(&p, NOW, Some(&n), Some(&c)), Verdict::Valid);

        assert_eq!(
            evaluate(&p, NOW, Some(&n), None),
            Verdict::Unverifiable { backend: Backend::Celestia, why: Unusable::Unavailable }
        );
    }

    #[test]
    fn both_revocation_on_either_wins() {
        let p = policy(Authority::Both);
        let n = obs(Backend::Near, active(100), 5);
        let c = obs(Backend::Celestia, revoked(), 5);
        assert_eq!(
            evaluate(&p, NOW, Some(&n), Some(&c)),
            Verdict::Revoked { backend: Backend::Celestia, reason: RevocationReason::KeyCompromise }
        );
        // Even if the other backend is down.
        assert!(matches!(
            evaluate(&p, NOW, Some(&BackendResult::Unavailable), Some(&c)),
            Verdict::Revoked { .. }
        ));
    }

    #[test]
    fn both_mirror_grace_then_split() {
        let p = policy(Authority::Both);
        let absent = obs(Backend::Celestia, EntryStatus::Absent, 5);
        let fresh = obs(Backend::Near, active(100), 5);
        assert_eq!(
            evaluate(&p, NOW, Some(&fresh), Some(&absent)),
            Verdict::AwaitingMirror { present_on: Backend::Near }
        );
        let old = obs(Backend::Near, active(1000), 5);
        assert_eq!(
            evaluate(&p, NOW, Some(&old), Some(&absent)),
            Verdict::SplitPublication { present_on: Backend::Near }
        );
    }

    #[test]
    fn both_absent_is_not_found() {
        let p = policy(Authority::Both);
        let n = obs(Backend::Near, EntryStatus::Absent, 5);
        let c = obs(Backend::Celestia, EntryStatus::Absent, 5);
        assert_eq!(evaluate(&p, NOW, Some(&n), Some(&c)), Verdict::NotFound);
    }
}
