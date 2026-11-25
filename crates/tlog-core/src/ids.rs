//! Fixed-size identifiers.

use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;
use core::str::FromStr;

macro_rules! bytes_id {
    ($(#[$m:meta])* $name:ident, $len:expr) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            /// Raw bytes.
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Lowercase hex encoding.
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex::encode(self.0))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }

        impl FromStr for $name {
            type Err = hex::FromHexError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let mut out = [0u8; $len];
                hex::decode_to_slice(s, &mut out)?;
                Ok(Self(out))
            }
        }
    };
}

bytes_id!(
    /// Identity of a logical log: `H(TAG_LOG_ID, borsh(LogConfig))`.
    ///
    /// Every statement carries the log id, so a signature for one log can
    /// never be replayed into another. The id does not depend on which
    /// backends host the log, so the same signed bytes are valid on both.
    LogId,
    32
);

bytes_id!(
    /// Identity of a published entry: `H(TAG_ENTRY_ID, borsh(Publish))`.
    ///
    /// Content-addressed and independent of the backend, so an entry has the
    /// same id on NEAR and Celestia and a dual-backend verifier can line the
    /// two up without trusting anyone to map between them.
    EntryId,
    32
);

bytes_id!(
    /// Ed25519 public key of a publisher or the log admin.
    PublicKey,
    32
);

bytes_id!(
    /// Ed25519 signature.
    Signature,
    64
);
