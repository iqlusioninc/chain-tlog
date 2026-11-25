//! Posting records to the log namespace through a celestia-node RPC endpoint.
//!
//! The publisher is not trusted by verifiers. A node operator who drops or
//! reorders a submission only delays it; it cannot forge or alter a record,
//! because records are signed before they reach the node.

use celestia_rpc::{BlobClient, Client, TxConfig};
use celestia_types::blob::Commitment;
use celestia_types::nmt::Namespace;
use tlog_core::statement::Record;

use crate::record_blob;

/// Errors from [`CelestiaPublisher`].
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// Building the blob failed.
    #[error("blob: {0}")]
    Blob(#[from] celestia_types::Error),
    /// The RPC call failed.
    #[error("rpc: {0}")]
    Rpc(String),
}

/// Where a record landed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submitted {
    /// Celestia height of inclusion.
    pub height: u64,
    /// Blob share commitment, for monitors and archivers.
    pub commitment: Commitment,
}

/// Submits records to one namespace.
pub struct CelestiaPublisher {
    client: Client,
    namespace: Namespace,
}

impl CelestiaPublisher {
    /// Connect to a celestia-node RPC endpoint (`http(s)://` or `ws(s)://`).
    pub async fn connect(
        url: &str,
        auth_token: Option<&str>,
        namespace: Namespace,
    ) -> Result<Self, PublishError> {
        let client =
            Client::new(url, auth_token, None, None).await.map_err(|e| PublishError::Rpc(e.to_string()))?;
        Ok(Self { client, namespace })
    }

    /// Submit one record and wait for inclusion.
    pub async fn submit(&self, record: &Record) -> Result<Submitted, PublishError> {
        let blob = record_blob(self.namespace, record)?;
        let commitment = blob.commitment;
        let height = self
            .client
            .blob_submit(&[blob], TxConfig::default())
            .await
            .map_err(|e| PublishError::Rpc(e.to_string()))?;
        Ok(Submitted { height, commitment })
    }
}
