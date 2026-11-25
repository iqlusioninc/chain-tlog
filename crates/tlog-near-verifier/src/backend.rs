//! The NEAR backend as a verifier sees it: sync the light client, then
//! observe entries and hand the result to [`tlog_core::policy::evaluate`].

use tlog_core::policy::BackendResult;
use tlog_core::EntryId;

use crate::entry::{observe_entry, EntryProofError, NearLogBinding};
use crate::layout::{entry_key, STATE_KEY};
use crate::light_client::{LightClient, LightClientError};
use crate::rpc::{NearRpc, RpcError};

/// Errors from [`NearBackend`].
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// RPC failed.
    #[error(transparent)]
    Rpc(#[from] RpcError),
    /// A light-client block was refused.
    #[error(transparent)]
    LightClient(#[from] LightClientError),
    /// The entry proof was refused.
    #[error(transparent)]
    Entry(#[from] EntryProofError),
}

/// A light client plus the log it watches.
#[derive(Debug)]
pub struct NearBackend {
    rpc: NearRpc,
    light_client: LightClient,
    binding: NearLogBinding,
}

impl NearBackend {
    /// New backend from a light client already started at a checkpoint.
    pub fn new(rpc: NearRpc, light_client: LightClient, binding: NearLogBinding) -> Self {
        Self { rpc, light_client, binding }
    }

    /// The light client.
    pub fn light_client(&self) -> &LightClient {
        &self.light_client
    }

    /// Advance the head as far as the RPC node offers. Returns the number of
    /// blocks accepted. Stops at the first refused block, so a lying node
    /// cannot move the head; the error says why.
    pub async fn sync(&mut self) -> Result<usize, BackendError> {
        let mut n = 0;
        while let Some(block) = self.rpc.next_light_client_block(&self.light_client.head().hash).await? {
            if block.inner_lite.height <= self.light_client.head().inner_lite.height {
                break;
            }
            self.light_client.update(&block)?;
            n += 1;
        }
        Ok(n)
    }

    /// Prove `entry_id`'s status at the current head.
    pub async fn try_observe(&self, entry_id: &EntryId) -> Result<tlog_core::Observation, BackendError> {
        let head = self.light_client.head();
        let key = entry_key(entry_id);
        let proof = self.rpc.contract_state_proof(head, &self.binding.account_id, &[STATE_KEY, &key]).await?;
        Ok(observe_entry(head, &self.binding, entry_id, &proof)?)
    }

    /// [`Self::try_observe`], mapped to what the verdict policy takes. Any
    /// failure is [`BackendResult::Unavailable`], never a status.
    pub async fn observe(&self, entry_id: &EntryId) -> BackendResult {
        match self.try_observe(entry_id).await {
            Ok(o) => BackendResult::Observed(o),
            Err(_) => BackendResult::Unavailable,
        }
    }
}
