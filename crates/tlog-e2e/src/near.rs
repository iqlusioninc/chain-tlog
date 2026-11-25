//! NEAR backend on a `near-workspaces` sandbox.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use anyhow::{bail, Context};
use base64::Engine;
use near_workspaces::network::Sandbox;
use near_workspaces::{Contract, Worker};
use serde_json::json;
use tlog_core::statement::{Record, RevocationReason};
use tlog_core::status::{Backend, ChainTime, EntryStatus, Observation};
use tlog_core::{BackendResult, EntryId, LogConfig};

use crate::LogBackend;

/// JSON returned by the contract's `get_entry` (see `tlog_near::EntryView`).
/// Declared here so the harness does not link `near-sdk` natively.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct EntryView {
    /// Hex entry id.
    pub entry_id: String,
    /// Hex publisher key.
    pub publisher: String,
    /// Subject.
    pub subject: String,
    /// Hex SHA-256 of the payload.
    pub content_hash: String,
    /// `"active"` or `"revoked"`.
    pub status: String,
    /// Block height of publication.
    #[serde(with = "u64_string")]
    pub published_height: u64,
    /// Block timestamp of publication, ns.
    #[serde(with = "u64_string")]
    pub published_ns: u64,
    /// Block height of revocation.
    #[serde(default, with = "opt_u64_string")]
    pub revoked_height: Option<u64>,
    /// Revocation reason code.
    pub revocation_reason: Option<u8>,
    /// Whether the payload is stored inline.
    pub has_payload: bool,
}

mod u64_string {
    use serde::{Deserialize, Deserializer};
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

mod opt_u64_string {
    use serde::{Deserialize, Deserializer};
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
        Option::<String>::deserialize(d)?.map(|s| s.parse().map_err(serde::de::Error::custom)).transpose()
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Inline payload limit the tests deploy with.
pub const DEFAULT_MAX_INLINE_PAYLOAD: u64 = 64 * 1024;

/// Path to the contract wasm.
///
/// `TLOG_NEAR_WASM` wins if set (CI builds the wasm once and points here).
/// Otherwise the contract is built with `cargo build --target
/// wasm32-unknown-unknown --release` on first use.
pub fn contract_wasm() -> anyhow::Result<PathBuf> {
    static BUILT: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    if let Ok(p) = std::env::var("TLOG_NEAR_WASM") {
        return Ok(PathBuf::from(p));
    }
    BUILT
        .get_or_init(|| {
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
            let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
            let status = Command::new(cargo)
                .current_dir(&root)
                .args(["build", "-p", "tlog-near", "--target", "wasm32-unknown-unknown", "--release"])
                .status()
                .map_err(|e| format!("running cargo: {e}"))?;
            if !status.success() {
                return Err("building tlog-near for wasm32-unknown-unknown failed \
                            (is the target installed? `rustup target add wasm32-unknown-unknown`)"
                    .into());
            }
            Ok(root.join("target/wasm32-unknown-unknown/release/tlog_near.wasm"))
        })
        .clone()
        .map_err(anyhow::Error::msg)
}

/// A `tlog-near` contract on a fresh sandbox.
pub struct NearLog {
    /// The sandbox.
    pub worker: Worker<Sandbox>,
    /// The deployed log contract.
    pub contract: Contract,
}

impl NearLog {
    /// Start a sandbox and deploy a log for `config`.
    pub async fn deploy(config: &LogConfig, max_inline_payload: u64) -> anyhow::Result<Self> {
        let worker = near_workspaces::sandbox().await.context("starting NEAR sandbox")?;
        Self::deploy_on(worker, config, max_inline_payload).await
    }

    /// Deploy a log for `config` on an existing sandbox.
    pub async fn deploy_on(
        worker: Worker<Sandbox>,
        config: &LogConfig,
        max_inline_payload: u64,
    ) -> anyhow::Result<Self> {
        let wasm = std::fs::read(contract_wasm()?).context("reading contract wasm")?;
        let contract = worker.dev_deploy(&wasm).await.context("deploying tlog-near")?;
        contract
            .call("new")
            .args_json(json!({
                "name": config.name,
                "admin": config.admin.to_hex(),
                "max_inline_payload": max_inline_payload.to_string(),
            }))
            .transact()
            .await?
            .into_result()
            .context("initialising tlog-near")?;
        Ok(Self { worker, contract })
    }

    /// `get_entry` at a given block height.
    pub async fn entry_at(&self, entry_id: &EntryId, height: u64) -> anyhow::Result<Option<EntryView>> {
        Ok(self
            .contract
            .view("get_entry")
            .args_json(json!({ "entry_id": entry_id.to_hex() }))
            .block_height(height)
            .await?
            .json()?)
    }

    /// Height and timestamp of the latest block.
    pub async fn head(&self) -> anyhow::Result<ChainTime> {
        let b = self.worker.view_block().await?;
        Ok(ChainTime { height: b.height(), unix_ns: b.timestamp() })
    }

    async fn time_at(&self, height: u64) -> anyhow::Result<ChainTime> {
        let b = self.worker.view_block().block_height(height).await?;
        Ok(ChainTime { height, unix_ns: b.timestamp() })
    }
}

fn reason_from_u8(r: u8) -> anyhow::Result<RevocationReason> {
    Ok(match r {
        0 => RevocationReason::Unspecified,
        1 => RevocationReason::KeyCompromise,
        2 => RevocationReason::Superseded,
        3 => RevocationReason::Withdrawn,
        _ => bail!("unknown revocation reason {r}"),
    })
}

impl LogBackend for NearLog {
    fn backend(&self) -> Backend {
        Backend::Near
    }

    async fn submit(&mut self, record: &Record) -> anyhow::Result<()> {
        let out = self
            .contract
            .call("submit")
            .args_json(json!({ "record": b64(&record.encode()) }))
            .max_gas()
            .transact()
            .await?;
        if out.is_failure() {
            bail!("NEAR rejected record: {:?}", out.into_result().err());
        }
        Ok(())
    }

    /// Reads the entry with a view call at the latest block.
    ///
    /// This trusts the sandbox RPC node. Replace it with the NEAR light-client
    /// verifier (state proof of `tlog_near::entry_storage_key` against a
    /// verified header) once that exists.
    async fn observe(&mut self, entry_id: &EntryId) -> anyhow::Result<BackendResult> {
        let head = self.head().await?;
        let status = match self.entry_at(entry_id, head.height).await? {
            None => EntryStatus::Absent,
            Some(v) => {
                let published = ChainTime { height: v.published_height, unix_ns: v.published_ns };
                match (v.status.as_str(), v.revoked_height, v.revocation_reason) {
                    ("active", None, None) => EntryStatus::Active { published },
                    ("revoked", Some(h), Some(r)) => EntryStatus::Revoked {
                        published,
                        revoked: self.time_at(h).await?,
                        reason: reason_from_u8(r)?,
                    },
                    _ => bail!("inconsistent entry view: {v:?}"),
                }
            }
        };
        Ok(BackendResult::Observed(Observation { backend: Backend::Near, status, head }))
    }
}
