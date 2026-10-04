//! The agent API client: JSON over the pinned mTLS connection, the epoch fence on every answer, and the error codes
//! the protocol names (docs/protocol.md, "Addressing and auth": Errors).

use serde_json::Value;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{status} {code}: {detail}")]
    Http { status: u16, code: String, detail: String, retry_after: Option<Duration>, body: Box<Value> },
    #[error("transport: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("stale_coordinator: it answered at epoch {got}, below {min}")]
    Stale { got: i64, min: i64 },
}

impl ApiError {
    pub fn code(&self) -> &str {
        match self {
            ApiError::Http { code, .. } => code,
            ApiError::Transport(_) => "transport",
            ApiError::Stale { .. } => "stale_coordinator",
        }
    }
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            ApiError::Http { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

pub struct Api {
    pub base: String,
    client: reqwest::Client,
    /// The highest epoch this agent has seen; answers below it are refused.
    pub min_epoch: AtomicI64,
}

impl Api {
    pub fn new(base: &str, client: reqwest::Client, min_epoch: i64) -> Self {
        Api { base: base.trim_end_matches('/').to_string(), client, min_epoch: AtomicI64::new(min_epoch) }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn finish(&self, r: reqwest::Response) -> Result<reqwest::Response, ApiError> {
        if let Some(e) = r.headers().get("x-oarbank-epoch").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<i64>().ok()) {
            let min = self.min_epoch.load(Ordering::SeqCst);
            if e < min {
                return Err(ApiError::Stale { got: e, min });
            }
            self.min_epoch.fetch_max(e, Ordering::SeqCst);
        }
        if r.status().is_success() {
            return Ok(r);
        }
        let status = r.status().as_u16();
        let retry_after = r.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs);
        let body: Value = r.json().await.unwrap_or(Value::Null);
        Err(ApiError::Http { status, code: body["error"].as_str().unwrap_or("http_error").to_string(),
                             detail: body["detail"].as_str().unwrap_or("").to_string(), retry_after, body: Box::new(body) })
    }

    pub async fn get(&self, path: &str) -> Result<Value, ApiError> {
        let r = self.client.get(self.url(path)).send().await?;
        Ok(self.finish(r).await?.json().await?)
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<Value, ApiError> {
        let r = self.client.post(self.url(path)).json(body).send().await?;
        let r = self.finish(r).await?;
        let bytes = r.bytes().await?;
        Ok(if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) })
    }

    pub async fn post_text(&self, path: &str, text: String) -> Result<(), ApiError> {
        let r = self.client.post(self.url(path)).header("content-type", "text/plain").body(text).send().await?;
        self.finish(r).await?;
        Ok(())
    }

    /// A streamed download (releases, blobs, agent builds), optionally resuming at `from` bytes.
    pub async fn download(&self, path: &str, from: u64) -> Result<reqwest::Response, ApiError> {
        let mut req = self.client.get(self.url(path));
        if from > 0 {
            req = req.header("range", format!("bytes={from}-"));
        }
        let r = req.timeout(Duration::from_secs(3600)).send().await?;
        self.finish(r).await
    }

    /// Upload a file as the blob `digest` (`size` bytes) through the coordinator's resumable upload (after tus 1.0:
    /// `POST /v1/uploads/{digest}` says where it stands, `PATCH` appends at `Upload-Offset`), resuming from the
    /// coordinator's offset after a cut. A blob the coordinator holds already costs one request.
    pub async fn upload(&self, digest: &str, file: &std::path::Path, size: u64) -> Result<(), ApiError> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let io = |e: std::io::Error| ApiError::Http { status: 0, code: "io".into(), detail: e.to_string(), retry_after: None,
                                                    body: Box::default() };
        let path = format!("/v1/uploads/{digest}");
        let st = self.post(&path, &serde_json::json!({"size": size})).await?;
        if st["complete"].as_bool() == Some(true) {
            return Ok(());
        }
        let mut offset = st["offset"].as_u64().unwrap_or(0);
        let mut f = tokio::fs::File::open(file).await.map_err(io)?;
        loop {
            f.seek(std::io::SeekFrom::Start(offset)).await.map_err(io)?;
            let mut chunk = vec![0u8; UPLOAD_CHUNK.min((size - offset) as usize)];
            f.read_exact(&mut chunk).await.map_err(io)?;
            let r = self.client.patch(self.url(&path)).header("upload-offset", offset.to_string())
                .header("content-type", "application/offset+octet-stream").body(chunk)
                .timeout(Duration::from_secs(3600)).send().await?;
            let conflict = r.status().as_u16() == 409;
            let at = r.headers().get("upload-offset").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
            let complete = r.headers().get("upload-complete").is_some_and(|v| v == "1");
            if conflict {
                if let Some(at) = at {
                    offset = at;                   // the coordinator stands elsewhere (an earlier try landed): go on from there
                    continue;
                }
            }
            self.finish(r).await?;
            if complete {
                return Ok(());
            }
            offset = at.unwrap_or(offset);
        }
    }
}

/// The size of one PATCH of an upload.
const UPLOAD_CHUNK: usize = 8 << 20;
