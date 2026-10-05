//! Portable checkpoints in the agent (spec/runner-protocol.md, "Checkpoints"; docs/design/datasets-media-checkpoints.md).
//!
//! A runner that declares `checkpoint`, on a stage the release marks with `checkpoint = {max_mb, min_interval_s}`,
//! appends `checkpoint` events to its events file. The job monitor reads the new complete lines in the pass that samples
//! the runner's usage, log and phase; for the latest checkpoint it takes the named files out of the workdir (they belong
//! to the agent once announced) into `<agent home>/checkpoints/<attempt>/<seq>/`, then uploads them as blobs (one
//! upload at a time; a newer checkpoint replaces one still waiting) and records them with
//! `POST /v1/attempts/{id}/checkpoint`. Each file is also linked into the blob cache, so this node resumes without a
//! download. A checkpoint over `max_mb`, or sooner than `min_interval_s` after the last upload, is skipped unless it
//! answers a checkpoint-then-stop request.

use crate::api::Api;
use crate::paths::Layout;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MB: u64 = 1 << 20;
const DATA_MAX: usize = 4096;

/// A stage's checkpoint limits, from the release's module entry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limits {
    pub max_mb: u64,
    pub min_interval: Duration,
}

/// The limits of `stage` in a module entry (None: the stage keeps no portable checkpoints). A job of the default stage
/// names none; the entry of a module that keeps checkpoints names its `default_stage`.
pub fn limits(entry: &Value, stage: Option<&str>) -> Option<Limits> {
    let name = stage.or(entry["default_stage"].as_str())?;
    let st = entry["stages"].as_array()?.iter().find(|s| s["name"].as_str() == Some(name) && s["checkpoint"].is_object())?;
    Some(Limits { max_mb: st["checkpoint"]["max_mb"].as_u64()?,
                  min_interval: Duration::from_secs_f64(st["checkpoint"]["min_interval_s"].as_f64().unwrap_or(600.0)) })
}

/// One checkpoint taken out of the workdir: its files in the spool, hashed.
#[derive(Debug)]
pub struct Taken {
    pub seq: i64,
    pub dir: PathBuf,
    /// (name, file, sha256, size)
    pub files: Vec<(String, PathBuf, String, u64)>,
    pub data: Value,
}

pub struct Checkpointer {
    ws: PathBuf,
    spool: PathBuf,
    limits: Limits,
    events: PathBuf,
    read: u64,
    seq: i64,
    last_upload: Option<Instant>,
}

impl Checkpointer {
    pub fn new(layout: &Layout, aid: i64, ws: &Path, limits: Limits) -> Checkpointer {
        Checkpointer { ws: ws.to_path_buf(), spool: layout.home.join("checkpoints").join(aid.to_string()), limits,
                       events: ws.join("events.ndjson"), read: 0, seq: 0, last_upload: None }
    }

    /// The latest checkpoint event among the events file's new complete lines (a line still being written waits).
    pub fn latest_event(&mut self) -> Option<Value> {
        let mut f = std::fs::File::open(&self.events).ok()?;
        f.seek(SeekFrom::Start(self.read)).ok()?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).ok()?;
        let end = buf.iter().rposition(|b| *b == b'\n')? + 1;
        self.read += end as u64;
        buf[..end].split(|b| *b == b'\n').filter_map(|l| serde_json::from_slice::<Value>(l).ok())
            .rfind(|e| e["kind"] == "checkpoint")
    }

    /// Take an announced checkpoint's files out of the workdir (`requested`: it answers a checkpoint-then-stop, so the
    /// upload-rate cap does not apply). Ok(None): skipped by the rate cap.
    pub fn take(&mut self, ev: &Value, requested: bool) -> Result<Option<Taken>> {
        if !requested && self.last_upload.is_some_and(|t| t.elapsed() < self.limits.min_interval) {
            return Ok(None);
        }
        let data = if ev["data"].is_null() { json!({}) } else { ev["data"].clone() };
        if !data.is_object() || serde_json::to_vec(&data)?.len() > DATA_MAX {
            bail!("its data is not an object of at most {DATA_MAX} bytes");
        }
        let files = ev["files"].as_array().filter(|f| !f.is_empty()).context("it names no files")?;
        let ws = std::fs::canonicalize(&self.ws)?;
        let mut picked = vec![];
        let mut total = 0u64;
        for f in files {
            let path = f["path"].as_str().context("a file without a path")?;
            let name = f["name"].as_str().unwrap_or(path);
            for p in [path, name] {
                oarbank_core::portable::check_portable_path(p, true).map_err(|e| anyhow::anyhow!("{p:?}: {}", e.0))?;
            }
            if picked.iter().any(|(n, _): &(String, PathBuf)| n == name) {
                bail!("the name {name} appears twice");
            }
            let src = self.ws.join(path);
            let meta = std::fs::symlink_metadata(&src).with_context(|| format!("{path} is missing"))?;
            if !meta.is_file() || !std::fs::canonicalize(&src)?.starts_with(&ws) {
                bail!("{path} is not a regular file in the workdir");
            }
            total += meta.len();
            picked.push((name.to_string(), src));
        }
        if total > self.limits.max_mb * MB {
            bail!("{total} bytes is over the stage's checkpoint.max_mb ({})", self.limits.max_mb);
        }
        self.seq += 1;
        let dir = self.spool.join(self.seq.to_string());
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let mut out = vec![];
        for (i, (name, src)) in picked.into_iter().enumerate() {
            let dst = dir.join(i.to_string());           // flat in the spool: names may nest
            if std::fs::rename(&src, &dst).is_err() {
                std::fs::copy(&src, &dst).with_context(|| format!("taking {name}"))?;
                let _ = std::fs::remove_file(&src);
            }
            let size = std::fs::metadata(&dst)?.len();
            out.push((name, dst.clone(), crate::fsutil::sha256_file(&dst)?, size));
        }
        Ok(Some(Taken { seq: self.seq, dir, files: out, data }))
    }

    pub fn uploaded(&mut self) {
        self.last_upload = Some(Instant::now());
    }

    pub fn clean(&self) {
        let _ = std::fs::remove_dir_all(&self.spool);
    }
}

/// Upload a taken checkpoint's files and record it: each file is linked into the blob cache (this node then resumes
/// without a download), uploaded as a blob, and the checkpoint is recorded for the attempt.
pub async fn upload(api: &Api, layout: &Layout, aid: i64, t: &Taken) -> Result<Value> {
    let mut files = vec![];
    for (name, path, digest, size) in &t.files {
        let cached = crate::staging::blob_path(layout, digest);
        if !cached.exists() {
            crate::fsutil::private_dir(cached.parent().unwrap())?;
            if std::fs::hard_link(path, &cached).is_err() {
                std::fs::copy(path, &cached)?;
            }
        }
        api.upload(digest, path, *size).await.map_err(|e| anyhow::anyhow!("uploading {name}: {e}"))?;
        files.push(json!({"name": name, "digest": digest, "size": size}));
    }
    let r = api.post(&format!("/v1/attempts/{aid}/checkpoint"), &json!({"seq": t.seq, "files": files, "data": t.data}))
        .await.map_err(|e| anyhow::anyhow!("recording the checkpoint: {e}"))?;
    let _ = std::fs::remove_dir_all(&t.dir);
    Ok(r)
}

/// Place the checkpoint a grant resumes from under `<W>/checkpoint/<name>`: each file from the blob cache or the
/// coordinator, as read-only regular files.
pub async fn stage_resume(api: &Api, layout: &Layout, grant: &Value, ws: &Path) -> Result<()> {
    for f in grant["checkpoint"]["files"].as_array().cloned().unwrap_or_default() {
        let name = f["name"].as_str().context("a checkpoint file without a name")?;
        oarbank_core::portable::check_portable_path(name, true).map_err(|e| anyhow::anyhow!("checkpoint file {name:?}: {}", e.0))?;
        let blob = crate::staging::fetch_blob(api, layout, &json!({"digest": f["digest"]})).await?;
        crate::staging::place(&blob, &ws.join("checkpoint").join(name))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (what removes the scratch directory when dropped, a home in it, a work directory in it)
    fn scratch(name: &str) -> (tempfile::TempDir, Layout, PathBuf) {
        let d = crate::scratch(&format!("ckpt-{name}"));
        let ws = d.path().join("work").join("1");
        std::fs::create_dir_all(&ws).unwrap();
        let l = Layout::new(d.path().join("home"));
        (d, l, ws)
    }

    fn write_event(ws: &Path, line: &str) {
        use std::io::Write;
        std::fs::OpenOptions::new().create(true).append(true).open(ws.join("events.ndjson")).unwrap().write_all(line.as_bytes()).unwrap();
    }

    #[test]
    fn limits_come_from_the_release_entry() {
        let entry = json!({"default_stage": "render",
                           "stages": [{"name": "fetch"}, {"name": "render", "checkpoint": {"max_mb": 64, "min_interval_s": 30.0}}]});
        assert_eq!(limits(&entry, Some("render")), Some(Limits { max_mb: 64, min_interval: Duration::from_secs(30) }));
        assert_eq!(limits(&entry, Some("fetch")), None);
        assert_eq!(limits(&entry, None).map(|l| l.max_mb), Some(64));
        assert_eq!(limits(&json!({"stages": [{"name": "x", "checkpoint": {"max_mb": 1}}]}), None), None);
    }

    #[test]
    fn the_latest_complete_checkpoint_event_is_taken_out_of_the_workdir() {
        let (_d, l, ws) = scratch("take");
        let mut c = Checkpointer::new(&l, 1, &ws, Limits { max_mb: 1, min_interval: Duration::from_secs(3600) });
        assert!(c.latest_event().is_none());
        std::fs::create_dir_all(ws.join("ckpt/000001")).unwrap();
        std::fs::write(ws.join("ckpt/000001/state.json"), b"{\"next\": 4}").unwrap();
        write_event(&ws, "{\"kind\": \"phase\", \"t\": 1}\n{\"kind\": \"checkpoint\", \"t\": 2, \"files\": [{\"path\": \"ckpt/000001/state.json\", \"name\": \"state.json\"}], \"data\": {\"next\": 4}}\n{\"kind\": \"checkp");
        let ev = c.latest_event().expect("one complete checkpoint event");
        let t = c.take(&ev, false).unwrap().unwrap();
        assert_eq!((t.seq, t.files[0].0.as_str(), t.files[0].3), (1, "state.json", 11));
        assert!(!ws.join("ckpt/000001/state.json").exists() && t.files[0].1.exists());   // the agent's now
        assert!(c.latest_event().is_none());                                            // the half line waits
        c.uploaded();
        std::fs::write(ws.join("ckpt/s2"), b"x").unwrap();
        let ev2 = json!({"kind": "checkpoint", "files": [{"path": "ckpt/s2"}]});
        assert!(c.take(&ev2, false).unwrap().is_none());                               // the upload-rate cap
        assert!(c.take(&ev2, true).unwrap().is_some());                                // a requested one is always taken
        c.clean();
    }

    #[test]
    fn symlinks_outside_files_duplicates_and_oversized_checkpoints_are_refused() {
        let (_d, l, ws) = scratch("refuse");
        let mut c = Checkpointer::new(&l, 2, &ws, Limits { max_mb: 1, min_interval: Duration::ZERO });
        let outside = ws.parent().unwrap().join("secret");
        std::fs::write(&outside, b"s").unwrap();
        std::fs::write(ws.join("big"), vec![0u8; (MB + 1) as usize]).unwrap();
        std::fs::write(ws.join("a"), b"a").unwrap();
        let mut err = |files: Value| c.take(&json!({"kind": "checkpoint", "files": files}), true).unwrap_err().to_string();
        assert!(err(json!([{"path": "../secret"}])).contains("\"../secret\""));
        assert!(err(json!([{"path": "big"}])).contains("max_mb"));
        assert!(err(json!([{"path": "a", "name": "x"}, {"path": "a", "name": "x"}])).contains("twice"));
        assert!(err(json!([])).contains("no files"));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, ws.join("link")).unwrap();
            assert!(err(json!([{"path": "link"}])).contains("not a regular file"));
        }
        drop(err);
        assert!(c.take(&json!({"kind": "checkpoint", "files": [{"path": "a"}], "data": {"x": "y".repeat(5000)}}), true).is_err());
    }
}
