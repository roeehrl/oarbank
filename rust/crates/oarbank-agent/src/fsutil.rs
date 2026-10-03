//! Owner-only files and directories, written atomically.

use std::io::Write;
use std::path::Path;

pub fn private_dir(p: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write `data` to `p` with mode 0600 from the first byte, through a temporary file and a rename.
pub fn write_private(p: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = p.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".{}.{}.tmp", p.file_name().and_then(|n| n.to_str()).unwrap_or("f"), std::process::id()));
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, p)
}

/// Point `link` at `target` (a name relative to its directory) atomically: a symlink renamed into place on Unix, a
/// pointer file holding the name on Windows (where links need privileges and a running .exe cannot be replaced).
pub fn point(link: &Path, target: &str) -> std::io::Result<()> {
    let tmp = link.with_file_name(format!(".{}.tmp", link.file_name().and_then(|n| n.to_str()).unwrap_or("link")));
    let _ = std::fs::remove_file(&tmp);
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, &tmp)?;
    #[cfg(not(unix))]
    std::fs::write(&tmp, target)?;
    std::fs::rename(&tmp, link)
}

/// What `link` points at: a symlink's target, or a pointer file's content.
pub fn pointed(link: &Path) -> Option<std::path::PathBuf> {
    if let Ok(t) = std::fs::read_link(link) {
        return Some(t);
    }
    let s = std::fs::read_to_string(link).ok()?;
    let s = s.trim();
    (!s.is_empty() && !s.contains(['\n', '\0'])).then(|| std::path::PathBuf::from(s))
}

pub fn sha256_file(p: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(hex::encode(h.finalize()))
}
