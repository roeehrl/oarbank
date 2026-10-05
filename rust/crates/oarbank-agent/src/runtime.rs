//! Module environments on this node (spec/bundles.md, "Dependencies"; spec/manifest.md, runtime kind `python`).
//!
//! The runtime is a CPython with the SDK (`runtime_python`; the product ships a pinned one). Each module that has a
//! runner requirements file gets `<release>/venvs/<module>`: a venv on that interpreter whose `.pth` adds the
//! runtime's site directories (the SDK), with the module's wheels installed offline from its own bundle, every hash
//! checked, nothing resolved, inside the sandbox. Installing a module runs none of its code.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct Runtime {
    pub python: PathBuf,
    pub uv: Option<PathBuf>,
    /// The interpreter's site directories (the SDK lives there) and the directories it needs to read to run.
    pub site_dirs: Vec<String>,
    pub roots: Vec<String>,
    /// What the runtime's environment provides, so a module never pins it (`oarbank_sdk.deps.host_provided()`: the SDK
    /// and its dependency closure); None when the runtime has no SDK.
    pub host_provided: Option<BTreeSet<String>>,
}

pub fn which(name: &str) -> Option<PathBuf> {
    let file = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    std::env::var_os("PATH").and_then(|paths| std::env::split_paths(&paths).map(|d| d.join(&file)).find(|p| p.is_file()))
}

impl Runtime {
    pub fn discover(python: Option<&Path>, uv: Option<&Path>) -> Result<Runtime> {
        let python = match python {
            Some(p) => p.to_path_buf(),
            None => std::env::var_os("OARBANK_RUNTIME_PYTHON").map(PathBuf::from)
                .or_else(|| which("python3")).or_else(|| which("python")).context("no runtime Python (set OARBANK_RUNTIME_PYTHON)")?,
        };
        let uv = uv.map(Path::to_path_buf).or_else(|| std::env::var_os("OARBANK_UV").map(PathBuf::from)).or_else(|| which("uv"));
        let probe = r##"
import json, os, sys, sysconfig
p = sysconfig.get_paths()
site = [p["purelib"], p["platlib"]]
# sys.executable: what the interpreter calls itself and execs again (multiprocessing); Homebrew's is its opt/ path
roots = {sys.prefix, sys.base_prefix, sys.exec_prefix, sys.executable, os.path.dirname(os.path.realpath(sys.executable))}
roots |= {os.path.realpath(r) for r in list(roots)}
extra = []
for d in site:
    for f in (os.listdir(d) if os.path.isdir(d) else []):
        if f.endswith(".pth"):
            for line in open(os.path.join(d, f), errors="ignore"):
                line = line.strip()
                if line and not line.startswith(("#", "import")) and os.path.isdir(line):
                    extra.append(os.path.realpath(line))
host = None
try:
    import oarbank_sdk
    extra.append(os.path.dirname(os.path.dirname(os.path.realpath(oarbank_sdk.__file__))))
    from oarbank_sdk import deps
    host = sorted(deps.host_provided())
except Exception:
    pass
print(json.dumps({"site": sorted(set(site)), "roots": sorted(roots | set(extra) | set(site)), "host_provided": host}))
"##;
        let out = Command::new(&python).args(["-I", "-c", probe]).output().context("running the runtime Python")?;
        if !out.status.success() {
            bail!("runtime Python failed: {}", String::from_utf8_lossy(&out.stderr));
        }
        let v: Value = serde_json::from_slice(&out.stdout)?;
        let strs = |k: &str| v[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
        let host_provided = v["host_provided"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect());
        Ok(Runtime { python, uv, site_dirs: strs("site"), roots: strs("roots"), host_provided })
    }

    pub fn venv_python(venv: &Path) -> PathBuf {
        if cfg!(windows) { venv.join("Scripts").join("python.exe") } else { venv.join("bin").join("python") }
    }

    /// The interpreter a module's `python` token resolves to: its venv when it has one, else the runtime's.
    pub fn module_python(&self, release: &Path, module: &str) -> PathBuf {
        let v = Self::venv_python(&release.join("venvs").join(module));
        if v.exists() { v } else { self.python.clone() }
    }

    fn clean_env(home: &Path) -> Vec<(String, String)> {
        let mut env = crate::sys::os_env(home, home);
        env.extend([("UV_NO_CONFIG".to_string(), "1".to_string()),
             ("UV_OFFLINE".into(), "1".into()), ("UV_LINK_MODE".into(), "copy".into()),
             ("UV_PYTHON_DOWNLOADS".into(), "never".into()), ("LANG".into(), "C.UTF-8".into())]);
        env
    }

    /// Build `<release>/venvs/<module>` for a module whose entry names a runner requirements file.
    pub fn build_env(&self, release: &Path, entry: &Value, scratch: &Path) -> Result<Option<PathBuf>> {
        let Some(req_rel) = entry["requirements"].as_str() else { return Ok(None) };
        let name = entry["name"].as_str().context("module entry without a name")?;
        let bundle = release.join(entry["bundle"].as_str().unwrap_or(&format!("modules/{name}")));
        let req = bundle.join(req_rel);
        let host = self.host_provided.as_ref()
            .context("the runtime Python has no oarbank-sdk, so what the host provides is unknown")?;
        oarbank_core::deps::parse_requirements(&std::fs::read_to_string(&req)?, host)
            .map_err(|e| anyhow::anyhow!("{name}: {req_rel}: {e}"))?;
        let uv = self.uv.as_ref().context("uv is not available; it installs module dependencies")?;
        let venv = release.join("venvs").join(name);
        crate::fsutil::private_dir(scratch)?;
        let st = Command::new(uv).args(["venv", "--quiet", "--no-config", "--no-cache", "--python"]).arg(&self.python).arg(&venv)
            .env_clear().envs(Self::clean_env(scratch)).current_dir(scratch).status()?;
        if !st.success() {
            bail!("{name}: creating its environment failed");
        }
        let site = std::fs::read_dir(venv.join("lib")).ok().and_then(|mut d| d.find_map(|e| {
            let p = e.ok()?.path().join("site-packages");
            p.is_dir().then_some(p)
        })).unwrap_or_else(|| venv.join("Lib").join("site-packages"));
        let pth: String = self.site_dirs.iter().map(|d| format!("import site; site.addsitedir({d:?})\n")).collect();
        std::fs::write(site.join("_oarbank_host.pth"), pth)?;
        // the interpreter recorded here, outside the sandbox, in this install's own cache: uv inside it then never starts
        // the interpreter, which it would do with a new NUL device as stdin, and some Windows builds refuse an
        // AppContainer the NUL device (the SDK's spec/bundles.md, "Install on a host")
        let cache = scratch.join(format!("{name}-uv-cache"));
        let _ = std::fs::remove_dir_all(&cache);
        let q = Command::new(uv).args(["pip", "list", "--quiet", "--no-config", "--offline", "--python"])
            .arg(Self::venv_python(&venv)).arg("--cache-dir").arg(&cache)
            .env_clear().envs(Self::clean_env(scratch)).current_dir(scratch).output()?;
        if !q.status.success() {
            let _ = std::fs::remove_dir_all(&venv);
            bail!("{name}: recording its environment's interpreter failed: {}", String::from_utf8_lossy(&q.stderr));
        }
        let mut argv: Vec<String> = vec![uv.display().to_string(), "pip".into(), "install".into(), "--quiet".into(),
            "--no-config".into(), "--python".into(), Self::venv_python(&venv).display().to_string(), "--offline".into(),
            "--no-index".into(), "--find-links".into(), bundle.join("wheels").display().to_string(), "--require-hashes".into(),
            "--only-binary".into(), ":all:".into(), "--no-deps".into(), "--cache-dir".into(), cache.display().to_string(),
            "-r".into(), req.display().to_string()];
        if crate::sandbox::available() {
            let mut pol = oarbank_core::sandbox::Policy::new(entry["module_id"].as_str().unwrap_or(name));
            pol.ro = vec![bundle.display().to_string(), Path::new(uv).parent().unwrap_or(Path::new("/")).display().to_string(),
                          Self::venv_python(&venv).display().to_string()];
            pol.ro.extend(self.roots.iter().cloned());
            pol.rw = vec![venv.display().to_string(), scratch.display().to_string()];
            pol.kind = "install".into();
            pol.exe = Some(uv.display().to_string());
            argv = crate::sandbox::wrap(&pol, &scratch.join(format!("{name}-install.sb")), &argv).map_err(|e| anyhow::anyhow!(e))?;
        }
        let out = Command::new(&argv[0]).args(&argv[1..]).env_clear().envs(Self::clean_env(scratch)).current_dir(scratch).output();
        let _ = std::fs::remove_dir_all(&cache);
        let out = out?;
        if !out.status.success() {
            let _ = std::fs::remove_dir_all(&venv);
            bail!("{name}: installing its wheels failed: {}", String::from_utf8_lossy(&out.stderr).chars().rev().take(800)
                .collect::<String>().chars().rev().collect::<String>());
        }
        Ok(Some(venv))
    }
}
