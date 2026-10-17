use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use walkdir::WalkDir;

pub fn steam_path() -> Option<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let candidates = [
        r"SOFTWARE\WOW6432Node\Valve\Steam",
        r"SOFTWARE\Valve\Steam",
    ];
    for sub in candidates {
        if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(sub) {
            if let Ok(v) = key.get_value::<String, _>("InstallPath") {
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

pub fn prepare_lua(steam: &str) -> PathBuf {
    let c = Path::new(steam).join("config");
    let sp = c.join("stplug-in");
    let ld = c.join("lua");
    let _ = std::fs::create_dir_all(&ld);
    let _ = std::fs::create_dir_all(&sp);
    ld
}

pub fn prepare_stplugin(steam: &str) -> PathBuf {
    let sp = Path::new(steam).join("config").join("stplug-in");
    let _ = std::fs::create_dir_all(&sp);
    sp
}

pub fn lua_dirs(steam: &str) -> Vec<PathBuf> {
    vec![prepare_lua(steam), prepare_stplugin(steam)]
}

pub fn depotcache_dirs(steam: &str) -> Vec<PathBuf> {
    let s = Path::new(steam);
    let d1 = s.join("config").join("depotcache");
    let d2 = s.join("depotcache");
    let _ = std::fs::create_dir_all(&d1);
    let _ = std::fs::create_dir_all(&d2);
    vec![d1, d2]
}

static STEAM_LIBS: Lazy<Mutex<Option<Vec<PathBuf>>>> = Lazy::new(|| Mutex::new(None));

pub fn steam_libraries(force: bool) -> Vec<PathBuf> {
    if !force {
        if let Some(v) = STEAM_LIBS.lock().unwrap().as_ref() {
            return v.clone();
        }
    }
    let mut libs: Vec<PathBuf> = Vec::new();
    let Some(sp) = steam_path() else {
        return libs;
    };
    let base = PathBuf::from(&sp);
    let mut roots = vec![base.clone()];
    let candidates = [
        base.join("steamapps").join("libraryfolders.vdf"),
        base.join("config").join("libraryfolders.vdf"),
    ];
    let re = Regex::new(r#""path"\s+"([^"]+)""#).unwrap();
    for cand in candidates {
        if cand.exists() {
            if let Ok(txt) = std::fs::read_to_string(&cand) {
                for cap in re.captures_iter(&txt) {
                    let p = cap[1].replace("\\\\", "\\");
                    if !p.is_empty() {
                        roots.push(PathBuf::from(p));
                    }
                }
            }
        }
    }
    let mut seen: HashSet<String> = HashSet::new();
    for r in roots {
        let st = r.join("steamapps");
        let key = st.to_string_lossy().to_lowercase();
        if seen.insert(key) {
            libs.push(st);
        }
    }
    *STEAM_LIBS.lock().unwrap() = Some(libs.clone());
    libs
}

pub fn game_install_info(appid: &str) -> (bool, Option<PathBuf>) {
    let appid = appid.trim();
    if !crate::util::is_digits(appid) {
        return (false, None);
    }
    let re = Regex::new(r#""installdir"\s+"([^"]+)""#).unwrap();
    for st in steam_libraries(false) {
        let acf = st.join(format!("appmanifest_{}.acf", appid));
        if !acf.exists() {
            continue;
        }
        let mut installdir: Option<String> = None;
        if let Ok(txt) = std::fs::read_to_string(&acf) {
            if let Some(c) = re.captures(&txt) {
                installdir = Some(c[1].to_string());
            }
        }
        let common = st.join("common");
        if let Some(d) = installdir {
            let p = common.join(d);
            return (true, if p.exists() { Some(p) } else { None });
        }
        return (true, None);
    }
    (false, None)
}

pub fn find_game_exe(install_dir: Option<&Path>) -> Option<PathBuf> {
    let dir = install_dir?;
    if !dir.exists() {
        return None;
    }
    let bad = [
        "unins", "vcredist", "dxsetup", "redist", "crash", "report", "dotnet", "directx",
        "setup", "helper", "cleanup",
    ];
    let bad_dirs = ["_commonredist", "directx", "redist", "vcredist"];
    let mut exes: Vec<(u64, PathBuf)> = Vec::new();
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if !name.ends_with(".exe") || bad.iter().any(|b| name.contains(b)) {
            continue;
        }
        let parent = p
            .parent()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if bad_dirs.iter().any(|b| parent.contains(b)) {
            continue;
        }
        if let Ok(md) = entry.metadata() {
            exes.push((md.len(), p.to_path_buf()));
        }
    }
    exes.sort_by(|a, b| b.0.cmp(&a.0));
    exes.into_iter().next().map(|(_, p)| p)
}

pub fn launch_game(appid: &str, install_dir: Option<&Path>) -> (bool, String) {
    let Some(exe) = find_game_exe(install_dir) else {
        return (false, "Game executable not found".into());
    };
    let cwd = exe.parent().map(|p| p.to_path_buf());
    launch_with_env(&exe, appid, cwd.as_deref())
}

pub fn launch_exe(path: &str, appid: &str) -> (bool, String) {
    let p = Path::new(path);
    if !p.exists() {
        return (false, "Executable not found".into());
    }
    let cwd = p.parent().map(|x| x.to_path_buf());
    launch_with_env(p, appid, cwd.as_deref())
}

fn launch_with_env(exe: &Path, appid: &str, cwd: Option<&Path>) -> (bool, String) {
    let mut cmd = std::process::Command::new(exe);
    if let Some(c) = cwd {
        cmd.current_dir(c);
    }
    cmd.env("SteamAppId", appid);
    cmd.env("SteamGameId", appid);
    if std::env::var("SteamAppUser").is_err() {
        cmd.env("SteamAppUser", "steamuser");
    }
    match cmd.spawn() {
        Ok(_) => (
            true,
            exe.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
        ),
        Err(e) => (false, e.to_string()),
    }
}

pub fn install_lua_content(steam: &str, src_path: &str, appid: Option<&str>) -> Vec<PathBuf> {
    let lua_targets = lua_dirs(steam);
    let manifest_targets = depotcache_dirs(steam);
    let mut installed: Vec<PathBuf> = Vec::new();
    let src = Path::new(src_path);
    let mut lua_files: Vec<PathBuf> = Vec::new();
    let mut manifest_files: Vec<PathBuf> = Vec::new();

    if src.is_file() {
        let ext = src
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if ext == "lua" {
            lua_files.push(src.to_path_buf());
        } else if ext == "manifest" {
            manifest_files.push(src.to_path_buf());
        } else {
            let name = match appid {
                Some(a) => format!("{}.lua", a),
                None => src.file_name().unwrap().to_string_lossy().to_string(),
            };
            for (i, t) in lua_targets.iter().enumerate() {
                let _ = std::fs::create_dir_all(t);
                let dest = t.join(&name);
                if std::fs::copy(src, &dest).is_ok() && i == 0 {
                    installed.push(dest);
                }
            }
            return installed;
        }
    } else if src.is_dir() {
        for entry in WalkDir::new(src).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            let ext = entry
                .path()
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if ext == "lua" {
                lua_files.push(entry.path().to_path_buf());
            } else if ext == "manifest" {
                manifest_files.push(entry.path().to_path_buf());
            }
        }
    } else {
        return installed;
    }

    if let Some(a) = appid {
        if !lua_files.is_empty() {
            let all = std::mem::take(&mut lua_files);
            let (pref, rest): (Vec<PathBuf>, Vec<PathBuf>) = all.into_iter().partition(|f| {
                f.file_stem()
                    .map(|s| s.to_string_lossy().contains(a))
                    .unwrap_or(false)
            });
            if !pref.is_empty() {
                lua_files = pref;
                lua_files.extend(rest);
            } else {
                lua_files = rest;
            }
        }
    }

    for lf in &lua_files {
        let Some(fname) = lf.file_name() else { continue };
        for (i, t) in lua_targets.iter().enumerate() {
            let _ = std::fs::create_dir_all(t);
            let dest = t.join(fname);
            if std::fs::copy(lf, &dest).is_ok() && i == 0 {
                installed.push(dest);
            }
        }
    }

    for mf in &manifest_files {
        let Some(fname) = mf.file_name() else { continue };
        for t in &manifest_targets {
            let _ = std::fs::create_dir_all(t);
            let _ = std::fs::copy(mf, t.join(fname));
        }
    }

    installed
}

pub fn list_lua_games(steam: &str) -> Vec<(String, PathBuf)> {
    let ld = Path::new(steam).join("config").join("lua");
    let mut out = Vec::new();
    if !ld.exists() {
        return out;
    }
    for entry in WalkDir::new(&ld).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        if p.extension().map(|e| e.eq_ignore_ascii_case("lua")).unwrap_or(false) {
            let stem = p
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            out.push((stem, p.to_path_buf()));
        }
    }
    out
}
