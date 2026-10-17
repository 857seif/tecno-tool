use base64::Engine;
use regex::Regex;
use serde_json::json;
use std::path::Path;
use tauri::{AppHandle, Emitter};

use crate::net::{self, friendly_error};
use crate::providers;
use crate::steam;
use crate::util;
use crate::util::log;

async fn blocking<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .unwrap_or_else(|e| panic!("blocking task failed: {}", e))
}

fn emit(app: &AppHandle, id: &str, kind: &str, value: serde_json::Value) {
    let _ = app.emit("job", json!({ "id": id, "kind": kind, "value": value }));
}



#[tauri::command]
pub async fn steam_path() -> Option<String> {
    blocking(steam::steam_path).await
}

#[tauri::command]
pub async fn steam_libraries() -> Vec<String> {
    blocking(|| {
        steam::steam_libraries(true)
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect()
    })
    .await
}

#[tauri::command]
pub async fn game_install_info(appid: String) -> serde_json::Value {
    blocking(move || {
        let (installed, dir) = steam::game_install_info(&appid);
        json!({
            "installed": installed,
            "dir": dir.map(|p| p.to_string_lossy().to_string()),
        })
    })
    .await
}

#[tauri::command]
pub async fn find_game_exe(dir: String) -> Option<String> {
    blocking(move || {
        steam::find_game_exe(Some(Path::new(&dir))).map(|p| p.to_string_lossy().to_string())
    })
    .await
}

#[tauri::command]
pub async fn launch_game(appid: String, dir: Option<String>) -> serde_json::Value {
    blocking(move || {
        let d = dir.map(std::path::PathBuf::from);
        let (ok, info) = steam::launch_game(&appid, d.as_deref());
        json!({ "ok": ok, "info": info })
    })
    .await
}

#[tauri::command]
pub async fn launch_exe(path: String, appid: String) -> serde_json::Value {
    blocking(move || {
        let (ok, info) = steam::launch_exe(&path, &appid);
        json!({ "ok": ok, "info": info })
    })
    .await
}

#[tauri::command]
pub async fn ryuu_token() -> Option<String> {
    blocking(net::ryuu_session).await
}

#[tauri::command]
pub async fn add_defender_exclusion() -> bool {
    blocking(util::add_defender_exclusion).await
}

#[tauri::command]
pub async fn cache_dir_path() -> String {
    util::cache_dir().to_string_lossy().to_string()
}

#[tauri::command]
pub async fn pick_folder() -> Option<String> {
    blocking(|| {
        rfd::FileDialog::new()
            .pick_folder()
            .map(|p| p.to_string_lossy().to_string())
    })
    .await
}

#[tauri::command]
pub async fn pick_exe(start: Option<String>) -> Option<String> {
    blocking(move || {
        let mut d = rfd::FileDialog::new().add_filter("Executables", &["exe"]);
        if let Some(s) = start {
            let p = Path::new(&s);
            if p.exists() {
                d = d.set_directory(p);
            }
        }
        d.pick_file().map(|p| p.to_string_lossy().to_string())
    })
    .await
}



#[tauri::command]
pub async fn steam_search(text: String) -> Vec<serde_json::Value> {
    blocking(move || {
        let mut out = Vec::new();
        let url = format!(
            "https://store.steampowered.com/api/storesearch/?term={}&l=english&cc=US",
            util::urlencode(&text)
        );
        if let Some(b) = net::get_bytes(&url, 8) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&b) {
                if let Some(items) = v.get("items").and_then(|x| x.as_array()) {
                    for it in items {
                        if it.get("type").and_then(|t| t.as_str()) != Some("app") {
                            continue;
                        }
                        let name = it.get("name").and_then(|n| n.as_str()).unwrap_or("Unknown");
                        let id = it.get("id").map(|i| i.to_string().trim_matches('"').to_string());
                        if let Some(id) = id {
                            out.push(json!({ "name": name, "id": id }));
                        }
                    }
                }
            }
        }
        out
    })
    .await
}

#[tauri::command]
pub async fn library_games() -> Vec<serde_json::Value> {
    blocking(|| {
        let mut out = Vec::new();
        if let Some(sp) = steam::steam_path() {
            for (appid, path) in steam::list_lua_games(&sp) {
                out.push(json!({ "appid": appid, "path": path.to_string_lossy().to_string() }));
            }
        }
        out
    })
    .await
}

#[tauri::command]
pub async fn library_info(appid: String) -> serde_json::Value {
    blocking(move || {
        let mut name = format!("Game {}", appid);
        let mut image = String::new();
        let url = format!(
            "https://store.steampowered.com/api/appdetails?appids={}&filters=basic",
            appid
        );
        if let Some(b) = net::get_bytes(&url, 5) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&b) {
                if let Some(d) = v.get(&appid).and_then(|x| x.get("data")) {
                    if let Some(n) = d.get("name").and_then(|x| x.as_str()) {
                        name = n.to_string();
                    }
                    let img = d
                        .get("header_image")
                        .and_then(|x| x.as_str())
                        .or_else(|| d.get("capsule").and_then(|x| x.as_str()));
                    if let Some(i) = img {
                        if let Some(bytes) = net::try_download(i, 8) {
                            image = format!(
                                "data:image/jpeg;base64,{}",
                                base64::engine::general_purpose::STANDARD.encode(&bytes)
                            );
                        }
                    }
                }
            }
        }
        json!({ "appid": appid, "name": name, "image": image })
    })
    .await
}

#[tauri::command]
pub async fn delete_lua(appid: String, path: String) -> serde_json::Value {
    blocking(move || {
        let ok = Path::new(&path).exists() && std::fs::remove_file(&path).is_ok();
        json!({ "appid": appid, "ok": ok })
    })
    .await
}

#[tauri::command]
pub async fn install_lua(path: String) -> serde_json::Value {
    blocking(move || {
        let Some(sp) = steam::steam_path() else {
            return json!({ "ok": false, "msg": "Steam not found" });
        };
        let installed = steam::install_lua_content(&sp, &path, None);
        if installed.is_empty() {
            json!({ "ok": false, "msg": "No lua installed" })
        } else {
            let name = Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            json!({ "ok": true, "msg": format!("{} → lua + stplug-in", name) })
        }
    })
    .await
}



#[tauri::command]
pub async fn list_providers() -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for (key, label, desc) in providers::builtin_list() {
        out.push(json!({
            "key": key, "name": label, "desc": desc, "builtin": true, "url": ""
        }));
    }
    for p in providers::get_custom() {
        out.push(json!({
            "key": p.key, "name": p.name, "desc": "Custom provider", "builtin": false, "url": p.url
        }));
    }
    out
}

#[tauri::command]
pub async fn add_provider(name: String, url: String) -> serde_json::Value {
    match providers::add_custom(&name, &url) {
        Ok(p) => json!({ "ok": true, "key": p.key, "name": p.name }),
        Err(e) => json!({ "ok": false, "msg": e }),
    }
}

#[tauri::command]
pub async fn remove_provider(key: String) -> bool {
    providers::remove_custom(&key);
    true
}



fn is_zip_file(path: &Path) -> bool {
    std::fs::File::open(path)
        .ok()
        .and_then(|f| zip::ZipArchive::new(f).ok())
        .map(|z| z.len() > 0)
        .unwrap_or(false)
}

fn is_rar_file(path: &Path) -> bool {
    use std::io::Read;
    let mut buf = [0u8; 7];
    match std::fs::File::open(path) {
        Ok(mut f) => match f.read(&mut buf) {
            Ok(n) => n == 7 && buf.starts_with(b"Rar!\x1a\x07"),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

fn is_7z_file(path: &Path) -> bool {
    use std::io::Read;
    let mut buf = [0u8; 6];
    match std::fs::File::open(path) {
        Ok(mut f) => match f.read(&mut buf) {
            Ok(n) => n == 6 && buf == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
            Err(_) => false,
        },
        Err(_) => false,
    }
}

fn do_download(app: &AppHandle, id: &str, url: &str, dest_dir: &str, name: &str) -> serde_json::Value {
    let url = net::clean_update_link(url);
    let url = url.as_str();
    emit(app, id, "status", json!(format!("Downloading {}...", name)));

    let clean_url = url.split('?').next().unwrap_or(url);
    let ext = Path::new(clean_url)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let tmp = net::temp_file(&ext);

    if let Err(e) = net::download_file(url, &tmp, |p| emit(app, id, "progress", json!(p))) {
        let _ = std::fs::remove_file(&tmp);
        return json!({ "ok": false, "info": friendly_error(&e) });
    }
    if !tmp.exists() {
        return json!({ "ok": false, "info": "File blocked — check antivirus" });
    }
    let size = match std::fs::metadata(&tmp) {
        Ok(m) => m.len(),
        Err(_) => return json!({ "ok": false, "info": "File blocked — check antivirus" }),
    };
    if size < 4096 {
        let _ = std::fs::remove_file(&tmp);
        return json!({ "ok": false, "info": "Download failed" });
    }

    let dest = Path::new(dest_dir);
    let result: Result<String, String> = if is_zip_file(&tmp) {
        emit(app, id, "status", json!("Extracting ZIP..."));
        net::extract_zip(&tmp, dest).map(|_| dest.to_string_lossy().to_string())
    } else if is_rar_file(&tmp) {
        let mut fname = name.to_string();
        if !fname.to_lowercase().ends_with(".rar") {
            fname.push_str(".rar");
        }
        let d = dest.join(&fname);
        std::fs::copy(&tmp, &d)
            .map(|_| format!("{} (RAR saved)", d.to_string_lossy()))
            .map_err(|e| e.to_string())
    } else if is_7z_file(&tmp) {
        let mut fname = name.to_string();
        if !fname.to_lowercase().ends_with(".7z") {
            fname.push_str(".7z");
        }
        let d = dest.join(&fname);
        std::fs::copy(&tmp, &d)
            .map(|_| format!("{} (7Z saved — install py7zr to auto-extract)", d.to_string_lossy()))
            .map_err(|e| e.to_string())
    } else {
        let mut fname = name.to_string();
        if !ext.is_empty() && !fname.to_lowercase().ends_with(&ext) {
            fname.push_str(&ext);
        }
        if fname.is_empty() || !fname.contains('.') {
            fname = clean_url
                .rsplit('/')
                .next()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{}.bin", uuid::Uuid::new_v4().simple()));
        }
        let d = dest.join(&fname);
        util::move_path(&tmp, &d)
            .map(|_| d.to_string_lossy().to_string())
            .map_err(|e| e.to_string())
    };

    let _ = std::fs::remove_file(&tmp);
    match result {
        Ok(p) => json!({ "ok": true, "info": p }),
        Err(e) => json!({ "ok": false, "info": friendly_error(&e) }),
    }
}

#[tauri::command]
pub async fn download(
    app: AppHandle,
    id: String,
    url: String,
    dest: String,
    name: String,
) -> serde_json::Value {
    blocking(move || do_download(&app, &id, &url, &dest, &name)).await
}

#[tauri::command]
pub async fn manifest_download(
    app: AppHandle,
    id: String,
    appid: String,
    provider: String,
) -> serde_json::Value {
    blocking(move || {
        let Some(steam_path) = steam::steam_path() else {
            return json!({ "ok": false, "msg": "Steam not found" });
        };
        let appid = appid.trim().to_string();
        if !util::is_digits(&appid) {
            return json!({ "ok": false, "msg": "Invalid AppID" });
        }

        let mut sources = providers::all_sources();
        if provider != "auto" && sources.iter().any(|p| p.key == provider) {
            sources.retain(|p| p.key == provider);
        }
        let total = sources.len();

        let mut data: Option<Vec<u8>> = None;
        let mut fname: Option<String> = None;
        for (idx, p) in sources.iter().enumerate() {
            emit(
                &app,
                &id,
                "status",
                json!(format!("Searching... ({}/{})", idx + 1, total)),
            );
            let (d, f) = (p.dl)(&appid);
            if d.is_some() {
                data = d;
                fname = f;
                break;
            }
        }
        if data.is_none() {
            emit(&app, &id, "status", json!("Final fallback..."));
            let (d, f) = providers::dl_manfist(&appid);
            data = d;
            fname = f;
        }
        let Some(data) = data else {
            return json!({ "ok": false, "msg": "Not found" });
        };

        emit(&app, &id, "status", json!("Installing..."));
        let work = util::temp_dir().join(format!("work_{}_{}", appid, uuid::Uuid::new_v4().simple()));
        if std::fs::create_dir_all(&work).is_err() {
            return json!({ "ok": false, "msg": "Failed to prepare workspace" });
        }

        let result = (|| -> Result<String, String> {
            let installed = if net::is_zip(&data) {
                let zpath = work.join(format!("{}.zip", appid));
                std::fs::write(&zpath, &data).map_err(|e| e.to_string())?;
                let extract_to = work.join("extracted");
                std::fs::create_dir_all(&extract_to).map_err(|e| e.to_string())?;
                net::extract_zip(&zpath, &extract_to)?;
                steam::install_lua_content(&steam_path, &extract_to.to_string_lossy(), Some(&appid))
            } else {
                let lua_tmp = work.join(format!("{}.lua", appid));
                std::fs::write(&lua_tmp, &data).map_err(|e| e.to_string())?;
                let _ = fname;
                steam::install_lua_content(&steam_path, &lua_tmp.to_string_lossy(), Some(&appid))
            };
            if installed.is_empty() {
                return Err("No .lua file found".into());
            }
            Ok(format!(
                "{} → lua + st-plug-in",
                installed[0]
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default()
            ))
        })();

        let _ = std::fs::remove_dir_all(&work);

        match result {
            Ok(msg) => json!({ "ok": true, "msg": msg }),
            Err(e) => json!({ "ok": false, "msg": e }),
        }
    })
    .await
}

#[tauri::command]
pub async fn get_json(url: String, cache_name: String, force: bool) -> serde_json::Value {
    blocking(move || {
        let cache = util::cache_dir().join(&cache_name);
        if !force && cache.exists() {
            if let Ok(txt) = std::fs::read_to_string(&cache) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
                    return v;
                }
            }
        }
        if let Some(b) = net::get_bytes(&url, 60) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&b) {
                let _ = std::fs::write(&cache, serde_json::to_string(&v).unwrap_or_default());
                return v;
            }
        }
        serde_json::Value::Array(vec![])
    })
    .await
}



#[tauri::command]
pub async fn launch_steam() -> serde_json::Value {
    blocking(|| {
        let Some(sp) = steam::steam_path() else {
            return json!({ "ok": false, "msg": "Steam not found" });
        };
        let exe = Path::new(&sp).join("Steam.exe");
        if !exe.exists() {
            return json!({ "ok": false, "msg": "Steam.exe not found" });
        }
        util::open_detached(&exe.to_string_lossy(), None);
        json!({ "ok": true, "msg": "Launching Steam" })
    })
    .await
}

#[tauri::command]
pub async fn reset_steam() -> serde_json::Value {
    let _ = tauri::async_runtime::spawn_blocking(|| {
        for name in ["steam.exe", "steamwebhelper.exe", "steamservice.exe"] {
            util::taskkill(name);
        }
        std::thread::sleep(std::time::Duration::from_millis(1500));
        if let Some(sp) = steam::steam_path() {
            let exe = Path::new(&sp).join("Steam.exe");
            if exe.exists() {
                util::open_detached(&exe.to_string_lossy(), None);
            }
        }
    })
    .await;
    json!({ "ok": true, "msg": "Steam restarted" })
}

#[tauri::command]
pub async fn cloud_fix() -> serde_json::Value {
    blocking(|| {
        let Some(sp) = steam::steam_path() else {
            return json!({ "ok": false, "info": "Steam not found" });
        };
        let base = std::path::PathBuf::from(&sp);
        let ud = base.join("userdata");
        if !ud.exists() {
            return json!({ "ok": false, "info": "userdata folder not found." });
        }
        let backup = base.join("afndi backup");
        if backup.exists() {
            let _ = std::fs::remove_dir_all(&backup);
        }
        if std::fs::create_dir_all(&backup).is_err() {
            return json!({ "ok": false, "info": "Failed to create backup folder" });
        }
        let entries = match std::fs::read_dir(&ud) {
            Ok(e) => e,
            Err(e) => return json!({ "ok": false, "info": e.to_string() }),
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name();
            let _ = util::move_path(&entry.path(), &backup.join(name));
        }
        let _ = std::fs::remove_dir(&ud);

        util::taskkill("Steam.exe");
        std::thread::sleep(std::time::Duration::from_millis(1000));
        if let Some(sp2) = steam::steam_path() {
            let exe = Path::new(&sp2).join("Steam.exe");
            if exe.exists() {
                util::open_detached(&exe.to_string_lossy(), None);
            }
        }
        json!({ "ok": true, "info": backup.to_string_lossy().to_string() })
    })
    .await
}



pub const APP_VERSION: &str = "1.9";

pub fn update_check_sync() -> serde_json::Value {
    serde_json::json!({ "kind": "latest", "info": { "v": APP_VERSION } })
}

#[tauri::command]
pub async fn check_update() -> serde_json::Value {
    blocking(update_check_sync).await
}

#[tauri::command]
pub async fn open_url(url: String) -> bool {
    util::open_url(&url);
    true
}

#[tauri::command]
pub async fn app_version() -> String {
    APP_VERSION.to_string()
}



fn theme_default() -> serde_json::Value {
    json!({
        "bg1": "#1f2937", "bg2": "#374151", "bg3": "#111827",
        "bg4": "#000000", "anim_speed": 1.0,
    })
}

#[tauri::command]
pub async fn load_theme() -> serde_json::Value {
    let mut theme = theme_default();
    let p = util::cache_dir().join("theme.json");
    if let Ok(txt) = std::fs::read_to_string(&p) {
        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&txt) {
            for k in ["bg1", "bg2", "bg3", "bg4"] {
                if let Some(v) = data.get(k).and_then(|x| x.as_str()) {
                    if v.starts_with('#') && matches!(v.len(), 4 | 7 | 9) {
                        theme[k] = json!(v);
                    }
                }
            }
            if let Some(sp) = data.get("anim_speed").and_then(|x| x.as_f64()) {
                theme["anim_speed"] = json!(sp);
            }
        }
    }
    theme
}

#[tauri::command]
pub async fn save_theme(theme: serde_json::Value) -> bool {
    let data = json!({
        "bg1": theme.get("bg1").cloned().unwrap_or(json!("#1f2937")),
        "bg2": theme.get("bg2").cloned().unwrap_or(json!("#374151")),
        "bg3": theme.get("bg3").cloned().unwrap_or(json!("#111827")),
        "bg4": theme.get("bg4").cloned().unwrap_or(json!("#000000")),
        "anim_speed": theme.get("anim_speed").cloned().unwrap_or(json!(1.0)),
    });
    let p = util::cache_dir().join("theme.json");
    std::fs::write(p, serde_json::to_string_pretty(&data).unwrap_or_default()).is_ok()
}
