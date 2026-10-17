use serde_json::{json, Value};

use crate::net;
use crate::providers;
use crate::steam;
use crate::util;

fn write_out(v: &Value) {
    let txt = serde_json::to_string_pretty(v).unwrap_or_default();
    println!("{}", txt);
    let p = util::temp_dir().join("selftest_out.json");
    let _ = std::fs::write(p, &txt);
}

pub fn run(args: &[String]) {
    providers::load_custom_providers();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("all");
    match cmd {
        "steam" => write_out(&steam_info()),
        "search" => {
            let text = args.get(1).cloned().unwrap_or_else(|| "portal".into());
            write_out(&json!({ "search": search(&text) }));
        }
        "provider" => {
            let key = args.get(1).cloned().unwrap_or_else(|| "none".into());
            let appid = args.get(2).cloned().unwrap_or_else(|| "400".into());
            write_out(&json!({ "provider": key, "appid": appid, "result": provider(&key, &appid) }));
        }
        "providers" => {
            let keys: Vec<String> = if args.len() > 1 {
                args[1..].to_vec()
            } else {
                vec![]
            };
            let appid = "400";
            let mut m = serde_json::Map::new();
            for k in keys {
                m.insert(k.clone(), provider(&k, appid));
            }
            write_out(&json!({ "appid": appid, "providers": m }));
        }
        "listprov" => {
            let builtin = providers::builtin_list()
                .into_iter()
                .map(|(k, n, d)| json!({ "key": k, "name": n, "desc": d }))
                .collect::<Vec<_>>();
            let custom = providers::get_custom()
                .into_iter()
                .map(|p| json!({ "key": p.key, "name": p.name, "url": p.url }))
                .collect::<Vec<_>>();
            write_out(&json!({ "builtin": builtin, "custom": custom }));
        }
        "net" => write_out(&json!({
            "ryuu_len": net::ryuu_session().map(|t| t.len()),
            "cache_dir": util::cache_dir().to_string_lossy(),
            "temp_dir": util::temp_dir().to_string_lossy(),
            "is_digits": [util::is_digits("400"), util::is_digits("abc"), util::is_digits("")],
            "urlencode": util::urlencode("a b&c/d"),
            "friendly": [
                net::friendly_error("HTTP 404 not found"),
                net::friendly_error("401 unauthorized access"),
                net::friendly_error("connection refused at https://x/y and C:\\a\\b"),
            ],
        })),
        "dl" => {
            let appid = args.get(1).cloned().unwrap_or_else(|| "400".into());
            let tmp = net::temp_file(".zip");
            let mut last = 0u32;
            let mut dl: Result<(), String> = Err("no url".into());
            let mut base_used = "";
            for base in [providers::SOJO_ZIP, providers::SOJO_ZIP_ALT] {
                let url = format!("{}/{}", base, appid);
                last = 0;
                dl = net::download_file(&url, &tmp, |p| last = p);
                if dl.is_ok() {
                    base_used = base;
                    break;
                }
            }
            let mut res =
                json!({ "url_ok": dl.is_ok(), "err": dl.err(), "base": base_used, "progress_last": last });
            if res.get("url_ok").and_then(|v| v.as_bool()) == Some(true) {
                let data = std::fs::read(&tmp).unwrap_or_default();
                let outdir = util::temp_dir().join(format!("selftest_dl_{}", appid));
                let _ = std::fs::remove_dir_all(&outdir);
                let ex = net::extract_zip(&tmp, &outdir);
                let mut lua = 0;
                let mut manifest = 0;
                if ex.is_ok() {
                    for e in walkdir::WalkDir::new(&outdir).into_iter().filter_map(|e| e.ok()) {
                        if e.file_type().is_file() {
                            match e.path().extension().and_then(|x| x.to_str()).unwrap_or("") {
                                "lua" => lua += 1,
                                "manifest" => manifest += 1,
                                _ => {}
                            }
                        }
                    }
                }
                res = json!({
                    "url_ok": true,
                    "bytes": data.len(),
                    "is_zip": net::is_zip(&data),
                    "extract_ok": ex.is_ok(),
                    "lua": lua,
                    "manifest": manifest,
                });
                let _ = std::fs::remove_file(&tmp);
                let _ = std::fs::remove_dir_all(&outdir);
            }
            write_out(&json!({ "dl": res }));
        }
        "install" => {
            let appid = args.get(1).cloned().unwrap_or_else(|| "400".into());
            let fake = util::temp_dir().join(format!("selftest_steam_{}", appid));
            let src = util::temp_dir().join(format!("selftest_src_{}", appid));
            let _ = std::fs::remove_dir_all(&fake);
            let _ = std::fs::remove_dir_all(&src);
            let _ = std::fs::create_dir_all(&src);
            let _ = std::fs::write(src.join(format!("{}.lua", appid)), "addappid(400)");
            let _ = std::fs::write(src.join(format!("{}.manifest", appid)), "FAKE");
            let installed =
                steam::install_lua_content(&fake.to_string_lossy(), &src.to_string_lossy(), Some(&appid));
            let lua_dest = fake.join("config").join("lua").join(format!("{}.lua", appid));
            let plug_dest = fake.join("config").join("stplug-in").join(format!("{}.lua", appid));
            let man_dest = fake.join("config").join("depotcache").join(format!("{}.manifest", appid));
            write_out(&json!({
                "installed": installed.iter().map(|p| p.to_string_lossy().to_string()).collect::<Vec<_>>(),
                "lua": lua_dest.exists(),
                "stplug": plug_dest.exists(),
                "manifest": man_dest.exists(),
            }));
            let _ = std::fs::remove_dir_all(&fake);
            let _ = std::fs::remove_dir_all(&src);
        }
        "library" => {
            let appid = args.get(1).cloned().unwrap_or_else(|| "400".into());
            let url = format!(
                "https://store.steampowered.com/api/appdetails?appids={}&filters=basic",
                appid
            );
            let mut name = String::new();
            let mut img_bytes = 0usize;
            if let Some(b) = net::get_bytes(&url, 8) {
                if let Ok(v) = serde_json::from_slice::<Value>(&b) {
                    if let Some(d) = v.get(&appid).and_then(|x| x.get("data")) {
                        name = d.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
                        if let Some(i) = d.get("header_image").and_then(|x| x.as_str()) {
                            img_bytes = net::try_download(i, 8).map(|b| b.len()).unwrap_or(0);
                        }
                    }
                }
            }
            write_out(&json!({ "appid": appid, "name": name, "image_bytes": img_bytes }));
        }
        "update" => write_out(&crate::commands::update_check_sync()),
        "av" => write_out(&json!({
            "is_admin": util::is_admin(),
            "targets": util::collect_av_targets(),
        })),
        other => {
            write_out(&json!({ "error": format!("unknown selftest: {}", other) }))
        }
    }
}

fn steam_info() -> Value {
    let sp = steam::steam_path();
    let libs = steam::steam_libraries(true)
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect::<Vec<_>>();
    let lua = match &sp {
        Some(s) => steam::list_lua_games(s)
            .into_iter()
            .map(|(id, p)| json!({ "appid": id, "path": p.to_string_lossy() }))
            .collect::<Vec<_>>(),
        None => Vec::new(),
    };
    let info400 = steam::game_install_info("400");
    json!({
        "steam_path": sp,
        "libraries": libs,
        "lua_count": lua.len(),
        "lua_sample": lua.into_iter().take(8).collect::<Vec<_>>(),
        "game_400": {
            "installed": info400.0,
            "dir": info400.1.map(|p| p.to_string_lossy().to_string()),
        },
    })
}

fn search(text: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let url = format!(
        "https://store.steampowered.com/api/storesearch/?term={}&l=english&cc=US",
        util::urlencode(text)
    );
    if let Some(b) = net::get_bytes(&url, 8) {
        if let Ok(v) = serde_json::from_slice::<Value>(&b) {
            if let Some(items) = v.get("items").and_then(|x| x.as_array()) {
                for it in items {
                    if it.get("type").and_then(|t| t.as_str()) != Some("app") {
                        continue;
                    }
                    if let Some(id) = it.get("id") {
                        out.push(json!({
                            "name": it.get("name").and_then(|n| n.as_str()).unwrap_or(""),
                            "id": id.to_string().trim_matches('"'),
                        }));
                    }
                }
            }
        }
    }
    out.into_iter().take(10).collect()
}

fn provider(key: &str, appid: &str) -> Value {
    let sources = providers::all_sources();
    match sources.iter().find(|p| p.key == key) {
        Some(p) => {
            let (d, name) = (p.dl)(appid);
            json!({ "found": d.is_some(), "bytes": d.map(|b| b.len()), "name": name })
        }
        None => json!({ "error": "unknown provider" }),
    }
}
