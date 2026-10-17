use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use crate::net::try_download;
use crate::util::cache_dir;

pub type DlResult = (Option<Vec<u8>>, Option<String>);
pub type DlFn = fn(&str) -> DlResult;

pub struct Provider {
    pub key: String,
    #[allow(dead_code)]
    pub label: String,
    pub dl: Box<dyn Fn(&str) -> DlResult + Send + Sync>,
}

impl Provider {
    fn new(key: &str, label: &str, f: DlFn) -> Self {
        Provider {
            key: key.to_string(),
            label: label.to_string(),
            dl: Box::new(f),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CustomProvider {
    pub key: String,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub filename: String,
}

static CUSTOM: Lazy<Mutex<Vec<CustomProvider>>> = Lazy::new(|| Mutex::new(Vec::new()));

fn custom_path() -> PathBuf {
    cache_dir().join("providers.json")
}

pub fn load_custom_providers() {
    let p = custom_path();
    if !p.exists() {
        return;
    }
    match std::fs::read_to_string(&p) {
        Ok(txt) => match serde_json::from_str::<Vec<CustomProvider>>(&txt) {
            Ok(list) => {
                let mut g = CUSTOM.lock().unwrap();
                g.clear();
                for item in list {
                    if !item.url.is_empty() && !item.key.is_empty() {
                        g.push(item);
                    }
                }
            }
            Err(e) => log(&format!("[providers] load fail: {}", e)),
        },
        Err(e) => log(&format!("[providers] read fail: {}", e)),
    }
}

pub fn save_custom_providers() {
    let list = CUSTOM.lock().unwrap().clone();
    if let Ok(txt) = serde_json::to_string_pretty(&list) {
        let _ = std::fs::write(custom_path(), txt);
    }
}

pub fn get_custom() -> Vec<CustomProvider> {
    CUSTOM.lock().unwrap().clone()
}

pub fn add_custom(name: &str, url: &str) -> Result<CustomProvider, String> {
    let name = name.trim();
    let url = url.trim();
    if name.is_empty() {
        return Err("Please enter a name.".into());
    }
    if !(url.to_lowercase().starts_with("http://") || url.to_lowercase().starts_with("https://")) {
        return Err("URL must start with http:// or https://".into());
    }
    let slug: String = {
        let mut out = String::new();
        let mut last_underscore = false;
        for ch in name.to_lowercase().chars() {
            if ch.is_ascii_alphanumeric() {
                out.push(ch);
                last_underscore = false;
            } else if !last_underscore {
                out.push('_');
                last_underscore = true;
            }
        }
        out.trim_matches('_').to_string()
    };
    let mut key = format!(
        "custom_{}",
        if slug.is_empty() {
            uuid::Uuid::new_v4().simple().to_string()[..6].to_string()
        } else {
            slug
        }
    );
    if key.len() > 40 {
        key.truncate(40);
    }
    {
        let g = CUSTOM.lock().unwrap();
        while g.iter().any(|p| p.key == key) {
            key = format!("{}_{}", &key[..key.len().min(36)], &uuid::Uuid::new_v4().simple().to_string()[..4]);
        }
    }
    let item = CustomProvider {
        key,
        name: name.to_string(),
        url: url.to_string(),
        filename: String::new(),
    };
    CUSTOM.lock().unwrap().push(item.clone());
    save_custom_providers();
    Ok(item)
}

pub fn remove_custom(key: &str) {
    CUSTOM.lock().unwrap().retain(|p| p.key != key);
    save_custom_providers();
}

pub fn builtin_list() -> Vec<(String, String, String)> {
    vec![]
}

pub fn all_sources() -> Vec<Provider> {
    let mut v: Vec<Provider> = vec![];
    for p in get_custom() {
        let url = p.url.clone();
        let filename = p.filename.clone();
        v.push(Provider {
            key: p.key.clone(),
            label: if p.name.is_empty() { p.key.clone() } else { p.name.clone() },
            dl: Box::new(move |appid: &str| {
                let resolved = crate::net::clean_update_link(&url.replace("{appid}", appid));
                let data = try_download(&resolved, 120);
                if data.is_none() {
                    return (None, None);
                }
                let mut fname = if !filename.is_empty() {
                    filename.clone()
                } else {
                    resolved
                        .rsplit('/')
                        .next()
                        .unwrap_or("")
                        .split('?')
                        .next()
                        .unwrap_or("")
                        .to_string()
                };
                if fname.is_empty() {
                    fname = format!("{}.lua", appid);
                }
                (data, Some(fname))
            }),
        });
    }
    v
}
