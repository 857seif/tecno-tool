use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, COOKIE, ORIGIN, REFERER, USER_AGENT};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use crate::util::{log, temp_dir};

pub static CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap_or_else(|_| Client::new())
});

const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

pub fn default_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(USER_AGENT, HeaderValue::from_static(UA));
    h.insert(ACCEPT, HeaderValue::from_static("*/*"));
    h.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    h.insert(REFERER, HeaderValue::from_static("https://generator.ryuu.lol/"));
    h.insert(ORIGIN, HeaderValue::from_static("https://generator.ryuu.lol"));
    h
}

static RYUU: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

pub fn ryuu_session() -> Option<String> {
    {
        let g = RYUU.lock().unwrap();
        if let Some(t) = g.as_ref() {
            if !t.is_empty() {
                return Some(t.clone());
            }
        }
    }
    let token: Option<String> = None;
    token
}

pub fn headers_for(url: &str) -> HeaderMap {
    let mut h = default_headers();
    if let Ok(u) = reqwest::Url::parse(url) {
        if let Some(host) = u.host_str() {
            if let Ok(v) = HeaderValue::from_str(&format!("https://{}/", host)) {
                h.insert(REFERER, v);
            }
            if let Ok(v) = HeaderValue::from_str(&format!("https://{}", host)) {
                h.insert(ORIGIN, v);
            }
            if host.contains("ryuu.lol") {
                if let Some(tok) = ryuu_session() {
                    if let Ok(v) = HeaderValue::from_str(&format!("session={}", tok)) {
                        h.insert(COOKIE, v);
                    }
                }
            }
        }
    }
    h
}

fn percent_encode(s: &str, safe: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') || safe.contains(c) {
            out.push(c);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

pub fn clean_update_link(url: &str) -> String {
    if url.is_empty() {
        return String::new();
    }
    let s = url.trim().to_string();
    if let Ok(u) = reqwest::Url::parse(&s) {
        let host = match u.host_str() {
            Some(h) => match u.port() {
                Some(p) => format!("{}:{}", h, p),
                None => h.to_string(),
            },
            None => return s.replace(' ', "%20"),
        };
        let path = percent_encode(u.path(), "/%");
        let query = match u.query() {
            Some(q) => format!("?{}", percent_encode(q, "=&%")),
            None => String::new(),
        };
        let frag = match u.fragment() {
            Some(f) => format!("#{}", f),
            None => String::new(),
        };
        return format!("{}://{}{}{}{}", u.scheme(), host, path, query, frag);
    }
    s.replace(' ', "%20")
}

pub fn is_probably_html(data: &[u8]) -> bool {
    let head: Vec<u8> = data
        .iter()
        .skip_while(|c| matches!(**c, b' ' | b'\n' | b'\r' | b'\t'))
        .take(512)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if head.starts_with(b"<!doctype html") || head.starts_with(b"<html") {
        return true;
    }
    let n = head.len().min(300);
    head[..n].windows(6).any(|w| w == b"<head>")
}

pub fn is_zip(data: &[u8]) -> bool {
    zip::ZipArchive::new(std::io::Cursor::new(data))
        .map(|z| z.len() > 0)
        .unwrap_or(false)
}

pub fn try_download(url: &str, timeout: u64) -> Option<Vec<u8>> {
    try_download_h(url, &headers_for(url), timeout)
}

pub fn try_download_h(url: &str, headers: &HeaderMap, timeout: u64) -> Option<Vec<u8>> {
    match CLIENT
        .get(url)
        .headers(headers.clone())
        .timeout(Duration::from_secs(timeout))
        .send()
    {
        Ok(r) => {
            if !r.status().is_success() {
                return None;
            }
            match r.bytes() {
                Ok(b) => {
                    if b.is_empty() {
                        return None;
                    }
                    let scan = &b[..b.len().min(800)];
                    if is_probably_html(scan) {
                        return None;
                    }
                    Some(b.to_vec())
                }
                Err(_) => None,
            }
        }
        Err(e) => {
            log(&format!("[dl] fail {}: {}", url, e));
            None
        }
    }
}

pub fn get_bytes(url: &str, timeout: u64) -> Option<Vec<u8>> {
    match CLIENT
        .get(url)
        .headers(default_headers())
        .timeout(Duration::from_secs(timeout))
        .send()
    {
        Ok(r) => {
            if r.status().is_success() {
                r.bytes().ok().map(|b| b.to_vec())
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

fn read_head(path: &Path) -> Option<Vec<u8>> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; 512];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

pub fn download_file<F: FnMut(u32)>(url: &str, dest: &Path, mut cb: F) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let cleaned = clean_update_link(url);
    let url = cleaned.as_str();
    let mut resp = CLIENT
        .get(url)
        .headers(headers_for(url))
        .timeout(Duration::from_secs(60))
        .send()
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    let total = resp.content_length().unwrap_or(0);

    if ctype.contains("text/html") && (total == 0 || total < 50_000) {
        let text = resp.text().unwrap_or_default();
        let re_zip = Regex::new(r#"(?i)https?://[^\s"'<>]+?\.(?:zip|rar|7z|lua)"#).unwrap();
        if let Some(c) = re_zip.captures(&text) {
            let u = c[0].to_string();
            if u != url {
                return download_file(&u, dest, cb);
            }
        }
        let re_url = Regex::new(r#"(?i)url=([^\s"'>]+)"#).unwrap();
        if let Some(c) = re_url.captures(&text) {
            let mut nu = c[1].to_string();
            if nu.starts_with('/') {
                if let Ok(base) = reqwest::Url::parse(url) {
                    if let Ok(joined) = base.join(&nu) {
                        nu = joined.to_string();
                    }
                }
            }
            if nu != url {
                return download_file(&nu, dest, cb);
            }
        }
        return Err("Download failed".into());
    }

    let tmp = dest
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".{}.part", &uuid::Uuid::new_v4().simple().to_string()[..10]));
    let write_res: Result<(), String> = (|| {
        let mut file = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        let mut done: u64 = 0;
        let mut buf = [0u8; 65536];
        loop {
            let n = resp.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n]).map_err(|e| e.to_string())?;
            done += n as u64;
            if total > 0 {
                cb((done * 100 / total) as u32);
            } else {
                let p = ((done / (5 * 1024 * 1024)) * 100).min(95) as u32;
                cb(p);
            }
        }
        let _ = file.flush();
        let _ = file.sync_all();
        drop(file);
        Ok(())
    })();
    if let Err(e) = write_res {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    if let Some(head) = read_head(&tmp) {
        if is_probably_html(&head) {
            let _ = std::fs::remove_file(&tmp);
            return Err("Download failed".into());
        }
    }
    if dest.exists() {
        let _ = std::fs::remove_file(dest);
    }
    crate::util::move_path(&tmp, dest).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn extract_zip(zip_path: &Path, to: &Path) -> Result<(), String> {
    let f = std::fs::File::open(zip_path).map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(f).map_err(|e| e.to_string())?;
    archive.extract(to).map_err(|e| e.to_string())
}

pub fn temp_file(suffix: &str) -> std::path::PathBuf {
    temp_dir().join(format!("{}{}", uuid::Uuid::new_v4().simple(), suffix))
}

pub fn friendly_error(err: &str) -> String {
    let s = err.to_string();
    let low = s.to_lowercase();
    let has = |keys: &[&str]| keys.iter().any(|k| low.contains(k));

    if has(&["401", "unauthorized", "403", "forbidden", "access denied"]) {
        return "Tell admin to open it".into();
    }
    if has(&["404", "not found", "no such"]) {
        return "File not available".into();
    }
    if has(&["429", "rate limit", "too many"]) {
        return "Too many requests — try later".into();
    }
    if has(&["timeout", "timed out"]) {
        return "Connection timed out".into();
    }
    if has(&[
        "ssl",
        "certificate",
        "connection",
        "network",
        "unreachable",
        "name or service",
        "getaddrinfo",
    ]) {
        return "Connection failed".into();
    }
    if has(&["defender", "bitdefender", "mcafee", "avast", "avg", "kaspersky"]) {
        return "Blocked by antivirus — add exclusion".into();
    }
    if low.contains("defender") || low.contains("disappeared") || low.contains("blocked") {
        return "File blocked — check antivirus".into();
    }
    if low.contains("html page") || low.contains("too small") {
        return "Download failed".into();
    }
    if low.contains("rarfile") {
        return "RAR support missing".into();
    }
    if low.contains("py7zr") {
        return "7Z support missing".into();
    }

    let mut s2 = s.clone();
    if let Ok(re) = Regex::new(r"https?://\S+") {
        s2 = re.replace_all(&s2, "").to_string();
    }
    if let Ok(re) = Regex::new(r"[A-Za-z]:\\[^\s]+") {
        s2 = re.replace_all(&s2, "").to_string();
    }
    if let Ok(re) = Regex::new(r"/[\w./\-]+") {
        s2 = re.replace_all(&s2, "").to_string();
    }
    let s2: String = s2.split_whitespace().collect::<Vec<_>>().join(" ");
    let s2 = s2.trim_matches(|c: char| c == ':' || c == '-' || c.is_whitespace()).to_string();
    if s2.len() < 3 || s2.len() > 80 {
        return "Download failed".into();
    }
    s2
}
