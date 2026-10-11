use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

use crate::config::{now_epoch_secs, state_dir, Config, FeedConfig};

pub const HTTP_SEND_TIMEOUT_SECS: u64 = 20;
pub const HTTP_READ_TIMEOUT_SECS: u64 = 30;
/// Tope de cuerpo por feed (evita OOM ante feed comprometido).
pub const MAX_FEED_BODY_BYTES: usize = 5 << 20;
const MAX_FEED_ID_LEN: usize = 64;

/// Host permitido para `refresh_url`/`lists`: mismo host https que `base_url`.
/// Puertos y mayúsculas se normalizan; solo https (salvo localhost para tests).
fn url_host(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let scheme = url.split("://").next().unwrap_or("").to_lowercase();
    if scheme != "https" && !rest.starts_with("localhost") && !rest.starts_with("127.") {
        return None;
    }
    let host_port = rest.split('/').next()?;
    let host = host_port.split(':').next()?.trim_end_matches('.').to_lowercase();
    if host.is_empty() {
        return None;
    }
    Some(host)
}

fn refresh_url_allowed(base_url: &str, target: &str) -> bool {
    match (url_host(base_url), url_host(target)) {
        (Some(b), Some(t)) => b == t,
        _ => false,
    }
}

fn clean_campaign_id(id: &str) -> Option<String> {
    let t = id.trim();
    if t.is_empty() || t.len() > MAX_FEED_ID_LEN || !valid_name(t) {
        return None;
    }
    Some(t.to_string())
}

fn rt() -> Result<&'static Runtime, anyhow::Error> {
    static RT: OnceLock<Runtime> = OnceLock::new();
    if let Some(rt) = RT.get() {
        return Ok(rt);
    }
    let rt = Runtime::new().map_err(|e| anyhow::anyhow!("no se pudo crear el runtime tokio: {}", e))?;
    Ok(RT.get_or_init(move || rt))
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FeedState {
    pub updated_at: i64,
    pub packages: HashMap<String, Vec<String>>,
}

#[derive(serde::Deserialize)]
struct CampaignIndex {
    campaigns: Vec<Campaign>,
}

#[derive(serde::Deserialize)]
struct Campaign {
    #[serde(rename = "id")]
    id: String,
    #[serde(rename = "type")]
    type_: String,
    #[serde(default)]
    lists: Vec<String>,
    #[serde(default)]
    refresh_url: Option<String>,
}

fn state_file() -> std::path::PathBuf {
    state_dir().join("feeds").join("current.json")
}

fn baseline_file() -> std::path::PathBuf {
    state_dir().join("feed_baseline.json")
}

/// GET con redirects desactivados, status 2xx exigido y tope de cuerpo en
/// streaming (no bufera sin límite antes de comprobar el tamaño).
fn http_get(client: &reqwest::Client, url: &str) -> Result<String> {
    let client = client.clone();
    let url = url.to_string();
    let rt = rt()?;
    rt.block_on(async move {
        let start = std::time::Instant::now();
        const TOTAL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(90);
        let mut resp = tokio::time::timeout(
            std::time::Duration::from_secs(HTTP_SEND_TIMEOUT_SECS),
            client.get(&url).send(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("timeout {}", url))??;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("HTTP {} para {}", resp.status(), url));
        }
        let mut buf: Vec<u8> = Vec::new();
        loop {
            if start.elapsed() > TOTAL_DEADLINE {
                return Err(anyhow::anyhow!("deadline total excedido {}", url));
            }
            let chunk_opt = tokio::time::timeout(
                std::time::Duration::from_secs(HTTP_READ_TIMEOUT_SECS),
                resp.chunk(),
            )
            .await
            .map_err(|_| anyhow::anyhow!("timeout lectura {}", url))?
            .map_err(|e| anyhow::anyhow!("error leyendo {}: {}", url, e))?;
            match chunk_opt {
                Some(chunk) => {
                    buf.extend_from_slice(&chunk);
                    if buf.len() > MAX_FEED_BODY_BYTES {
                        return Err(anyhow::anyhow!("cuerpo demasiado grande {} (> {} bytes)", url, MAX_FEED_BODY_BYTES));
                    }
                }
                None => break,
            }
        }
        Ok::<String, anyhow::Error>(String::from_utf8_lossy(&buf).into_owned())
    })
}

pub fn parse_list(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('`'))
        .map(|l| l.split_whitespace().next().unwrap_or("").to_string())
        .filter(|l| valid_name(l))
        .collect()
}

/// Solo nombres de paquete validos (sin ruido de markdown ni basura).
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "@._+:-".contains(c))
        && s.chars().next().map(|c| c.is_ascii_alphanumeric()).unwrap_or(false)
}

fn refresh_lenucksi(client: &reqwest::Client, f: &FeedConfig, map: &mut HashMap<String, Vec<String>>) -> Result<()> {
    let base_url = f.base_url.as_deref().unwrap_or_default();
    if url_host(base_url).is_none() {
        return Err(anyhow::anyhow!("base_url debe ser https: {}", base_url));
    }
    let base = base_url.trim_end_matches('/');
    let index_url = format!("{}/data/campaigns.json", base);
    let index_text = http_get(client, &index_url)?;
    let index: CampaignIndex = serde_json::from_str(&index_text)?;
    for camp in index.campaigns {
        if camp.type_ != "aur" {
            continue;
        }
        let Some(camp_id) = clean_campaign_id(&camp.id) else { continue };
        for list in camp.lists {
            let url = format!("{}/{}", base, list.trim_start_matches('/'));
            if !refresh_url_allowed(base_url, &url) {
                continue;
            }
            if let Ok(txt) = http_get(client, &url) {
                for name in parse_list(&txt) {
                    map.entry(name).or_default().push(camp_id.clone());
                }
            }
        }
        if let Some(ru) = &camp.refresh_url {
            if !refresh_url_allowed(base_url, ru) {
                continue;
            }
            if let Ok(txt) = http_get(client, ru) {
                for name in parse_list(&txt) {
                    map.entry(name).or_default().push(camp_id.clone());
                }
            }
        }
    }
    Ok(())
}

fn refresh_plain(client: &reqwest::Client, f: &FeedConfig, map: &mut HashMap<String, Vec<String>>) -> Result<()> {
    let url = f.url.as_deref().unwrap_or_default();
    // Solo https (salvo localhost para tests): un feed plain por http es MITM-able.
    if url_host(url).is_none() {
        return Err(anyhow::anyhow!("URL de feed plain debe ser https: {}", url));
    }
    let txt = http_get(client, url)?;
    for name in parse_list(&txt) {
        map.entry(name).or_default().push(f.name.clone());
    }
    Ok(())
}

fn load_cached() -> Option<FeedState> {
    fs::read_to_string(state_file())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
}

/// Estado con fallback a cache vieja (nunca vacío si hay cache).
/// Si el refresco falla del todo, devuelve la cache anterior y avisa.
pub fn load_or_empty(cfg: &Config) -> FeedState {
    match refresh(cfg, false) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aur-guard: usando cache vieja ({})", e);
            load_cached().unwrap_or(FeedState { updated_at: 0, packages: HashMap::new() })
        }
    }
}

/// Refresca los feeds (o devuelve la cache si esta fresca y no se fuerza).
/// Fail-closed: si todos los feeds fallan, devuelve la cache vieja o error
/// (nunca escribe un estado vacío que envenene la cache ni el baseline).
pub fn refresh(cfg: &Config, force: bool) -> Result<FeedState> {
    if !force {
        if let Some(s) = load_cached() {
            let ttl = i64::try_from(cfg.cache_ttl_secs).unwrap_or(i64::MAX);
            let age = now_epoch_secs().saturating_sub(s.updated_at);
            if age < ttl {
                return Ok(s);
            }
        }
    }

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    let mut ok_feeds = 0usize;
    for f in &cfg.feeds {
        if !f.enabled.unwrap_or(true) {
            continue;
        }
        let r = match f.kind.as_str() {
            "lenucksi" => refresh_lenucksi(&client, f, &mut map),
            "plain" => refresh_plain(&client, f, &mut map),
            other => Err(anyhow::anyhow!("tipo de feed desconocido: {}", other)),
        };
        match r {
            Ok(()) => ok_feeds += 1,
            Err(e) => eprintln!("aur-guard: feed '{}' fallo: {}", f.name, e),
        }
    }
    if ok_feeds == 0 {
        if let Some(stale) = load_cached() {
            eprintln!("aur-guard: todos los feeds fallaron; usando cache vieja");
            return Ok(stale);
        }
        return Err(anyhow::anyhow!("todos los feeds fallaron y no hay cache"));
    }
    if map.is_empty() {
        // Respuesta vacía con feeds "ok": no envenenar una cache previa no vacía.
        if let Some(stale) = load_cached() {
            if !stale.packages.is_empty() {
                eprintln!("aur-guard: feed vacío; conservando cache previa");
                return Ok(stale);
            }
        }
    }

    for reasons in map.values_mut() {
        reasons.sort();
        reasons.dedup();
    }
    let state = FeedState {
        updated_at: now_epoch_secs(),
        packages: map,
    };
    crate::config::write_file_atomic(&state_file(), &serde_json::to_string_pretty(&state)?)?;
    Ok(state)
}

pub fn malware_set(state: &FeedState) -> HashSet<String> {
    state.packages.keys().cloned().collect()
}

pub fn normalize(name: &str) -> Vec<String> {
    let mut out = vec![name.to_string()];
    for suffix in ["-git", "-bin", "-svn", "-hg", "-bzr", "-cvs", "-dev"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            out.push(stripped.to_string());
        }
    }
    out
}

/// Veredicto de un paquete frente al feed: devuelve (infectado, campañas).
pub fn feed_verdict(state: &FeedState, name: &str) -> (bool, Vec<String>) {
    for n in normalize(name) {
        if let Some(reasons) = state.packages.get(&n) {
            return (true, reasons.clone());
        }
    }
    (false, Vec::new())
}

// ------- baseline / alertas de cambios -------

pub fn load_baseline() -> HashSet<String> {
    fs::read_to_string(baseline_file())
        .ok()
        .and_then(|t| serde_json::from_str::<Vec<String>>(&t).ok())
        .map(|v| v.into_iter().filter(|n| valid_name(n)).collect())
        .unwrap_or_default()
}

pub fn has_baseline() -> bool {
    baseline_file().exists()
}

pub fn save_baseline(set: &HashSet<String>) -> Result<()> {
    let mut v: Vec<String> = set.iter().cloned().collect();
    v.sort();
    crate::config::write_file_atomic(&baseline_file(), &serde_json::to_string(&v)?)?;
    Ok(())
}

/// Comprueba si un paquete concreto esta instalado.
pub fn is_installed(name: &str) -> bool {
    let pacman = crate::audit::resolve_bin("pacman", &["/usr/bin/pacman", "/bin/pacman"]);
    let mut cmd = std::process::Command::new(pacman);
    cmd.args(["-Q", name]);
    cmd.output().map(|o| o.status.success()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn parse_list_basic() {
        let text = "foo\n# commentario\n`marcado\nbar baz\n\n  qux\n";
        assert_eq!(parse_list(text), vec!["foo", "bar", "qux"]);
    }

    #[test]
    fn parse_list_drops_invalid_names() {
        let text = " valid1 \n..\n_invalido\nok-pkg\n";
        assert_eq!(parse_list(text), vec!["valid1", "ok-pkg"]);
    }

    #[test]
    fn valid_name_accepts_pkg_chars() {
        assert!(valid_name("foo"));
        assert!(valid_name("foo-git"));
        assert!(valid_name("a.b_c+2"));
        assert!(valid_name("foo@bar"));
        assert!(valid_name("x:y"));
    }

    #[test]
    fn valid_name_rejects_bad() {
        assert!(!valid_name(""));
        assert!(!valid_name(".dot"));
        assert!(!valid_name("-dash"));
        assert!(!valid_name("con espacio"));
        assert!(!valid_name("acentuó"));
        assert!(!valid_name("a*b"));
    }

    #[test]
    fn normalize_keeps_base_and_strips_suffixes() {
        assert_eq!(normalize("pkg-git"), vec!["pkg-git".to_string(), "pkg".to_string()]);
        assert_eq!(normalize("tool-bin"), vec!["tool-bin".to_string(), "tool".to_string()]);
        assert_eq!(normalize("plain"), vec!["plain".to_string()]);
    }

    #[test]
    fn feed_verdict_hits_on_normalized_name() {
        let mut packages = HashMap::new();
        packages.insert("evil".to_string(), vec!["camp1".to_string(), "camp2".to_string()]);
        let state = FeedState { updated_at: 1, packages };
        let (infected, reasons) = feed_verdict(&state, "evil-git");
        assert!(infected);
        assert_eq!(reasons, vec!["camp1", "camp2"]);
    }

    #[test]
    fn feed_verdict_misses() {
        let state = FeedState { updated_at: 1, packages: HashMap::new() };
        let (infected, reasons) = feed_verdict(&state, "clean");
        assert!(!infected);
        assert!(reasons.is_empty());
    }

    #[test]
    fn refresh_url_only_same_host() {
        let base = "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master";
        assert!(refresh_url_allowed(base, "https://raw.githubusercontent.com/other/list.txt"));
        assert!(!refresh_url_allowed(base, "https://evil.example.com/list.txt"));
        assert!(!refresh_url_allowed(base, "http://evil.example.com/x"));
        // Downgrade http en el mismo host también se rechaza.
        assert!(!refresh_url_allowed(base, "http://raw.githubusercontent.com/other/list.txt"));
    }

    #[test]
    fn campaign_id_rejects_injection() {
        assert_eq!(clean_campaign_id("aur-infected"), Some("aur-infected".into()));
        assert_eq!(clean_campaign_id("evil\nid"), None);
        assert_eq!(clean_campaign_id(""), None);
        assert_eq!(clean_campaign_id(&"x".repeat(65)), None);
    }
}