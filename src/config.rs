use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("aur-guard")
}

pub fn state_dir() -> PathBuf {
    dirs::state_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("aur-guard")
}

pub fn config_file() -> PathBuf {
    config_dir().join("config.toml")
}

pub fn socket_path() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(state_dir)
        .join("aur-guard.sock")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub cache_ttl_secs: u64,
    pub recent_days: u64,
    pub notify: bool,
    /// stderr logging. Acepta `log` como alias legacy; no poner ambos a la vez
    /// (serde lo rechaza como campo duplicado).
    #[serde(alias = "log")]
    pub log_stderr: bool,
    pub feeds: Vec<FeedConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeedConfig {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

const DEFAULT_CONFIG: &str = r##"# Configuracion de aur-guard
# TTL de la cache de feeds en segundos (3600 = 1 hora).
cache_ttl_secs = 3600
# Dias hacia atras para considerar una unit/cron/rc como "modificada recientemente".
recent_days = 30
# Enviar alertas con notify-send.
notify = true
# Escribir alertas en stderr (journald lo captura). El log a fichero siempre se escribe.
log_stderr = true

# Feeds de paquetes AUR considerados malware. Se pueden anadir mas listas
# con kind = "plain" y una URL https a un archivo de texto (un paquete por linea,
# comentarios con #).
[[feeds]]
name = "aur-malware-check"
kind = "lenucksi"
base_url = "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master"
enabled = true
"##;

impl Config {
    pub fn load() -> Result<Self> {
        let path = config_file();
        if !path.exists() {
            write_file_atomic(&path, DEFAULT_CONFIG)?;
        }
        let text = std::fs::read_to_string(&path)?;
        toml::from_str(&text).map_err(|e| anyhow!("config invalida {}: {}", path.display(), e))
    }
}

pub fn now_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Rechaza symlinks antes de escribir (evita overwrite arbitrario vía swap).
/// Revisa el path final y cada padre hasta la raíz (superset seguro).
pub fn reject_symlink(path: &std::path::Path) -> Result<()> {
    let mut cur: Option<&std::path::Path> = Some(path);
    while let Some(p) = cur {
        if let Ok(meta) = std::fs::symlink_metadata(p) {
            if meta.file_type().is_symlink() {
                return Err(anyhow!("{} es un symlink; no se modifica por seguridad", p.display()));
            }
        }
        cur = p.parent();
        // No subir más allá de home para no escanear todo el FS.
        if cur.map(|p| p.as_os_str().is_empty() || p == std::path::Path::new("/")).unwrap_or(true) {
            break;
        }
    }
    Ok(())
}

/// Escritura atómica real: temporal único con `create_new` + fsync + rename.
/// Falla si el temporal ya existe (evita redirección por plantado previo).
pub fn write_file_atomic(path: &std::path::Path, content: &str) -> Result<()> {
    reject_symlink(path)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing_mode = std::fs::metadata(path).ok().map(|m| m.permissions());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    for attempt in 0..10 {
        let tmp = path.with_extension(format!("tmp.aur-guard.{}-{}-{}", std::process::id(), nanos, attempt));
        let created = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp);
        let mut f = match created {
            Ok(f) => f,
            Err(_) => continue,
        };
        {
            use std::io::Write;
            f.write_all(content.as_bytes())?;
            f.sync_all()?;
        }
        if let Some(mode) = existing_mode {
            let _ = std::fs::set_permissions(&tmp, mode);
        }
        std::fs::rename(&tmp, path)?;
        return Ok(());
    }
    Err(anyhow!("no se pudo crear temporal atómico para {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_symlink_ok_on_regular_file() {
        let dir = std::env::temp_dir().join(format!("aur_guard_cfg_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("regular.txt");
        std::fs::write(&f, "x").unwrap();
        assert!(reject_symlink(&f).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reject_symlink_fails_on_symlink() {
        let dir = std::env::temp_dir().join(format!("aur_guard_cfg_link_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target.txt");
        std::fs::write(&target, "x").unwrap();
        let link = dir.join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(unix)]
        assert!(reject_symlink(&link).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_file_atomic_roundtrip() {
        let dir = std::env::temp_dir().join(format!("aur_guard_atomic_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let f = dir.join("sub").join("out.txt");
        write_file_atomic(&f, "hola").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "hola");
        write_file_atomic(&f, "adios").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "adios");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
