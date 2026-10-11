use anyhow::{anyhow, Result};
use std::fs;
use std::path::PathBuf;

const HOOK_LINE: &str = "PreBuildCommand = aur-guard gate";

fn paru_conf() -> PathBuf {
    let dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(dirs::config_dir)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    dir.join("paru").join("paru.conf")
}

fn line_is_ours(line: &str) -> bool {
    let t = line.trim();
    t == HOOK_LINE || (t.starts_with("PreBuildCommand") && t.contains("aur-guard gate"))
}

fn has_conflicting_prebuild(lines: &[String]) -> Option<String> {
    lines.iter().find_map(|l| {
        let t = l.trim();
        if t.starts_with("PreBuildCommand") && !t.contains("aur-guard gate") {
            Some(t.to_string())
        } else {
            None
        }
    })
}

fn insert_under_bin(lines: Vec<String>) -> (Vec<String>, bool) {
    // Dedup: si el hook vive fuera de [bin], quitarlo y reinsertar bajo [bin].
    let ours_count = lines.iter().filter(|l| line_is_ours(l)).count();
    let bin_idx = lines.iter().position(|l| l.trim() == "[bin]");
    if let Some(idx) = bin_idx {
        let under_bin = lines[idx + 1..].iter().any(|l| line_is_ours(l));
        if under_bin && ours_count == 1 {
            return (lines, false);
        }
        let mut cleaned: Vec<String> = lines.into_iter().filter(|l| !line_is_ours(l)).collect();
        let new_idx = cleaned.iter().position(|l| l.trim() == "[bin]").unwrap_or(0);
        cleaned.insert(new_idx + 1, HOOK_LINE.to_string());
        return (cleaned, true);
    }

    // 2) no hay [bin]: anadir la seccion al final
    let mut out: Vec<String> = lines.into_iter().filter(|l| !line_is_ours(l)).collect();
    if out.last().map(|l| !l.trim().is_empty()).unwrap_or(false) {
        out.push(String::new());
    }
    out.push("[bin]".to_string());
    out.push(HOOK_LINE.to_string());
    (out, true)
}

/// Asegura el gancho `PreBuildCommand` bajo la seccion [bin] de paru (idempotente).
pub fn ensure_hook() -> Result<String> {
    let path = paru_conf();
    // Revisar symlink antes de crear dirs (no seguir padres plantados),
    // y de nuevo después por si el create resolvió algo raro.
    if path.exists() {
        crate::config::reject_symlink(&path)?;
    }
    let parent = path.parent().ok_or_else(|| anyhow!("ruta paru.conf sin padre: {}", path.display()))?;
    fs::create_dir_all(parent)?;
    crate::config::reject_symlink(&path)?;

    let text = if path.exists() {
        fs::read_to_string(&path)?
    } else {
        String::new()
    };
    let lines: Vec<String> = text.lines().map(String::from).collect();

    if let Some(conflict) = has_conflicting_prebuild(&lines) {
        return Err(anyhow!(
            "paru.conf ya tiene un PreBuildCommand distinto ({}); no se modifica. Ajustalo a: {}",
            conflict,
            HOOK_LINE
        ));
    }

    let (new_lines, changed) = insert_under_bin(lines);
    if changed {
        let content = new_lines.join("\n") + "\n";
        crate::config::write_file_atomic(&path, &content)?;
        Ok(format!("gancho paru instalado en {}", path.display()))
    } else {
        Ok("gancho paru ya instalado".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_is_ours_accepts_hook_variants() {
        assert!(line_is_ours(HOOK_LINE));
        assert!(line_is_ours("  PreBuildCommand = aur-guard gate  "));
        assert!(line_is_ours("PreBuildCommand   aur-guard gate"));
    }

    #[test]
    fn line_is_ours_rejects_others() {
        assert!(!line_is_ours("PreBuildCommand = something else"));
        assert!(!line_is_ours("# comentario"));
        assert!(!line_is_ours(""));
    }

    #[test]
    fn has_conflicting_prebuild_finds_conflict() {
        let lines = vec!["[bin]".to_string(), "PreBuildCommand = other".to_string()];
        assert_eq!(
            has_conflicting_prebuild(&lines),
            Some("PreBuildCommand = other".to_string())
        );
    }

    #[test]
    fn has_conflicting_prebuild_none_when_ok() {
        let lines = vec!["[bin]".to_string(), HOOK_LINE.to_string()];
        assert_eq!(has_conflicting_prebuild(&lines), None);
    }

    #[test]
    fn insert_under_bin_after_existing_section() {
        let (out, changed) = insert_under_bin(vec!["[bin]".to_string(), "MakepkgArgs".to_string()]);
        assert!(changed);
        assert_eq!(out, vec![
            "[bin]".to_string(),
            HOOK_LINE.to_string(),
            "MakepkgArgs".to_string(),
        ]);
    }

    #[test]
    fn insert_under_bin_no_section_appends() {
        let (out, changed) = insert_under_bin(vec!["A".to_string()]);
        assert!(changed);
        assert_eq!(out, vec![
            "A".to_string(),
            String::new(),
            "[bin]".to_string(),
            HOOK_LINE.to_string(),
        ]);
    }

    #[test]
    fn insert_under_bin_idempotent() {
        let lines = vec!["[bin]".to_string(), HOOK_LINE.to_string()];
        let (out, changed) = insert_under_bin(lines);
        assert!(!changed);
        assert_eq!(out, vec!["[bin]".to_string(), HOOK_LINE.to_string()]);
    }

    #[test]
    fn insert_under_bin_dedups_stray_hook() {
        let (out, changed) = insert_under_bin(vec![HOOK_LINE.to_string(), "[bin]".to_string(), "X".to_string()]);
        assert!(changed);
        assert_eq!(out.iter().filter(|l| line_is_ours(l)).count(), 1);
        assert_eq!(out[0], "[bin]".to_string());
        assert_eq!(out[1], HOOK_LINE.to_string());
    }
}
