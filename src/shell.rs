use anyhow::Result;
use std::fs;
use std::path::PathBuf;

const MARK: &str = "#### aur-guard: paru wrapper (comprobacion de malware antes de instalar) ####";

const FISH_MARK: &str = "# aur-guard: paru wrapper (comprobacion de malware antes de instalar)";

const SNIPPET: &str = r#"paru() {
  # Operación sync transaccional: -S, -Sy, -Su, -Syu, -Sc... (-Ss/-Si/-Sl son solo consulta)
  if [[ "$1" =~ ^-S[yuc]*$ ]]; then
    local _pkgs=() _a
    for _a in "${@:2}"; do
      [[ "$_a" == -* || -z "$_a" ]] && continue
      _pkgs+=("$_a")
    done
    if (( ${#_pkgs[@]} )); then
      aur-guard install "${_pkgs[@]}" || {
        echo "aur-guard: instalacion bloqueada (paquete comprometido)." >&2
        return 1
      }
    fi
  fi
  command paru "$@"
}
"#;

const FISH_SNIPPET: &str = r#"function paru --wraps paru
  # Operación sync transaccional: -S, -Sy, -Su, -Syu, -Sc... (-Ss/-Si/-Sl son solo consulta)
  if string match -q -r -- '^-S[yuc]*$' "$argv[1]"
    set -l pkgs
    for a in $argv[2..-1]
      if test -z "$a"; or string match -q -- '-*' "$a"
        continue
      end
      set -a pkgs "$a"
    end
    if test (count $pkgs) -gt 0
      aur-guard install $pkgs; or begin
        echo "aur-guard: instalacion bloqueada (paquete comprometido)." >&2
        return 1
      end
    end
  end
  command paru $argv
end
"#;

fn rc_path() -> PathBuf {
    let shell = std::env::var("SHELL").unwrap_or_default();
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    if shell.contains("fish") {
        home.join(".config").join("fish").join("config.fish")
    } else if shell.contains("zsh") {
        home.join(".zshrc")
    } else {
        home.join(".bashrc")
    }
}

fn guard_exe() -> String {
    std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "aur-guard".to_string())
}

/// Cita una ruta para shell POSIX (maneja espacios y comillas).
fn sh_quote(path: &str) -> String {
    format!("'{}'", path.replace('\'', "'\\''"))
}

/// Migrar invocaciones `aur-guard install` resueltas por PATH a ruta absoluta.
/// Solo toca ocurrencias NO precedidas por `/` (no reescribe dentro de una
/// ruta ya absoluta). Devuelve el contenido migrado y si cambió algo.
fn migrate_to_absolute(existing: &str, exe: &str) -> (String, bool) {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"(?m)(^|[\s;|&(])aur-guard install").expect("regex migración válida"));
    let out = re.replace_all(existing, format!("$1{} install", exe)).into_owned();
    let changed = out != existing;
    (out, changed)
}

pub fn install_hook() -> Result<String> {
    let path = rc_path();
    crate::config::reject_symlink(&path)?;
    let is_fish = path.ends_with("config.fish");
    let (mark, template) = if is_fish {
        (FISH_MARK, FISH_SNIPPET)
    } else {
        (MARK, SNIPPET)
    };
    let snippet = template.replace("aur-guard install", &format!("{} install", sh_quote(&guard_exe())));
    let existing = fs::read_to_string(&path).unwrap_or_default();
    if existing.contains(mark) {
        // Migrar hooks viejos: ruta absoluta + match de op sync (-Syu etc).
        let (mut migrated, mut changed) = migrate_to_absolute(&existing, &sh_quote(&guard_exe()));
        if migrated.contains(r#"[[ "$1" == "-S" ]]"#) {
            migrated = migrated.replace(
                r#"[[ "$1" == "-S" ]]"#,
                r#"[[ "$1" =~ ^-S[yuc]*$ ]]"#,
            );
            changed = true;
        }
        if migrated.contains(r#"if test "$argv[1]" = "-S""#) {
            migrated = migrated.replace(
                r#"if test "$argv[1]" = "-S""#,
                r#"if string match -q -r -- '^-S[yuc]*$' "$argv[1]""#,
            );
            changed = true;
        }
        if changed {
            crate::config::write_file_atomic(&path, &migrated)?;
            return Ok(format!("gancho de shell migrado a ruta absoluta en {}", path.display()));
        }
        return Ok(format!("el gancho de shell ya esta instalado en {}", path.display()));
    }
    let mut content = existing;
    if !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(mark);
    content.push('\n');
    content.push_str(&snippet);
    content.push('\n');
    crate::config::write_file_atomic(&path, &content)?;
    Ok(format!(
        "gancho de shell instalado en {}. Abre una terminal nueva para que aplique.",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_bare_path_hook() {
        let old = "#### aur-guard: paru wrapper (comprobacion de malware antes de instalar) ####\nparu() {\n  aur-guard install \"$@\"\n}\n";
        let (out, changed) = migrate_to_absolute(old, "/usr/bin/aur-guard");
        assert!(changed);
        assert!(out.contains("/usr/bin/aur-guard install"));
    }

    #[test]
    fn migrate_is_idempotent() {
        let migrated = "mark\n  /usr/bin/aur-guard install \"$@\"\n";
        let (out, changed) = migrate_to_absolute(migrated, "/usr/bin/aur-guard");
        assert!(!changed);
        assert_eq!(out, migrated);
        // Segunda pasada tampoco cambia (no duplica la ruta).
        let (out2, changed2) = migrate_to_absolute(&out, "/usr/bin/aur-guard");
        assert!(!changed2);
        assert_eq!(out2, out);
    }

    #[test]
    fn snippets_match_syu_but_not_search() {
        for snip in [SNIPPET, FISH_SNIPPET] {
            assert!(snip.contains("-S[yuc]"), "snippet debe matchear -Syu: {}", &snip[..60]);
            assert!(!snip.contains(r#"== "-S""#));
        }
    }
}