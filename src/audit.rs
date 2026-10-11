use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use crate::config::Config;
use crate::feeds;
use crate::gate::Verdict;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub severity: String,
    pub message: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Report {
    pub scanned_installed: usize,
    pub foreign_installed: Vec<String>,
    pub infected: Vec<Verdict>,
    pub processes: Vec<Finding>,
    pub persistence: Vec<Finding>,
}

fn pacman_all_installed() -> Vec<String> {
    cmd_stdout(&pacman_bin(), &["-Qq"])
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('<'))
        .map(String::from)
        .collect()
}

fn pacman_foreign() -> Vec<String> {
    cmd_stdout(&pacman_bin(), &["-Qqm"])
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('<'))
        .map(|l| l.split_whitespace().next().unwrap_or("").to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Tope de `pacman -Qo` por scan: 30 × 3 s = 90 s peor caso, bajo el
/// timeout de lectura del cliente (120 s).
const MAX_OWNERSHIP_CHECKS: usize = 30;
const CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const OWNS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Resuelve un binario a ruta absoluta (no fiarse del PATH heredado).
/// Devuelve el primer candidato existente+ejecutable, o el nombre como fallback.
pub fn resolve_bin(name: &str, candidates: &[&str]) -> String {
    for c in candidates {
        let p = std::path::Path::new(c);
        if p.is_absolute() {
            if let Ok(m) = std::fs::metadata(p) {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if !m.is_dir() && m.permissions().mode() & 0o111 != 0 {
                        return c.to_string();
                    }
                }
                #[cfg(not(unix))]
                {
                    if !m.is_dir() {
                        return c.to_string();
                    }
                }
            }
        }
    }
    name.to_string()
}

fn pacman_bin() -> String {
    resolve_bin("pacman", &["/usr/bin/pacman", "/bin/pacman"])
}

fn ss_bin() -> String {
    resolve_bin("ss", &["/usr/bin/ss", "/bin/ss"])
}

fn iptables_bin() -> String {
    resolve_bin("iptables", &["/usr/sbin/iptables", "/usr/bin/iptables", "/sbin/iptables"])
}

/// Ejecuta un comando con timeout matando al hijo (no deja hijos colgados).
/// Drena el pipe en un hilo aparte: sin esto, salidas >64 KiB bloquean al hijo
/// y el timeout se vuelve un fail-open (auditoría incompleta silenciosa).
fn output_with_timeout(cmd: &mut Command, timeout: std::time::Duration) -> Option<std::process::Output> {
    use std::io::Read;
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null());
    let mut child = cmd.spawn().ok()?;
    let mut stdout = child.stdout.take();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(ref mut out) = stdout {
            let _ = out.read_to_end(&mut buf);
        }
        let _ = tx.send(buf);
    });
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let buf = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap_or_default();
                return Some(std::process::Output { status, stdout: buf, stderr: Vec::new() });
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    }
}

fn cmd_stdout(prog: &str, args: &[&str]) -> String {
    let mut cmd = Command::new(prog);
    cmd.args(args);
    match output_with_timeout(&mut cmd, CMD_TIMEOUT) {
        Some(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        None => format!("<{} no disponible o timeout>", prog),
    }
}

fn pacman_owns(path: &str) -> bool {
    let mut cmd = Command::new(pacman_bin());
    cmd.args(["-Qo", path]);
    output_with_timeout(&mut cmd, OWNS_TIMEOUT).map(|o| o.status.success()).unwrap_or(false)
}

fn is_kernel_thread(cmd: &str, cmdline: &[u8], ppid: u32) -> bool {
    cmdline.is_empty() && ppid == 2 && cmd.starts_with('[') && cmd.ends_with(']')
}

/// Topes para que el informe quepa en el canal del socket (1 MiB por línea).
pub const MAX_INFECTED_ITEMS: usize = 1000;
pub const MAX_FINDING_ITEMS: usize = 2000;
pub const MAX_FOREIGN_ITEMS: usize = 5000;

fn truncate_vec<T>(v: &mut Vec<T>, max: usize) -> bool {
    if v.len() > max {
        v.truncate(max);
        true
    } else {
        false
    }
}

/// Recorta un informe para que su JSON quepa en `MAX_LINE_BYTES`.
pub fn truncate_report(r: &mut Report) {
    let mut truncated = false;
    truncated |= truncate_vec(&mut r.infected, MAX_INFECTED_ITEMS);
    truncated |= truncate_vec(&mut r.processes, MAX_FINDING_ITEMS);
    truncated |= truncate_vec(&mut r.persistence, MAX_FINDING_ITEMS);
    truncated |= truncate_vec(&mut r.foreign_installed, MAX_FOREIGN_ITEMS);
    if truncated {
        r.persistence.push(Finding {
            severity: "warn".into(),
            message: "informe truncado por tamaño (ver log completo con --verbose)".into(),
        });
    }
}

/// Recorte por bytes: serializa y reduce hasta caber en `max_bytes`.
/// Llama después de `truncate_report`.
pub fn fit_report_to_bytes(r: &mut Report, max_bytes: usize) {
    let mut guard = 0usize;
    while serde_json::to_string(r).map(|s| s.len()).unwrap_or(0) > max_bytes {
        guard += 1;
        if guard > 16 {
            break;
        }
        // Recortar el vec más grande primero (mitad cada pasada).
        let lens = [r.infected.len(), r.processes.len(), r.persistence.len(), r.foreign_installed.len()];
        let biggest = lens.iter().enumerate().max_by_key(|(_, n)| **n).map(|(i, _)| i).unwrap_or(0);
        let target = lens[biggest].saturating_sub(lens[biggest] / 2 + 1);
        let changed = match biggest {
            0 => truncate_vec(&mut r.infected, target),
            1 => truncate_vec(&mut r.processes, target),
            2 => truncate_vec(&mut r.persistence, target),
            _ => truncate_vec(&mut r.foreign_installed, target),
        };
        if !changed {
            break;
        }
    }
}

pub fn run(cfg: &Config) -> Report {
    let state = feeds::load_or_empty(cfg);

    let mut infected: Vec<Verdict> = Vec::new();
    let installed = pacman_all_installed();
    for name in &installed {
        let (bad, feed_hits) = feeds::feed_verdict(&state, name);
        if bad {
            infected.push(Verdict::new(name.clone(), feed_hits, Vec::new()));
        }
    }
    let foreign = pacman_foreign();

    let processes = scan_processes();
    let persistence = scan_persistence(cfg);

    Report {
        scanned_installed: installed.len(),
        foreign_installed: foreign,
        infected,
        processes,
        persistence,
    }
}

// ---------- procesos ----------

const SUSPICIOUS_DIRS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/"];

pub const CMDLINE_PREVIEW: usize = 120;
/// Vista corta para mensajes con contexto extra (binario + cmdline).
const CMDLINE_PREVIEW_SHORT: usize = 100;

pub fn truncate_ellipsis(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        return s.to_string();
    }
    let truncated: String = s.chars().take(max_chars).collect();
    format!("{}…", truncated)
}

fn in_suspicious_dir(p: &str) -> Option<&'static str> {
    SUSPICIOUS_DIRS.iter().find(|d| p.starts_with(**d)).copied()
}

fn not_pacman_owned_path(p: &str) -> bool {
    !(p.starts_with("/usr")
        || p.starts_with("/bin")
        || p.starts_with("/sbin")
        || p.starts_with("/lib")
        || p.starts_with("/proc")
        || p.starts_with("/app/")
        || p.starts_with("/snap/"))
}

fn scan_processes() -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut ownership: HashMap<String, bool> = HashMap::new();
    let mut ownership_checks = 0usize;
    let mut reported_exe: std::collections::HashSet<String> = std::collections::HashSet::new();

    let proc_root = Path::new("/proc");
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        findings.push(Finding {
            severity: "warn".into(),
            message: "no se pudo leer /proc".into(),
        });
        return findings;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        let cmdline_path = PathBuf::from(format!("/proc/{}/cmdline", pid));
        let cmdline_bytes = std::fs::read(&cmdline_path).unwrap_or_default();
        let cmdline = cmdline_bytes
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect::<Vec<_>>()
            .join(" ");

        let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).unwrap_or_default();
        let ppid = status
            .lines()
            .find_map(|l| l.strip_prefix("PPid:"))
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(0);
        let comm = status
            .lines()
            .find_map(|l| l.strip_prefix("Name:"))
            .map(|v| v.trim().to_string())
            .unwrap_or_default();

        if is_kernel_thread(&comm, &cmdline_bytes, ppid) {
            continue;
        }
        if cmdline.contains("aur-guard") {
            continue;
        }

        let exe = std::fs::read_link(format!("/proc/{}/exe", pid)).ok();

        if let Some(exe) = &exe {
            let es = exe.to_string_lossy().to_string();
            if let Some(d) = in_suspicious_dir(&es) {
                findings.push(Finding {
                    severity: "crit".into(),
                    message: format!(
                        "proceso {} [{}] con binario en {}: {}",
                        pid,
                        comm,
                        d,
                        truncate_ellipsis(&cmdline, CMDLINE_PREVIEW)
                    ),
                });
            }
            if ownership_checks < MAX_OWNERSHIP_CHECKS && not_pacman_owned_path(&es) {
                let owned = *ownership.entry(es.clone()).or_insert_with(|| {
                    ownership_checks += 1;
                    pacman_owns(&es)
                });
                if !owned && reported_exe.insert(es.clone()) {
                    findings.push(Finding {
                        severity: "warn".into(),
                        message: format!(
                            "proceso {} [{}] con binario sin paquete: {} ({})",
                            pid,
                            comm,
                            es,
                            truncate_ellipsis(&cmdline, CMDLINE_PREVIEW_SHORT)
                        ),
                    });
                }
            }
        } else if let Some(d) = in_suspicious_dir(&cmdline) {
            findings.push(Finding {
                severity: "info".into(),
                message: format!(
                    "proceso {} [{}] en ruta sospechosa {}: {}",
                    pid,
                    comm,
                    d,
                    truncate_ellipsis(&cmdline, CMDLINE_PREVIEW)
                ),
            });
        }
    }

    // puertos escuchando
    static PID_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let pid_re = PID_RE.get_or_init(|| regex::Regex::new(r#"pid=(\d+)"#).expect("regex pid válida"));
    for (opt, proto) in [("-tlnp", "TCP"), ("-ulnp", "UDP")] {
        let out = cmd_stdout(&ss_bin(), &[opt]);
        if out.starts_with("<ss") {
            continue;
        }
        let mut seen = std::collections::HashSet::new();
        for line in out.lines() {
            for cap in pid_re.captures_iter(line) {
                let pid = cap[1].to_string();
                if !seen.insert(pid.clone()) {
                    continue;
                }
                if let Ok(exe) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
                    let es = exe.to_string_lossy().to_string();
                    if let Some(d) = in_suspicious_dir(&es) {
                        findings.push(Finding {
                            severity: "crit".into(),
                            message: format!("puerto {} escuchando desde {} (pid {}): {}", proto, d, pid, es),
                        });
                    }
                }
            }
        }
    }
    findings
}

// ---------- persistencia ----------

fn recent_secs(cfg: &Config) -> u64 {
    cfg.recent_days.saturating_mul(86400)
}

fn mtime_recent(path: &Path, recent: u64) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .map(|d| d.as_secs() <= recent)
        .unwrap_or(false)
}

fn scan_persistence(cfg: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    let recent = recent_secs(cfg);

    for dir in ["/etc/systemd/system"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let p = e.path();
                let name = e.file_name().to_string_lossy().to_string();
                if !name.ends_with(".service") && !name.ends_with(".timer") && !name.ends_with(".socket") {
                    continue;
                }
                if mtime_recent(&p, recent) {
                    findings.push(Finding {
                        severity: "warn".into(),
                        message: format!("unit systemd modificada recientemente: {} ({})", dir, name),
                    });
                }
            }
        }
    }

    if let Some(home) = dirs::home_dir() {
        let udir = home.join(".config").join("systemd").join("user");
        if let Ok(entries) = std::fs::read_dir(&udir) {
            for e in entries.flatten() {
                let p = e.path();
                let name = e.file_name().to_string_lossy().to_string();
                if !name.ends_with(".service") && !name.ends_with(".timer") {
                    continue;
                }
                if mtime_recent(&p, recent) {
                    findings.push(Finding {
                        severity: "warn".into(),
                        message: format!("unit systemd de usuario modificada recientemente: {}", name),
                    });
                }
            }
        }

        // autostart
        let autostart = home.join(".config").join("autostart");
        if let Ok(entries) = std::fs::read_dir(&autostart) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.ends_with(".desktop") {
                    findings.push(Finding {
                        severity: "info".into(),
                        message: format!("entrada de autostart presente: {}", name),
                    });
                }
            }
        }

        // authorized_keys
        let ak = home.join(".ssh").join("authorized_keys");
        if ak.exists() {
            let count = std::fs::read_to_string(&ak)
                .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
                .unwrap_or(0);
            let rec = if mtime_recent(&ak, recent) { " (modificado recientemente)" } else { "" };
            findings.push(Finding {
                severity: if count > 0 { "warn".into() } else { "info".into() },
                message: format!("authorized_keys con {} claves{}", count, rec),
            });
        }

        // shell rc recientes
        for rc in [".bashrc", ".zshrc", ".profile", ".bash_profile"] {
            let p = home.join(rc);
            if p.exists() && mtime_recent(&p, recent) {
                findings.push(Finding {
                    severity: "info".into(),
                    message: format!("{} modificado recientemente", rc),
                });
            }
        }
    }

    // cron
    for p in ["/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"] {
        let path = Path::new(p);
        if path.is_file() {
            if mtime_recent(path, recent) {
                findings.push(Finding {
                    severity: "warn".into(),
                    message: format!("{} modificado recientemente", p),
                });
            }
        } else if path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for e in entries.flatten() {
                    let ep = e.path();
                    if mtime_recent(&ep, recent) {
                        findings.push(Finding {
                            severity: "warn".into(),
                            message: format!("{} modificado recientemente", ep.display()),
                        });
                    }
                }
            }
        }
    }

    if Path::new("/etc/rc.local").exists() {
        findings.push(Finding {
            severity: "info".into(),
            message: "/etc/rc.local existe".into(),
        });
    }

    let iptables = cmd_stdout(&iptables_bin(), &["-L", "-n"]);
    if iptables.starts_with("<iptables") {
        findings.push(Finding {
            severity: "info".into(),
            message: "iptables no disponible o requiere permisos".into(),
        });
    } else {
        let n = iptables.lines().filter(|l| l.contains("ACCEPT") || l.contains("DROP") || l.contains("REJECT")).count();
        if n > 0 {
            findings.push(Finding {
                severity: "info".into(),
                message: format!("{} reglas activas en iptables", n),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_ellipsis_no_panic_multibyte() {
        let s = "hola 🌍🌍🌍 mundo largo con emojis 🎉🎉🎉 y texto extra para cortar";
        let out = truncate_ellipsis(s, 10);
        assert_eq!(out.chars().count(), 11); // 10 + …
        assert!(out.ends_with('…'));
        // Corto no toca
        assert_eq!(truncate_ellipsis("abc", 10), "abc");
    }

    #[test]
    fn truncate_counts_chars_not_bytes() {
        let s = "é".repeat(200);
        let out = truncate_ellipsis(&s, 100);
        assert_eq!(out.chars().count(), 101);
    }

    #[test]
    fn truncate_report_caps_items() {
        let mut r = Report {
            scanned_installed: 0,
            foreign_installed: vec!["x".to_string(); MAX_FOREIGN_ITEMS + 10],
            infected: vec![],
            processes: vec![Finding { severity: "info".into(), message: "m".into() }; MAX_FINDING_ITEMS + 5],
            persistence: vec![],
        };
        truncate_report(&mut r);
        assert_eq!(r.foreign_installed.len(), MAX_FOREIGN_ITEMS);
        assert_eq!(r.processes.len(), MAX_FINDING_ITEMS);
        assert!(r.persistence.iter().any(|f| f.message.contains("truncado")));
    }

    #[test]
    fn fit_report_to_bytes_shrinks() {
        let mut r = Report {
            scanned_installed: 0,
            foreign_installed: vec!["y".repeat(500); 100],
            infected: vec![],
            processes: vec![],
            persistence: vec![],
        };
        fit_report_to_bytes(&mut r, 1024);
        assert!(serde_json::to_string(&r).unwrap().len() <= 1024);
    }

    #[test]
    fn resolve_bin_prefers_absolute() {
        let got = resolve_bin("sh", &["/usr/bin/sh", "/bin/sh"]);
        assert!(got.starts_with('/'));
        assert_eq!(resolve_bin("noexiste-xyz", &["/no/existe"]), "noexiste-xyz");
    }
}
