use anyhow::Result;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::audit;
use crate::config::{socket_path, state_dir, Config};
use crate::feeds;

const IDLE_TIMEOUT: Duration = Duration::from_secs(3); // inactividad antes de morir
const MAX_LIFETIME: Duration = Duration::from_secs(300);
/// Tope de una línea de protocolo JSON (evita OOM por cliente local).
pub const MAX_LINE_BYTES: u64 = 1 << 20;

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Ping,
    CheckFeeds,
    CheckPackages { names: Vec<String> },
    GateCheck { name: String, dir: Option<String> },
    ScanHost,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Pong { version: String },
    FeedsResult { new_malware: Vec<String>, total: usize, error: Option<String> },
    CheckResult { verdicts: Vec<crate::gate::Verdict> },
    GateResult { verdict: crate::gate::Verdict },
    ScanResult { report: audit::Report },
    Error { message: String },
}

fn pidfile() -> PathBuf {
    state_dir().join("daemon.pid")
}

/// Parsea y valida un pid leído del pidfile. Rechaza 0, 1 y valores que no
/// caben en `i32` (evita `kill(-1)` por truncamiento `as i32`).
pub fn pid_from_str(s: &str) -> Option<u32> {
    let pid: u32 = s.trim().parse().ok()?;
    let as_i32 = i32::try_from(pid).ok()?;
    if as_i32 <= 1 {
        return None;
    }
    Some(pid)
}

pub fn daemon_pid() -> Option<u32> {
    fs::read_to_string(pidfile()).ok().and_then(|t| pid_from_str(&t))
}

/// Comprueba que `/proc/<pid>/exe` apunte a nuestro binario antes de señalizar.
fn is_our_daemon(pid: u32) -> bool {
    let own = std::env::current_exe().ok();
    let other = std::fs::read_link(format!("/proc/{}/exe", pid)).ok();
    match (own, other) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

pub fn validated_kill_target(pid: u32) -> Option<nix::unistd::Pid> {
    let raw = i32::try_from(pid).ok()?;
    if raw <= 1 {
        return None;
    }
    if !is_our_daemon(pid) {
        return None;
    }
    Some(nix::unistd::Pid::from_raw(raw))
}

fn now_nanos() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i128::from(d.as_secs()) * 1_000_000_000 + i128::from(d.subsec_nanos()))
        .unwrap_or(0)
}

fn dispatch(cfg: &Config, req: Request) -> Response {
    match req {
        Request::Ping => Response::Pong {
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        Request::CheckFeeds => match feeds::refresh(cfg, true) {
            Ok(state) => {
                let set = feeds::malware_set(&state);
                let baseline = feeds::load_baseline();
                let had_baseline = feeds::has_baseline();
                let mut new: Vec<String> = set.difference(&baseline).cloned().collect();
                new.sort();
                if !new.is_empty() {
                    // Tapar tormenta de ~2000 notifys: avisar los primeros + resumen.
                    const MAX_FEED_ALERTS: usize = 20;
                    let shown = new.len().min(MAX_FEED_ALERTS);
                    for n in new.iter().take(shown) {
                        let reasons = state
                            .packages
                            .get(n)
                            .map(|r| r.join(", "))
                            .unwrap_or_default();
                        let installed = feeds::is_installed(n);
                        if had_baseline {
                            // Cambio nuevo en el feed: alertar siempre.
                            let extra = if installed {
                                " — ¡INSTALADO EN TU SISTEMA!"
                            } else {
                                ""
                            };
                            crate::alerts::notify(
                                cfg,
                                &format!("AUR: paquete marcado como malware{}", extra),
                                &format!("{} [{}]", n, reasons),
                            );
                        } else if installed {
                            // Sincronizacion inicial: solo alertar lo instalado.
                            crate::alerts::notify(
                                cfg,
                                "AUR: paquete instalado y marcado como malware",
                                &format!("{} [{}]", n, reasons),
                            );
                        }
                    }
                    if new.len() > shown {
                        crate::alerts::notify(
                            cfg,
                            "AUR: más paquetes marcados como malware",
                            &format!("…y {} más (ver `aur-guard check`)", new.len() - shown),
                        );
                    }
                    let _ = feeds::save_baseline(&set);
                } else if !had_baseline {
                    let _ = feeds::save_baseline(&set);
                }
                // En la primera sincronización no hay "nuevos": evita volcar miles de líneas.
                let new_malware = if had_baseline { new } else { Vec::new() };
                Response::FeedsResult {
                    new_malware,
                    total: set.len(),
                    error: None,
                }
            }
            Err(e) => Response::FeedsResult {
                new_malware: Vec::new(),
                total: 0,
                error: Some(e.to_string()),
            },
        },
        Request::CheckPackages { names } => {
            // Tapar DoS local: tope de entradas y de longitud, solo nombres válidos.
            const MAX_CHECK_PACKAGES: usize = 256;
            const MAX_PACKAGE_NAME_LEN: usize = 256;
            if names.len() > MAX_CHECK_PACKAGES {
                return Response::Error { message: format!("demasiados paquetes (máx {})", MAX_CHECK_PACKAGES) };
            }
            let mut clean: Vec<String> = Vec::with_capacity(names.len());
            for n in &names {
                let t = n.trim();
                if t.is_empty() || t.len() > MAX_PACKAGE_NAME_LEN || !feeds::valid_name(t) {
                    let shown: String = t.chars().filter(|c| !c.is_control()).take(64).collect();
                    return Response::Error { message: format!("nombre de paquete inválido: {}", shown) };
                }
                clean.push(t.to_string());
            }
            let verdicts = clean
                .iter()
                .map(|n| crate::gate::check(cfg, n, None))
                .collect();
            Response::CheckResult { verdicts }
        }
        Request::GateCheck { name, dir } => {
            const MAX_GATE_NAME_LEN: usize = 256;
            let t = name.trim();
            if t.is_empty() || t.len() > MAX_GATE_NAME_LEN || !feeds::valid_name(t) {
                return Response::Error { message: "nombre de paquete inválido".into() };
            }
            Response::GateResult {
                verdict: crate::gate::check(cfg, t, dir.as_deref()),
            }
        }
        Request::ScanHost => {
            let mut report = audit::run(cfg);
            audit::truncate_report(&mut report);
            let max = usize::try_from(crate::daemon::MAX_LINE_BYTES).unwrap_or(usize::MAX).saturating_sub(1024);
            audit::fit_report_to_bytes(&mut report, max);
            Response::ScanResult { report }
        }
    }
}

fn handle_conn(mut stream: UnixStream, cfg: Arc<Config>) {
    let clone = match stream.try_clone() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("aur-guard: fallo al clonar el socket de conexion: {}", e);
            return;
        }
    };
    let mut reader = BufReader::new(clone);
    loop {
        let mut line = String::new();
        let n = match reader.by_ref().take(MAX_LINE_BYTES + 1).read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let max = usize::try_from(MAX_LINE_BYTES).unwrap_or(usize::MAX);
        if n > max || line.len() > max {
            let resp = Response::Error { message: "linea demasiado larga".into() };
            if let Ok(s) = serde_json::to_string(&resp) {
                let _ = writeln!(stream, "{}", s);
                let _ = stream.flush();
            }
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Request = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::Error { message: e.to_string() };
                if let Ok(s) = serde_json::to_string(&resp) {
                    let _ = writeln!(stream, "{}", s);
                    let _ = stream.flush();
                }
                continue;
            }
        };
        let resp = dispatch(&cfg, req);
        if let Ok(s) = serde_json::to_string(&resp) {
            let _ = writeln!(stream, "{}", s);
            let _ = stream.flush();
        }
    }
}

fn nanos_now_i64() -> i64 {
    i64::try_from(now_nanos()).unwrap_or(i64::MAX)
}

pub fn run(cfg: Config) -> Result<()> {
    let sock = socket_path();
    let _ = fs::remove_file(&sock);
    if let Some(parent) = sock.parent() {
        fs::create_dir_all(parent)?;
        // En sockets Unix el permiso que controla `connect` es el del
        // directorio, no el del path del socket. Forzar 0700 salvo que el
        // padre sea $XDG_RUNTIME_DIR (ya 0700 por especificación).
        let is_runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from).as_deref() == Some(parent);
        if !is_runtime_dir {
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    fs::create_dir_all(state_dir())?;
    crate::config::write_file_atomic(&pidfile(), &format!("{}\n", std::process::id()))?;

    let listener = UnixListener::bind(&sock)?;
    let _ = fs::set_permissions(&sock, fs::Permissions::from_mode(0o700));
    listener.set_nonblocking(true)?;
    eprintln!("aur-guard daemon listo en {}", sock.display());

    let terminate = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, terminate.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, terminate.clone())?;

    let active = Arc::new(AtomicUsize::new(0));
    let last_activity = Arc::new(AtomicI64::new(nanos_now_i64()));

    let term = terminate.clone();
    let act = active.clone();
    let la = last_activity.clone();
    let cfg = Arc::new(cfg);
    let cfg_thread = cfg.clone();
    let accept_thread = std::thread::spawn(move || {
        let listener = listener;
        while !term.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    la.store(nanos_now_i64(), Ordering::Relaxed);
                    act.fetch_add(1, Ordering::Relaxed);
                    let cfg = cfg_thread.clone();
                    let act = act.clone();
                    std::thread::spawn(move || {
                        handle_conn(stream, cfg);
                        act.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    });

    let start = Instant::now();
    loop {
        if terminate.load(Ordering::Relaxed) {
            break;
        }
        if active.load(Ordering::Relaxed) == 0
            && Duration::from_nanos(
                u64::try_from(nanos_now_i64() - last_activity.load(Ordering::Relaxed)).unwrap_or(0),
            ) >= IDLE_TIMEOUT
        {
            break;
        }
        if start.elapsed() > MAX_LIFETIME {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    terminate.store(true, Ordering::Relaxed);
    let _ = accept_thread.join();
    let _ = fs::remove_file(&sock);
    let _ = fs::remove_file(pidfile());
    eprintln!("aur-guard daemon terminado");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_from_str_rejects_zero_one_and_overflow() {
        assert_eq!(pid_from_str("0"), None);
        assert_eq!(pid_from_str("1"), None);
        assert_eq!(pid_from_str("1234"), Some(1234));
        assert_eq!(pid_from_str("  42\n"), Some(42));
        assert_eq!(pid_from_str("4294967295"), None);
        assert_eq!(pid_from_str("2147483648"), None);
        assert_eq!(pid_from_str("nope"), None);
    }

    #[test]
    fn validated_kill_target_rejects_non_aur_guard_pid() {
        // pid 1 nunca es nuestro daemon en tests
        assert_eq!(validated_kill_target(1), None);
        assert_eq!(validated_kill_target(u32::MAX), None);
    }
}
