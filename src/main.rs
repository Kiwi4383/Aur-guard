mod alerts;
mod audit;
mod config;
mod daemon;
mod feeds;
mod gate;
mod paru;
mod shell;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Stdio};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use nix::sys::signal::{kill, Signal};

use crate::config::{socket_path, Config};
use crate::daemon::{Request, Response};

#[derive(Parser)]
#[command(name = "aur-guard", version, about = "Monitor de malware AUR + auditoria de host (daemon efimero + gancho paru)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Instala el gancho de paru y revisa paquetes contra el feed antes de instalar
    Install {
        /// Paquetes a comprobar contra el feed (opcional)
        packages: Vec<String>,
    },
    /// Despierta el daemon solo para refrescar el repositorio, registrar cambios y avisar
    Check,
    /// Despierta el daemon para escanear el sistema (paquetes infectados, procesos, persistencia)
    Scan,
    /// Gancho interno llamado por paru (PreBuildCommand) antes de cada build
    #[command(hide = true)]
    Gate,
    /// Estado del daemon
    Status,
    /// Detiene el daemon
    Stop,
    /// Instala en .bashrc/.zshrc una funcion `paru` que comprueba malware ANTES de instalar
    ShellHook,
    /// Daemon efimero (uso interno)
    #[command(hide = true)]
    Daemon,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Daemon => {
            let cfg = Config::load()?;
            daemon::run(cfg)
        }
        Command::Install { packages } => cmd_install(packages),
        Command::Check => cmd_check(),
        Command::Scan => cmd_scan(),
        Command::Gate => cmd_gate(),
        Command::Status => cmd_status(),
        Command::Stop => cmd_stop(),
        Command::ShellHook => cmd_shell_hook(),
    }
}

// ---------- daemon lifecycle ----------

fn send_request(req: &Request) -> Result<Response> {
    let sock = socket_path();
    let mut stream = UnixStream::connect(&sock)
        .map_err(|e| anyhow!("no hay daemon escuchando en {}: {}", sock.display(), e))?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    writeln!(stream, "{}", serde_json::to_string(req)?)?;
    stream.flush()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = reader.by_ref().take(crate::daemon::MAX_LINE_BYTES + 1).read_line(&mut line)?;
    if u64::try_from(n).unwrap_or(u64::MAX) > crate::daemon::MAX_LINE_BYTES {
        anyhow::bail!("respuesta demasiado larga (ver `aur-guard scan` truncado en el daemon)");
    }
    let resp: Response =
        serde_json::from_str(line.trim()).map_err(|e| anyhow!("respuesta invalida: {}", e))?;
    Ok(resp)
}

fn ping() -> bool {
    matches!(
        send_request(&Request::Ping),
        Ok(Response::Pong { .. })
    )
}

fn spawn_daemon() -> Result<Child> {
    let exe = std::env::current_exe()?;
    let child = std::process::Command::new(exe)
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(child)
}

/// Asegura un daemon escuchando. Devuelve el Child si lo lanzo este proceso.
fn ensure_daemon() -> Result<Option<Child>> {
    if ping() {
        return Ok(None);
    }
    let mut child = spawn_daemon()?;
    for _ in 0..DAEMON_START_RETRIES {
        if ping() {
            return Ok(Some(child));
        }
        std::thread::sleep(Duration::from_millis(DAEMON_START_POLL_MS));
    }
    let _ = child.kill();
    bail!("no se pudo arrancar el daemon")
}

/// Intenta detener el daemon. Devuelve true si se señalizó un target válido.
fn shutdown_daemon(child: Option<Child>) -> bool {
    let mut signaled = false;
    if let Some(pid) = crate::daemon::daemon_pid() {
        if let Some(target) = crate::daemon::validated_kill_target(pid) {
            signaled = true;
            let _ = kill(target, Signal::SIGTERM);
            for _ in 0..DAEMON_STOP_RETRIES {
                if crate::daemon::daemon_pid().is_none() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(DAEMON_STOP_POLL_MS));
            }
            if crate::daemon::daemon_pid().is_some() {
                let _ = kill(target, Signal::SIGKILL);
            }
        }
    }
    if let Some(mut c) = child {
        let _ = c.wait();
    }
    signaled
}

fn with_daemon<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    // Pre-flight: valida config antes de levantar el daemon efímero.
    Config::load().map(|_| ())?;
    let child = ensure_daemon()?;
    let r = f();
    shutdown_daemon(child);
    r
}

// ---------- comandos ----------

const DAEMON_START_RETRIES: u32 = 60;
const DAEMON_START_POLL_MS: u64 = 100;
const DAEMON_STOP_RETRIES: u32 = 40;
const DAEMON_STOP_POLL_MS: u64 = 100;

fn daemon_error(e: String) -> anyhow::Error {
    anyhow!("daemon reportó error: {}", e)
}

fn cmd_install(packages: Vec<String>) -> Result<()> {
    let hook_msg = match paru::ensure_hook() {
        Ok(m) => m,
        Err(e) => e.to_string(),
    };
    println!("[install] {}", hook_msg);

    if packages.is_empty() {
        println!("[install] no se pasaron paquetes; solo se dejo listo el gancho de paru.");
        return Ok(());
    }

    with_daemon(|| {
        let resp = send_request(&Request::CheckPackages { names: packages })?;
        match resp {
            Response::CheckResult { verdicts } => {
                let mut any_bad = false;
                for v in &verdicts {
                    if v.malicious {
                        any_bad = true;
                        println!(
                            "[INSTALAR BLOQUEADO] {} -> COMPROMETIDO [{}]",
                            v.name,
                            v.combined_reasons().join(", ")
                        );
                    } else {
                        println!("[ok] {} -> sin coincidencias de malware", v.name);
                    }
                }
                if any_bad {
                    bail!("paquetes comprometidos; abortando instalacion");
                }
                Ok(())
            }
            Response::Error { message } => Err(daemon_error(message)),
            other => Err(anyhow!("respuesta inesperada: {:?}", other)),
        }
    })
}

fn cmd_check() -> Result<()> {
    with_daemon(|| {
        let resp = send_request(&Request::CheckFeeds)?;
        match resp {
            Response::FeedsResult {
                new_malware,
                total,
                error,
            } => {
                if let Some(e) = error {
                    eprintln!("[check] error refrescando feeds: {}", e);
                }
                println!("[check] feed actualizado: {} paquetes en la lista de malware.", total);
                if new_malware.is_empty() {
                    println!("[check] sin cambios nuevos.");
                } else {
                    println!("[check] paquetes NUEVOS marcados como malware:");
                    for n in &new_malware {
                        println!("  - {}", n);
                    }
                }
                Ok(())
            }
            Response::Error { message } => Err(daemon_error(message)),
            other => Err(anyhow!("respuesta inesperada: {:?}", other)),
        }
    })
}

fn cmd_scan() -> Result<()> {
    with_daemon(|| {
        let resp = send_request(&Request::ScanHost)?;
        match resp {
            Response::ScanResult { report } => {
                print_report(&report);
                Ok(())
            }
            Response::Error { message } => Err(daemon_error(message)),
            other => Err(anyhow!("respuesta inesperada: {:?}", other)),
        }
    })
}

/// Extrae todos los `pkgname` (soporta arrays `pkgname=('a' 'b')`) + `pkgbase`.
fn pkg_names_from_cwd() -> Vec<String> {
    // metadata primero: no leer un PKGBUILD gigante a memoria antes del tope.
    if std::fs::metadata("PKGBUILD").map(|m| m.len()).unwrap_or(0) > crate::gate::MAX_SCAN_BYTES {
        return vec![];
    }
    let Ok(text) = std::fs::read_to_string("PKGBUILD") else { return vec![] };
    let max_scan = usize::try_from(crate::gate::MAX_SCAN_BYTES).unwrap_or(usize::MAX);
    if text.len() > max_scan {
        return vec![];
    }
    parse_pkgbuild_names(&text)
}

fn parse_pkgbuild_names(text: &str) -> Vec<String> {
    static PKG_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = PKG_RE.get_or_init(|| regex::Regex::new(r"(?m)^\s*(pkgbase|pkgname)\s*=\s*([^#\n]+)").expect("regex pkgbase válida"));
    // Colapsar arrays multilínea `pkgname=(\n 'a'\n 'b'\n)` en una línea.
    let mut joined = String::with_capacity(text.len());
    let mut depth = 0usize;
    for ch in text.chars() {
        match ch {
            '(' => { depth += 1; joined.push(ch); }
            ')' => { depth = depth.saturating_sub(1); joined.push(ch); }
            '\n' if depth > 0 => joined.push(' '),
            _ => joined.push(ch),
        }
    }
    let mut base: Option<String> = None;
    let mut names: Vec<String> = Vec::new();
    for cap in re.captures_iter(&joined) {
        let key = &cap[1];
        let raw = cap[2].trim().trim_matches(|c| c == '"' || c == '\'' || c == '(' || c == ')');
        for token in raw.split_whitespace() {
            let val = token.trim_matches(|c| c == '"' || c == '\'' || c == '(' || c == ')').trim();
            if val.is_empty() || val.contains('=') {
                continue;
            }
            let val = val.to_string();
            if key == "pkgbase" && base.is_none() {
                base = Some(val.clone());
            }
            if !names.contains(&val) {
                names.push(val);
            }
        }
    }
    if let Some(b) = base {
        // pkgbase primero: es el nombre que publica el feed.
        let mut out = vec![b.clone()];
        out.extend(names.into_iter().filter(|n| n != &b));
        out
    } else {
        names
    }
}

fn cmd_gate() -> Result<()> {
    // PKGBASE manda; si no, chequear TODOS los nombres (split-packages fail-closed).
    // PKGBASE sin validar se rechaza (fail-closed en vez de "ok" silencioso).
    let names: Vec<String> = match std::env::var("PKGBASE").ok().map(|v| v.trim().to_string()) {
        Some(v) if !v.is_empty() => {
            if !crate::feeds::valid_name(&v) {
                let shown: String = v.chars().filter(|c| !c.is_control()).take(64).collect();
                anyhow::bail!("PKGBASE inválido: {}", shown);
            }
            vec![v]
        }
        _ => pkg_names_from_cwd(),
    };
    let name = names.first().cloned().ok_or_else(|| anyhow!("no se pudo determinar el nombre del paquete"))?;
    let dir = std::env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    println!("[aur-guard gate] comprobando '{}'...", names.join(", "));

    let verdicts = with_daemon(|| {
        let mut out = Vec::new();
        for n in &names {
            let resp = send_request(&Request::GateCheck {
                name: n.clone(),
                dir: dir.clone(),
            })?;
            match resp {
                Response::GateResult { verdict } => out.push(verdict),
                Response::Error { message } => return Err(daemon_error(message)),
                other => return Err(anyhow!("respuesta inesperada: {:?}", other)),
            }
        }
        Ok(out)
    })?;

    let mut blocked: Vec<String> = Vec::new();
    for v in &verdicts {
        if v.malicious {
            blocked.push(format!("{} [{}]", v.name, v.combined_reasons().join(", ")));
        }
    }
    if !blocked.is_empty() {
        println!("[BLOQUEADO] '{}' es malware: [{}]", name, blocked.join("; "));
        eprintln!("aur-guard: BLOQUEADO '{}' — {}", name, blocked.join("; "));
        std::process::exit(1);
    }
    println!("[ok] '{}' sin coincidencias de malware.", name);
    Ok(())
}

fn cmd_status() -> Result<()> {
    match send_request(&Request::Ping) {
        Ok(Response::Pong { version }) => {
            match crate::daemon::daemon_pid() {
                Some(pid) => println!("daemon activo (pid {}, v{})", pid, version),
                None => println!("daemon activo (v{}, sin pidfile)", version),
            }
        }
        Ok(Response::Error { message }) => println!("daemon respondió error: {}", message),
        Err(e) => println!("daemon no activo ({})", e),
        _ => println!("daemon no activo"),
    }
    Ok(())
}

fn cmd_stop() -> Result<()> {
    if !ping() {
        println!("daemon no activo");
        return Ok(());
    }
    if shutdown_daemon(None) {
        println!("daemon detenido");
    } else {
        println!("daemon no se pudo detener (pid inválido o no pertenece a aur-guard)");
    }
    Ok(())
}

fn cmd_shell_hook() -> Result<()> {
    println!("{}", shell::install_hook()?);
    Ok(())
}

fn print_report(r: &audit::Report) {
    println!("== ESCANEO DEL SISTEMA ==");
    println!(
        "[+] {} paquetes instalados revisados ({} de AUR)",
        r.scanned_installed,
        r.foreign_installed.len()
    );

    println!("\n== PAQUETES INFECTADOS INSTALADOS ==");
    if r.infected.is_empty() {
        println!("  sin coincidencias");
    } else {
        for v in &r.infected {
            println!("  [CRIT] {} [{}]", v.name, v.combined_reasons().join(", "));
        }
    }

    println!("\n== PROCESOS SOSPECHOSOS ==");
    if r.processes.is_empty() {
        println!("  sin anomalias");
    } else {
        for f in &r.processes {
            println!("  [{}] {}", f.severity.to_uppercase(), f.message);
        }
    }

    println!("\n== PERSISTENCIA / AUTORUN ==");
    if r.persistence.is_empty() {
        println!("  sin anomalias");
    } else {
        for f in &r.persistence {
            println!("  [{}] {}", f.severity.to_uppercase(), f.message);
        }
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pkgbuild_split_packages() {
        let text = "pkgbase=foo\npkgname=('foo' 'foo-bar')\n";
        let names = parse_pkgbuild_names(text);
        assert_eq!(names[0], "foo");
        assert!(names.contains(&"foo-bar".to_string()));
    }

    #[test]
    fn parse_pkgbuild_single_and_quotes() {
        let text = "pkgname=\"mypkg\"\n";
        assert_eq!(parse_pkgbuild_names(text), vec!["mypkg".to_string()]);
    }

    #[test]
    fn parse_pkgbuild_empty() {
        assert!(parse_pkgbuild_names("").is_empty());
    }

    #[test]
    fn parse_pkgbuild_multiline_array() {
        let text = "pkgbase=foo\npkgname=(\n  'foo'\n  'foo-bar'\n)\n";
        let names = parse_pkgbuild_names(text);
        assert!(names.contains(&"foo".to_string()));
        assert!(names.contains(&"foo-bar".to_string()));
    }
}
