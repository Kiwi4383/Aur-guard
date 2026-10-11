use std::fs;
use std::process::Command;

use crate::config::{now_epoch_secs, state_dir, Config};

const MAX_LOG_BYTES: u64 = 1 << 20;

fn rotate_if_needed(path: &std::path::Path) {
    if std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) > MAX_LOG_BYTES {
        let bak = path.with_extension("log.1");
        let _ = std::fs::rename(path, bak);
    }
}

fn log_line(level: &str, msg: &str) {
    let dir = state_dir();
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("aur-guard.log");
    // Fail-closed ante symlink plantado: no anexar a archivos arbitrarios.
    if crate::config::reject_symlink(&path).is_err() {
        eprintln!("aur-guard: log es symlink, no se escribe");
        return;
    }
    rotate_if_needed(&path);
    let ts = now_epoch_secs();
    let _ = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| {
            use std::io::Write;
            f.write_fmt(format_args!("[{}][{}] {}\n", ts, level, msg))
        });
}

pub fn notify(cfg: &Config, title: &str, body: &str) {
    // Sanitizar: el body puede incluir ids del feed remoto.
    let title = title.replace('\n', " ");
    let body = body.replace('\n', " ");
    log_line("ALERTA", &format!("{} — {}", title, body));
    if cfg.log_stderr {
        eprintln!("aur-guard: {} — {}", title, body);
    }
    if cfg.notify {
        let notify_bin = crate::audit::resolve_bin("notify-send", &["/usr/bin/notify-send", "/bin/notify-send"]);
        // Reaped en hilo aparte: spawn() sin wait deja zombies hasta que muera el daemon.
        if let Ok(mut child) = Command::new(notify_bin)
            .args([
                "--app-name=aur-guard",
                "--urgency=critical",
                "--expire-time=60000",
                &title,
                &body,
            ])
            .spawn()
        {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
}
