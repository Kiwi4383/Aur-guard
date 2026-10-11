# aur-guard

Monitor de malware para el AUR + auditoría del host, escrito en Rust.

`aur-guard` te avisa y **bloquea** la instalación de paquetes AUR comprometidos usando como fuente de verdad listas públicas de malware. Sin LLM, sin *scoring*: si el paquete está en la lista, se trata como malware.

> 🇪🇸 Documentación en español abajo. *English version below.*

---

## Español

### Características

- **Bloqueo pre-instalación**: revisa cada paquete contra el feed antes de compilar o instalar.
- **Triple capa de protección**: gancho `PreBuildCommand` de `paru`, función envoltorio `paru` en tu shell y chequeo manual con `install`.
- **Escaneo de IOCs**: detecta patrones sospechosos (`curl … | sh`, `eval $(…)`, reverse shells, persistencia) en el `PKGBUILD` antes de compilar.
- **Auditoría del host**: detecta paquetes infectados ya instalados, procesos sospechosos y mecanismos de persistencia (systemd, cron, autostart, `authorized_keys`…).
- **Alertas**: notificaciones de escritorio (`notify-send`) + registro en log.
- **Daemon efímero**: sin servicio permanente; cada comando levanta el daemon, hace su trabajo y lo apaga solo.

### Cómo funciona

1. **Feed de malware**: por defecto se consulta [`lenucksi/aur-malware-check`](https://github.com/lenucksi/aur-malware-check) (índice `data/campaigns.json`, campañas tipo `aur` como `aur-infected`, `chaos-rat` y `russian-spam`). Se pueden agregar listas propias.
2. **Tres capas de bloqueo**:
   - `aur-guard install <paquete…>` — chequeo manual antes de instalar.
   - Gancho de `paru` (`PreBuildCommand = aur-guard gate` en `paru.conf`) — `aur-guard gate` corre antes de cada compilación y sale con código 1 si el paquete es malware.
   - Función `paru` en tu shell (`aur-guard shell-hook`) — intercepta `paru -S`, `-Sy`, `-Su`, `-Syu` y chequea primero.
3. **Daemon efímero**: la comunicación va por un socket Unix con JSON; el daemon muere solo tras 3 s inactivo o 5 min de vida. No hay nada corriendo en segundo plano entre comandos.

### Requisitos

- Arch Linux (o derivada) con `pacman`.
- `paru` para la protección automática en compilaciones.
- Opcional: `libnotify` (`notify-send`) para alertas de escritorio, `iproute2` (`ss`) para detección de puertos, `iptables` para auditoría de firewall.
- Rust ≥ 1.75 solo si compilas desde fuente.

### Instalación

La forma más simple:

```bash
git clone https://github.com/Kiwi4383/Aur-guard aur-guard
cd aur-guard
./install.sh              # interactivo
./install.sh --yes        # instala todo sin preguntar
```

O empaquetado desde el repo (incluye unidades systemd):

```bash
git clone https://github.com/Kiwi4383/Aur-guard aur-guard
cd aur-guard
./packaging/mktarball.sh            # genera el tarball fuente
cd /tmp/aur-guard-pkg && makepkg -si
```

O directamente con cargo (necesitas `rust`, `cargo`, `openssl` y `pkg-config`):

```bash
cargo build --release
sudo install -Dm755 target/release/aur-guard /usr/bin/aur-guard
```

### Inicio rápido

```bash
# 1. Instalar el gancho de paru + revisar un paquete
aur-guard install <paquete>

# 2. Activar el envoltorio de shell (nueva terminal para que aplique)
aur-guard shell-hook

# 3. Auditoría puntual del sistema
aur-guard scan

# 4. Chequeo periódico automático (cada hora)
systemctl --user enable --now aur-guard-check.timer
```

### Comandos

| Comando | Qué hace |
| --- | --- |
| `aur-guard install [paquete …]` | Asegura el gancho de `paru` y chequea los paquetes contra el feed. Sin paquetes, solo deja listo el gancho. Bloquea (exit 1) si hay malware. |
| `aur-guard check` | Refresca los feeds, registra paquetes nuevos marcados como malware y avisa (alerta especial si ya está instalado). |
| `aur-guard scan` | Audita el host: instalados infectados, procesos sospechosos, persistencia. |
| `aur-guard gate` | Gancho interno de `paru`; se ejecuta solo antes de compilar. |
| `aur-guard shell-hook` | Instala la función `paru` en `~/.bashrc`, `~/.zshrc` o `config.fish`. |
| `aur-guard status` | Muestra si el daemon está activo. |
| `aur-guard stop` | Detiene el daemon. |

### Configuración

Archivo `~/.config/aur-guard/config.toml` (se genera solo en la primera ejecución):

```toml
cache_ttl_secs = 3600   # TTL de la caché de feeds (segundos)
recent_days = 30        # ventana de "modificado recientemente" en la auditoría
notify = true           # alertas con notify-send
log_stderr = true       # alertas en stderr (el log a fichero siempre se escribe)

# Agregar una lista propia (un paquete por línea, # = comentario, solo https)
[[feeds]]
name = "mi-lista"
kind = "plain"
url = "https://example.com/pkgs.txt"
enabled = true
```

Rutas usadas:

| Qué | Dónde |
| --- | --- |
| Configuración | `~/.config/aur-guard/config.toml` |
| Estado, caché y log | `~/.local/state/aur-guard/` |
| Socket del daemon | `$XDG_RUNTIME_DIR/aur-guard.sock` |

### Automatización

El paquete instala un timer systemd de usuario que corre `aur-guard check` cada hora (y 10 min tras arrancar):

```bash
systemctl --user enable --now aur-guard-check.timer
systemctl --user status aur-guard-check.timer
```

### Desinstalación

```bash
# 1. Apagar automatización y daemon
systemctl --user disable --now aur-guard-check.timer
aur-guard stop

# 2. Quitar el gancho de paru (~/.config/paru/paru.conf)
#    Borra la línea: PreBuildCommand = aur-guard gate

# 3. Quitar la función paru de tu shell
#    Borra el bloque marcado con "aur-guard: paru wrapper" en
#    ~/.bashrc, ~/.zshrc o ~/.config/fish/config.fish
```

### Desarrollo

```bash
cargo build
cargo clippy --all-targets   # cero warnings
cargo test                   # 41 tests
```

Los tests viven junto al código (`mod tests` en cada módulo) y cada helper puro tiene el suyo. Ver `AGENTS.md` para las convenciones del proyecto.

### Licencia

0BSD (BSD Zero Clause License). Ver [LICENSE](LICENSE).

---

## English

### Features

- **Pre-install blocking**: checks every package against the feed before building or installing.
- **Triple protection layer**: `paru` `PreBuildCommand` hook, `paru` shell wrapper function, and manual checks via `install`.
- **IOC scanning**: detects suspicious patterns (`curl … | sh`, `eval $(…)`, reverse shells, persistence) in the `PKGBUILD` before building.
- **Host auditing**: finds already-installed infected packages, suspicious processes, and persistence mechanisms (systemd, cron, autostart, `authorized_keys`, …).
- **Alerts**: desktop notifications (`notify-send`) + log file.
- **Ephemeral daemon**: no permanent service; each command wakes the daemon, gets the work done, and shuts it down.

### How it works

1. **Malware feed**: by default it queries [`lenucksi/aur-malware-check`](https://github.com/lenucksi/aur-malware-check) (`data/campaigns.json` index, `aur`-type campaigns such as `aur-infected`, `chaos-rat`, and `russian-spam`). You can add your own lists.
2. **Three blocking layers**:
   - `aur-guard install <package…>` — manual check before installing.
   - `paru` hook (`PreBuildCommand = aur-guard gate` in `paru.conf`) — `aur-guard gate` runs before every build and exits 1 on malware.
   - Shell `paru` function (`aur-guard shell-hook`) — intercepts `paru -S`, `-Sy`, `-Su`, `-Syu` and checks first.
3. **Ephemeral daemon**: communication goes over a Unix socket with JSON; the daemon exits on its own after 3 s idle or 5 min lifetime. Nothing runs in the background between commands.

### Requirements

- Arch Linux (or derivative) with `pacman`.
- `paru` for automatic build-time protection.
- Optional: `libnotify` (`notify-send`) for desktop alerts, `iproute2` (`ss`) for listening-port detection, `iptables` for firewall auditing.
- Rust ≥ 1.75 only if building from source.

### Installation

The easiest way:

```bash
git clone https://github.com/Kiwi4383/Aur-guard aur-guard
cd aur-guard
./install.sh              # interactive
./install.sh --yes        # installs everything without asking
```

Or packaged from the repo (includes systemd units):

```bash
git clone https://github.com/Kiwi4383/Aur-guard aur-guard
cd aur-guard
./packaging/mktarball.sh            # builds the source tarball
cd /tmp/aur-guard-pkg && makepkg -si
```

Or directly with cargo (you need `rust`, `cargo`, `openssl`, and `pkg-config`):

```bash
cargo build --release
sudo install -Dm755 target/release/aur-guard /usr/bin/aur-guard
```

### Quickstart

```bash
# 1. Install the paru hook + check a package
aur-guard install <package>

# 2. Enable the shell wrapper (open a new terminal afterwards)
aur-guard shell-hook

# 3. One-shot system audit
aur-guard scan

# 4. Automatic periodic checks (hourly)
systemctl --user enable --now aur-guard-check.timer
```

### Commands

| Command | What it does |
| --- | --- |
| `aur-guard install [package …]` | Ensures the `paru` hook and checks packages against the feed. With no packages, it only sets up the hook. Blocks (exit 1) on malware. |
| `aur-guard check` | Refreshes feeds, records newly flagged packages, and alerts (extra warning if already installed). |
| `aur-guard scan` | Audits the host: infected installed packages, suspicious processes, persistence. |
| `aur-guard gate` | Internal `paru` hook; runs before each build. |
| `aur-guard shell-hook` | Installs the `paru` function into `~/.bashrc`, `~/.zshrc`, or `config.fish`. |
| `aur-guard status` | Shows whether the daemon is running. |
| `aur-guard stop` | Stops the daemon. |

### Configuration

File `~/.config/aur-guard/config.toml` (auto-created on first run):

```toml
cache_ttl_secs = 3600   # feed cache TTL (seconds)
recent_days = 30        # "recently modified" window for the audit
notify = true           # notify-send alerts
log_stderr = true       # stderr alerts (file log is always written)

# Add your own list (one package per line, # = comment, https only)
[[feeds]]
name = "my-list"
kind = "plain"
url = "https://example.com/pkgs.txt"
enabled = true
```

Paths used:

| What | Where |
| --- | --- |
| Configuration | `~/.config/aur-guard/config.toml` |
| State, cache, and log | `~/.local/state/aur-guard/` |
| Daemon socket | `$XDG_RUNTIME_DIR/aur-guard.sock` |

### Automation

The package ships a user systemd timer running `aur-guard check` hourly (and 10 min after boot):

```bash
systemctl --user enable --now aur-guard-check.timer
systemctl --user status aur-guard-check.timer
```

### Uninstallation

```bash
# 1. Stop automation and daemon
systemctl --user disable --now aur-guard-check.timer
aur-guard stop

# 2. Remove the paru hook (~/.config/paru/paru.conf)
#    Delete the line: PreBuildCommand = aur-guard gate

# 3. Remove the paru function from your shell
#    Delete the block marked "aur-guard: paru wrapper" in
#    ~/.bashrc, ~/.zshrc, or ~/.config/fish/config.fish
```

### Development

```bash
cargo build
cargo clippy --all-targets   # zero warnings
cargo test                   # 41 tests
```

Tests live next to the code (`mod tests` in each module) and every pure helper has its own. See `AGENTS.md` for project conventions.

### License

0BSD (BSD Zero Clause License). See [LICENSE](LICENSE).
