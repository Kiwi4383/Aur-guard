# aur-guard

Monitor de malware de AUR + auditoria de host escrito en Rust.

Te avisa y **bloquea** la instalacion de paquetes AUR comprometidos, usando
como fuente de verdad listas publicas de malware (por defecto
[`lenucksi/aur-malware-check`](https://github.com/lenucksi/aur-malware-check)).
Sin LLM, sin "scoring": si el paquete esta en el feed, se marca como malware.

Todo corre bajo un **daemon efímero**: cada comando lo despierta sobre un
socket Unix, hace su trabajo y se mata solo (auto-cierra a los 3 s inactivos
o 5 min de vida).

## Que revisa para saber si algo esta infectado

Por defecto se consulta el repositorio **`lenucksi/aur-malware-check`**:

    https://raw.githubusercontent.com/lenucksi/aur-malware-check/master

Ahi se lee el indice `data/campaigns.json` (campañas de tipo `aur`) y,
para cada campana, sus listas de paquetes y `refresh_url`. Incluye
campañas como `aur-infected` (~2000 paquetes, p. ej. `alvr`), `chaos-rat`
y `russian-spam`. Cualquier paquete listado se considera malware.

Se pueden añadir mas listas en `~/.config/aur-guard/config.toml`:

```toml
[[feeds]]
name = "mi-lista"
kind = "plain"
url = "https://example.com/pkgs.txt"   # un paquete por linea, # = comentario
enabled = true
```

## Comandos

| Comando | Que hace |
| --- | --- |
| `aur-guard install [paquete ...]` | Comprueba `paquete` contra el feed; si es malware, **lo bloquea** (exit 1). Ademas instala el gancho `PreBuildCommand` de paru. |
| `aur-guard check` | Despierta el daemon, refresca los feeds, registra cambios y avisa (notify-send + log). |
| `aur-guard scan` | Audita el host: paquetes instalados infectados, procesos corriendo, persistencia (systemd, cron, authorized_keys, ...). |
| `aur-guard gate` | Gancho interno de paru; bloquea antes de compilar un paquete comprometido. |
| `aur-guard shell-hook` | Anade a `~/.bashrc`/`~/.zshrc` una funcion `paru` que comprueba ANTES de instalar. |
| `aur-guard status` | Muestra si el daemon esta activo. |
| `aur-guard stop` | Detiene el daemon. |

## Uso

```bash
# Instalar / comprobar un paquete antes de instalarlo
aur-guard install foo

# Shell hook: al escribir paru -S foo, aur-guard revisa primero
aur-guard shell-hook   # luego abre terminal nueva

# Auditoria periodica (opcional, con systemd)
systemctl --user enable --now aur-guard-check.timer
```

## Instalacion (para tu amigo)

Desde fuentes del repo:

```bash
git clone https://github.com/pansususu/Aur-Guard aur-guard
cd aur-guard
./packaging/mktarball.sh            # genera el tarball fuente
cd packaging && makepkg -si        # compila + instala (pide sudo)
aur-guard shell-hook                # activa el wrapper de paru
```

O directamente con cargo:

```bash
cargo b --release
sudo install -Dm755 target/release/aur-guard /usr/bin/aur-guard
aur-guard shell-hook
```

## Configuracion

En `~/.config/aur-guard/config.toml` (se genera automaticamente):

```toml
cache_ttl_secs = 3600   # TTL del cache de feeds
recent_days = 30        # unidades "modificadas recientemente" en el escaneo
notify = true           # alertas con notify-send
log_stderr = true       # escribir alertas en stderr (el log a fichero siempre se escribe)
```

## Licencia

GPL-3.0-or-later. Ver [LICENSE](LICENSE).