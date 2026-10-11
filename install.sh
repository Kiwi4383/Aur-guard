#!/usr/bin/env bash
# Instalador de aur-guard para Arch Linux (y derivadas).
# Uso:
#   ./install.sh              # interactivo: pregunta antes de cada paso opcional
#   ./install.sh --yes        # no interactivo: instala todo (binario, hook paru,
#                             # gancho shell y timer systemd)
#   ./install.sh --no-shell-hook --no-timer   # solo binario + hook de paru
set -euo pipefail

YES=0
SHELL_HOOK=1
TIMER=1

for arg in "$@"; do
  case "$arg" in
    --yes) YES=1 ;;
    --no-shell-hook) SHELL_HOOK=0 ;;
    --no-timer) TIMER=0 ;;
    -h|--help)
      sed -n '2,9p' "$0"
      exit 0
      ;;
    *)
      echo "flag desconocido: $arg (usa --help)" >&2
      exit 1
      ;;
  esac
done

ask() {
  local prompt="$1"
  if [[ "$YES" -eq 1 ]]; then
    return 0
  fi
  local ans
  read -r -p "$prompt [S/n] " ans
  [[ "$ans" =~ ^([Nn]|[Nn][Oo])$ ]] && return 1 || return 0
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "falta '$1'. Instalalo con: sudo pacman -S $2" >&2
    exit 1
  }
}

cd "$(dirname "$0")"

echo "==> comprobando dependencias"
need cargo rust
need pkg-config pkg-config
need openssl openssl
command -v paru >/dev/null 2>&1 || echo "aviso: 'paru' no encontrado; el gancho de compilacion se instalara igual cuando lo tengas."

echo "==> compilando (release)"
cargo build --release --locked

echo "==> instalando binario y unidades systemd (pide sudo)"
sudo install -Dm755 target/release/aur-guard /usr/bin/aur-guard
sudo install -Dm644 packaging/aur-guard-check.service /usr/lib/systemd/user/aur-guard-check.service
sudo install -Dm644 packaging/aur-guard-check.timer /usr/lib/systemd/user/aur-guard-check.timer
systemctl --user daemon-reload

echo "==> instalando gancho de paru"
aur-guard install

if [[ "$SHELL_HOOK" -eq 1 ]]; then
  if ask "instalar el envoltorio 'paru' en tu shell (~/.bashrc/.zshrc/config.fish)?"; then
    aur-guard shell-hook
  fi
fi

if [[ "$TIMER" -eq 1 ]]; then
  if ask "activar el chequeo automatico cada hora (systemd --user)?"; then
    systemctl --user enable --now aur-guard-check.timer
  fi
fi

echo
echo "listo. Comprobalo con: aur-guard status && aur-guard scan"
