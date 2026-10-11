#!/usr/bin/env bash
# Genera un directorio de paquete a partir de la fuente local y el PKGBUILD.
# Uso:
#   ./packaging/mktarball.sh            # genera /tmp/aur-guard-pkg
#   cd /tmp/aur-guard-pkg && makepkg -i
set -euo pipefail

cd "$(dirname "$0")/.."
PKGVER="$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
PKGNAME="$(grep -m1 '^name' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
SRC="aur-guard-$PKGVER"

# Asegura Cargo.lock para --locked
cargo metadata --offline >/dev/null 2>&1 || true

DEST="/tmp/aur-guard-pkg"
mkdir -p "$DEST"
# --transform anade el directorio superior $SRC/ para el layout estandar de makepkg
tar -czf "$DEST/$SRC.tar.gz" \
  --transform "s,^,$SRC/," \
  --exclude target --exclude .git \
  Cargo.toml Cargo.lock LICENSE README.md src packaging
cp packaging/PKGBUILD "$DEST/PKGBUILD"

echo "Listo. Paquete '$PKGNAME' ver '$PKGVER':"
echo "  cd $DEST && makepkg -i"