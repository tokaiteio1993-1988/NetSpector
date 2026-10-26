#!/usr/bin/env bash
# NetSpector - Script de instalación
# Repositorio oficial: https://github.com/tokaiteio1993-1988/NetSpector
# Instala NetSpector como el comando de sistema "netspector".
#   ./install.sh               -> instala para tu usuario (~/.local/bin)
#   sudo ./install.sh --system -> instala para todo el sistema (/usr/local/bin)
#   ./install.sh --uninstall   -> desinstala NetSpector
set -euo pipefail

NOMBRE="netspector"
ORIGEN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/netspector.py"
MODO="user"; ACCION="install"

for a in "$@"; do
  case "$a" in
    --system) MODO="system" ;;
    --uninstall) ACCION="uninstall" ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "[NetSpector] Opción desconocida: $a"; exit 1 ;;
  esac
done

if [ "$MODO" = "system" ]; then DESTINO_DIR="/usr/local/bin"; else DESTINO_DIR="$HOME/.local/bin"; fi
DESTINO="$DESTINO_DIR/$NOMBRE"

if [ "$ACCION" = "uninstall" ]; then
  rm -f "$DESTINO" && echo "[NetSpector] Desinstalado con éxito: $DESTINO"
  exit 0
fi

command -v python3 >/dev/null 2>&1 || { echo "[NetSpector] Error: se necesita python3 (sudo apt install python3)"; exit 1; }
[ -f "$ORIGEN" ] || { echo "[NetSpector] Error: no encuentro netspector.py junto a install.sh"; exit 1; }

mkdir -p "$DESTINO_DIR"
install -m 755 "$ORIGEN" "$DESTINO"
echo "[NetSpector] Instalado correctamente: $DESTINO"

# Asegurar que el directorio está en el PATH (solo instalación de usuario)
if [ "$MODO" = "user" ] && [[ ":$PATH:" != *":$DESTINO_DIR:"* ]]; then
  LINEA='export PATH="$HOME/.local/bin:$PATH"'
  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [ -f "$rc" ] && ! grep -qF "$LINEA" "$rc" && echo "$LINEA" >> "$rc" && echo "[NetSpector] PATH añadido a $rc"
  done
  echo "[NetSpector] Abre una terminal nueva (o ejecuta: source ~/.bashrc) para usar '$NOMBRE'."
fi

echo "[NetSpector] Comprueba la instalación ejecutando: $NOMBRE --help"
