#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetSpector - Generador de informes de auditoría de seguridad.
(Ejecutable principal / lanzador compatible)
https://github.com/tokaiteio1993-1988/NetSpector
"""
import sys
from pathlib import Path

directorio = Path(__file__).resolve().parent
if str(directorio) not in sys.path:
    sys.path.insert(0, str(directorio))

try:
    from netspector import main
except ImportError as e:
    sys.exit(f"Error cargando netspector: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operación cancelada por el usuario.", file=sys.stderr)
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as e:
        print(f"\n[!] Error crítico en NetSpector: {e}", file=sys.stderr)
        sys.exit(1)
