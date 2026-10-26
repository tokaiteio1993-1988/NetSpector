#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetSpector - Generador automatizado de informes de auditoría de seguridad y análisis de red.
Formato oficial conforme a la plantilla de auditoría técnica (Secciones 1 a 10).

USO MEDIANTE PARÁMETROS:
    python netspector.py -d <carpeta> -e <salida.html> -a <auditor> -f -n <nombre_auditoria> -c <codigo_informe>

PARÁMETROS SOPORTADOS:
    -d, --directorio    Carpeta donde trabajar y buscar los ficheros .txt
    -e, --salida        Nombre del HTML o ruta completa donde guardarlo
    -a, --auditor       Nombre del auditor
    -f, --fecha         Pone automáticamente la fecha de hoy en todos los campos de fecha (o la fecha indicada)
    -n, --nombre        Nombre o título de la auditoría
    -c, -i, --codigo    Código o número de informe (si no se indica, genera AUD-YYYY-MM-DD-0 auto-incremental)
    -v, --verbose       Modo detallado (muestra el proceso paso a paso)
    --version           Muestra la versión instalada de NetSpector
    -update, --update   Actualiza NetSpector desde el repositorio de GitHub
"""
import argparse
import html
import os
import re
import subprocess
import sys
import unicodedata
from datetime import datetime
from pathlib import Path

VERSION = "2.2.0"
GITHUB_REPO_URL = "https://github.com/tokaiteio1993-1988/NetSpector"
ND = "No verificado"
RESERVADOS = {"general.txt", "hallazgos.txt", "controles.txt", "herramientas.txt", "servicios.txt"}
MAX_ANEXO = 300_000


# ----------------------------------------------------------------- Utilidades
def obtener_logo_data_uri(nombre="1_logo_principal_fondo_oscuro.png"):
    """
    Localiza el archivo de imagen especificado en la carpeta Logo/ (o raíz) del script o de trabajo
    y devuelve un Data URI en Base64 para que los informes HTML generados sean
    100% autónomos y portables (sin depender de rutas externas ni romperse al moverlos).
    """
    candidatos = [
        Path(__file__).resolve().parent / "Logo" / nombre,
        Path(__file__).resolve().parent / nombre,
        Path.cwd() / "Logo" / nombre,
        Path.cwd() / nombre,
        Path(__file__).resolve().parent / "Logo.png",
        Path.cwd() / "Logo.png",
    ]
    for p in candidatos:
        if p.exists() and p.is_file():
            try:
                import base64
                datos = base64.b64encode(p.read_bytes()).decode("ascii")
                ext = p.suffix.lstrip(".").lower()
                mime = "image/png" if ext == "png" else f"image/{ext}"
                return f"data:{mime};base64,{datos}"
            except Exception:
                return f"Logo/{nombre}"
    return f"Logo/{nombre}"


def esc(s):
    return html.escape(str(s if s not in (None, "") else ND))


def norm(s):
    if not s:
        return ""
    s = unicodedata.normalize("NFD", str(s))
    s = "".join(c for c in s if unicodedata.category(c) != "Mn")
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def leer(path):
    p = Path(path)
    if not p.exists() or not p.is_file():
        return ""
    for enc in ("utf-8-sig", "utf-8", "utf-16", "latin-1", "cp1252"):
        try:
            return p.read_text(encoding=enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
        except PermissionError:
            print(f"[!] Advertencia: Sin permisos de lectura en '{p.name}'.", file=sys.stderr)
            return ""
        except OSError as e:
            print(f"[!] Advertencia: Error del sistema al leer '{p.name}': {e}", file=sys.stderr)
            return ""
    return ""


def parse_kv(texto):
    """Parsea líneas clave: valor con soporte para multilinea indentada."""
    d, ultima = {}, None
    for linea in texto.splitlines():
        if not linea.strip() or linea.lstrip().startswith("#"):
            continue
        m = re.match(r"^([^\s:][^:]{0,60}):\s*(.*)$", linea)
        if m and not linea.startswith((" ", "\t")):
            ultima = norm(m.group(1))
            d[ultima] = m.group(2).strip()
        elif ultima:
            d[ultima] += "\n" + linea.strip()
    return d


def parse_bloques(texto):
    """Parsea bloques separados por líneas ---."""
    bloques = re.split(r"^\s*-{3,}\s*$", texto, flags=re.M)
    return [b for b in (parse_kv(x) for x in bloques) if b]


def parse_tabla(texto, n):
    filas = []
    for l in texto.splitlines():
        if not l.strip() or l.lstrip().startswith("#"):
            continue
        partes = [p.strip() for p in l.split("|")]
        partes += [""] * (n - len(partes))
        filas.append(partes[:n])
    return filas


def parse_controles(texto):
    secciones, actual = [], None
    for l in texto.splitlines():
        if not l.strip() or l.lstrip().startswith("#"):
            continue
        m = re.match(r"^\s*\[(.+)\]\s*$", l)
        if m:
            actual = {"titulo": m.group(1).strip(), "filas": []}
            secciones.append(actual)
        elif actual is not None:
            p = [x.strip() for x in l.split("|")]
            p += [""] * (4 - len(p))
            actual["filas"].append(p[:4])
    return secciones


# ------------------------------------------------------- Parseo de Nmap y SS
def parse_nmap(texto):
    ports = {}
    for l in texto.splitlines():
        m = re.match(r"^(\d+)/(tcp|udp)\s+(open\S*)\s+(\S+)\s*(.*)$", l.strip())
        if m:
            puerto, proto, _, servicio, version = m.groups()
            ports[(int(puerto), proto.lower())] = {
                "servicio": servicio,
                "version": version.strip(),
            }
    return ports


def parse_ss(texto):
    res = {}
    for l in texto.splitlines():
        if not re.search(r"LISTEN|UNCONN|^udp", l, flags=re.I):
            continue
        toks = l.split()
        if not toks or toks[0].lower() not in ("tcp", "tcp6", "udp", "udp6", "tcp4", "udp4"):
            continue
        proto = "udp" if toks[0].lower().startswith("udp") else "tcp"
        direcciones = [t for t in toks[1:] if re.match(r"^\S*:(\d+|\*)$", t)]
        if not direcciones:
            continue
        local = direcciones[0]
        dir_, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        proc = ""
        m = re.search(r'users:\(\("([^"]+)"', l) or re.search(r"\d+/(\S+)\s*$", l)
        if m:
            proc = m.group(1)
        res[(int(port), proto)] = {"bind": dir_.strip("[]") or "*", "proceso": proc}
    return res


def accesible(bind):
    if bind in ("127.0.0.1", "::1", "localhost"):
        return "Solo localhost"
    return "Red local"


def construir_inventario(nmaps, sss, extra):
    claves = set(nmaps) | set(sss)
    filas = []
    for k in sorted(claves, key=lambda x: x[0]):
        n, s = nmaps.get(k, {}), sss.get(k, {})
        e = extra.get(f"{k[0]}/{k[1]}", {})
        servicio = n.get("servicio", ND)
        software = n.get("version") or ND
        proceso = s.get("proceso") or (f"{servicio}/root" if servicio != ND else ND)
        filas.append({
            "puerto": f"{k[0]}/{k[1]}",
            "servicio": servicio,
            "software": software,
            "proceso": proceso,
            "acceso": accesible(s["bind"]) if s else "Red local",
            "necesario": e.get("necesario", ND),
            "obs": e.get("obs", (f"Servicio {servicio} detectado." if servicio != ND else "")),
        })
    return filas


# ---------------------------------------------------------------- Severidades
def sev_norm(s):
    t = norm(s or "")
    for clave, nombre in (("critic", "Crítica"), ("alta", "Alta"), ("media", "Media"),
                          ("baja", "Baja"), ("inform", "Informativa")):
        if t.startswith(clave):
            return nombre
    return "Por valorar"


def clase_sev(nombre):
    return {
        "Crítica": "badge-critica",
        "Alta": "badge-alta",
        "Media": "badge-media",
        "Baja": "badge-baja",
        "Informativa": "badge-informativa",
    }.get(nombre, "badge-nd")


def clase_estado(e):
    t = norm(e or "")
    if t.startswith("no_cumple") or t in ("fallo", "ko"):
        return "badge-no-cumple"
    if t.startswith("cumple") or t in ("ok", "correcto"):
        return "badge-cumple"
    if t in ("stopped", "parcial", "revision", "verificado"):
        return "badge-stopped"
    return "badge-nd"


# ------------------------------------------------ Auto-detección en ficheros TXT
def autodetectar_ficheros(carpeta, verbose=False):
    """Escanea la carpeta en busca de evidencias en texto y extrae metadatos."""
    info_extra = {}
    nmaps = {}
    sss = {}
    anexos = []

    if verbose:
        print(f"[*] [Verbose] Explorando carpeta de evidencias: {carpeta}")

    try:
        ficheros = sorted(carpeta.iterdir())
    except PermissionError:
        print(f"[!] Error de permisos: No se tiene acceso para listar la carpeta '{carpeta}'.", file=sys.stderr)
        return info_extra, nmaps, sss, anexos
    except OSError as e:
        print(f"[!] Error del sistema al acceder a la carpeta '{carpeta}': {e}", file=sys.stderr)
        return info_extra, nmaps, sss, anexos

    for f in ficheros:
        if not f.is_file() or f.name.lower() in RESERVADOS or f.suffix.lower() not in (".txt", ".log", ".md", ".out"):
            continue
        if f.name.lower() == "informe.html":
            continue

        txt = leer(f)
        if not txt:
            continue

        n = f.name.lower()
        if verbose:
            print(f"    -> Analizando archivo: {f.name} ({len(txt)} caracteres)")

        # Nmap
        if "nmap" in n or "Nmap scan report" in txt or "PORT   STATE SERVICE" in txt:
            detected_ports = parse_nmap(txt)
            nmaps.update(detected_ports)
            if verbose:
                print(f"       [+] Detectados {len(detected_ports)} puertos abiertos por Nmap.")
            m_host = re.search(r"Nmap scan report for (?:([^\s()]+)\s+\(([\d.]+)\)|([\d.]+)|([^\s()]+))", txt)
            if m_host:
                info_extra.setdefault("host", m_host.group(1) or m_host.group(4) or m_host.group(3))
                if m_host.group(2) or m_host.group(3):
                    ip = m_host.group(2) or m_host.group(3)
                    m_mac = re.search(r"MAC Address:\s*([0-9A-Fa-f:]+)", txt)
                    info_extra.setdefault("ip_mac", f"{ip} / {m_mac.group(1)}" if m_mac else ip)
            m_os = re.search(r"(?:OS details|Running|Service Info: OS):\s*([^\r\n]+)", txt)
            if m_os:
                info_extra.setdefault("so", m_os.group(1).strip())

        # ss / netstat
        elif "ss" in n or "netstat" in n or "Local Address:Port" in txt or ("LISTEN" in txt and "tcp" in txt):
            detected_sockets = parse_ss(txt)
            sss.update(detected_sockets)
            if verbose:
                print(f"       [+] Detectados {len(detected_sockets)} sockets escuchando por ss/netstat.")

        # hostname / uname
        elif "hostname" in n or "uname" in n or "os-release" in n or "issue" in n:
            if "GNU/Linux" in txt or "Linux " in txt:
                info_extra.setdefault("kernel", txt.strip().splitlines()[0])
            m_dist = re.search(r"(Ubuntu|Debian|CentOS|Red Hat|Fedora|Arch|Windows)[^\n\r\"]*", txt, re.I)
            if m_dist:
                info_extra.setdefault("so", m_dist.group(0).strip())
            if verbose:
                print(f"       [+] Metadatos del sistema identificados en {f.name}.")

        # Registro en Anexos
        relacion = "Sección 4 y 5"
        if "nmap" in n:
            relacion = "Sección 4 (Inventario de servicios)"
        elif "ss" in n or "netstat" in n:
            relacion = "Sección 4 y 5.2"
        elif "find" in n or "perm" in n:
            relacion = "Sección 5.3 y Permisos de ficheros"

        anexos.append((f.name, txt, relacion))

    return info_extra, nmaps, sss, anexos


# ------------------------------------------- Cálculo de código de informe único
def calcular_codigo_informe(carpeta_salida, fecha_iso, verbose=False):
    """
    Genera AUD-YYYY-MM-DD-0. Si ya existen informes generados el mismo día,
    incrementa el número secuencial: AUD-YYYY-MM-DD-1, AUD-YYYY-MM-DD-2...
    """
    prefijo = f"AUD-{fecha_iso}-"
    max_idx = -1
    p_salida = Path(carpeta_salida)
    
    if p_salida.exists():
        directorio_busqueda = p_salida if p_salida.is_dir() else p_salida.parent
        for f in directorio_busqueda.glob("*.html"):
            try:
                txt = f.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(re.escape(prefijo) + r"(\d+)", txt):
                    val = int(m.group(1))
                    if val > max_idx:
                        max_idx = val
            except Exception:
                pass
            m_name = re.search(re.escape(prefijo) + r"(\d+)", f.name)
            if m_name:
                val = int(m_name.group(1))
                if val > max_idx:
                    max_idx = val

    siguiente = max_idx + 1 if max_idx >= 0 else 0
    codigo_calculado = f"{prefijo}{siguiente}"
    if verbose:
        print(f"[*] [Verbose] Código de informe calculado automáticamente: {codigo_calculado}")
    return codigo_calculado


# ----------------------------------------------------------- Plantillas Genéricas
PLANTILLA_CONTROLES_DEFAULT = """[5.1 Cuentas y autenticación]
Acceso SSH directo como root deshabilitado | grep PermitRootLogin /etc/ssh/sshd_config | PermitRootLogin no | Cumple
Política de contraseñas (longitud, caducidad) | /etc/login.defs, /etc/security/pwquality.conf | PASS_MAX_DAYS: 90<br>PASS_MIN_DAYS: 7<br>PASS_WARN_AGE: 14 | Cumple
Cuentas sin contraseña o inactivas | awk -F: '($2==""){print $1}' /etc/shadow | Ninguna | Cumple
Usuarios con privilegios sudo | getent group sudo | Verificado | Cumple
Autenticación multifactor en acceso remoto | Revisión de PAM / VPN | No implantada | No cumple

[5.2 Red y cortafuegos]
Cortafuegos activo con política por defecto restrictiva | ufw status verbose / iptables -L | No activo | No cumple
Servicios escuchando solo donde corresponde | ss -tulpn | Verificado según inventario | Cumple
IPv6 y reenvío de paquetes controlados | sysctl net.ipv6.conf.all.disable_ipv6 net.ipv4.ip_forward | ip_forward = 0 | Cumple

[5.3 Sistema de archivos y permisos]
Permisos de ficheros sensibles (/etc/shadow, claves privadas) | ls -l /etc/shadow | 1 root shadow 1544 /etc/shadow | Cumple
Ficheros con permisos de escritura global | find / -xdev -type f -perm -0002 | Ninguno | Cumple
Particiones separadas / opciones de montaje (noexec, nosuid) | mount, /etc/fstab | No verificado | No verificado

[5.4 Actualizaciones y parches]
Sistema actualizado | apt list --upgradable / Linux Update | No verificado | No verificado
Actualizaciones automáticas de seguridad | unattended-upgrades | No verificado | No verificado

[5.5 Registro, auditoría y copias de seguridad]
Registro de eventos activo (rsyslog / journald / auditd) | systemctl status auditd | No verificado | No verificado
Logs enviados a un servidor central | /etc/rsyslog.d/ | no | No cumple
Sincronización horaria (NTP) | timedatectl | Sincronizado | Cumple
Copias de seguridad probadas | Entrevista y evidencia del último restore | No verificado | No verificado

[5.6 Servicios concretos (ejemplo: servidor web)]
Versión del servidor oculta | Curl –I IP | Expuesta | No cumple
HTTPS con TLS 1.2 o superior | nmap --script ssl-enum-ciphers -p 443 | Habilitado | Cumple
Cabeceras de seguridad (HSTS, CSP, X-FrameOptions) | curl -I https:// | Ausente | No cumple
"""

PLANTILLA_GENERAL_DEFAULT = """# 1. Datos generales del informe
titulo: Auditoría de Seguridad
codigo: 
fecha: 
auditor: 
solicitante: Departamento de Seguridad
version: V1.0 - Revisado
confidencialidad: Confidencial

# 2. Alcance y autorización
activo: Infraestructura Evaluada
fuera_de_alcance: Red de usuarios finales
tipo_de_analisis: Caja blanca
autorizacion: Autorizado

# 3. Identificación del equipo
host: 
ip_mac: 
so: 
kernel: 
tipo_de_equipo: Servidor
funcion: Servidor de infraestructura
propietario: Responsable del sistema
ultimo_arranque: 

resumen: Informe técnico de auditoría de seguridad conforme a la plantilla oficial de 10 secciones.
firma_auditor: 
"""

# ----------------------------------------------------------------- CSS Oficial
CSS = """
:root {
  --primary: #1b3a5f;
  --primary-light: #2c5282;
  --accent: #2563eb;
  --bg-page: #f8fafc;
  --bg-card: #ffffff;
  --text-main: #1e293b;
  --text-muted: #64748b;
  --border: #cbd5e1;
  --border-table: #94a3b8;
  --th-bg: #1b3a5f;
  --th-text: #ffffff;
  --td-key-bg: #f8fafc;
  --ok: #15803d;
  --ok-bg: #dcfce7;
  --bad: #b91c1c;
  --bad-bg: #fee2e2;
  --warn: #b45309;
  --warn-bg: #fef3c7;
  --nd: #475569;
  --nd-bg: #f1f5f9;
}
@media (prefers-color-scheme: dark) {
  :root {
    --primary: #0f172a;
    --primary-light: #1e293b;
    --accent: #38bdf8;
    --bg-page: #0b1120;
    --bg-card: #1e293b;
    --text-main: #f1f5f9;
    --text-muted: #94a3b8;
    --border: #334155;
    --border-table: #475569;
    --th-bg: #0f172a;
    --th-text: #ffffff;
    --td-key-bg: #172033;
    --ok: #4ade80;
    --ok-bg: #064e3b;
    --bad: #f87171;
    --bad-bg: #7f1d1d;
    --warn: #fbbf24;
    --warn-bg: #78350f;
    --nd: #94a3b8;
    --nd-bg: #334155;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 0;
  background-color: var(--bg-page);
  color: var(--text-main);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  font-size: 13.5px;
  line-height: 1.5;
}
header.brand-bar {
  background: var(--primary);
  color: #fff;
  padding: 12px 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
header.brand-bar .brand { font-weight: 700; font-size: 16px; display: flex; align-items: center; gap: 10px; }
.brand-bar-logo-wrap {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  overflow: hidden;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 1.5px solid rgba(255,255,255,0.45);
  background: #0a1118;
  vertical-align: middle;
  flex-shrink: 0;
  box-shadow: 0 1px 3px rgba(0,0,0,0.3);
}
.brand-bar-logo-wrap img {
  width: 100%;
  height: 100%;
  object-fit: contain;
  display: block;
}
header.brand-bar .actions { display: flex; gap: 10px; }
.btn-print {
  background: #fff;
  color: var(--primary);
  border: none;
  padding: 6px 14px;
  border-radius: 6px;
  font-weight: 600;
  cursor: pointer;
  font-size: 12.5px;
  text-decoration: none;
}
.btn-print:hover { background: #e2e8f0; }

main.report-wrapper {
  max-width: 1050px;
  margin: 25px auto 60px auto;
  padding: 0 20px;
}
.report-sheet {
  background: var(--bg-card);
  padding: 45px 55px;
  border-radius: 8px;
  box-shadow: 0 4px 6px -1px rgba(0,0,0,0.07);
  border: 1px solid var(--border);
}
.report-header {
  border-bottom: 2px solid var(--accent);
  padding-bottom: 20px;
  margin-bottom: 30px;
}
.report-header-flex {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 20px;
}
.report-header-text { flex: 1; }
.report-header-brand {
  max-width: 200px;
  max-height: 95px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.brand-report-logo {
  max-width: 195px;
  max-height: 90px;
  object-fit: contain;
  border-radius: 6px;
  display: block;
  transition: transform 0.2s ease;
}
.brand-report-logo:hover {
  transform: scale(1.02);
}
.report-header h1 {
  margin: 0 0 6px 0;
  font-size: 26px;
  color: var(--primary);
  font-weight: 700;
}
.report-header p {
  margin: 0;
  color: var(--text-muted);
  font-size: 14px;
}
.section { margin-bottom: 35px; }
.section-title {
  color: #1b4478;
  font-size: 17px;
  font-weight: 700;
  margin: 24px 0 12px 0;
}
.subsection-title {
  color: #2c5282;
  font-size: 14.5px;
  font-weight: 700;
  margin: 18px 0 8px 0;
}
.table-container { width: 100%; overflow-x: auto; margin-bottom: 15px; }
table.pdf-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
  background: var(--bg-card);
}
table.pdf-table th, table.pdf-table td {
  border: 1px solid var(--border-table);
  padding: 8px 12px;
  text-align: left;
  vertical-align: top;
}
table.pdf-table th {
  background-color: var(--th-bg);
  color: var(--th-text);
  font-weight: 600;
  white-space: nowrap;
}
td.campo-key {
  width: 32%;
  font-weight: 600;
  background-color: var(--td-key-bg);
}
td.campo-val {
  color: #1e3a8a;
  font-weight: 500;
}
.badge {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 9999px;
  font-size: 11.5px;
  font-weight: 600;
  white-space: nowrap;
}
.badge-cumple { background-color: var(--ok-bg); color: var(--ok); }
.badge-no-cumple { background-color: var(--bad-bg); color: var(--bad); }
.badge-stopped { background-color: var(--warn-bg); color: var(--warn); }
.badge-nd { background-color: var(--nd-bg); color: var(--nd); }

.badge-critica { background-color: #7f1d1d; color: #ffffff; }
.badge-alta { background-color: #fee2e2; color: #b91c1c; font-weight: 700; }
.badge-media { background-color: #fef3c7; color: #b45309; }
.badge-baja { background-color: #dbeafe; color: #1d4ed8; }
.badge-informativa { background-color: #f1f5f9; color: #475569; }

.vuln-card {
  margin-bottom: 22px;
  border: 1px solid var(--border-table);
  border-radius: 4px;
  overflow: hidden;
}
.vuln-card table.pdf-table { margin: 0; }
.vuln-card th { background-color: #20456e; }

details.anexo-details {
  margin: 10px 0;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg-card);
}
details.anexo-details summary {
  padding: 10px 14px;
  cursor: pointer;
  font-weight: 600;
  background: var(--td-key-bg);
}
details.anexo-details pre {
  margin: 0;
  padding: 14px;
  background: var(--bg-page);
  font-family: Consolas, monospace;
  font-size: 12px;
  overflow-x: auto;
  max-height: 400px;
  white-space: pre-wrap;
}

@media print {
  body { background: #fff !important; color: #000 !important; font-size: 10.5pt !important; }
  header.brand-bar, .no-print { display: none !important; }
  main.report-wrapper { max-width: 100% !important; margin: 0 !important; padding: 0 !important; }
  .report-sheet { box-shadow: none !important; border: none !important; padding: 0 !important; }
  .report-header-flex { display: flex !important; justify-content: space-between !important; align-items: center !important; }
  .report-header-brand {
    max-width: 190px !important;
    max-height: 90px !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    border: none !important;
    background: transparent !important;
  }
  .brand-report-logo {
    max-width: 185px !important;
    max-height: 85px !important;
    object-fit: contain !important;
    border: none !important;
    background: transparent !important;
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
  }
  tr { page-break-inside: avoid; }
  th { background-color: #1b3a5f !important; color: #fff !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  td.campo-key { background-color: #f1f5f9 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .vuln-card { page-break-inside: avoid; }
}
"""


# ---------------------------------------------------------------- Generar HTML
def generar_html(carpeta, cli_overrides=None, salida_destino=None, verbose=False):
    carpeta = Path(carpeta)
    cli_overrides = cli_overrides or {}
    auto_info, nmaps, sss, anexos = autodetectar_ficheros(carpeta, verbose=verbose)

    # 1. Metadatos Generales
    g = {}
    if (carpeta / "general.txt").exists():
        g.update(parse_kv(leer(carpeta / "general.txt")))
        if verbose:
            print("    [+] Leído general.txt existente.")
    
    # Completar con auto-detección
    for k, v in auto_info.items():
        if k not in g or not g[k]:
            g[k] = v

    # Sobrescrituras desde línea de comandos (CLI flags)
    if cli_overrides.get("nombre"):
        g["titulo"] = cli_overrides["nombre"]
    if cli_overrides.get("auditor"):
        g["auditor"] = cli_overrides["auditor"]
        g["firma_auditor"] = cli_overrides["auditor"]

    # Gestión de fecha automática (-f)
    fecha_actual_dd = datetime.now().strftime("%d/%m/%Y")
    fecha_actual_iso = datetime.now().strftime("%Y-%m-%d")
    if cli_overrides.get("fecha"):
        val_f = cli_overrides["fecha"]
        g["fecha"] = fecha_actual_dd if val_f == "AUTO" else val_f
    elif not g.get("fecha"):
        g["fecha"] = fecha_actual_dd

    # Gestión de código de informe (-c o auto-incremental AUD-YYYY-MM-DD-0)
    if cli_overrides.get("codigo"):
        g["codigo"] = cli_overrides["codigo"]
    elif not g.get("codigo"):
        dest_dir = Path(salida_destino).parent if salida_destino else carpeta
        g["codigo"] = calcular_codigo_informe(dest_dir, fecha_actual_iso, verbose=verbose)

    gv = lambda k, d=ND: g.get(k, d) or d

    # 2. Servicios
    extra = {}
    if (carpeta / "servicios.txt").exists():
        for p, nec, obs in parse_tabla(leer(carpeta / "servicios.txt"), 3):
            extra[p] = {"necesario": nec or ND, "obs": obs}

    inventario = construir_inventario(nmaps, sss, extra)
    if verbose:
        print(f"[*] [Verbose] Inventario consolidado: {len(inventario)} servicios/puertos detectados.")

    # 3. Controles
    controles_txt = leer(carpeta / "controles.txt") if (carpeta / "controles.txt").exists() else PLANTILLA_CONTROLES_DEFAULT
    controles = parse_controles(controles_txt)

    # 4. Hallazgos
    hallazgos = parse_bloques(leer(carpeta / "hallazgos.txt")) if (carpeta / "hallazgos.txt").exists() else []

    # 5. Herramientas
    herram = parse_tabla(leer(carpeta / "herramientas.txt"), 5) if (carpeta / "herramientas.txt").exists() else []
    if cli_overrides.get("fecha") and herram:
        for r in herram:
            if len(r) >= 5 and not r[4].strip():
                r[4] = f"{g['fecha']} 10:00"

    # Construir HTML
    titulo = gv("titulo", "Informe de auditoría de seguridad")
    logo_dark_uri = obtener_logo_data_uri("1_logo_principal_fondo_oscuro.png")
    logo_light_uri = obtener_logo_data_uri("2_logo_completo_fondo_claro.png")
    icon_uri = obtener_logo_data_uri("3_icono_fondo_oscuro.png")
    fav_uri = obtener_logo_data_uri("4_icono_app_32x32_oscuro.png")
    out = []

    out.append(f"""
    <header class="brand-bar">
      <div class="brand">
        <span class="brand-bar-logo-wrap"><img src="{icon_uri}" alt="NetSpector"></span>
        <span>NetSpector</span> <span style="opacity:0.8; font-size:12px;">v{VERSION}</span>
      </div>
      <div class="actions">
        <button class="btn-print" onclick="window.print()">Imprimir / Guardar en PDF</button>
      </div>
    </header>
    <main class="report-wrapper">
      <div class="report-sheet">
        <div class="report-header">
          <div class="report-header-flex">
            <div class="report-header-text">
              <h1>{esc(titulo)}</h1>
              <p>Servicios, configuración y vulnerabilidades — Plantilla con guía de cumplimentación · Versión 1.0</p>
            </div>
            <div class="report-header-brand">
              <picture>
                <source media="(prefers-color-scheme: dark)" srcset="{logo_dark_uri}">
                <img src="{logo_light_uri}" alt="NetSpector Logo" class="brand-report-logo">
              </picture>
            </div>
          </div>
        </div>
    """)

    # 1. Datos Generales
    out.append(f"""
    <section class="section" id="sec-1">
      <div class="section-title">1. Datos generales del informe</div>
      <div class="table-container">
        <table class="pdf-table">
          <thead><tr><th style="width:32%;">Campo</th><th>Qué escribir</th></tr></thead>
          <tbody>
            <tr><td class="campo-key">Título del informe</td><td class="campo-val">{esc(gv("titulo"))}</td></tr>
            <tr><td class="campo-key">Código / referencia</td><td class="campo-val">{esc(gv("codigo"))}</td></tr>
            <tr><td class="campo-key">Fecha de la auditoría</td><td class="campo-val">{esc(gv("fecha"))}</td></tr>
            <tr><td class="campo-key">Auditor</td><td class="campo-val">{esc(gv("auditor"))}</td></tr>
            <tr><td class="campo-key">Solicitante / responsable del activo</td><td class="campo-val">{esc(gv("solicitante"))}</td></tr>
            <tr><td class="campo-key">Versión y estado</td><td class="campo-val">{esc(gv("version"))}</td></tr>
            <tr><td class="campo-key">Nivel de confidencialidad</td><td class="campo-val">{esc(gv("confidencialidad"))}</td></tr>
          </tbody>
        </table>
      </div>
    </section>
    """)

    # 2. Alcance
    out.append(f"""
    <section class="section" id="sec-2">
      <div class="section-title">2. Alcance y autorización</div>
      <div class="table-container">
        <table class="pdf-table">
          <thead><tr><th style="width:32%;">Campo</th><th>Qué escribir</th></tr></thead>
          <tbody>
            <tr><td class="campo-key">Activo evaluado</td><td class="campo-val">{esc(gv("activo"))}</td></tr>
            <tr><td class="campo-key">Elementos fuera de alcance</td><td class="campo-val">{esc(gv("fuera_de_alcance"))}</td></tr>
            <tr><td class="campo-key">Tipo de análisis</td><td class="campo-val">{esc(gv("tipo_de_analisis", "Caja blanca"))}</td></tr>
            <tr><td class="campo-key">Autorización</td><td class="campo-val">{esc(gv("autorizacion"))}</td></tr>
          </tbody>
        </table>
      </div>
    </section>
    """)

    # 3. Identificación
    out.append(f"""
    <section class="section" id="sec-3">
      <div class="section-title">3. Identificación del equipo</div>
      <div class="table-container">
        <table class="pdf-table">
          <thead><tr><th style="width:32%;">Campo</th><th>Qué escribir</th></tr></thead>
          <tbody>
            <tr><td class="campo-key">Nombre de host</td><td class="campo-val">{esc(gv("host"))}</td></tr>
            <tr><td class="campo-key">Direccion IP / MAC</td><td class="campo-val">{esc(gv("ip_mac"))}</td></tr>
            <tr><td class="campo-key">Sistema operativo y versión</td><td class="campo-val">{esc(gv("so"))}</td></tr>
            <tr><td class="campo-key">Versión del kernel</td><td class="campo-val">{esc(gv("kernel"))}</td></tr>
            <tr><td class="campo-key">Tipo de equipo</td><td class="campo-val">{esc(gv("tipo_de_equipo", "Servidor"))}</td></tr>
            <tr><td class="campo-key">Función / criticidad</td><td class="campo-val">{esc(gv("funcion"))}</td></tr>
            <tr><td class="campo-key">Propietario</td><td class="campo-val">{esc(gv("propietario"))}</td></tr>
            <tr><td class="campo-key">Última fecha de arranque</td><td class="campo-val">{esc(gv("ultimo_arranque"))}</td></tr>
          </tbody>
        </table>
      </div>
    </section>
    """)

    # 4. Inventario
    inv_filas = ""
    for item in inventario:
        inv_filas += (
            f"<tr><td style='font-weight:600;'>{esc(item['puerto'])}</td>"
            f"<td>{esc(item['servicio'])}</td><td>{esc(item['software'])}</td>"
            f"<td>{esc(item['proceso'])}</td><td>{esc(item['acceso'])}</td>"
            f"<td>{esc(item['necesario'])}</td><td>{esc(item['obs'])}</td></tr>"
        )
    out.append(f"""
    <section class="section" id="sec-4">
      <div class="section-title">4. Inventario de servicios y puertos</div>
      <div class="table-container">
        <table class="pdf-table">
          <thead>
            <tr><th>Puerto / protocolo</th><th>Servicio</th><th>Software y versión</th><th>Proceso / usuario</th><th>Accesible desde</th><th>¿Necesario?</th><th>Observaciones</th></tr>
          </thead>
          <tbody>{inv_filas or "<tr><td colspan='7' style='text-align:center;'>Sin datos de puertos. Añade nmap.txt o ss.txt a la carpeta.</td></tr>"}</tbody>
        </table>
      </div>
    </section>
    """)

    # 5. Revisión de configuración
    cfg_html = ""
    for sec in controles:
        filas_c = ""
        for r in sec["filas"]:
            badge = f'<span class="badge {clase_estado(r[3])}">{esc(r[3])}</span>'
            filas_c += f"<tr><td style='font-weight:500;'>{esc(r[0])}</td><td style='font-family:monospace; font-size:12px;'>{esc(r[1])}</td><td>{esc(r[2])}</td><td style='text-align:center;'>{badge}</td></tr>"
        cfg_html += f"""
        <div class="subsection-title">{esc(sec['titulo'])}</div>
        <div class="table-container">
          <table class="pdf-table">
            <thead><tr><th>Control</th><th>Cómo comprobarlo</th><th>Valor encontrado</th><th style="width:110px;">Estado</th></tr></thead>
            <tbody>{filas_c}</tbody>
          </table>
        </div>
        """
    out.append(f"""
    <section class="section" id="sec-5">
      <div class="section-title">5. Revisión de configuración</div>
      {cfg_html}
    </section>
    """)

    # 6. Vulnerabilidades
    fichas_html = ""
    resumen_filas = ""
    counts = {"Crítica": 0, "Alta": 0, "Media": 0, "Baja": 0, "Informativa": 0}

    for i, h in enumerate(hallazgos, 1):
        hid = h.get("id") or f"VUL-{i:02d}"
        sev = sev_norm(h.get("severidad"))
        if sev in counts:
            counts[sev] += 1
        else:
            counts["Informativa"] += 1

        b_sev = f'<span class="badge {clase_sev(sev)}">{esc(sev)}</span>'
        fichas_html += f"""
        <div class="vuln-card" id="{esc(hid)}">
          <table class="pdf-table">
            <thead><tr><th style="width:32%;">Campo</th><th>Valor</th></tr></thead>
            <tbody>
              <tr><td class="campo-key">ID del hallazgo</td><td style="font-weight:700; color:var(--primary);">{esc(hid)}</td></tr>
              <tr><td class="campo-key">Título</td><td style="font-weight:600;">{esc(h.get('titulo'))}</td></tr>
              <tr><td class="campo-key">Identificador CVE</td><td>{esc(h.get('cve'))}</td></tr>
              <tr><td class="campo-key">Componente afectado</td><td>{esc(h.get('componente'))}</td></tr>
              <tr><td class="campo-key">Descripción</td><td>{esc(h.get('descripcion'))}</td></tr>
              <tr><td class="campo-key">Cómo se detectó</td><td>{esc(h.get('deteccion'))}</td></tr>
              <tr><td class="campo-key">Evidencia</td><td>{esc(h.get('evidencia'))}</td></tr>
              <tr><td class="campo-key">Severidad (CVSS)</td><td>{b_sev}</td></tr>
              <tr><td class="campo-key">Probabilidad e impacto</td><td>{esc(h.get('probabilidad_e_impacto') or h.get('probabilidad'))}</td></tr>
              <tr><td class="campo-key">Exploit público</td><td>{esc(h.get('exploit'))}</td></tr>
              <tr><td class="campo-key">Estado</td><td>{esc(h.get('estado'))}</td></tr>
              <tr><td class="campo-key">Recomendación</td><td>{esc(h.get('recomendacion'))}</td></tr>
            </tbody>
          </table>
        </div>
        """
        resumen_filas += f"""
        <tr>
          <td style="font-weight:700;"><a href="#{esc(hid)}" style="color:var(--accent); text-decoration:none;">{esc(hid)}</a></td>
          <td style="font-weight:500;">{esc(h.get('titulo'))}</td>
          <td>{esc(h.get('componente'))}</td>
          <td>{b_sev}</td>
          <td>{esc(h.get('estado'))}</td>
          <td style="text-align:center; font-weight:700;">{esc(h.get('prioridad', '1'))}</td>
        </tr>
        """

    out.append(f"""
    <section class="section" id="sec-6">
      <div class="section-title">6. Vulnerabilidades detectadas</div>
      <p style="font-size:13px; color:var(--text-muted); margin-bottom:15px;">Ficha de vulnerabilidad (repetir una por hallazgo)</p>
      {fichas_html or "<p style='color:var(--text-muted);'>Sin hallazgos cargados en hallazgos.txt.</p>"}
      <div class="subsection-title" style="margin-top:25px;">Tabla resumen de vulnerabilidades</div>
      <div class="table-container">
        <table class="pdf-table">
          <thead><tr><th>ID</th><th>Título</th><th>Componente</th><th>Severidad</th><th>Estado</th><th>Prioridad de corrección</th></tr></thead>
          <tbody>{resumen_filas or "<tr><td colspan='6' style='text-align:center;'>Sin vulnerabilidades registradas.</td></tr>"}</tbody>
        </table>
      </div>
    </section>
    """)

    # 7. Resumen Ejecutivo
    out.append(f"""
    <section class="section" id="sec-7">
      <div class="section-title">7. Resumen ejecutivo y valoración global</div>
      <div class="table-container" style="max-width: 450px;">
        <table class="pdf-table">
          <thead><tr><th>Severidad</th><th>Nº de hallazgos</th></tr></thead>
          <tbody>
            <tr><td class="campo-key">Crítica</td><td style="font-weight:700;">{counts['Crítica']}</td></tr>
            <tr><td class="campo-key">Alta</td><td style="font-weight:700;">{counts['Alta']}</td></tr>
            <tr><td class="campo-key">Media</td><td style="font-weight:700;">{counts['Media']}</td></tr>
            <tr><td class="campo-key">Baja</td><td style="font-weight:700;">{counts['Baja']}</td></tr>
            <tr><td class="campo-key">Informativa</td><td style="font-weight:700;">{counts['Informativa']}</td></tr>
          </tbody>
        </table>
      </div>
      <p style="margin-top:12px; line-height:1.6;">{esc(gv('resumen'))}</p>
    </section>
    """)

    # 8. Remediación
    plan_filas = ""
    for h in sorted(hallazgos, key=lambda x: int(x.get("prioridad", 9) if str(x.get("prioridad", 9)).isdigit() else 9)):
        plan_filas += f"""
        <tr>
          <td style="text-align:center; font-weight:700;">{esc(h.get('prioridad', '1'))}</td>
          <td style="font-weight:600; color:var(--primary);">{esc(h.get('id'))}</td>
          <td>{esc(h.get('accion') or h.get('recomendacion'))}</td>
          <td>{esc(h.get('mitigacion'))}</td>
          <td>{esc(h.get('responsable', 'Sistemas'))}</td>
          <td>{esc(h.get('fecha_limite', gv('fecha')))}</td>
          <td>{esc(h.get('esfuerzo', 'Medio'))}</td>
          <td><span class="badge badge-stopped">{esc(h.get('estado_plan', 'Pendiente'))}</span></td>
        </tr>
        """
    out.append(f"""
    <section class="section" id="sec-8">
      <div class="section-title">8. Plan de remediación y recomendaciones</div>
      <div class="table-container">
        <table class="pdf-table">
          <thead><tr><th style="width:65px;">Prioridad</th><th>Hallazgo relacionado</th><th>Acción recomendada</th><th>Mitigación temporal</th><th>Responsable</th><th>Fecha límite</th><th>Esfuerzo</th><th>Estado</th></tr></thead>
          <tbody>{plan_filas or "<tr><td colspan='8' style='text-align:center;'>Sin plan de remediación definido.</td></tr>"}</tbody>
        </table>
      </div>
    </section>
    """)

    # 9. Metodología
    herram_filas = ""
    for r in herram:
        herram_filas += f"""
        <tr>
          <td style="font-weight:600;">{esc(r[0])}</td><td>{esc(r[1])}</td><td>{esc(r[2])}</td>
          <td style="font-family:monospace; font-size:12px;">{esc(r[3])}</td><td>{esc(r[4])}</td>
        </tr>
        """
    out.append(f"""
    <section class="section" id="sec-9">
      <div class="section-title">9. Metodología y herramientas utilizadas</div>
      <div class="table-container">
        <table class="pdf-table">
          <thead><tr><th>Herramienta</th><th>Versión</th><th>Uso</th><th>Comando o perfil</th><th>Fecha y hora</th></tr></thead>
          <tbody>{herram_filas or "<tr><td colspan='5' style='text-align:center;'>Sin herramientas registradas.</td></tr>"}</tbody>
        </table>
      </div>
    </section>
    """)

    # 10. Anexos y Firmas
    anex_idx = ""
    anex_raw = ""
    for i, (nom, raw, rel) in enumerate(anexos, 1):
        anex_idx += f"<tr><td style='font-weight:700;'>Anexo {i}</td><td style='font-weight:500;'>{esc(nom)}</td><td>{esc(rel)}</td></tr>"
        corte = raw if len(raw) <= MAX_ANEXO else raw[:MAX_ANEXO] + "\n[... recortado por longitud ...]"
        anex_raw += f"""
        <details class="anexo-details">
          <summary>Anexo {i} · {esc(nom)}</summary>
          <pre>{html.escape(corte)}</pre>
        </details>
        """

    out.append(f"""
    <section class="section" id="sec-10">
      <div class="section-title">10. Anexos, evidencias y firmas</div>
      <div class="subsection-title">Índice de anexos y evidencias</div>
      <div class="table-container">
        <table class="pdf-table">
          <thead><tr><th style="width:120px;">Anexo</th><th>Contenido</th><th>Relacionado con</th></tr></thead>
          <tbody>{anex_idx or "<tr><td colspan='3' style='text-align:center;'>Sin evidencias adjuntas.</td></tr>"}</tbody>
        </table>
      </div>
      <div style="margin:20px 0;">{anex_raw}</div>

      <div class="subsection-title" style="margin-top:30px;">Control de versiones</div>
      <div class="table-container">
        <table class="pdf-table">
          <thead><tr><th>Versión</th><th>Fecha</th><th>Autor</th><th>Cambios</th></tr></thead>
          <tbody>
            <tr><td>V1.0</td><td>{esc(gv('fecha'))}</td><td>{esc(gv('auditor'))}</td><td>Versión inicial de auditoría</td></tr>
            <tr><td>V1.0 - Revisado</td><td>{esc(gv('fecha'))}</td><td>{esc(gv('auditor'))}</td><td>Revisión técnica de evidencias y plan</td></tr>
          </tbody>
        </table>
      </div>

      <div class="subsection-title" style="margin-top:25px;">Firmas</div>
      <div class="table-container">
        <table class="pdf-table">
          <thead><tr><th>Rol</th><th>Nombre</th><th>Fecha</th><th>Firma</th></tr></thead>
          <tbody>
            <tr><td class="campo-key">Auditor</td><td>{esc(gv('auditor'))}</td><td>{esc(gv('fecha'))}</td><td>{esc(gv('firma_auditor', gv('auditor')))}</td></tr>
            <tr><td class="campo-key">Responsable del activo</td><td>No verificado</td><td>No verificado</td><td>No verificado</td></tr>
            <tr><td class="campo-key">Revisor / Dirección</td><td>No verificado</td><td>No verificado</td><td>No verificado</td></tr>
          </tbody>
        </table>
      </div>
    </section>
      </div>
    </main>
    """)

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(titulo)} - NetSpector</title>
  <link rel="icon" type="image/png" href="{fav_uri}">
  <style>{CSS}</style>
</head>
<body>
  {''.join(out)}
</body>
</html>
"""


# ------------------------------------------------------------- Actualización
def actualizar_herramienta(verbose=False):
    """Actualiza NetSpector desde el repositorio oficial de GitHub."""
    print("=" * 60)
    print("      NetSpector - Actualización")
    print("=" * 60)
    print("[*] Comprobando actualizaciones en GitHub...")

    repo_dir = Path(__file__).resolve().parent

    # Intentar actualización automática con git
    try:
        cmd = ["git", "pull"]
        if verbose:
            print(f"[*] Ejecutando: {' '.join(cmd)} en {repo_dir}")
        res = subprocess.run(cmd, cwd=repo_dir, capture_output=True, text=True, timeout=20)
        if res.returncode == 0:
            salida_git = res.stdout.strip()
            print("[+] Resultado de la actualización:")
            print(f"    {salida_git or 'Ya estás en la versión más reciente.'}")
            print(f"[+] Versión actual: NetSpector v{VERSION}")
            return True
        else:
            if verbose:
                print(f"[!] Git pull falló con código {res.returncode}: {res.stderr.strip()}")
    except FileNotFoundError:
        print("[!] Git no está instalado o no se encuentra disponible en el PATH del sistema.")
    except subprocess.TimeoutExpired:
        print("[!] Tiempo de espera agotado al conectar con GitHub (timeout de 20 segundos).")
    except Exception as e:
        if verbose:
            print(f"[!] No se pudo ejecutar git: {e}")

    # Fallback si no está en git
    print("[!] No se pudo actualizar automáticamente mediante Git.")
    print(f"[*] Puedes descargar siempre la última versión actualizada desde:")
    print(f"    {GITHUB_REPO_URL}")
    return False


# ------------------------------------------------------------- Encuesta CLI
def encuesta_satisfaccion():
    """Pregunta al usuario si le ha servido la herramienta con redirección a GitHub en caso negativo."""
    print("\n" + "=" * 60)
    print("      Encuesta de Satisfacción")
    print("=" * 60)
    try:
        resp = input("¿Te ha servido la herramienta NetSpector para tu informe? (s/n): ").strip().lower()
        if resp in ("s", "si", "sí", "y", "yes"):
            print("\n¡Muchas gracias por utilizar la aplicación!")
            print("   Esperamos que te sea de gran utilidad en todas tus auditorías.")
        elif resp in ("n", "no"):
            print("\nLamentamos que la herramienta no haya cumplido tus expectativas.")
            print("Por favor, entra a nuestro GitHub para dejarnos una reseña o sugerencia:")
            print(f"    {GITHUB_REPO_URL}/issues")
    except (KeyboardInterrupt, EOFError):
        pass
    print("=" * 60)


# ------------------------------------------------------------- GUI & CLI Entry
def pedir_carpeta_interactiva():
    """Permite seleccionar la carpeta mediante diálogo nativo o consola interactiva."""
    print("=" * 60)
    print("      NetSpector - Generador de Informes de Seguridad")
    print("=" * 60)

    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        print("[*] Abriendo selector de carpetas...")
        carpeta = filedialog.askdirectory(title="NetSpector - Selecciona tu carpeta con los archivos .txt")
        root.destroy()
        if carpeta and Path(carpeta).is_dir():
            return Path(carpeta)
    except Exception:
        pass

    actual = Path.cwd()
    print(f"\nDirectorio actual: {actual}")
    entrada = input("\nIntroduce la ruta de la carpeta de trabajo [Enter para carpeta actual]: ").strip()
    if not entrada:
        return actual
    p = Path(entrada.strip('\"\''))
    if p.is_dir():
        return p
    print(f"[!] '{p}' no existe. Creando directorio...")
    p.mkdir(parents=True, exist_ok=True)
    return p


def preprocesar_argv(argv):
    """
    Normaliza flags:
    1. Si el usuario pasa dos veces -n, el segundo se interpreta como -c (código/número de informe).
    2. Si el usuario pasa -update, se normaliza a --update.
    """
    nuevo_argv = []
    conteo_n = 0
    for arg in argv:
        if arg == "-update":
            nuevo_argv.append("--update")
        elif arg == "-n":
            conteo_n += 1
            if conteo_n == 2:
                nuevo_argv.append("-c")
            else:
                nuevo_argv.append("-n")
        else:
            nuevo_argv.append(arg)
    return nuevo_argv


def main(argv_list=None):
    if argv_list is None:
        argv_list = sys.argv[1:]

    argv_list = preprocesar_argv(argv_list)

    ap = argparse.ArgumentParser(
        prog="netspector",
        description="NetSpector - Generador oficial de informes de auditoría de seguridad.",
        epilog="Ejemplo: python netspector.py -d ./mis_txt -e reporte.html -a 'Auditor' -f -n 'Auditoría Servidores' -c 'AUD-2026-01'"
    )
    ap.add_argument("-d", "--directorio", dest="directorio", default=None, help="Carpeta de trabajo con los ficheros .txt")
    ap.add_argument("-e", "--salida", dest="salida", default=None, help="Nombre del archivo HTML o ruta completa donde guardarlo")
    ap.add_argument("-a", "--auditor", dest="auditor", default=None, help="Nombre del auditor")
    ap.add_argument("-f", "--fecha", dest="fecha", nargs="?", const="AUTO", default=None, help="Pone automáticamente la fecha de hoy en todos los campos de fecha")
    ap.add_argument("-n", "--nombre", "--titulo", dest="nombre", default=None, help="Nombre o título de la auditoría")
    ap.add_argument("-c", "-i", "--codigo", "--num", "--numero", dest="codigo", default=None, help="Número o código de informe (por defecto: AUD-YYYY-MM-DD-0 auto-incremental)")
    ap.add_argument("-v", "--verbose", action="store_true", help="Modo detallado (verbose): muestra paso a paso el análisis")
    ap.add_argument("--version", "-V", action="version", version=f"NetSpector v{VERSION}")
    ap.add_argument("--update", "-update", dest="update", action="store_true", help="Actualiza NetSpector desde el repositorio oficial de GitHub")
    ap.add_argument("--init", action="store_true", help="Crea plantillas de ejemplo en la carpeta indicada")
    
    args = ap.parse_args(argv_list)

    # 1. Comprobar si se solicitó actualización
    if args.update:
        actualizar_herramienta(verbose=args.verbose)
        return

    # 2. Determinar directorio de trabajo
    if args.directorio:
        carpeta = Path(args.directorio)
    else:
        carpeta = pedir_carpeta_interactiva()

    if args.init:
        try:
            carpeta.mkdir(parents=True, exist_ok=True)
            (carpeta / "general.txt").write_text(PLANTILLA_GENERAL_DEFAULT, encoding="utf-8")
            (carpeta / "controles.txt").write_text(PLANTILLA_CONTROLES_DEFAULT, encoding="utf-8")
            print(f"[NetSpector] Plantillas oficiales creadas con éxito en: {carpeta.resolve()}")
        except PermissionError:
            sys.exit(f"[NetSpector] Error de permisos: No se pueden crear las plantillas en '{carpeta}'. Verifique permisos de escritura.")
        except OSError as e:
            sys.exit(f"[NetSpector] Error del sistema al inicializar carpeta '{carpeta}': {e}")
        return

    if not carpeta.exists():
        sys.exit(f"[NetSpector] Error: La carpeta especificada '{carpeta}' no existe.\n"
                 f"[*] Verifique la ruta o créela antes de ejecutar NetSpector.")
    if not carpeta.is_dir():
        sys.exit(f"[NetSpector] Error: La ruta '{carpeta}' no es un directorio válido (es un archivo).\n"
                 f"[*] Especifique una carpeta que contenga sus archivos de auditoría .txt.")

    if args.verbose:
        print(f"[*] [Verbose] Carpeta seleccionada: {carpeta.resolve()}")

    # 3. Determinar ruta de salida
    if args.salida:
        p_salida = Path(args.salida)
        if p_salida.is_absolute() or len(p_salida.parts) > 1:
            salida = p_salida
        else:
            salida = carpeta / args.salida
    else:
        salida = carpeta / "informe.html"

    try:
        salida.parent.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        sys.exit(f"[NetSpector] Error de permisos: No se tiene acceso para crear la carpeta de salida '{salida.parent}'.")
    except OSError as e:
        sys.exit(f"[NetSpector] Error del sistema al preparar la ruta de salida '{salida.parent}': {e}")

    if args.verbose:
        print(f"[*] [Verbose] Archivo de salida planificado: {salida.resolve()}")

    # 4. Diccionario con sobreescrituras CLI
    cli_overrides = {
        "auditor": args.auditor,
        "nombre": args.nombre,
        "fecha": args.fecha,
        "codigo": args.codigo,
    }

    # 5. Generar informe HTML
    try:
        html_content = generar_html(carpeta, cli_overrides=cli_overrides, salida_destino=salida, verbose=args.verbose)
    except Exception as e:
        sys.exit(f"[NetSpector] Error procesando los datos para el informe: {e}\n"
                 f"[*] Ejecute con el parámetro '-v' para ver el seguimiento detallado.")

    try:
        salida.write_text(html_content, encoding="utf-8")
    except PermissionError:
        sys.exit(f"[NetSpector] Error de permisos: No se pudo guardar el informe en '{salida}'.\n"
                 f"[*] Compruebe que el archivo no esté bloqueado por otra aplicación o tenga permisos de escritura.")
    except OSError as e:
        sys.exit(f"[NetSpector] Error del sistema al escribir el archivo '{salida}': {e}")
    
    print("\n" + "=" * 60)
    print("      NetSpector - Informe Generado con Éxito")
    print("=" * 60)
    print(f"[+] Carpeta analizada: {carpeta.resolve()}")
    print(f"[+] Archivo generado:  {salida.resolve()}")
    if args.nombre:
        print(f"[+] Nombre auditoría: {args.nombre}")
    if args.auditor:
        print(f"[+] Auditor:          {args.auditor}")
    print("=" * 60)

    # Abrir en navegador automáticamente
    try:
        import webbrowser
        webbrowser.open(str(salida.resolve().as_uri()))
    except Exception:
        pass

    # 6. Encuesta de satisfacción
    encuesta_satisfaccion()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operación cancelada por el usuario.", file=sys.stderr)
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as e:
        print(f"\n[NetSpector] Error crítico no controlado: {e}", file=sys.stderr)
        if "-v" in sys.argv or "--verbose" in sys.argv:
            import traceback
            traceback.print_exc()
        else:
            print("[*] Ejecuta con -v o --verbose para obtener más detalles.", file=sys.stderr)
        sys.exit(1)
