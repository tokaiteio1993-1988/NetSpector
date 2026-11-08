#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetSpector - Generador automatizado de informes de auditoría de seguridad y análisis de red.
Formato oficial conforme a la plantilla de auditoría técnica (Secciones 1 a 10).
Soporta Modo Equipo Único y Modo Infraestructura (Netdiscover + Nmap por equipos y de red + Topografía).

USO MEDIANTE PARÁMETROS:
    python netspector.py -d <carpeta> -e <salida.html> -a <auditor> -f -n <nombre_auditoria> -c <codigo_informe> [-m <equipo|infra>]

PARÁMETROS SOPORTADOS:
    -d, --directorio    Carpeta donde trabajar y buscar los ficheros .txt
    -e, --salida        Nombre del HTML o ruta completa donde guardarlo
    -a, --auditor       Nombre del auditor
    -f, --fecha         Pone automáticamente la fecha de hoy en todos los campos de fecha (o la fecha indicada)
    -n, --nombre        Nombre o título de la auditoría
    -c, -i, --codigo    Código o número de informe (si no se indica, genera AUD-YYYY-MM-DD-0 auto-incremental)
    -m, --modo          Modo de informe: auto (por defecto), equipo o infra
    -infra, --infra     Fuerza el Modo Infraestructura con Topografía de Red
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

VERSION = "2.3.0"
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


# ------------------------------------------------------- Parseo de Red, Nmap y SS
def limpiar_ansi(texto):
    """Elimina secuencias de escape ANSI (habituales si se vuelca netdiscover interactivo a un txt)."""
    return re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", texto or "")


def es_netdiscover(nombre, texto):
    """Determina si un fichero corresponde a una salida de netdiscover o tabla ARP."""
    n = (nombre or "").lower()
    if "netdiscover" in n or "arp-scan" in n:
        return True
    txt_limpio = limpiar_ansi(texto)
    if "Currently scanning:" in txt_limpio or "Captured ARP Req/Rep packets" in txt_limpio:
        return True
    if re.search(r"IP\s+At\s+MAC\s+Address\s+Count\s+Len\s+MAC\s+Vendor", txt_limpio, re.I):
        return True
    matches = re.findall(
        r"^\s*\d{1,3}(?:\.\d{1,3}){3}\s+[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}\s+\d+\s+\d+\s+.+$",
        txt_limpio,
        re.M,
    )
    return len(matches) >= 1


def parse_netdiscover(texto):
    """
    Parsea salidas de netdiscover (modo interactivo volcado a txt o modo -P / pasivo)
    así como formatos equivalentes de arp-scan.
    Devuelve: {"rango": str, "hosts": {ip: {"ip": str, "mac": str, "vendor": str}}}
    """
    txt = limpiar_ansi(texto)
    hosts = {}
    rango = ""

    m_scan = re.search(r"Currently scanning:\s*([^\s\r\n(]+)", txt, re.I)
    if m_scan and m_scan.group(1).lower() != "finished!":
        rango = m_scan.group(1).strip()

    for raw_line in txt.splitlines():
        l = raw_line.strip()
        if not l:
            continue
        # Formato estándar netdiscover: IP   MAC   Count   Len   MAC Vendor / Hostname
        m = re.match(
            r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\s+(\d+)\s+(\d+)\s*(.*)$",
            l,
        )
        if m:
            ip, mac, _cnt, _length, vendor = m.groups()
            mac_norm = mac.upper().replace("-", ":")
            vendor_clean = vendor.strip() or "Fabricante desconocido"
            hosts[ip] = {
                "ip": ip,
                "mac": mac_norm,
                "vendor": vendor_clean,
            }
            continue

        # Formato alternativo arp-scan / arp: IP   MAC   Vendor
        m_alt = re.match(
            r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\s+([^\d].*)$",
            l,
        )
        if m_alt:
            ip, mac, vendor = m_alt.groups()
            mac_norm = mac.upper().replace("-", ":")
            hosts.setdefault(ip, {
                "ip": ip,
                "mac": mac_norm,
                "vendor": vendor.strip() or "Fabricante desconocido",
            })

    return {"rango": rango, "hosts": hosts}


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


def parse_nmap_multi(texto, nombre_archivo=""):
    """
    Parsea un archivo Nmap que puede contener:
      - Un único equipo (ej: nmap_192.168.1.10.txt)
      - Múltiples equipos de toda la red (ej: nmap -sn 192.168.1.0/24 o nmap -sV 192.168.1.0/24)
      - Formato Grepable (-oG)
    Devuelve un diccionario {clave_host: {"ip": ..., "host": ..., "mac": ..., "vendor": ..., "so": ..., "ports": {...}}}
    """
    hosts = {}
    partes = re.split(r"(?=^Nmap scan report for )", texto, flags=re.M)

    for bloque in partes:
        if not bloque.strip().startswith("Nmap scan report for "):
            continue
        primera_linea = bloque.strip().splitlines()[0]
        if "[host down]" in primera_linea.lower():
            continue

        m_hdr = re.match(
            r"^Nmap scan report for (?:([^\s()]+)\s+\(([\d.]+)\)|([\d.]+)|([^\s()]+))",
            primera_linea.strip(),
        )
        if not m_hdr:
            continue

        hostname = m_hdr.group(1) or m_hdr.group(4) or ""
        ip = m_hdr.group(2) or m_hdr.group(3) or ""
        key = ip or hostname
        if not key:
            continue

        h = hosts.setdefault(key, {
            "ip": ip or hostname,
            "host": hostname,
            "mac": "",
            "vendor": "",
            "so": "",
            "ports": {},
        })

        if hostname and not h["host"]:
            h["host"] = hostname
        if ip and h["ip"] == h["host"]:
            h["ip"] = ip

        m_mac = re.search(r"MAC Address:\s*([0-9A-Fa-f:]{17})(?:\s*\(([^)]+)\))?", bloque)
        if m_mac:
            h["mac"] = m_mac.group(1).upper()
            if m_mac.group(2):
                h["vendor"] = m_mac.group(2).strip()

        m_os = re.search(r"(?:OS details|Running|Service Info: OS):\s*([^\r\n;]+)", bloque)
        if m_os:
            h["so"] = m_os.group(1).strip()
        else:
            m_os_guess = re.search(r"(?:Running \(JUST GUESSING\)|Aggressive OS guesses):\s*([^\r\n;,]+)", bloque)
            if m_os_guess:
                h["so"] = f"{m_os_guess.group(1).strip()} (Estimado)"

        bloque_ports = parse_nmap(bloque)
        h["ports"].update(bloque_ports)

    # Soporte para formato Grepable (-oG) si no había bloques estándar
    if not hosts and "Host:" in texto:
        for l in texto.splitlines():
            m_g = re.match(r"^Host:\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\(([^)]*)\)", l.strip())
            if m_g:
                ip, hname = m_g.group(1), m_g.group(2).strip()
                if "Status: Down" in l:
                    continue
                h = hosts.setdefault(ip, {
                    "ip": ip,
                    "host": hname,
                    "mac": "",
                    "vendor": "",
                    "so": "",
                    "ports": {},
                })
                m_p = re.search(r"Ports:\s*(.+?)(?:\t|$)", l)
                if m_p:
                    for item_p in m_p.group(1).split(","):
                        campos = [c.strip() for c in item_p.split("/")]
                        if len(campos) >= 5 and campos[1].startswith("open"):
                            pnum, proto, srv = campos[0], campos[2].lower(), campos[4]
                            ver = campos[6] if len(campos) > 6 else ""
                            if pnum.isdigit():
                                h["ports"][(int(pnum), proto)] = {"servicio": srv or ND, "version": ver}

    # Si era un fragmento de salida Nmap sin cabecera "Nmap scan report for", extraer puertos e inferir IP del nombre
    if not hosts:
        fallback_ports = parse_nmap(texto)
        if fallback_ports:
            m_ip_file = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", nombre_archivo or "")
            ip_inferida = m_ip_file.group(1) if m_ip_file else (Path(nombre_archivo).stem if nombre_archivo else "Host")
            hosts[ip_inferida] = {
                "ip": ip_inferida,
                "host": Path(nombre_archivo).stem if nombre_archivo else "",
                "mac": "",
                "vendor": "",
                "so": "",
                "ports": fallback_ports,
            }

    return hosts


def ip_sort_key(ip_str):
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", (ip_str or "").strip())
    if m:
        return (0, tuple(int(x) for x in m.groups()), ip_str)
    return (1, (999, 999, 999, 999), ip_str or "")


def inferir_rol_equipo(h):
    """Deduce el rol técnico y categoría visual del activo según IP, fabricante y puertos."""
    ip = h.get("ip", "")
    ports = {k[0] for k in h.get("ports", {}).keys()}
    vendor = (h.get("vendor") or "").lower()
    so = (h.get("so") or "").lower()
    host = (h.get("host") or "").lower()

    if any(w in vendor for w in ("aruba", "ruckus", "unifi", "ubiquiti", "cambium", "aerohive")):
        return ("Controlador Wi-Fi / Punto de Acceso", "gateway")
    if ip.endswith(".1") or ip.endswith(".254") or "router" in host or "gw" in host or "gateway" in host:
        return ("Gateway / Router", "gateway")
    if 88 in ports or 389 in ports or 636 in ports or 3268 in ports or ("53" in str(ports) and 445 in ports):
        return ("Controlador de Dominio", "dc")
    if 3306 in ports or 5432 in ports or 1433 in ports or 1521 in ports or 27017 in ports or 6379 in ports:
        return ("Servidor de Base de Datos", "db")
    if 80 in ports or 443 in ports or 8080 in ports or 8443 in ports or 8000 in ports:
        if any(w in vendor for w in ("cisco", "mikrotik", "ubiquiti", "fortinet", "tp-link", "netgear", "juniper", "huawei")):
            return ("Gateway / Equipo de Red", "gateway")
        return ("Servidor Web / Aplicación", "web")
    if 445 in ports or 139 in ports or 2049 in ports or 21 in ports:
        return ("Servidor de Archivos / FTP", "files")
    if 22 in ports or 3389 in ports or 5900 in ports or 5985 in ports:
        return ("Servidor / Host Administrable", "server")
    if any(w in vendor for w in ("cisco", "mikrotik", "ubiquiti", "fortinet", "tp-link", "netgear", "juniper", "huawei")):
        return ("Dispositivo de Red", "gateway")
    if "windows" in so or "linux" in so or ports:
        return ("Servidor / Activo con Servicios", "server")
    return ("Equipo / Host Activo", "host")


def consolidar_infraestructura(netdiscovers, nmaps_hosts, sss, extra):
    """
    Fusiona todos los hosts descubiertos por netdiscover y por múltiples escaneos de nmap
    (tanto escaneos globales de subred como escaneos individuales por equipo).
    Detecta y agrupa automáticamente anomalías de Proxy ARP / MAC multi-IP para evitar
    inflar el mapa con cientos de IPs ficticias que responden desde una misma tarjeta de red.
    """
    merged = {}
    rangos = []

    for nd_data in netdiscovers:
        if nd_data.get("rango") and nd_data["rango"] not in rangos:
            rangos.append(nd_data["rango"])
        for ip, info in nd_data.get("hosts", {}).items():
            h = merged.setdefault(ip, {
                "ip": ip,
                "host": "",
                "mac": "",
                "vendor": "",
                "so": "",
                "ports": {},
                "origen": set(),
            })
            if info.get("mac") and not h["mac"]:
                h["mac"] = info["mac"]
            if info.get("vendor") and not h["vendor"]:
                h["vendor"] = info["vendor"]
            h["origen"].add("Netdiscover")

    for ip_key, info in nmaps_hosts.items():
        h = merged.setdefault(ip_key, {
            "ip": info.get("ip") or ip_key,
            "host": "",
            "mac": "",
            "vendor": "",
            "so": "",
            "ports": {},
            "origen": set(),
        })
        if info.get("host") and not h["host"]:
            h["host"] = info["host"]
        if info.get("mac") and not h["mac"]:
            h["mac"] = info["mac"]
        if info.get("vendor") and not h["vendor"]:
            h["vendor"] = info["vendor"]
        if info.get("so") and not h["so"]:
            h["so"] = info["so"]
        if info.get("ports"):
            h["ports"].update(info["ports"])
        h["origen"].add("Nmap")

    sorted_ips = sorted(merged.keys(), key=ip_sort_key)
    total_ips_brutas = len(sorted_ips)

    # Agrupar por MAC para detectar Proxy ARP (una misma MAC respondiendo por múltiples IPs)
    mac_groups = {}
    for ip_k in sorted_ips:
        mac_val = (merged[ip_k].get("mac") or "").strip().upper()
        if mac_val:
            mac_groups.setdefault(mac_val, []).append(ip_k)

    proxy_arp_macs = {m: ips for m, ips in mac_groups.items() if len(ips) >= 4}
    ips_colapsadas_por_mac = {}
    ips_omitidas = set()

    for mac_val, ips_list in proxy_arp_macs.items():
        principales = [ip for ip in ips_list if merged[ip].get("ports")]
        if not principales:
            preferidas = [ip for ip in ips_list if ip.endswith(".254") or ip.endswith(".1")]
            principales = [preferidas[-1]] if preferidas else [ips_list[-1]]
        secundarias = [ip for ip in ips_list if ip not in principales]
        if len(secundarias) >= 3:
            for s_ip in secundarias:
                ips_omitidas.add(s_ip)
            ips_colapsadas_por_mac[mac_val] = {
                "principales": principales,
                "secundarias": secundarias,
                "total": len(ips_list),
                "vendor": merged[principales[0]].get("vendor") or "Equipo de Red",
            }

    equipos = []
    inventario_infra = []

    for ip_key in sorted_ips:
        if ip_key in ips_omitidas:
            continue
        h = merged[ip_key]
        rol_nombre, rol_tipo = inferir_rol_equipo(h)
        ports_dict = h["ports"]
        ports_sorted = sorted(ports_dict.keys(), key=lambda x: x[0])
        lista_puertos_str = [f"{p}/{pr}" for p, pr in ports_sorted]

        # Construir observación técnica automática por equipo de forma genérica
        obs_equipo = []
        mac_actual = (h.get("mac") or "").strip().upper()
        if mac_actual in proxy_arp_macs:
            total_mac_ips = len(proxy_arp_macs[mac_actual])
            obs_equipo.append(
                f"MAC compartida en {total_mac_ips} IPs de la red (Proxy ARP activo en {h.get('vendor') or 'pasarela'})."
            )
        if any("?" in (ports_dict[k].get("servicio") or "") for k in ports_sorted):
            obs_equipo.append(
                "Servicios marcados con '?' por Nmap: puerto abierto sin banner de aplicación confirmado (posible filtrado/NAT)."
            )
        if "estimado" in (h.get("so") or "").lower():
            obs_equipo.append(
                "Huella de SO aproximada (estimación heurística de Nmap con baja certeza)."
            )

        equipos.append({
            "ip": h["ip"],
            "host": h["host"] or ND,
            "mac": h["mac"] or ND,
            "vendor": h["vendor"] or ND,
            "so": h["so"] or ND,
            "rol": rol_nombre,
            "rol_tipo": rol_tipo,
            "ports_dict": ports_dict,
            "puertos_lista": lista_puertos_str,
            "puertos_resumen": ", ".join(lista_puertos_str) if lista_puertos_str else "Sin puertos abiertos detectados",
            "num_puertos": len(lista_puertos_str),
            "origen": " + ".join(sorted(h["origen"])),
            "observacion": " ".join(obs_equipo) if obs_equipo else "Activo verificado en red",
            "es_rango_proxy": False,
        })

        # Si esta MAC tenía rango de IPs secundarias colapsadas por Proxy ARP, añadir 1 único nodo resumen
        if mac_actual in ips_colapsadas_por_mac and ip_key == ips_colapsadas_por_mac[mac_actual]["principales"][-1]:
            info_col = ips_colapsadas_por_mac[mac_actual]
            sec_ips = info_col["secundarias"]
            rango_lbl = f"{sec_ips[0]} - {sec_ips[-1]} ({len(sec_ips)} IPs)"
            incluye_red_bcast = any(x.endswith(".0") or x.endswith(".255") for x in sec_ips)
            detalle_bcast = " (incluye .0 de red y .255 de broadcast)" if incluye_red_bcast else ""
            equipos.append({
                "ip": rango_lbl,
                "host": f"Alias ARP ({len(sec_ips)} direcciones)",
                "mac": mac_actual,
                "vendor": info_col["vendor"] or ND,
                "so": "Respuesta delegada L2 (Proxy ARP)",
                "rol": "Rango Proxy ARP / Multi-IP",
                "rol_tipo": "files",
                "ports_dict": {},
                "puertos_lista": [],
                "puertos_resumen": f"{len(sec_ips)} IPs responden con la misma MAC (0 puertos)",
                "num_puertos": 0,
                "origen": "Netdiscover + Nmap",
                "observacion": (
                    f"Anomalía: La MAC {mac_actual} responde a {info_col['total']} IPs{detalle_bcast}. "
                    f"No son {info_col['total']} máquinas físicas distintas, sino Proxy ARP / Client Isolation del gateway."
                ),
                "es_rango_proxy": True,
            })

        etiqueta_equipo = f"{h['ip']} ({h['host']})" if h.get("host") and h["host"] != h["ip"] else h["ip"]
        for k in ports_sorted:
            n_info = ports_dict[k]
            s_info = sss.get(k, {}) if len(merged) == 1 else {}
            clave_p = f"{k[0]}/{k[1]}"
            e_info = extra.get(f"{h['ip']}:{clave_p}") or extra.get(clave_p, {})
            servicio = n_info.get("servicio", ND)
            software = n_info.get("version") or ND
            proceso = s_info.get("proceso") or (f"{servicio.replace('?', '')}/root" if servicio != ND else ND)
            obs_def = f"Servicio {servicio} en {h['ip']}."
            if "?" in servicio:
                obs_def = f"Puerto {clave_p} abierto en {h['ip']}; servicio ({servicio}) estimado por número de puerto sin confirmación de banner."
            elif software != ND:
                obs_def = f"Servicio {servicio} ({software}) expuesto en {h['ip']}."
            inventario_infra.append({
                "equipo_ip": etiqueta_equipo,
                "puerto": clave_p,
                "servicio": servicio,
                "software": software,
                "proceso": proceso,
                "acceso": accesible(s_info["bind"]) if s_info else "Red local",
                "necesario": e_info.get("necesario", ND),
                "obs": e_info.get("obs", obs_def),
            })

    # Calcular subredes detectadas (ej: 192.168.1.0/24)
    subredes = []
    for ip_k in sorted_ips:
        m_sub = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$", ip_k)
        if m_sub:
            sub = f"{m_sub.group(1)}.0/24"
            if sub not in subredes:
                subredes.append(sub)
    rango_principal = ", ".join(rangos) if rangos else (", ".join(subredes) if subredes else "Segmento local")

    # Redactar observaciones automáticas de infraestructura para la Sección 3.3 (100% genéricas y basadas en los datos)
    observaciones_auto = []
    for mac_val, info_col in ips_colapsadas_por_mac.items():
        sec_ips = info_col["secundarias"]
        princ_str = ", ".join(info_col["principales"])
        incluye_extremos = any(x.endswith(".0") or x.endswith(".255") for x in sec_ips)
        extremos_txt = " (incluyendo las direcciones de red .0 y broadcast .255)" if incluye_extremos else ""
        idx_num = len(observaciones_auto) + 1
        observaciones_auto.append(
            f"{idx_num}. Anomalía de MAC única para múltiples IPs (Proxy ARP / Aislamiento L2): La dirección MAC {mac_val} ({info_col['vendor']}) "
            f"responde como activa para {info_col['total']} direcciones IP distintas ({sec_ips[0]} a {sec_ips[-1]}){extremos_txt}. "
            f"Esto no significa que existan {info_col['total']} máquinas físicas conectadas, sino que la pasarela/controlador ({princ_str}) "
            f"tiene habilitado Proxy ARP y/o Client Isolation en capa 2, respondiendo a las solicitudes ARP de toda la subred."
        )

    for ip_k in sorted_ips:
        if ip_k in ips_omitidas:
            continue
        h_item = merged[ip_k]
        p_dict = h_item.get("ports", {})
        puertos_incognita = [f"{p}/{pr} ({info_p.get('servicio')})" for (p, pr), info_p in p_dict.items() if "?" in (info_p.get("servicio") or "")]
        so_val = h_item.get("so") or ""
        if puertos_incognita or "estimado" in so_val.lower():
            idx_num = len(observaciones_auto) + 1
            detalles_amb = []
            if "estimado" in so_val.lower():
                detalles_amb.append(f"huella de SO aproximada '{so_val}'")
            if puertos_incognita:
                detalles_amb.append(f"servicios sin banner verificado ({', '.join(puertos_incognita)})")
            observaciones_auto.append(
                f"{idx_num}. Respuestas ambiguas o intercepción de tráfico en {ip_k} ({h_item.get('vendor') or 'Host'}): "
                f"Se detectó {' y '.join(detalles_amb)}. Cuando un controlador de red, portal cautivo o firewall intermedio "
                f"intercepta conexiones TCP, Nmap no recibe banners de aplicación reales (marcando los puertos con '?') y puede "
                f"estimar un sistema operativo inexacto."
            )

    if not observaciones_auto and equipos:
        observaciones_auto.append(
            f"Se han identificado {len(equipos)} nodo(s) en el segmento {rango_principal} con un total de {len(inventario_infra)} puerto(s) abiertos."
        )

    equipos_fisicos = len(mac_groups) if mac_groups else len(equipos)

    resumen_red = {
        "rango": rango_principal,
        "subredes": subredes,
        "total_equipos": total_ips_brutas,
        "macs_unicas": equipos_fisicos,
        "ips_proxy_arp": len(ips_omitidas),
        "total_ips_arp": total_ips_brutas,
        "proxy_arp_activo": bool(proxy_arp_macs),
        "equipos_con_puertos": sum(1 for e in equipos if e["num_puertos"] > 0),
        "total_puertos": len(inventario_infra),
        "observaciones_auto": "\n\n".join(observaciones_auto),
    }

    return equipos, inventario_infra, resumen_red


def generar_topografia_html(equipos, resumen_red):
    """
    Construye el bloque visual HTML + SVG vectorial con la Topografía de Red de la infraestructura.
    No emplea emojis e incluye soporte completo para impresión PDF y modo oscuro.
    """
    if not equipos:
        return "<p style='color:var(--text-muted);'>No se detectaron equipos activos para generar la topografía.</p>"

    rango_txt = esc(resumen_red.get("rango", "Red Local"))
    macs_unicas = resumen_red.get("macs_unicas", len(equipos))
    total_ips_arp = resumen_red.get("total_ips_arp", len(equipos))
    proxy_arp = resumen_red.get("proxy_arp_activo", False)
    con_srv = resumen_red.get("equipos_con_puertos", 0)
    total_pts = resumen_red.get("total_puertos", 0)

    eq_kpi_str = f"{macs_unicas} físicos ({total_ips_arp} IPs Proxy ARP)" if proxy_arp else str(macs_unicas)

    # Disposición de nodos en cuadrícula conectada al bus de conmutación
    cols = min(4, max(1, len(equipos)))
    filas_nodos = [equipos[i:i + cols] for i in range(0, len(equipos), cols)]

    svg_w = 920
    card_w = 204
    card_h = 128
    gap_x = 18
    row_gap_y = 168
    top_bus_y = 92
    svg_h = top_bus_y + len(filas_nodos) * row_gap_y + 20
    cx_root = svg_w // 2

    svg_elems = []

    # Troncal vertical desde el nodo central de subred hasta la última fila del bus
    last_bus_y = top_bus_y + (len(filas_nodos) - 1) * row_gap_y
    svg_elems.append(
        f'<line x1="{cx_root}" y1="58" x2="{cx_root}" y2="{last_bus_y}" class="svg-line" stroke-width="2.5" stroke-dasharray="5,3"/>'
    )

    # Nodo raíz: Segmento de Red / Switch Principal
    root_w = 390
    root_x = cx_root - (root_w // 2)
    svg_elems.append(f"""
    <g>
      <rect x="{root_x}" y="12" width="{root_w}" height="46" rx="7" fill="#1b3a5f" stroke="#2563eb" stroke-width="1.8"/>
      <text x="{cx_root}" y="31" text-anchor="middle" fill="#ffffff" font-size="11.5" font-weight="700" font-family="Segoe UI, Arial, sans-serif">SEGMENTO DE INFRAESTRUCTURA: {rango_txt[:34]}</text>
      <text x="{cx_root}" y="47" text-anchor="middle" fill="#93c5fd" font-size="10" font-family="Consolas, monospace">{esc(eq_kpi_str)} | {con_srv} con Puertos | {total_pts} Servicios</text>
    </g>
    """)

    colores_rol = {
        "gateway": "#0284c7",
        "dc": "#7c3aed",
        "db": "#0d9488",
        "web": "#2563eb",
        "files": "#d97706",
        "server": "#1b3a5f",
        "host": "#475569",
    }

    for r_idx, fila in enumerate(filas_nodos):
        n_en_fila = len(fila)
        row_total_w = n_en_fila * card_w + (n_en_fila - 1) * gap_x
        start_x = (svg_w - row_total_w) / 2.0
        bus_y = top_bus_y + r_idx * row_gap_y
        card_y = bus_y + 20

        # Calcular extremos del bus horizontal de esta fila
        first_cx = start_x + card_w / 2.0
        last_cx = start_x + (n_en_fila - 1) * (card_w + gap_x) + card_w / 2.0
        bus_left = min(first_cx, cx_root)
        bus_right = max(last_cx, cx_root)

        svg_elems.append(
            f'<line x1="{bus_left:.1f}" y1="{bus_y}" x2="{bus_right:.1f}" y2="{bus_y}" class="svg-line" stroke-width="2"/>'
        )
        svg_elems.append(
            f'<circle cx="{cx_root}" cy="{bus_y}" r="4" fill="#2563eb"/>'
        )

        for c_idx, eq in enumerate(fila):
            x = start_x + c_idx * (card_w + gap_x)
            cx = x + card_w / 2.0
            color_cab = colores_rol.get(eq.get("rol_tipo", "host"), "#475569")

            # Línea de bajada desde el bus al equipo
            svg_elems.append(
                f'<line x1="{cx:.1f}" y1="{bus_y}" x2="{cx:.1f}" y2="{card_y}" class="svg-line" stroke-width="1.8"/>'
            )
            svg_elems.append(
                f'<circle cx="{cx:.1f}" cy="{bus_y}" r="3.2" fill="{color_cab}"/>'
            )

            ip_raw = eq["ip"]
            ip_label = esc(ip_raw[:24] + (".." if len(ip_raw) > 24 else ""))
            rol_label = esc((eq["rol"] or "Equipo")[:28].upper())

            # Hostname o fabricante resumido
            sub_str = eq["host"] if eq["host"] != ND and eq["host"] != eq["ip"] else (eq["vendor"] if eq["vendor"] != ND else "Host detectado")
            if len(sub_str) > 27:
                sub_str = sub_str[:25] + ".."
            sub_label = esc(sub_str)

            mac_str = eq["mac"] if eq["mac"] != ND else "MAC no disponible"
            mac_label = esc(mac_str[:24])

            so_str = eq["so"] if eq["so"] != ND else "SO sin huella activa"
            if len(so_str) > 27:
                so_str = so_str[:25] + ".."
            so_label = esc(so_str)

            pts_list = eq.get("puertos_lista", [])
            if pts_list:
                pts_preview = ", ".join(pts_list[:4])
                if len(pts_list) > 4:
                    pts_preview += f" (+{len(pts_list) - 4})"
                pts_str = f"Puertos ({len(pts_list)}): {pts_preview}"
                pts_fill = "#15803d"
                pts_bg = "#dcfce7"
            elif eq.get("rol_tipo") == "files" and "Proxy ARP" in (eq.get("rol") or ""):
                pts_str = "Proxy ARP (MAC repetida)"
                pts_fill = "#b45309"
                pts_bg = "#fef3c7"
            else:
                pts_str = "ARP Activo (0 puertos)"
                pts_fill = "#475569"
                pts_bg = "#f1f5f9"

            if len(pts_str) > 29:
                pts_str = pts_str[:27] + ".."
            pts_label = esc(pts_str)

            svg_elems.append(f"""
            <g>
              <rect x="{x:.1f}" y="{card_y}" width="{card_w}" height="{card_h}" rx="6" class="svg-card" stroke="{color_cab}" stroke-width="1.6"/>
              <rect x="{x:.1f}" y="{card_y}" width="{card_w}" height="22" rx="5" fill="{color_cab}"/>
              <text x="{cx:.1f}" y="{card_y + 14.5}" text-anchor="middle" fill="#ffffff" font-size="9.5" font-weight="700" font-family="Segoe UI, Arial, sans-serif">{rol_label}</text>
              <text x="{cx:.1f}" y="{card_y + 39}" text-anchor="middle" class="svg-text-main" font-size="11.5" font-weight="700" font-family="Consolas, monospace">{ip_label}</text>
              <text x="{cx:.1f}" y="{card_y + 55}" text-anchor="middle" class="svg-text-muted" font-size="10" font-family="Segoe UI, Arial, sans-serif">{sub_label}</text>
              <text x="{cx:.1f}" y="{card_y + 71}" text-anchor="middle" class="svg-text-muted" font-size="9.5" font-family="Consolas, monospace">{mac_label}</text>
              <text x="{cx:.1f}" y="{card_y + 86}" text-anchor="middle" class="svg-text-muted" font-size="9.5" font-family="Segoe UI, Arial, sans-serif">{so_label}</text>
              <rect x="{x + 10:.1f}" y="{card_y + 96}" width="{card_w - 20}" height="22" rx="4" fill="{pts_bg}"/>
              <text x="{cx:.1f}" y="{card_y + 110.5}" text-anchor="middle" fill="{pts_fill}" font-size="9.5" font-weight="700" font-family="Consolas, monospace">{pts_label}</text>
            </g>
            """)

    return f"""
    <div class="topo-box">
      <div class="topo-kpis">
        <div class="topo-kpi">
          <span class="topo-kpi-label">Subred / Segmento</span>
          <span class="topo-kpi-val">{rango_txt}</span>
        </div>
        <div class="topo-kpi">
          <span class="topo-kpi-label">{'Equipos Físicos (MACs)' if proxy_arp else 'Equipos Descubiertos'}</span>
          <span class="topo-kpi-val">{esc(eq_kpi_str)}</span>
        </div>
        <div class="topo-kpi">
          <span class="topo-kpi-label">Equipos con Servicios</span>
          <span class="topo-kpi-val">{con_srv}</span>
        </div>
        <div class="topo-kpi">
          <span class="topo-kpi-label">Puertos Abiertos Totales</span>
          <span class="topo-kpi-val">{total_pts}</span>
        </div>
      </div>
      <div class="topo-svg-container">
        <svg viewBox="0 0 {svg_w} {svg_h}" width="100%" height="auto" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Topografía de Red">
          <rect x="0" y="0" width="{svg_w}" height="{svg_h}" rx="8" class="svg-bg"/>
          {''.join(svg_elems)}
        </svg>
      </div>
    </div>
    """


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
    """Escanea la carpeta en busca de evidencias en texto y extrae metadatos (individuales y de infraestructura)."""
    info_extra = {}
    nmaps = {}
    sss = {}
    anexos = []
    netdiscovers = []
    nmaps_hosts = {}
    herram_auto = []

    if verbose:
        print(f"[*] [Verbose] Explorando carpeta de evidencias: {carpeta}")

    try:
        ficheros = sorted(carpeta.iterdir())
    except PermissionError:
        print(f"[!] Error de permisos: No se tiene acceso para listar la carpeta '{carpeta}'.", file=sys.stderr)
        return info_extra, nmaps, sss, anexos, netdiscovers, nmaps_hosts, herram_auto
    except OSError as e:
        print(f"[!] Error del sistema al acceder a la carpeta '{carpeta}': {e}", file=sys.stderr)
        return info_extra, nmaps, sss, anexos, netdiscovers, nmaps_hosts, herram_auto

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

        # Netdiscover / ARP Scan
        if es_netdiscover(f.name, txt):
            nd_parsed = parse_netdiscover(txt)
            if nd_parsed["hosts"]:
                netdiscovers.append(nd_parsed)
                herram_auto.append([
                    "Netdiscover",
                    "0.10",
                    "Descubrimiento ARP de equipos en red",
                    f"netdiscover ({f.name})",
                    "",
                ])
                if verbose:
                    print(f"       [+] Detectados {len(nd_parsed['hosts'])} equipos activos en {f.name} (Netdiscover).")
            relacion = "Sección 3 (Topografía e inventario de equipos en red)"
            anexos.append((f.name, limpiar_ansi(txt), relacion))
            continue

        # Nmap (individual o de red completa)
        if "nmap" in n or "Nmap scan report" in txt or "PORT   STATE SERVICE" in txt:
            detected_ports = parse_nmap(txt)
            nmaps.update(detected_ports)

            multi_hosts = parse_nmap_multi(txt, f.name)
            for h_key, h_info in multi_hosts.items():
                existing = nmaps_hosts.setdefault(h_key, {
                    "ip": h_info["ip"],
                    "host": "",
                    "mac": "",
                    "vendor": "",
                    "so": "",
                    "ports": {},
                })
                if h_info.get("host") and not existing["host"]:
                    existing["host"] = h_info["host"]
                if h_info.get("mac") and not existing["mac"]:
                    existing["mac"] = h_info["mac"]
                if h_info.get("vendor") and not existing["vendor"]:
                    existing["vendor"] = h_info["vendor"]
                if h_info.get("so") and not existing["so"]:
                    existing["so"] = h_info["so"]
                existing["ports"].update(h_info.get("ports", {}))

            m_ver_nmap = re.search(r"Nmap\s+([\d.]+)", txt)
            ver_nmap = m_ver_nmap.group(1) if m_ver_nmap else "7.9x"
            m_cmd_nmap = re.search(r"Nmap .* as:\s*([^\r\n]+)", txt)
            cmd_nmap = m_cmd_nmap.group(1).strip() if m_cmd_nmap else f"nmap ({f.name})"
            m_fecha_nmap = re.search(r"Starting Nmap [\d.]+ .* at (\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})", txt)
            fecha_nmap = m_fecha_nmap.group(1).strip() if m_fecha_nmap else ""
            herram_auto.append([
                "Nmap",
                ver_nmap,
                f"Escaneo de red y servicios ({len(multi_hosts)} host(s))",
                cmd_nmap,
                fecha_nmap,
            ])

            if verbose:
                print(f"       [+] Nmap ({f.name}): {len(multi_hosts)} equipo(s) y {len(detected_ports)} puerto(s) abiertos.")

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
            else:
                m_os_guess = re.search(r"(?:Running \(JUST GUESSING\)|Aggressive OS guesses):\s*([^\r\n]+)", txt)
                if m_os_guess:
                    primer_guess = m_os_guess.group(1).split(",")[0].strip()
                    info_extra.setdefault("so", f"{primer_guess} (estimado por Nmap)")

        # ss / netstat
        elif "ss" in n or "netstat" in n or "Local Address:Port" in txt or ("LISTEN" in txt and "tcp" in txt):
            detected_sockets = parse_ss(txt)
            sss.update(detected_sockets)
            herram_auto.append([
                "ss / iproute2",
                "Sistema",
                "Inspección local de sockets en escucha",
                f"ss -tulpn ({f.name})",
                "",
            ])
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
            relacion = "Sección 3 y 4 (Equipos e inventario de servicios)"
        elif "ss" in n or "netstat" in n:
            relacion = "Sección 4 y 5.2"
        elif "find" in n or "perm" in n:
            relacion = "Sección 5.3 y Permisos de ficheros"

        anexos.append((f.name, txt, relacion))

    return info_extra, nmaps, sss, anexos, netdiscovers, nmaps_hosts, herram_auto


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

.topo-box {
  margin: 14px 0 22px 0;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  background: var(--bg-page);
}
.topo-kpis {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}
.topo-kpi {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-left: 4px solid var(--accent);
  border-radius: 6px;
  padding: 10px 14px;
  display: flex;
  flex-direction: column;
}
.topo-kpi-label {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  font-weight: 700;
}
.topo-kpi-val {
  font-size: 18px;
  font-weight: 700;
  color: var(--primary);
  margin-top: 2px;
}
@media (prefers-color-scheme: dark) {
  .topo-kpi-val { color: var(--text-main); }
}
.topo-svg-container {
  width: 100%;
  overflow-x: auto;
  border-radius: 6px;
}
.svg-bg { fill: #f8fafc; stroke: #cbd5e1; stroke-width: 1; }
.svg-card { fill: #ffffff; }
.svg-line { stroke: #64748b; }
.svg-text-main { fill: #0f172a; }
.svg-text-muted { fill: #475569; }
@media (prefers-color-scheme: dark) {
  .svg-bg { fill: #0f172a; stroke: #334155; }
  .svg-card { fill: #1e293b; }
  .svg-line { stroke: #64748b; }
  .svg-text-main { fill: #f1f5f9; }
  .svg-text-muted { fill: #94a3b8; }
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
  .vuln-card, .topo-box { page-break-inside: avoid; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .svg-bg { fill: #f8fafc !important; stroke: #cbd5e1 !important; }
  .svg-card { fill: #ffffff !important; }
  .svg-text-main { fill: #0f172a !important; }
  .svg-text-muted { fill: #475569 !important; }
}
"""


# ---------------------------------------------------------------- Generar HTML
def generar_controles_y_hallazgos_infra(equipos, inventario_infra, resumen_red, fecha_ref):
    """
    Genera controles de seguridad de red (Sección 5) y hallazgos automáticos (Sección 6 y 8)
    basados en la evidencia real de Netdiscover y Nmap cuando se audita una infraestructura
    sin ficheros locales manuales (controles.txt / hallazgos.txt).
    """
    ips_proxy = resumen_red.get("ips_proxy_arp", 0)
    macs_unicas = resumen_red.get("macs_unicas", 0)
    total_ips = resumen_red.get("total_equipos", 0)

    puertos_http_plano = []
    banners_expuestos = []
    puertos_inseguros_o_voip = []
    tiene_https = False

    for item in inventario_infra:
        p = item["puerto"]
        ip_eq = item["equipo_ip"]
        sw = item["software"]
        srv = item["servicio"]
        if p == "443/tcp" or "https" in srv.lower() or "ssl" in srv.lower():
            tiene_https = True
        if p in ("80/tcp", "8080/tcp") and "https" not in srv.lower():
            puertos_http_plano.append(f"{ip_eq} ({p} - {sw if sw != ND else srv})")
        if sw and sw != ND and any(ch.isdigit() for ch in sw):
            banners_expuestos.append(f"{ip_eq} ({p}: {sw})")
        if p.startswith(("21/", "23/", "2000/", "5060/")):
            puertos_inseguros_o_voip.append(f"{ip_eq} ({p} {srv})")

    # Controles de red (Sección 5)
    ctrl_proxy_val = (
        f"Detectadas {ips_proxy} IPs clonadas bajo una misma MAC (Proxy ARP activo)"
        if ips_proxy > 0
        else "Cada dirección IP responde con su propia dirección MAC única"
    )
    ctrl_proxy_est = "No cumple" if ips_proxy > 0 else "Cumple"

    ctrl_http_val = (
        f"HTTP sin cifrar activo en: {', '.join(puertos_http_plano)}"
        if puertos_http_plano
        else ("HTTPS activo" if tiene_https else "Sin paneles web expuestos")
    )
    ctrl_http_est = "No cumple" if (puertos_http_plano and not tiene_https) else "Cumple"

    ctrl_banner_val = (
        f"Expuesta ({', '.join(banners_expuestos)})"
        if banners_expuestos
        else "Versiones ocultas o no divulgadas en cabeceras"
    )
    ctrl_banner_est = "No cumple" if banners_expuestos else "Cumple"

    ctrl_voip_val = (
        f"Expuestos ({', '.join(puertos_inseguros_o_voip)})"
        if puertos_inseguros_o_voip
        else "Ningún puerto FTP/Telnet/VoIP expuesto"
    )
    ctrl_voip_est = "No cumple" if puertos_inseguros_o_voip else "Cumple"

    controles_infra = [
        {
            "titulo": "5.1 Segmentación de red y capa de enlace (ARP / VLAN)",
            "filas": [
                [
                    "Ausencia de respuestas Proxy ARP masivas en el segmento",
                    "netdiscover / nmap -sn (análisis de tabla ARP)",
                    ctrl_proxy_val,
                    ctrl_proxy_est,
                ],
                [
                    "Correspondencia de equipos físicos (MACs reales vs IPs)",
                    "Consolidación de direcciones MAC OUI",
                    f"{macs_unicas} MAC(s) física(s) única(s) para {total_ips} IP(s) activas",
                    "Cumple" if ips_proxy == 0 else "No verificado",
                ],
            ],
        },
        {
            "titulo": "5.2 Exposición de servicios y filtrado perimetral",
            "filas": [
                [
                    "Superficie de servicios expuestos en la subred",
                    "nmap -sV (escaneo de puertos TCP/UDP)",
                    f"{resumen_red.get('equipos_con_puertos', 0)} host(s) con puertos abiertos ({resumen_red.get('total_puertos', 0)} puerto(s) en total)",
                    "Cumple" if resumen_red.get("total_puertos", 0) <= 5 else "No cumple",
                ],
                [
                    "Restricción de protocolos en texto claro o señalización (FTP, Telnet, SIP, VoIP)",
                    "nmap -sV (puertos de transferencia y señalización)",
                    ctrl_voip_val,
                    ctrl_voip_est,
                ],
            ],
        },
        {
            "titulo": "5.3 Cifrado y endurecimiento de servicios de administración",
            "filas": [
                [
                    "Paneles de administración web exclusivamente sobre HTTPS (TLS)",
                    "nmap -p 80,443,8080",
                    ctrl_http_val,
                    ctrl_http_est,
                ],
                [
                    "Ocultación de versión de servidor y banners de software",
                    "nmap -sV (inspección de banners)",
                    ctrl_banner_val,
                    ctrl_banner_est,
                ],
            ],
        },
    ]

    # Hallazgos automáticos de red (Secciones 6 y 8)
    hallazgos_infra = []
    idx = 1

    if puertos_http_plano or banners_expuestos:
        comp_str = ", ".join(puertos_http_plano or banners_expuestos)
        hallazgos_infra.append({
            "id": f"VUL-{idx:02d}",
            "titulo": "Servicio web de administración sobre HTTP sin cifrar y divulgación de versión de software",
            "cve": "CWE-319 / CWE-200",
            "componente": comp_str,
            "descripcion": (
                "Se ha detectado un servicio HTTP activo sin cifrado TLS (el puerto 443/tcp se encuentra "
                "filtrado o cerrado) que además expone de forma pública el nombre y versión exacta del servidor web en sus cabeceras."
            ),
            "deteccion": "Escaneo de versiones y puertos con Nmap (-sV).",
            "evidencia": f"Respuesta Nmap en {comp_str}.",
            "severidad": "Media",
            "probabilidad_e_impacto": "Probabilidad Media / Impacto Medio (interceptación de tráfico en red local y enumeración de versión).",
            "exploit": "No requiere exploit para captura pasiva o fingerprinting",
            "estado": "Abierta",
            "recomendacion": (
                "Deshabilitar el acceso administrativo sobre HTTP plano o forzar redirección a HTTPS (443/tcp) con TLS 1.2/1.3, "
                "y ocultar la etiqueta de versión en la configuración del servidor web."
            ),
            "accion": "Habilitar HTTPS (TLS 1.2+) y ocultar el banner de versión en el servicio web expuesto.",
            "mitigacion": "Restringir el acceso al puerto HTTP exclusivamente a la VLAN de gestión.",
            "responsable": "Administración de Red / Sistemas",
            "fecha_limite": fecha_ref,
            "esfuerzo": "Bajo",
            "estado_plan": "Pendiente",
            "prioridad": "1",
        })
        idx += 1

    if puertos_inseguros_o_voip:
        comp_voip = ", ".join(puertos_inseguros_o_voip)
        hallazgos_infra.append({
            "id": f"VUL-{idx:02d}",
            "titulo": "Exposición de puertos de transferencia en texto claro o señalización de voz (FTP / Telnet / VoIP)",
            "cve": "CWE-284",
            "componente": comp_voip,
            "descripcion": (
                "Se han detectado abiertos hacia el segmento auditado puertos asociados a transferencia en texto claro "
                "o señalización de telefonía/voz, aumentando la superficie de ataque en la red local."
            ),
            "deteccion": "Escaneo de puertos y servicios con Nmap.",
            "evidencia": f"Puertos detectados en estado open: {comp_voip}.",
            "severidad": "Media",
            "probabilidad_e_impacto": "Probabilidad Media / Impacto Medio (enumeración o acceso no autorizado a servicios internos).",
            "exploit": "No verificado",
            "estado": "Abierta",
            "recomendacion": (
                "Aplicar listas de control de acceso (ACL) en el equipo o controlador de red para restringir el acceso desde "
                "clientes a los puertos expuestos innecesarios."
            ),
            "accion": f"Filtrar mediante ACL de cortafuegos los puertos expuestos ({comp_voip}).",
            "mitigacion": "Segmentar el tráfico de gestión y señalización en una VLAN dedicada.",
            "responsable": "Administración de Red",
            "fecha_limite": fecha_ref,
            "esfuerzo": "Bajo",
            "estado_plan": "Pendiente",
            "prioridad": "2",
        })
        idx += 1

    if ips_proxy > 0:
        hallazgos_infra.append({
            "id": f"VUL-{idx:02d}",
            "titulo": "Respuesta ARP masiva (Proxy ARP) / Enmascaramiento de subred bajo una única dirección MAC",
            "cve": "CWE-706",
            "componente": f"Segmento {resumen_red.get('rango', ND)} ({ips_proxy} IPs secundarias clonadas)",
            "descripcion": (
                "Una única interfaz física de pasarela responde a las solicitudes ARP de múltiples direcciones del rango "
                "de red (incluyendo direcciones de red .0 y broadcast .255 cuando aplica), haciendo que los escáneres de red "
                "reporten cientos de hosts aparentes que en realidad corresponden al mismo equipo físico."
            ),
            "deteccion": "Descubrimiento ARP pasivo/activo con Netdiscover y Nmap (-sn).",
            "evidencia": resumen_red.get("observaciones_auto", "Múltiples IPs asociadas a una sola dirección MAC."),
            "severidad": "Baja",
            "probabilidad_e_impacto": "Probabilidad Baja / Impacto Bajo (distorsión de inventario y monitorización de red).",
            "exploit": "No aplica (configuración de capa 2 / Proxy ARP)",
            "estado": "Abierta",
            "recomendacion": (
                "Verificar si Proxy ARP es estrictamente necesario para el aislamiento de clientes (Client Isolation). Si no es "
                "requerido por diseño, deshabilitar Proxy ARP en la interfaz del gateway para evitar respuestas ARP sobre IPs "
                "no asignadas."
            ),
            "accion": "Revisar y ajustar la configuración de Proxy ARP en la interfaz de la pasarela de red.",
            "mitigacion": "Documentar la configuración de Proxy ARP / Client Isolation en el inventario de red.",
            "responsable": "Administración de Red",
            "fecha_limite": fecha_ref,
            "esfuerzo": "Bajo",
            "estado_plan": "Pendiente",
            "prioridad": "3",
        })

    return controles_infra, hallazgos_infra


def generar_html(carpeta, cli_overrides=None, salida_destino=None, verbose=False):
    carpeta = Path(carpeta)
    cli_overrides = cli_overrides or {}
    auto_info, nmaps, sss, anexos, netdiscovers, nmaps_hosts, herram_auto = autodetectar_ficheros(carpeta, verbose=verbose)

    # 1. Metadatos Generales
    g = {}
    if (carpeta / "general.txt").exists():
        g.update(parse_kv(leer(carpeta / "general.txt")))
        if verbose:
            print("    [+] Leído general.txt existente.")

    # 2. Servicios adicionales desde servicios.txt
    extra = {}
    if (carpeta / "servicios.txt").exists():
        for p, nec, obs in parse_tabla(leer(carpeta / "servicios.txt"), 3):
            extra[p] = {"necesario": nec or ND, "obs": obs}

    # Consolidación de infraestructura (Netdiscover + múltiples Nmaps)
    equipos, inventario_infra, resumen_red = consolidar_infraestructura(netdiscovers, nmaps_hosts, sss, extra)

    # Determinar modo de auditoría: 'equipo' vs 'infra'
    modo_cfg = norm(cli_overrides.get("modo") or g.get("modo") or "auto")
    if modo_cfg in ("infra", "infraestructura", "red", "network"):
        modo_efectivo = "infra"
    elif modo_cfg in ("equipo", "host", "individual", "single"):
        modo_efectivo = "equipo"
    else:
        modo_efectivo = "infra" if (len(netdiscovers) > 0 or len(equipos) > 1) else "equipo"

    if verbose:
        print(f"[*] [Verbose] Modo de informe activo: {'Infraestructura de Red' if modo_efectivo == 'infra' else 'Equipo Único'} ({len(equipos)} equipo(s) detectados).")

    # Si estamos en modo infraestructura, rellenar valores resumen por defecto en Sección 2 y 3 si no estaban en general.txt
    if modo_efectivo == "infra" and equipos:
        macs_txt = f"{resumen_red.get('macs_unicas', len(equipos))} equipos físicos (MACs únicas)"
        if resumen_red.get("ips_proxy_arp", 0) > 0:
            macs_txt += f" / {resumen_red['total_equipos']} IPs respondieron por Proxy ARP"
        auto_info["activo"] = f"Infraestructura de red ({resumen_red['rango']}) — {macs_txt}"
        auto_info["tipo_de_analisis"] = "Caja negra / Escaneo de red local (ARP y TCP)"
        ips_principales = [e["ip"] for e in equipos if not e.get("es_rango_proxy")][:6]
        ips_sample = ", ".join(ips_principales)
        if resumen_red.get("ips_proxy_arp", 0) > 0:
            ips_sample += f" (+ {resumen_red['ips_proxy_arp']} IPs secundarias en Proxy ARP)"
        auto_info["host"] = f"Segmento {resumen_red['rango']} ({macs_txt})"
        auto_info["ip_mac"] = ips_sample
        sos_unicos = sorted({e["so"] for e in equipos if e["so"] != ND and not e.get("es_rango_proxy")})
        if sos_unicos:
            auto_info["so"] = " / ".join(sos_unicos[:4])
        roles_unicos = sorted({e["rol"] for e in equipos if e.get("rol") and not e.get("es_rango_proxy")})
        auto_info["tipo_de_equipo"] = f"Infraestructura de red ({', '.join(roles_unicos[:3])})"
        auto_info["funcion"] = f"Pasarela y controladores de red / {resumen_red['equipos_con_puertos']} host(s) con servicios expuestos ({resumen_red['total_puertos']} puertos abiertos)"
        if resumen_red.get("observaciones_auto"):
            auto_info["observaciones_red"] = resumen_red["observaciones_auto"]
        auto_info["resumen"] = (
            f"Auditoría técnica de red sobre el segmento {resumen_red['rango']}. Aunque los barridos iniciales devolvieron "
            f"{resumen_red['total_equipos']} direcciones IP aparentes, el análisis de capa de enlace (MAC OUI) demostró la existencia "
            f"de {resumen_red.get('macs_unicas', len(equipos))} equipo(s) físico(s) real(es)"
            + (
                f", debido a que una misma dirección MAC responde mediante Proxy ARP a {resumen_red['ips_proxy_arp']} direcciones IP adicionales del rango. "
                if resumen_red.get("ips_proxy_arp", 0) > 0
                else ". "
            )
            + f"Se identificaron {resumen_red['total_puertos']} puerto(s) abierto(s) distribuidos en {resumen_red['equipos_con_puertos']} equipo(s)."
        )

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

    inventario_equipo = construir_inventario(nmaps, sss, extra)
    if verbose:
        total_inv = len(inventario_infra) if modo_efectivo == "infra" else len(inventario_equipo)
        print(f"[*] [Verbose] Inventario consolidado: {total_inv} servicios/puertos detectados.")

    # 3. Controles y 4. Hallazgos (con generación automática inteligente en modo infraestructura)
    controles_infra_auto, hallazgos_infra_auto = generar_controles_y_hallazgos_infra(
        equipos, inventario_infra, resumen_red, g["fecha"]
    )

    if (carpeta / "controles.txt").exists():
        controles = parse_controles(leer(carpeta / "controles.txt"))
    elif modo_efectivo == "infra":
        controles = controles_infra_auto
    else:
        controles = parse_controles(PLANTILLA_CONTROLES_DEFAULT)

    if (carpeta / "hallazgos.txt").exists():
        hallazgos = parse_bloques(leer(carpeta / "hallazgos.txt"))
    elif modo_efectivo == "infra":
        hallazgos = hallazgos_infra_auto
    else:
        hallazgos = []

    # 5. Herramientas
    herram = parse_tabla(leer(carpeta / "herramientas.txt"), 5) if (carpeta / "herramientas.txt").exists() else herram_auto
    if herram:
        fechas_detectadas = [r[4] for r in herram if len(r) >= 5 and r[4].strip()]
        fecha_fallback_herram = fechas_detectadas[0] if fechas_detectadas else f"{g['fecha']} 10:00"
        for r in herram:
            if len(r) >= 5 and not r[4].strip():
                r[4] = fecha_fallback_herram

    # Construir HTML
    titulo = gv("titulo", "Informe de auditoría de seguridad")
    subtitulo_modo = "Modo Infraestructura de Red (Multi-Host + Topografía)" if modo_efectivo == "infra" else "Servicios, configuración y vulnerabilidades — Plantilla oficial · Versión 1.0"
    logo_dark_uri = obtener_logo_data_uri("1_logo_principal_fondo_oscuro.png")
    logo_light_uri = obtener_logo_data_uri("2_logo_completo_fondo_claro.png")
    icon_uri = obtener_logo_data_uri("3_icono_fondo_oscuro.png")
    fav_uri = obtener_logo_data_uri("4_icono_app_32x32_oscuro.png")
    out = []

    out.append(f"""
    <header class="brand-bar">
      <div class="brand">
        <span class="brand-bar-logo-wrap"><img src="{icon_uri}" alt="NetSpector"></span>
        <span>NetSpector</span> <span style="opacity:0.8; font-size:12px;">v{VERSION} · {'Infraestructura' if modo_efectivo == 'infra' else 'Equipo'}</span>
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
              <p>{esc(subtitulo_modo)}</p>
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

    # 3. Identificación (Equipo o Infraestructura con Topografía)
    infra_extra_sec3 = ""
    if modo_efectivo == "infra":
        topo_html = generar_topografia_html(equipos, resumen_red)
        filas_eq_html = ""
        for eq in equipos:
            if eq.get("es_rango_proxy"):
                badge_pts = '<span class="badge badge-stopped">Proxy ARP</span>'
            elif eq["num_puertos"] > 0:
                badge_pts = f'<span class="badge badge-cumple">{eq["num_puertos"]} abierto(s)</span>'
            else:
                badge_pts = '<span class="badge badge-nd">0 abiertos</span>'
            obs_eq = eq.get("observacion") or "—"
            filas_eq_html += (
                f"<tr>"
                f"<td style='font-weight:700; font-family:Consolas,monospace; color:var(--primary);'>{esc(eq['ip'])}</td>"
                f"<td style='font-family:Consolas,monospace; font-size:12px;'>{esc(eq['mac'])}</td>"
                f"<td>{esc(eq['vendor'])}</td>"
                f"<td style='font-weight:600;'>{esc(eq['host'])}</td>"
                f"<td>{esc(eq['so'])}</td>"
                f"<td>{esc(eq['rol'])}</td>"
                f"<td>{badge_pts} <span style='font-size:11.5px; color:var(--text-muted); margin-left:4px;'>{esc(eq['puertos_resumen'])}</span></td>"
                f"<td style='font-size:12px;'>{esc(obs_eq)}</td>"
                f"</tr>"
            )
        obs_red_texto = gv(
            "observaciones_red",
            resumen_red.get("observaciones_auto")
            or "Sin anomalías de capa de enlace (Proxy ARP / duplicidad MAC) detectadas. Puede añadir observaciones adicionales en la clave 'observaciones_red' de general.txt.",
        )
        infra_extra_sec3 = f"""
        <div class="subsection-title" style="margin-top:24px;">3.1 Topografía de la infraestructura (Mapa de Red)</div>
        {topo_html}
        <div class="subsection-title" style="margin-top:22px;">3.2 Inventario de equipos descubiertos (Netdiscover / Nmap)</div>
        <div class="table-container">
          <table class="pdf-table">
            <thead>
              <tr>
                <th>Dirección IP</th>
                <th>Dirección MAC</th>
                <th>Fabricante (Vendor)</th>
                <th>Hostname</th>
                <th>Sistema Operativo</th>
                <th>Rol inferido</th>
                <th>Puertos abiertos</th>
                <th>Observaciones</th>
              </tr>
            </thead>
            <tbody>
              {filas_eq_html or "<tr><td colspan='8' style='text-align:center;'>No se detectaron equipos en los ficheros de red.</td></tr>"}
            </tbody>
          </table>
        </div>
        <div class="subsection-title" style="margin-top:22px;">3.3 Observaciones de la infraestructura y anomalías de red</div>
        <div class="topo-box" style="border-left: 4px solid var(--warn); background: var(--bg-card);">
          <div style="font-size:12px; font-weight:700; color:var(--warn); text-transform:uppercase; margin-bottom:6px;">
            Notas técnicas del auditor sobre la topología, direccionamiento y respuestas ARP/ICMP
          </div>
          <div style="font-size:13px; line-height:1.6; white-space:pre-wrap;">{esc(obs_red_texto)}</div>
        </div>
        """

    out.append(f"""
    <section class="section" id="sec-3">
      <div class="section-title">3. Identificación del equipo{' / infraestructura' if modo_efectivo == 'infra' else ''}</div>
      <div class="table-container">
        <table class="pdf-table">
          <thead><tr><th style="width:32%;">Campo</th><th>Qué escribir</th></tr></thead>
          <tbody>
            <tr><td class="campo-key">{'Segmento / Nombre de red' if modo_efectivo == 'infra' else 'Nombre de host'}</td><td class="campo-val">{esc(gv("host"))}</td></tr>
            <tr><td class="campo-key">{'Direcciones IP detectadas' if modo_efectivo == 'infra' else 'Direccion IP / MAC'}</td><td class="campo-val">{esc(gv("ip_mac"))}</td></tr>
            <tr><td class="campo-key">Sistema operativo y versión</td><td class="campo-val">{esc(gv("so"))}</td></tr>
            <tr><td class="campo-key">Versión del kernel</td><td class="campo-val">{esc(gv("kernel"))}</td></tr>
            <tr><td class="campo-key">Tipo de equipo</td><td class="campo-val">{esc(gv("tipo_de_equipo", "Servidor"))}</td></tr>
            <tr><td class="campo-key">Función / criticidad</td><td class="campo-val">{esc(gv("funcion"))}</td></tr>
            <tr><td class="campo-key">Propietario</td><td class="campo-val">{esc(gv("propietario"))}</td></tr>
            <tr><td class="campo-key">Última fecha de arranque</td><td class="campo-val">{esc(gv("ultimo_arranque"))}</td></tr>
          </tbody>
        </table>
      </div>
      {infra_extra_sec3}
    </section>
    """)

    # 4. Inventario
    inv_filas = ""
    if modo_efectivo == "infra":
        for item in inventario_infra:
            inv_filas += (
                f"<tr>"
                f"<td style='font-weight:700; font-family:Consolas,monospace; color:var(--primary);'>{esc(item['equipo_ip'])}</td>"
                f"<td style='font-weight:600;'>{esc(item['puerto'])}</td>"
                f"<td>{esc(item['servicio'])}</td><td>{esc(item['software'])}</td>"
                f"<td>{esc(item['proceso'])}</td><td>{esc(item['acceso'])}</td>"
                f"<td>{esc(item['necesario'])}</td><td>{esc(item['obs'])}</td></tr>"
            )
        out.append(f"""
        <section class="section" id="sec-4">
          <div class="section-title">4. Inventario de servicios y puertos (Consolidado por Equipo)</div>
          <div class="table-container">
            <table class="pdf-table">
              <thead>
                <tr><th>Equipo / IP</th><th>Puerto / protocolo</th><th>Servicio</th><th>Software y versión</th><th>Proceso / usuario</th><th>Accesible desde</th><th>¿Necesario?</th><th>Observaciones</th></tr>
              </thead>
              <tbody>{inv_filas or "<tr><td colspan='8' style='text-align:center;'>Sin puertos abiertos detectados en los equipos analizados.</td></tr>"}</tbody>
            </table>
          </div>
        </section>
        """)
    else:
        for item in inventario_equipo:
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
    3. Si el usuario pasa -infra, se normaliza a --infra.
    """
    nuevo_argv = []
    conteo_n = 0
    for arg in argv:
        if arg == "-update":
            nuevo_argv.append("--update")
        elif arg == "-infra":
            nuevo_argv.append("--infra")
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
        description="NetSpector - Generador oficial de informes de auditoría de seguridad (Equipo e Infraestructura).",
        epilog="Ejemplo: python netspector.py -d ./mis_txt -e reporte.html -a 'Auditor' -f -n 'Auditoría Red' -m infra"
    )
    ap.add_argument("-d", "--directorio", dest="directorio", default=None, help="Carpeta de trabajo con los ficheros .txt")
    ap.add_argument("-e", "--salida", dest="salida", default=None, help="Nombre del archivo HTML o ruta completa donde guardarlo")
    ap.add_argument("-a", "--auditor", dest="auditor", default=None, help="Nombre del auditor")
    ap.add_argument("-f", "--fecha", dest="fecha", nargs="?", const="AUTO", default=None, help="Pone automáticamente la fecha de hoy en todos los campos de fecha")
    ap.add_argument("-n", "--nombre", "--titulo", dest="nombre", default=None, help="Nombre o título de la auditoría")
    ap.add_argument("-c", "-i", "--codigo", "--num", "--numero", dest="codigo", default=None, help="Número o código de informe (por defecto: AUD-YYYY-MM-DD-0 auto-incremental)")
    ap.add_argument("-m", "--modo", dest="modo", choices=["auto", "equipo", "infra", "infraestructura"], default="auto", help="Modo de informe: auto (por defecto), equipo o infra (infraestructura + topografía)")
    ap.add_argument("--infra", "--infraestructura", dest="forzar_infra", action="store_true", help="Fuerza el modo Infraestructura de Red (Netdiscover + múltiples Nmap + Topografía)")
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
    modo_elegido = "infra" if args.forzar_infra else args.modo
    cli_overrides = {
        "auditor": args.auditor,
        "nombre": args.nombre,
        "fecha": args.fecha,
        "codigo": args.codigo,
        "modo": modo_elegido,
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
