import os
import re
import sys
import time
import csv
import threading
from datetime import datetime
from typing import Optional, List, Dict, Tuple

# -------------------- Ajustes --------------------
VELOCIDAD_DEF = 9600
TIMEOUT_S = 0.0  # non-blocking lectura
LOGS_DIR = "logs"

# Interfaces
STATE_FILE = "interfaces_state.csv"
CHANGES_FILE = "interfaces_changes.csv"

# Inventario
INV_STATE_FILE = "inventory_state.csv"
INV_CHANGES_FILE = "inventory_changes.csv"

# -------------------- Regex útiles --------------------
RE_PROMPT_HOST = re.compile(r"^\s*([A-Za-z0-9._\-]+)\s*[>#]\s*$", re.M)
RE_PROMPT = re.compile(r"([A-Za-z0-9._\-]+)\s*([>#])\s*$")
RE_SERIE = re.compile(
    r"(?:Processor board ID\s+(\S+))|(?:SN:\s*([A-Za-z0-9\-]+))|(?:Serial Number:\s*([A-Za-z0-9\-]+))",
    re.IGNORECASE
)
RE_SERIE_VALIDA = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{4,24}$")

# Errores típicos de IOS a evitar parsear
CLI_ERROR_PATTERNS = [
    r"%\s*Invalid input detected at '\^' marker\.",
    r"%\s*Incomplete command\.",
    r"%\s*Ambiguous command\.",
    r"%\s*Unknown command or computer name, or unable to find computer address",
    r"%\s*Error",
]
RE_CLI_ERROR = re.compile("|".join(CLI_ERROR_PATTERNS), re.IGNORECASE)

# Nombres plausibles de interfaces para el fallback
INTERFACE_PREFIX = r"(?:GigabitEthernet|FastEthernet|Ethernet|TenGigabitEthernet|TwoGigabitEthernet|Vlan|Loopback|Tu|Tunnel|Serial|Cellular|Dialer|Port\-channel|PortChannel|Bdi|Vl|Gi|Fa|Te|Fo|Hu|MgmtEth|MgmtEthernet)"

# -------------------- TextFSM Templates (embebidas) --------------------
# Interfaces (show ip interface brief)
TEMPLATE_SHOW_IP_INT_BRIEF = r"""
Value INTERFACE (\S+)
Value IP_ADDRESS (\S+)
Value OK (\S+)
Value METHOD (\S+)
Value STATUS (administratively down|up|down|reset|deleted|unknown|\S+(?:\s\S+)*)
Value PROTOCOL (up|down|administratively down|unset|\S+)

Start
  ^Interface\s+IP-Address\s+OK\?\s+Method\s+Status\s+Protocol -> Continue
  ^-{3,}.* -> Continue
  ^${INTERFACE}\s+${IP_ADDRESS}\s+${OK}\s+${METHOD}\s+${STATUS}\s+${PROTOCOL}\s*$ -> Record
"""

# Interfaces (show interfaces status)
TEMPLATE_SHOW_INTERFACES_STATUS = r"""
Value PORT (\S+)
Value NAME (.*?)
Value STATUS (connected|notconnect|disabled|err\-disabled|suspended|inactive|monitoring|^S.*|^R.*|^[A-Za-z]+)
Value VLAN (\S+)
Value DUPLEX (\S+)
Value SPEED (\S+)
Value TYPE (.+)

Start
  ^Port\s+Name\s+Status\s+Vlan\s+Duplex\s+Speed\s+Type -> Continue
  ^-{3,}.* -> Continue
  ^${PORT}\s+${NAME}\s+${STATUS}\s+${VLAN}\s+${DUPLEX}\s+${SPEED}\s+${TYPE}\s*$ -> Record
  ^${PORT}\s+${STATUS}\s+${VLAN}\s+${DUPLEX}\s+${SPEED}\s+${TYPE}\s*$ -> Record
"""

# Inventario (show inventory) — dos líneas por bloque
# NAME: "...", DESCR: "..."
# PID: ..., VID: ..., SN: ...
TEMPLATE_SHOW_INVENTORY = r"""
Value NAME (.+)
Value DESCR (.+)
Value PID (\S+)
Value VID (\S+)
Value SN (\S+)

Start
  ^NAME:\s+"${NAME}",\s+DESCR:\s+"${DESCR}" -> Continue
  ^PID:\s+${PID}\s*,\s+VID:\s+${VID}\s*,\s+SN:\s+${SN}\s*$ -> Record
"""

# -------------------- Serial --------------------
try:
    import serial
    from serial.tools import list_ports
except Exception:
    serial = None
    list_ports = None

def puertos_disponibles() -> List[str]:
    if list_ports is None:
        return []
    return [p.device for p in list_ports.comports()]

def abrir_puerto(com: str, baud: int = VELOCIDAD_DEF, timeout: float = 1.0):
    if serial is None:
        raise RuntimeError("pyserial no está instalado. Instala con: pip install pyserial")
    return serial.Serial(
        port=com,
        baudrate=baud,
        timeout=timeout,
        write_timeout=timeout,
        rtscts=False,
        dsrdtr=False
    )

def txrx(ser, cmd: str, espera: float = 0.5, repeticiones: int = 8) -> str:
    """Envía cmd + CRLF y lee en ráfagas cortas para no bloquear."""
    try:
        _ = ser.read(ser.in_waiting or 0)  # limpia buffer
    except Exception:
        pass
    try:
        if cmd is not None:
            ser.write((cmd + "\r\n").encode(errors="ignore"))
    except Exception:
        return ""
    out = ""
    for _ in range(repeticiones):
        time.sleep(espera)
        try:
            chunk = ser.read(ser.in_waiting or 0).decode(errors="ignore")
        except Exception:
            chunk = ""
        if chunk:
            out += chunk
    return out

def despertar(ser) -> None:
    for _ in range(3):
        txrx(ser, "", 0.15, 2)
    txrx(ser, "terminal length 0", 0.2, 3)

# -------------------- Helpers --------------------
def now_tag() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def asegurar_logs():
    os.makedirs(LOGS_DIR, exist_ok=True)

def guardar_log(nombre_base: str, contenido: str) -> str:
    asegurar_logs()
    ruta = os.path.join(LOGS_DIR, f"{nombre_base}_{now_tag()}.log")
    with open(ruta, "w", encoding="utf-8", errors="ignore") as f:
        f.write(contenido or "")
    return ruta

def extraer_hostname(texto: str) -> Optional[str]:
    m = RE_PROMPT_HOST.search(texto or "")
    return m.group(1) if m else None

RE_PROMPT = re.compile(r"([A-Za-z0-9._\-]+)\s*([>#])\s*$")
def extraer_prompt(texto: str) -> Tuple[Optional[str], Optional[str]]:
    m = RE_PROMPT.search(texto or "")
    if not m:
        return None, None
    return m.group(1), m.group(2)

def extraer_serie(texto: str) -> Optional[str]:
    m = RE_SERIE.search(texto or "")
    if not m:
        return None
    for g in m.groups():
        if g:
            s = g.strip()
            if RE_SERIE_VALIDA.match(s):
                return s
            return s
    return None

def es_error_cli(s: str) -> bool:
    return bool(RE_CLI_ERROR.search(s or ""))

def en_privilegiado(ser) -> bool:
    prompt = txrx(ser, "", 0.1, 2)
    _, ch = extraer_prompt(prompt)
    return ch == "#"

def asegurar_privilegiado(ser) -> None:
    prompt = txrx(ser, "", 0.1, 2)
    _, ch = extraer_prompt(prompt)
    if ch == "#":
        return
    if ch == ">":
        rx = txrx(ser, "enable", 0.2, 4)
        if "Password" in rx or "password" in rx:
            txrx(ser, "", 0.2, 2)
        time.sleep(0.2)

# -------------------- TextFSM parsing --------------------
def parse_textfsm(template_str: str, text: str) -> List[Dict[str, str]]:
    try:
        import textfsm
        from io import StringIO
    except Exception:
        print("[-] Falta textfsm. Instala: pip install textfsm")
        return []
    try:
        fsm = textfsm.TextFSM(StringIO(template_str))
        headers = list(fsm.header) if getattr(fsm, "header", None) else []
        rows = fsm.ParseText(text or "")
        parsed = []
        for r in rows:
            d = {headers[i]: (r[i] if i < len(r) else "") for i in range(len(headers))}
            parsed.append(d)
        return parsed
    except Exception as e:
        print(f"[i] TextFSM no pudo parsear (se omite): {e}")
        return []

# -------------------- CSV genéricas --------------------
def escribir_csv(nombre: str, rows: List[Dict[str, str]], fields: List[str]):
    if not rows:
        return
    with open(nombre, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})

# -------------------- Estado/Cambios: Interfaces --------------------
def leer_estado_actual() -> Dict[Tuple[str, str], Tuple[str, str, str]]:
    estado = {}
    if not os.path.exists(STATE_FILE):
        return estado
    with open(STATE_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            k = (row.get("HOSTNAME",""), row.get("INTERFACE",""))
            estado[k] = (row.get("IP_ADDRESS",""), row.get("STATUS",""), row.get("PROTOCOL",""))
    return estado

def escribir_estado_actual(rows: List[Dict[str, str]]):
    fields = ["HOSTNAME","INTERFACE","IP_ADDRESS","STATUS","PROTOCOL","SOURCE_CMD","SNAPSHOT_TS"]
    escribir_csv(STATE_FILE, rows, fields)

def append_cambios(cambios: List[Dict[str, str]]):
    existe = os.path.exists(CHANGES_FILE)
    fields = ["TS","HOSTNAME","INTERFACE",
              "OLD_IP","OLD_STATUS","OLD_PROTOCOL",
              "NEW_IP","NEW_STATUS","NEW_PROTOCOL",
              "SOURCE_CMD"]
    with open(CHANGES_FILE, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        if not existe:
            w.writeheader()
        for c in cambios:
            w.writerow(c)

def escribir_snapshot_interfaces(nombre: str, rows: List[Dict[str, str]]):
    fields = ["HOSTNAME","INTERFACE","IP_ADDRESS","STATUS","PROTOCOL","SOURCE_CMD","SNAPSHOT_TS"]
    escribir_csv(nombre, rows, fields)

# -------------------- Estado/Cambios: Inventario --------------------
def leer_estado_inv() -> Dict[Tuple[str, str], Tuple[str, str, str, str]]:
    """
    (HOSTNAME, NAME) -> (DESCR, PID, VID, SN)
    """
    estado = {}
    if not os.path.exists(INV_STATE_FILE):
        return estado
    with open(INV_STATE_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            k = (row.get("HOSTNAME",""), row.get("NAME",""))
            estado[k] = (row.get("DESCR",""), row.get("PID",""), row.get("VID",""), row.get("SN",""))
    return estado

def escribir_estado_inv(rows: List[Dict[str, str]]):
    fields = ["HOSTNAME","NAME","DESCR","PID","VID","SN","SOURCE_CMD","SNAPSHOT_TS"]
    escribir_csv(INV_STATE_FILE, rows, fields)

def append_cambios_inv(cambios: List[Dict[str, str]]):
    existe = os.path.exists(INV_CHANGES_FILE)
    fields = ["TS","HOSTNAME","NAME",
              "OLD_DESCR","OLD_PID","OLD_VID","OLD_SN",
              "NEW_DESCR","NEW_PID","NEW_VID","NEW_SN",
              "SOURCE_CMD"]
    with open(INV_CHANGES_FILE, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        if not existe:
            w.writeheader()
        for c in cambios:
            w.writerow(c)

def escribir_snapshot_inventario(nombre: str, rows: List[Dict[str, str]]):
    fields = ["HOSTNAME","NAME","DESCR","PID","VID","SN","SOURCE_CMD","SNAPSHOT_TS"]
    escribir_csv(nombre, rows, fields)

# -------------------- Captura de interfaces --------------------
def _filtrar_filas_invalidas(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    filtradas = []
    for r in rows:
        intf = (r.get("INTERFACE","") or "").strip()
        if not intf or intf == "%":
            continue
        filtradas.append(r)
    return filtradas

def _fallback_parse_show_ip_brief(raw_ip: str, host: str, snap_ts: str) -> List[Dict[str, str]]:
    rows = []
    if not raw_ip:
        return rows
    pat = re.compile(
        rf"^({INTERFACE_PREFIX}\S*)\s+(\S+)\s+\S+\s+\S+\s+(\S+(?:\s\S+)*)\s+(\S+)\s*$"
    )
    for line in raw_ip.splitlines():
        line = line.strip()
        m = pat.match(line)
        if m:
            rows.append({
                "HOSTNAME": host,
                "INTERFACE": m.group(1),
                "IP_ADDRESS": m.group(2),
                "STATUS": m.group(3),
                "PROTOCOL": m.group(4),
                "SOURCE_CMD": "show ip interface brief (fallback)",
                "SNAPSHOT_TS": snap_ts
            })
    return rows

def _intentar_show_ip_brief(ser) -> str:
    rx = txrx(ser, "show ip interface brief", 0.35, 12)
    if es_error_cli(rx):
        rx2 = txrx(ser, "show ip interface brief | exclude unassigned", 0.35, 12)
        if not es_error_cli(rx2) and rx2.strip():
            return rx2
        rx3 = txrx(ser, "show ipv4 interface brief", 0.35, 12)  # IOS-XE
        if not es_error_cli(rx3) and rx3.strip():
            return rx3
    return rx

def capturar_interfaces(ser) -> Tuple[str, List[Dict[str, str]]]:
    despertar(ser)
    asegurar_privilegiado(ser)

    prompt_raw = txrx(ser, "", 0.2, 2)
    host = extraer_hostname(prompt_raw) or "UNKNOWN"
    if host == "UNKNOWN":
        rc = txrx(ser, "show running-config | include ^hostname", 0.3, 6)
        m = re.search(r"^hostname\s+(\S+)", rc, re.M)
        if m:
            host = m.group(1)

    snapshot_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    raw_ip = _intentar_show_ip_brief(ser)
    if es_error_cli(raw_ip):
        asegurar_privilegiado(ser)
        raw_ip_retry = _intentar_show_ip_brief(ser)
        if not es_error_cli(raw_ip_retry) and raw_ip_retry.strip():
            raw_ip = raw_ip_retry

    guardar_log(f"{host}_show_ip_interface_brief", raw_ip)

    rows1: List[Dict[str, str]] = []
    if raw_ip and not es_error_cli(raw_ip):
        p1 = parse_textfsm(TEMPLATE_SHOW_IP_INT_BRIEF, raw_ip)
        for d in p1:
            rows1.append({
                "HOSTNAME": host,
                "INTERFACE": d.get("INTERFACE",""),
                "IP_ADDRESS": d.get("IP_ADDRESS","unassigned"),
                "STATUS": d.get("STATUS",""),
                "PROTOCOL": d.get("PROTOCOL",""),
                "SOURCE_CMD": "show ip interface brief",
                "SNAPSHOT_TS": snapshot_ts
            })
        if not rows1:
            rows1 = _fallback_parse_show_ip_brief(raw_ip, host, snapshot_ts)

    raw_st = txrx(ser, "show interfaces status", 0.35, 12)
    if raw_st and raw_st.strip() and "Invalid input" not in raw_st and not es_error_cli(raw_st):
        guardar_log(f"{host}_show_interfaces_status", raw_st)
        p2 = parse_textfsm(TEMPLATE_SHOW_INTERFACES_STATUS, raw_st)
        for d in p2:
            rows1.append({
                "HOSTNAME": host,
                "INTERFACE": d.get("PORT",""),
                "IP_ADDRESS": "",
                "STATUS": d.get("STATUS",""),
                "PROTOCOL": "",
                "SOURCE_CMD": "show interfaces status",
                "SNAPSHOT_TS": snapshot_ts
            })

    rows1 = _filtrar_filas_invalidas(rows1)
    if not rows1:
        rows1.append({
            "HOSTNAME": host, "INTERFACE": "", "IP_ADDRESS": "", "STATUS": "",
            "PROTOCOL": "", "SOURCE_CMD": "no-data", "SNAPSHOT_TS": snapshot_ts
        })
    return host, rows1

def detectar_y_guardar_cambios(rows: List[Dict[str, str]]):
    estado_prev = leer_estado_actual()
    cambios: List[Dict[str,str]] = []
    estado_nuevo: Dict[Tuple[str,str], Dict[str,str]] = {}

    for r in rows:
        k = (r.get("HOSTNAME",""), r.get("INTERFACE",""))
        if not k[1]:
            continue
        estado_nuevo[k] = {
            "HOSTNAME": k[0],
            "INTERFACE": k[1],
            "IP_ADDRESS": r.get("IP_ADDRESS",""),
            "STATUS": r.get("STATUS",""),
            "PROTOCOL": r.get("PROTOCOL",""),
            "SOURCE_CMD": r.get("SOURCE_CMD",""),
            "SNAPSHOT_TS": r.get("SNAPSHOT_TS",""),
        }

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for k, nuevo in estado_nuevo.items():
        old = estado_prev.get(k, ("","",""))
        old_ip, old_status, old_proto = old
        new_ip = nuevo["IP_ADDRESS"] or ""
        new_status = nuevo["STATUS"] or ""
        new_proto = nuevo["PROTOCOL"] or ""
        if (str(old_ip or ""), str(old_status or ""), str(old_proto or "")) != (new_ip, new_status, new_proto):
            cambios.append({
                "TS": ts,
                "HOSTNAME": k[0],
                "INTERFACE": k[1],
                "OLD_IP": old_ip or "", "OLD_STATUS": old_status or "", "OLD_PROTOCOL": old_proto or "",
                "NEW_IP": new_ip, "NEW_STATUS": new_status, "NEW_PROTOCOL": new_proto,
                "SOURCE_CMD": nuevo["SOURCE_CMD"]
            })

    if cambios:
        append_cambios(cambios)
        print(f"[✓] Cambios en interfaces: {len(cambios)} (registrados en {CHANGES_FILE})")
    else:
        print("[i] Sin cambios en interfaces.")
    escribir_estado_actual(list(estado_nuevo.values()))

# -------------------- Captura de inventario --------------------
def _fallback_parse_inventory(raw: str) -> List[Dict[str, str]]:
    """
    Empareja bloques:
    NAME: "xxx", DESCR: "yyy"
    PID: ZZZ , VID: Vxx , SN: AAA
    """
    if not raw:
        return []
    rows = []
    name = descr = pid = vid = sn = None
    name_re = re.compile(r'^NAME:\s*"(.+?)",\s*DESCR:\s*"(.+?)"\s*$', re.I)
    pid_re  = re.compile(r'^PID:\s*([^ ,]+)\s*,\s*VID:\s*([^ ,]+)\s*,\s*SN:\s*([^\s]+)\s*$', re.I)

    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    i = 0
    while i < len(lines):
        m1 = name_re.match(lines[i])
        if m1:
            name, descr = m1.group(1), m1.group(2)
            if i+1 < len(lines):
                m2 = pid_re.match(lines[i+1])
                if m2:
                    pid, vid, sn = m2.group(1), m2.group(2), m2.group(3)
                    rows.append({
                        "NAME": name, "DESCR": descr, "PID": pid, "VID": vid, "SN": sn
                    })
                    i += 2
                    continue
        i += 1
    return rows

def capturar_inventario(ser, host: str, snapshot_ts: str) -> List[Dict[str, str]]:
    raw_inv = txrx(ser, "show inventory", 0.35, 18)
    if es_error_cli(raw_inv) or not raw_inv.strip():
        # Intento IOS-XE variante (suele ser igual)
        raw_inv2 = txrx(ser, "show inventory raw", 0.35, 18)
        if not es_error_cli(raw_inv2) and raw_inv2.strip():
            raw_inv = raw_inv2
    guardar_log(f"{host}_show_inventory", raw_inv)

    rows: List[Dict[str, str]] = []
    if raw_inv and not es_error_cli(raw_inv):
        p = parse_textfsm(TEMPLATE_SHOW_INVENTORY, raw_inv)
        for d in p:
            rows.append({
                "HOSTNAME": host,
                "NAME": d.get("NAME",""),
                "DESCR": d.get("DESCR",""),
                "PID": d.get("PID",""),
                "VID": d.get("VID",""),
                "SN": d.get("SN",""),
                "SOURCE_CMD": "show inventory",
                "SNAPSHOT_TS": snapshot_ts
            })
        if not rows:
            # Fallback
            fb = _fallback_parse_inventory(raw_inv)
            for d in fb:
                rows.append({
                    "HOSTNAME": host,
                    "NAME": d.get("NAME",""),
                    "DESCR": d.get("DESCR",""),
                    "PID": d.get("PID",""),
                    "VID": d.get("VID",""),
                    "SN": d.get("SN",""),
                    "SOURCE_CMD": "show inventory (fallback)",
                    "SNAPSHOT_TS": snapshot_ts
                })

    if not rows:
        rows.append({
            "HOSTNAME": host, "NAME": "", "DESCR": "", "PID": "", "VID": "", "SN": "",
            "SOURCE_CMD": "no-data", "SNAPSHOT_TS": snapshot_ts
        })
    return rows

def detectar_y_guardar_cambios_inv(rows: List[Dict[str, str]]):
    """
    Clave: (HOSTNAME, NAME). Si cambia DESCR/PID/VID/SN, lo registramos.
    """
    prev = leer_estado_inv()
    cambios: List[Dict[str,str]] = []
    nuevo: Dict[Tuple[str,str], Dict[str,str]] = {}

    for r in rows:
        k = (r.get("HOSTNAME",""), r.get("NAME",""))
        if not k[1]:
            continue
        nuevo[k] = {
            "HOSTNAME": k[0],
            "NAME": k[1],
            "DESCR": r.get("DESCR",""),
            "PID": r.get("PID",""),
            "VID": r.get("VID",""),
            "SN": r.get("SN",""),
            "SOURCE_CMD": r.get("SOURCE_CMD",""),
            "SNAPSHOT_TS": r.get("SNAPSHOT_TS",""),
        }

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for k, nv in nuevo.items():
        old = prev.get(k, ("","","",""))
        od, op, ov, osn = old
        nd, np, nvvid, nsn = nv["DESCR"] or "", nv["PID"] or "", nv["VID"] or "", nv["SN"] or ""
        if (str(od), str(op), str(ov), str(osn)) != (nd, np, nvvid, nsn):
            cambios.append({
                "TS": ts,
                "HOSTNAME": k[0],
                "NAME": k[1],
                "OLD_DESCR": od, "OLD_PID": op, "OLD_VID": ov, "OLD_SN": osn,
                "NEW_DESCR": nd, "NEW_PID": np, "NEW_VID": nvvid, "NEW_SN": nsn,
                "SOURCE_CMD": nv["SOURCE_CMD"]
            })

    if cambios:
        append_cambios_inv(cambios)
        print(f"[✓] Cambios en inventario: {len(cambios)} (registrados en {INV_CHANGES_FILE})")
    else:
        print("[i] Sin cambios en inventario.")
    escribir_estado_inv(list(nuevo.values()))

# -------------------- Consola en vivo --------------------
def consola_en_vivo(ser):
    """
    Passthrough en tiempo real.
    Salir con Ctrl + ].
    """
    if os.name == "nt":
        _consola_windows(ser)
    else:
        _consola_posix(ser)

def _consola_windows(ser):
    import msvcrt
    stop = False
    def lector():
        nonlocal stop
        while not stop:
            try:
                data = ser.read(ser.in_waiting or 1)
                if data:
                    try:
                        sys.stdout.write(data.decode(errors="ignore"))
                    except Exception:
                        sys.stdout.write(data.hex() + " ")
                    sys.stdout.flush()
            except Exception:
                break
            time.sleep(0.001)
    hilo = threading.Thread(target=lector, daemon=True)
    hilo.start()
    print("\n[Conectado] Escribe tus comandos. Salir: Ctrl + ]\n")
    try:
        while True:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ord(ch) == 0x1D:  # Ctrl + ]
                    stop = True
                    break
                if ch in ("\r", "\n"):
                    ser.write(b"\r\n")
                else:
                    if ch == "\b":
                        ser.write(b"\b")
                    else:
                        ser.write(ch.encode(errors="ignore"))
            time.sleep(0.001)
    finally:
        stop = True
        hilo.join(timeout=1.0)

def _consola_posix(ser):
    import termios, tty, select
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        print("\n[Conectado] Escribe tus comandos. Salir: Ctrl + ]\n")
        while True:
            rlist, _, _ = select.select([fd, ser], [], [], 0.05)
            if ser in rlist:
                data = ser.read(ser.in_waiting or 1)
                if data:
                    sys.stdout.write(data.decode(errors="ignore"))
                    sys.stdout.flush()
            if fd in rlist:
                ch = os.read(fd, 1)
                if ch and ch[0] == 0x1D:
                    break
                if ch in (b"\r", b"\n"):
                    ser.write(b"\r\n")
                else:
                    ser.write(ch)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

# -------------------- UI --------------------
def elegir_puerto() -> Optional[str]:
    if list_ports is None:
        print("[-] pyserial no disponible.")
        return None
    ports = puertos_disponibles()
    if not ports:
        print("[-] No hay puertos serial detectados.")
        return None
    if len(ports) == 1:
        print(f"[i] Usando puerto: {ports[0]}")
        return ports[0]
    print("Puertos detectados:", ports)
    while True:
        sel = input("Puerto a usar (ej. COM5 o /dev/ttyUSB0): ").strip()
        if sel:
            return sel

def menu():
    print("\n=== Cisco Serial Utility (compact) ===")
    print("1) Consola en vivo")
    print("2) Capturar snapshot (Interfaces + Inventario) y detectar cambios")
    print("3) Monitorear cambios cada N segundos (Ctrl+C para salir)")
    print("0) Salir")

def main():
    port = elegir_puerto()
    if not port:
        return
    try:
        ser = abrir_puerto(port, VELOCIDAD_DEF, TIMEOUT_S)
        time.sleep(1.0)
        try:
            ser.write(b"\r\n")
            time.sleep(0.1)
            ser.write(b"terminal length 0\r\n")
        except Exception:
            pass

        while True:
            menu()
            op = input("Opción: ").strip()
            if op == "1":
                consola_en_vivo(ser)
            elif op == "2":
                # Interfaces
                host, rows_if = capturar_interfaces(ser)
                snap_if = f"interfaces_snapshot_{now_tag()}.csv"
                escribir_snapshot_interfaces(snap_if, rows_if)
                print(f"[✓] Snapshot interfaces: {snap_if}")
                detectar_y_guardar_cambios(rows_if)

                # Inventario
                snapshot_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                rows_inv = capturar_inventario(ser, host, snapshot_ts)
                snap_inv = f"inventory_snapshot_{now_tag()}.csv"
                escribir_snapshot_inventario(snap_inv, rows_inv)
                print(f"[✓] Snapshot inventario: {snap_inv}")
                detectar_y_guardar_cambios_inv(rows_inv)

            elif op == "3":
                try:
                    n = input("Intervalo (segundos, default 30): ").strip() or "30"
                    intervalo = max(5, int(n))
                except Exception:
                    intervalo = 30
                print(f"[i] Monitoreando cada {intervalo}s. Ctrl+C para detener.")
                try:
                    while True:
                        host, rows_if = capturar_interfaces(ser)
                        detectar_y_guardar_cambios(rows_if)

                        snapshot_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        rows_inv = capturar_inventario(ser, host, snapshot_ts)
                        detectar_y_guardar_cambios_inv(rows_inv)

                        time.sleep(intervalo)
                except KeyboardInterrupt:
                    print("\n[+] Monitoreo detenido.")
            elif op == "0":
                break
            else:
                print("Opción inválida.")
        ser.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
