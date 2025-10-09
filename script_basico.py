# script.py
# Autor: tú 😎
# Objetivo:
# - Consola en vivo para controlar routers/switches Cisco por consola serial.
# - Capturar y parsear estado de interfaces con TextFSM.
# - Guardar snapshots y detectar cambios reales en CSVs.
#
# Requisitos:
#   pip install pyserial textfsm
#
# Uso:
#   python script.py
#
# Notas:
# - Hotkey para salir de la consola: Ctrl + ]
# - Si hay varios puertos, te pedirá cuál usar.
# - CSVs generados:
#   * interfaces_snapshot_<YYYYmmdd_HHMMSS>.csv  (snapshot completo)
#   * interfaces_state.csv  (último estado por interfaz)
#   * interfaces_changes.csv (solo cambios, con before/after y timestamp)
# - Logs crudos en ./logs/

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
STATE_FILE = "interfaces_state.csv"
CHANGES_FILE = "interfaces_changes.csv"

# -------------------- Regex útiles --------------------
RE_PROMPT_HOST = re.compile(r"^\s*([A-Za-z0-9._\-]+)\s*[>#]\s*$", re.M)
RE_SERIE = re.compile(
    r"(?:Processor board ID\s+(\S+))|(?:SN:\s*([A-Za-z0-9\-]+))|(?:Serial Number:\s*([A-Za-z0-9\-]+))",
    re.IGNORECASE
)
RE_SERIE_VALIDA = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{4,24}$")

# -------------------- TextFSM Templates (embebidas) --------------------
TEMPLATE_SHOW_IP_INT_BRIEF = r"""
Value Required INTERFACE (\S+)
Value IP_ADDRESS (\S+)
Value OK (\S+)
Value METHOD (\S+)
Value STATUS (administratively down|up|down|reset|deleted|unknown|\S+(?:\s\S+)*)
Value PROTOCOL (up|down|administratively down|unset|\S+)

Start
  ^${INTERFACE}\s+${IP_ADDRESS}\s+${OK}\s+${METHOD}\s+${STATUS}\s+${PROTOCOL}\s*$ -> Record
"""

TEMPLATE_SHOW_INTERFACES_STATUS = r"""
Value Required PORT (\S+)
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
    ser.write((cmd + "\r\n").encode(errors="ignore"))
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

# -------------------- TextFSM parsing --------------------
def parse_textfsm(template_str: str, text: str) -> List[Dict[str, str]]:
    try:
        import textfsm
    except Exception:
        print("[-] Falta textfsm. Instala: pip install textfsm")
        return []
    from io import StringIO
    fsm = textfsm.TextFSM(StringIO(template_str))
    headers = list(fsm.header) if getattr(fsm, "header", None) else []
    rows = fsm.ParseText(text or "")
    parsed = []
    for r in rows:
        d = {headers[i]: (r[i] if i < len(r) else "") for i in range(len(headers))}
        parsed.append(d)
    return parsed

# -------------------- CSV state management --------------------
def leer_estado_actual() -> Dict[Tuple[str, str], Tuple[str, str, str]]:
    """
    Regresa dict: (hostname, interface) -> (ip, status, protocol)
    """
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
    with open(STATE_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k,"") for k in fields})

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

def escribir_snapshot(nombre: str, rows: List[Dict[str, str]]):
    if not rows:
        return
    fields = ["HOSTNAME","INTERFACE","IP_ADDRESS","STATUS","PROTOCOL","SOURCE_CMD","SNAPSHOT_TS"]
    with open(nombre, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k,"") for k in fields})

# -------------------- Captura de interfaces --------------------
def capturar_interfaces(ser) -> Tuple[str, List[Dict[str, str]]]:
    """
    Devuelve (hostname, filas_unificadas)
    Filas contienen: HOSTNAME, INTERFACE/IP/STATUS/PROTOCOL, SOURCE_CMD, SNAPSHOT_TS
    """
    despertar(ser)

    # Obtén prompt para hostname
    prompt_raw = txrx(ser, "", 0.2, 2)
    host = extraer_hostname(prompt_raw) or "UNKNOWN"
    # Intenta hostname del running-config si no hubo prompt claro
    if host == "UNKNOWN":
        rc = txrx(ser, "show running-config | include ^hostname", 0.3, 6)
        m = re.search(r"^hostname\s+(\S+)", rc, re.M)
        if m:
            host = m.group(1)

    snapshot_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # --- show ip interface brief ---
    raw_ip = txrx(ser, "show ip interface brief", 0.35, 12)
    guardar_log(f"{host}_show_ip_interface_brief", raw_ip)
    p1 = parse_textfsm(TEMPLATE_SHOW_IP_INT_BRIEF, raw_ip)
    rows1 = []
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

    # --- show interfaces status (si existe) ---
    raw_st = txrx(ser, "show interfaces status", 0.35, 12)
    if raw_st and len(raw_st.strip()) > 0 and "Invalid input" not in raw_st:
        guardar_log(f"{host}_show_interfaces_status", raw_st)
        p2 = parse_textfsm(TEMPLATE_SHOW_INTERFACES_STATUS, raw_st)
        # Lo mapeamos para que INTERFACE coincida con PORT y protocol sin campo (lo dejamos vacío)
        for d in p2:
            rows1.append({
                "HOSTNAME": host,
                "INTERFACE": d.get("PORT",""),
                "IP_ADDRESS": "",  # no viene en este comando
                "STATUS": d.get("STATUS",""),
                "PROTOCOL": "",    # no aplica aquí
                "SOURCE_CMD": "show interfaces status",
                "SNAPSHOT_TS": snapshot_ts
            })

    # Si no hubo parseo, preserva crudo en una fila
    if not rows1:
        rows1.append({
            "HOSTNAME": host, "INTERFACE": "", "IP_ADDRESS": "", "STATUS": "",
            "PROTOCOL": "", "SOURCE_CMD": "raw", "SNAPSHOT_TS": snapshot_ts
        })

    return host, rows1

def detectar_y_guardar_cambios(rows: List[Dict[str, str]]):
    """
    Compara contra interfaces_state.csv; agrega cambios a interfaces_changes.csv
    y refresca interfaces_state.csv con última foto.
    """
    estado_prev = leer_estado_actual()
    cambios: List[Dict[str,str]] = []
    # Construye estado nuevo por última snapshot (preferimos entrada por entrada, último valor gana)
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

    # Detecta cambios
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for k, nuevo in estado_nuevo.items():
        old = estado_prev.get(k, ("","",""))
        old_ip, old_status, old_proto = old
        new_ip = nuevo["IP_ADDRESS"]
        new_status = nuevo["STATUS"]
        new_proto = nuevo["PROTOCOL"]
        if (old_ip, old_status, old_proto) != (new_ip, new_status, new_proto):
            cambios.append({
                "TS": ts,
                "HOSTNAME": k[0],
                "INTERFACE": k[1],
                "OLD_IP": old_ip, "OLD_STATUS": old_status, "OLD_PROTOCOL": old_proto,
                "NEW_IP": new_ip, "NEW_STATUS": new_status, "NEW_PROTOCOL": new_proto,
                "SOURCE_CMD": nuevo["SOURCE_CMD"]
            })

    # Escribe cambios si hay
    if cambios:
        append_cambios(cambios)
        print(f"[✓] Cambios detectados: {len(cambios)} (registrados en {CHANGES_FILE})")
    else:
        print("[i] Sin cambios respecto al último estado.")

    # Actualiza estado actual
    escribir_estado_actual(list(estado_nuevo.values()))

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
    print("2) Capturar snapshot de interfaces (CSV) y detectar cambios")
    print("3) Monitorear cambios cada N segundos (Ctrl+C para salir)")
    print("0) Salir")

def main():
    port = elegir_puerto()
    if not port:
        return
    try:
        ser = abrir_puerto(port, VELOCIDAD_DEF, TIMEOUT_S)
        time.sleep(1.0)
        # Quita paginación
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
                host, rows = capturar_interfaces(ser)
                snap = f"interfaces_snapshot_{now_tag()}.csv"
                escribir_snapshot(snap, rows)
                print(f"[✓] Snapshot guardado: {snap}")
                detectar_y_guardar_cambios(rows)
            elif op == "3":
                try:
                    n = input("Intervalo (segundos, default 30): ").strip() or "30"
                    intervalo = max(5, int(n))
                except Exception:
                    intervalo = 30
                print(f"[i] Monitoreando cada {intervalo}s. Ctrl+C para detener.")
                try:
                    while True:
                        host, rows = capturar_interfaces(ser)
                        detectar_y_guardar_cambios(rows)
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
