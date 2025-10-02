# mi_practica_router.py
# Autor: tú 😎
# Objetivo: Menú para (1) consola interactiva en vivo y (2) configurar equipos Cisco en lote
#           leyendo Data.csv o inventario.xlsx en la misma carpeta.
# Nota: Requiere: pip install pyserial pandas openpyxl

import os
import re
import sys
import time
import threading
from typing import Optional, List, Dict

import pandas as pd

# -------------------- Ajustes --------------------
ARCHIVOS_BUSCADOS = ["Data.csv", "inventario.xlsx"]   # se intentan en ese orden
VELOCIDAD_DEF = 9600
TIMEOUT_S = 0.0  # 0.0 = non-blocking para la consola en vivo

# Regex de lectura del serial en Cisco
RE_SERIE = re.compile(r"(?:Processor board ID\s+(\S+))|(?:SN:\s*([A-Za-z0-9\-]+))|(?:Serial Number:\s*([A-Za-z0-9\-]+))",
                      re.IGNORECASE)

# Validación “sana” para serie (opcional)
RE_SERIE_VALIDA = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{4,24}$")

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
    # Desactiva RTS/CTS y DSR/DTR para la mayoría de cables USB-serial consola Cisco
    return serial.Serial(
        port=com,
        baudrate=baud,
        timeout=timeout,
        write_timeout=timeout,
        rtscts=False,
        dsrdtr=False
    )

def txrx(ser, cmd: str, espera: float = 0.6, repeticiones: int = 6) -> str:
    """Envía cmd + CRLF y hace lecturas pequeñas para evitar bloqueos."""
    try:
        _ = ser.read(ser.in_waiting or 0)  # limpia buffer
    except Exception:
        pass
    ser.write((cmd + "\r\n").encode(errors="ignore"))
    salida = ""
    for _ in range(repeticiones):
        time.sleep(espera)
        try:
            chunk = ser.read(ser.in_waiting or 0).decode(errors="ignore")
        except Exception:
            chunk = ""
        if chunk:
            salida += chunk
    return salida

def despertar(ser) -> None:
    # varios ENTER para sacar prompt y activar terminal length 0
    for _ in range(3):
        txrx(ser, "", 0.2, 2)
    txrx(ser, "terminal length 0", 0.3, 3)

def extraer_serie(texto: str) -> Optional[str]:
    m = RE_SERIE.search(texto or "")
    if not m:
        return None
    for g in m.groups():
        if g:
            return g.strip()
    return None

def leer_serie_equipo(ser) -> Optional[str]:
    despertar(ser)
    out = txrx(ser, "show inventory", 0.7, 10)
    if len(out.strip()) < 10:
        out += "\n" + txrx(ser, "show version", 0.7, 10)
    serie = extraer_serie(out)
    if serie and RE_SERIE_VALIDA.match(serie):
        return serie
    return serie

# -------------------- Inventario --------------------
def buscar_archivo_inventario() -> Optional[str]:
    for nombre in ARCHIVOS_BUSCADOS:
        p = os.path.join(os.getcwd(), nombre)
        if os.path.exists(p):
            return p
    return None

def cargar_inventario(path: str) -> pd.DataFrame:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".csv":
        df = pd.read_csv(path)
    elif ext in [".xlsx", ".xls"]:
        df = pd.read_excel(path, sheet_name=0, engine="openpyxl")
    else:
        raise RuntimeError(f"Formato no soportado: {ext}")
    df.columns = [str(c).strip().lower() for c in df.columns]
    return df

def generar_hostname(device_str: str, serie: str) -> str:
    """
    Regla: primera letra de Device + Serie.
    Si Device está vacío, usa 'D' como prefijo.
    """
    pref = (device_str.strip()[:1] or "D")
    return f"{pref}{serie}"

# -------------------- Configuración --------------------
def configurar_equipo(ser, hostname: str, user: str, secret: str, dominio: str) -> None:
    txrx(ser, "enable", 0.4, 6)
    txrx(ser, "configure terminal", 0.4, 6)
    txrx(ser, f"hostname {hostname}", 0.5, 6)
    txrx(ser, f"username {user} privilege 15 secret {secret}", 0.6, 6)
    txrx(ser, f"ip domain-name {dominio}", 0.5, 6)
    txrx(ser, "crypto key generate rsa modulus 1024", 1.2, 8)
    txrx(ser, "line vty 0 4", 0.3, 4)
    txrx(ser, "login local", 0.3, 4)
    txrx(ser, "transport input ssh", 0.3, 4)
    txrx(ser, "transport output ssh", 0.3, 4)
    txrx(ser, "ip ssh version 2", 0.3, 4)
    txrx(ser, "end", 0.3, 4)
    txrx(ser, "write memory", 0.8, 6)

# -------------------- Consola en vivo (tipo Moba/Putty) --------------------
def _consola_windows(ser):
    """
    Passthrough en Windows usando msvcrt.
    Salida de serial -> stdout en tiempo real.
    Teclado -> serial byte a byte.
    Salir con Ctrl + ].
    """
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
                        # imprime bytes crudos si no decodifica
                        sys.stdout.write(data.hex() + " ")
                    sys.stdout.flush()
            except Exception:
                break
            time.sleep(0.001)

    hilo = threading.Thread(target=lector, daemon=True)
    hilo.start()

    sys.stdout.write("\n[Conectado] Escribe tus comandos. Salir: Ctrl + ]\n\n")
    sys.stdout.flush()

    try:
        while True:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()  # wide char
                # Ctrl + ] => 0x1D
                if ord(ch) == 0x1D:
                    stop = True
                    break
                # Enter = CRLF para Cisco
                if ch == "\r" or ch == "\n":
                    ser.write(b"\r\n")
                else:
                    # backspace manejo básico
                    if ch == "\b":
                        ser.write(b"\b")
                    else:
                        ser.write(ch.encode(errors="ignore"))
            time.sleep(0.001)
    finally:
        stop = True
        hilo.join(timeout=1.0)

def _consola_posix(ser):
    """
    Passthrough en Linux/macOS usando termios + select.
    Salir con Ctrl + ].
    """
    import termios, tty, select

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        sys.stdout.write("\n[Conectado] Escribe tus comandos. Salir: Ctrl + ]\n\n")
        sys.stdout.flush()
        while True:
            rlist, _, _ = select.select([fd, ser], [], [], 0.05)
            if ser in rlist:
                data = ser.read(ser.in_waiting or 1)
                if data:
                    sys.stdout.write(data.decode(errors="ignore"))
                    sys.stdout.flush()
            if fd in rlist:
                ch = os.read(fd, 1)
                if ch and ch[0] == 0x1D:  # Ctrl + ]
                    break
                if ch in (b"\r", b"\n"):
                    ser.write(b"\r\n")
                else:
                    ser.write(ch)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def consola_en_vivo():
    """
    Abre una sesión de consola en vivo en el puerto indicado.
    Muestra el prompt y toda la salida como un terminal real.
    """
    limpiar_pantalla()
    disponibles = puertos_disponibles()
    print("Puertos detectados:", disponibles or "(ninguno)")
    com = input("Puerto a usar (ej. COM5): ").strip()
    if not com:
        print("Sin puerto. Regresando…")
        pausa()
        return

    try:
        ser = abrir_puerto(com, VELOCIDAD_DEF, TIMEOUT_S)
        # pequeña siesta para estabilizar
        time.sleep(1.2)
        # “despertar” y quitar paginación para que los show no se corten
        try:
            ser.write(b"\r\n")
            time.sleep(0.1)
            ser.write(b"terminal length 0\r\n")
        except Exception:
            pass

        if os.name == "nt":
            _consola_windows(ser)
        else:
            _consola_posix(ser)

        ser.close()
        print("\n[Sesión cerrada]")
    except Exception as e:
        print(f"Error abriendo la consola: {e}")
    pausa()

# -------------------- Menús --------------------
def limpiar_pantalla():
    os.system("cls" if os.name == "nt" else "clear")

def pausa(msg="Presiona ENTER para continuar..."):
    try:
        input(msg)
    except EOFError:
        pass

def menu():
    limpiar_pantalla()
    print("=== Utilidad de Consola Cisco ===")
    print("1) Consola interactiva (EN VIVO, tipo PuTTY/Moba)  [Salir: Ctrl + ]]")
    print("2) Configuración en lote (CSV/XLSX en esta carpeta)")
    print("0) Salir")

def configuracion_en_lote():
    limpiar_pantalla()
    path = buscar_archivo_inventario()
    if not path:
        print("No encontré Data.csv ni inventario.xlsx en esta carpeta.")
        pausa()
        return

    print(f"Usando inventario: {path}\n")
    try:
        df = cargar_inventario(path)
    except Exception as e:
        print(f"No pude leer el inventario: {e}")
        pausa()
        return

    # Columnas esperadas (case-insensitive):
    # Port (opcional), Device, Serie, User, Password, Ip-domain, Baud (opcional)
    cols = df.columns
    for falta in ["device", "serie", "user", "password", "ip-domain"]:
        if falta not in cols:
            print(f"Falta columna requerida: {falta}")
            pausa()
            return

    print(df)
    pausa("\nRevisa el inventario. Conecta el primer equipo y presiona ENTER...")

    resultados: List[Dict[str, str]] = []

    for idx, row in df.iterrows():
        device = str(row.get("device") or "").strip()
        serie_esperada = str(row.get("serie") or "").strip()
        usuario = str(row.get("user") or "").strip()
        clave = str(row.get("password") or "").strip()
        dominio = str(row.get("ip-domain") or "").strip()
        com_csv = str(row.get("port") or "").strip()
        try:
            baud = int(row.get("baud")) if ("baud" in df.columns and str(row.get("baud")).strip()) else VELOCIDAD_DEF
        except Exception:
            baud = VELOCIDAD_DEF

        limpiar_pantalla()
        print(f"=== Dispositivo #{idx+1} ===")
        print(f"CSV -> Device={device}  Serie={serie_esperada}  User={usuario}  Dom={dominio}  Baud={baud}")
        detectados = puertos_disponibles()
        print("Puertos detectados ahora:", detectados or "(ninguno)")
        com = com_csv or input("Puerto a usar (ej. COM5): ").strip()
        if not com:
            resultados.append({"index": idx, "status": "SKIP", "detalle": "Sin puerto asignado"})
            continue

        input("Conecta el equipo al puerto indicado y presiona ENTER...")

        try:
            ser = abrir_puerto(com, baud, 1.0)
            time.sleep(1.5)
        except Exception as e:
            print(f"[X] No se pudo abrir {com}: {e}")
            resultados.append({"index": idx, "status": "ERROR_CONEXION", "detalle": str(e)})
            pausa()
            continue

        # Lee serial real del equipo
        real = leer_serie_equipo(ser)
        print(f"Serie detectada: {real or '(vacía)'}")

        if not real:
            print("[!] No pude obtener serie. ¿Continuar solo con hostname por CSV? (y/N): ", end="")
            if input("").strip().lower() != "y":
                ser.close()
                resultados.append({"index": idx, "status": "SIN_SERIE", "detalle": "No se detectó serie"})
                pausa()
                continue

        # Arma hostname (regla: primera letra de Device + serie detectada o esperada)
        serie_para_hostname = real or serie_esperada
        hostname = generar_hostname(device, serie_para_hostname)
        print(f"Hostname objetivo: {hostname}")

        # Verificación opcional de mismatch
        if serie_esperada and real and (serie_esperada.strip().upper() != real.strip().upper()):
            print(f"[!] Ojo: serie CSV ({serie_esperada}) != serie detectada ({real}).")
            print("¿Configurar de todos modos? (y/N): ", end="")
            if input("").strip().lower() != "y":
                ser.close()
                resultados.append({"index": idx, "status": "MISMATCH_SERIE", "detalle": f"CSV={serie_esperada} != REAL={real}"})
                pausa()
                continue

        # Configuración
        try:
            configurar_equipo(ser, hostname, usuario, clave, dominio)
            status = "OK"
            detalle = f"Aplicada config en {hostname}"
        except Exception as e:
            status = "ERROR_CONFIG"
            detalle = str(e)

        # Consola manual para probar (rápida con txrx; si quieres en vivo, usa opción 1 del menú)
        print("\n¿Probar comandos manualmente (modo simple)? (Y/n): ", end="")
        if input("").strip().lower() != "n":
            print("\nEscribe 'quit' para regresar.\n")
            while True:
                cmd = input("cmd> ").strip()
                if cmd.lower() == "quit":
                    break
                print(txrx(ser, cmd, 0.5, 10))

        ser.close()
        resultados.append({"index": idx, "status": status, "detalle": detalle, "serie_real": real or ""})
        pausa("Listo ese equipo. ENTER para continuar con el siguiente...")

    # Guardar reporte
    rep = pd.DataFrame(resultados)
    rep.to_csv("reporte_config.csv", index=False, encoding="utf-8-sig")
    limpiar_pantalla()
    print("[✓] Reporte guardado en reporte_config.csv")
    print(rep)
    pausa()

# -------------------- Main Loop --------------------
def main():
    while True:
        menu()
        opcion = input("Elige una opción: ").strip()
        if opcion == "1":
            consola_en_vivo()
        elif opcion == "2":
            configuracion_en_lote()
        elif opcion == "0":
            print("Bye.")
            break
        else:
            print("Opción inválida.")
            pausa()

if __name__ == "__main__":
    main()
