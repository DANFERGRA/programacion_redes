#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
find_ip_switch.py — Rápido y robusto: IP→MAC→SWITCH/PUERTO (solo SSH al SW-CORE).

Objetivo: Mantener la confiabilidad, pero reducir el tiempo total.
Estrategia de velocidad (sin perder exactitud):
  1) "Quick path" primero (ligero): no limpia nada; usa consultas específicas
     (ARP puntual, CAM por MAC, CDP/LLDP por interfaz) y abandona apenas haya
     un puerto final válido. Nada de pings múltiples ni pauses largos.
  2) Sólo si el quick path no alcanza (multi‐puerto, uplink sin vecino, o desactualizado),
     activa "heavy refresh" de forma selectiva (clear ARP/CAM + 1 ping rápido),
     y reintenta en ese switch únicamente.
  3) Anti-bucle conservado, pero con umbral más alto y reintentos internos
     muy cortos para no cortar el flujo ni hacerlo repetir desde cero.

Requisitos:
  pip install netmiko textfsm ntc-templates
  export NET_TEXTFSM=/ruta/a/ntc-templates/templates
"""

from netmiko import ConnectHandler
import re, time, socket
from ipaddress import ip_network, ip_address
from typing import Optional, Tuple, List, Set, Dict, Union

# ===================== CONFIG BÁSICA =====================
CORE = {
    "device_type": "cisco_ios",
    "host": "192.168.1.1",
    "username": "cisco",
    "password": "cisco99",
    "secret":   "cisco99",
    "port": 22,
    # Activamos fast_cli para recortar RTTs; mantenemos delays manuales donde importa.
    "fast_cli": True,
    "global_delay_factor": 1,
    "banner_timeout": 45,
    "auth_timeout": 30,
    "conn_timeout": 12,
    "session_log": "netmiko_swcore.log",
}

MGMT_NET = ip_network("192.168.1.0/24")   # Vlan de gestión
UPLINK_PORT_NUMBERS = {"47", "48"}        # Nunca reportar estos como puerto final
MAX_HOPS = 10

# ===================== TUNING DE VELOCIDAD/ROBUSTEZ =====================
# Quick path: consultas mínimas, sin limpiar.
QP_PING_REPEAT        = 1     # cuando haya que forzar, usa 1 eco
QP_PING_TIMEOUT_MS    = 300
QP_SLEEP_SHORT        = 0.20  # sleeps cortos entre pasos
QP_BULK_REFRESH_CYC   = 0     # quick path NO limpia en primer intento

# Heavy refresh (sólo cuando haga falta):
HR_PING_REPEAT        = 2
HR_PING_TIMEOUT_MS    = 400
HR_CYCLES             = 1     # 1 ciclo suele bastar
HR_SLEEP              = 0.25

# Antibucle más permisivo (para no cortar temprano) y con autorrecuperación corta:
LOOP_SAME_STATE_THRESHOLD = 3   # declarar lazo si vemos el MISMO estado 3 veces seguidas
LOOP_AUTO_RECOVERY_TRIES  = 2   # cuántas limpiezas rápidas antes de rendirse

# ===================== COMANDOS =====================
CMD_NO_PAGE  = "terminal length 0"
CMD_HOSTNAME = "show running-config | include ^hostname"
CMD_MGMT_IP  = "show ip interface brief | inc Vlan1|BVI1|Loopback0"

MAC_RE = r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})"
IP_RE  = r"(\d{1,3}(?:\.\d{1,3}){3})"

# ===================== HELPERS BASE =====================

def tcp_check(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

def send_t(conn, cmd: str) -> str:
    """send_command_timing con paginación simple."""
    out = conn.send_command_timing(cmd, strip_prompt=False, strip_command=False)
    while "--More--" in out or "--More -" in out:
        out += conn.send_command_timing(" ", strip_prompt=False, strip_command=False)
    return out

def manual_session_prep(conn):
    conn.write_channel("\n"); time.sleep(0.05)
    try:
        conn.set_base_prompt()
    except Exception:
        pass
    send_t(conn, CMD_NO_PAGE)

def ensure_enable(conn):
    try:
        out = conn.send_command_timing("show privilege", strip_prompt=False, strip_command=False)
        if "Level 15" in out or "level 15" in out:
            manual_session_prep(conn)
            return
    except Exception:
        pass
    out = conn.send_command_timing("enable", strip_prompt=False, strip_command=False)
    if "Password" in out or "password" in out:
        send_t(conn, CORE["secret"])
    manual_session_prep(conn)

def run(conn, cmd: str) -> str:
    return send_t(conn, cmd)

def normalize_mac(mac: str) -> str:
    mac = mac.strip().lower().replace("-", "").replace(":", "").replace(".", "")
    return f"{mac[0:4]}.{mac[4:8]}.{mac[8:12]}" if re.fullmatch(r"[0-9a-f]{12}", mac) else mac.lower()

def port_looks_uplink(ifname: str) -> bool:
    m = re.search(r"/(\d+)$", ifname)
    return bool(m and m.group(1) in UPLINK_PORT_NUMBERS)

def is_definitely_trunk(conn, iface: str) -> bool:
    try:
        text = run(conn, f"show interfaces {iface} switchport")
    except Exception:
        return False
    if re.search(r"Administrative Mode:\s*trunk", text, re.I): return True
    if re.search(r"Operational Mode:\s*trunk", text, re.I):   return True
    if re.search(r"(Administrative|Operational) Mode:\s*access", text, re.I): return False
    return False

def listify_ifaces(if_field: Union[str, List[str]]) -> List[str]:
    if if_field is None: return []
    if isinstance(if_field, list): return [i.strip() for i in if_field if i and isinstance(i, str)]
    if isinstance(if_field, str):
        return [p.strip() for p in if_field.split(",")] if "," in if_field else [if_field.strip()]
    return []

def get_hostname(conn) -> str:
    text = run(conn, CMD_HOSTNAME)
    m = re.search(r"^hostname\s+(\S+)", text, re.M)
    return m.group(1) if m else "UNKNOWN"

def get_mgmt_ip(conn) -> Optional[str]:
    text = run(conn, CMD_MGMT_IP)
    m = re.search(IP_RE + r"\s+\S+\s+YES.*?up\s+up", text)
    if m: return m.group(1)
    m = re.search(IP_RE, text)
    return m.group(1) if m else None

# ===================== REFRESCOS SELECTIVOS =====================

def ping_host(conn, ip: str, repeat: int, timeout_ms: int):
    run(conn, f"ping {ip} repeat {repeat} timeout {timeout_ms}")

def clear_arp_mac(conn, ip: Optional[str], mac: Optional[str]):
    if ip:  run(conn, f"clear ip arp {ip}")
    if mac: run(conn, f"clear mac address-table dynamic address {normalize_mac(mac)}")

def light_refresh(conn, ip: str, mac: Optional[str]):
    """Refresco mínimo para acelerar convergencia, usado selectivamente."""
    clear_arp_mac(conn, ip, mac)
    ping_host(conn, ip, repeat=QP_PING_REPEAT, timeout_ms=QP_PING_TIMEOUT_MS)
    time.sleep(QP_SLEEP_SHORT)

def heavy_refresh(conn, ip: str, mac: Optional[str]):
    """Refresco 'fuerte' pero compacto (1 ciclo)."""
    for _ in range(HR_CYCLES):
        clear_arp_mac(conn, ip, mac)
        ping_host(conn, ip, repeat=HR_PING_REPEAT, timeout_ms=HR_PING_TIMEOUT_MS)
        time.sleep(HR_SLEEP)

# ===================== IP → MAC (rápido) =====================

def find_mac_for_ip(conn, ip: str) -> Optional[str]:
    # Orden: DHCP Snooping → IDT → ARP puntual. No limpiar a menos que no salga.
    out = conn.send_command("show ip dhcp snooping binding", use_textfsm=True)
    if isinstance(out, list):
        for row in out:
            if str(row.get("ipaddr","")) == ip and row.get("mac"):
                return normalize_mac(row["mac"])
    else:
        text = run(conn, "show ip dhcp snooping binding")
        for ln in text.splitlines():
            if ip in ln:
                m = re.search(MAC_RE, ln, re.I)
                if m: return normalize_mac(m.group(1))

    text = run(conn, "show ip device tracking all")
    for ln in text.splitlines():
        if ip in ln:
            m = re.search(MAC_RE, ln, re.I)
            if m: return normalize_mac(m.group(1))

    text = run(conn, f"show ip arp {ip}")
    m = re.search(MAC_RE, text, re.I)
    if m: return normalize_mac(m.group(1))

    # Un único refresco ligero si aún no se obtuvo MAC
    light_refresh(conn, ip, None)
    text = run(conn, f"show ip arp {ip}")
    m = re.search(MAC_RE, text, re.I)
    if m: return normalize_mac(m.group(1))

    # Último recurso: ARP global (rápido)
    txt = conn.send_command("show ip arp", use_textfsm=True)
    if isinstance(txt, list):
        for row in txt:
            if str(row.get("address")) == ip and row.get("mac"):
                return normalize_mac(row["mac"])
    else:
        text = run(conn, "show ip arp")
        for ln in text.splitlines():
            if ip in ln:
                m = re.search(MAC_RE, ln, re.I)
                if m: return normalize_mac(m.group(1))
    return None

# ===================== CAM (MAC → puertos) =====================

def cam_lookup_all_ports(conn, mac: str) -> List[str]:
    mac = normalize_mac(mac)
    ports: List[str] = []

    # Primero: consulta específica por MAC (evita barrer toda la tabla)
    text = run(conn, f"show mac address-table address {mac}")
    for ln in text.splitlines():
        m = re.search(r"(?:dynamic|DYNAMIC)\s+([A-Za-z]+\S+)\s*$", ln)
        if m: ports.append(m.group(1).strip())

    if not ports:
        out = conn.send_command("show mac address-table", use_textfsm=True)
        if isinstance(out, list):
            for r in out:
                if normalize_mac(str(r.get("destination_address",""))) == mac:
                    ports += listify_ifaces(r.get("destination_port"))
        else:
            text = run(conn, f"show mac address-table | include {mac}")
            for ln in text.splitlines():
                if mac in ln.lower():
                    m = re.search(r"([A-Za-z]+\S+)\s*$", ln)
                    if m: ports.append(m.group(1).strip())

    # Dedup conservando orden
    res, seen = [], set()
    for p in ports:
        if p and p not in seen:
            res.append(p); seen.add(p)
    return res

# ===================== Vecinos (CDP/LLDP + Inferencia) =====================

def neighbor_ip_from_interface(conn, iface: str) -> Optional[str]:
    # CDP/LLDP por interfaz específica (rápido)
    for cmd in (f"show cdp neighbors {iface} detail",
                f"show cdp neighbor detail interface {iface}",
                f"show lldp neighbors {iface} detail"):
        out = conn.send_command(cmd, use_textfsm=False)
        # Busca una Management IP en el output
        m = re.search(r"(?:IP (?:Address|address)|Management Address|IP address):\s*" + IP_RE, out, re.I)
        if m:
            return m.group(1)
    return None

def get_arp_entries(conn) -> List[Tuple[str, str]]:
    res: List[Tuple[str,str]] = []
    text = run(conn, "show ip arp")
    for ln in text.splitlines():
        m_ip  = re.search(IP_RE, ln)
        m_mac = re.search(MAC_RE, ln, re.I)
        if m_ip and m_mac:
            res.append((m_ip.group(1), normalize_mac(m_mac.group(1))))
    return res

def mac_on_interface(conn, mac: str, iface: str) -> bool:
    return iface in cam_lookup_all_ports(conn, mac)

def candidate_neighbor_ips_by_inference(conn, uplink_iface: str, self_ip: Optional[str]) -> List[str]:
    candidates: Set[str] = set()
    for ip, mac in get_arp_entries(conn):
        try:
            if self_ip and ip == self_ip: continue
            if ip_address(ip) not in MGMT_NET: continue
        except Exception:
            continue
        try:
            if mac_on_interface(conn, mac, uplink_iface):
                candidates.add(ip)
        except Exception:
            continue
    def score(ip):
        last = int(ip.split(".")[-1])
        pref = 0 if last in (11,12,13) else 1
        return (pref, last)
    return sorted(list(candidates), key=score)

# ===================== SSH interno SIN redispatch =====================

def ssh_to_neighbor_from_device(conn, username: str, password: str, neighbor_ip: str, current_hostname: str) -> Optional[str]:
    """Salto rápido; valida que cambió el hostname."""
    conn.write_channel("\n"); time.sleep(0.05)
    conn.clear_buffer()
    conn.write_channel(f"ssh -l {username} {neighbor_ip}\n")
    time.sleep(0.5)

    out = conn.read_channel()
    if "yes/no" in out.lower():
        conn.write_channel("yes\n"); time.sleep(0.3)
        out = conn.read_channel()
    if "Password:" in out or "password:" in out:
        conn.write_channel(password + "\n"); time.sleep(0.6)

    manual_session_prep(conn)
    ensure_enable(conn)
    new_hostname = get_hostname(conn)
    if new_hostname and new_hostname != current_hostname:
        return new_hostname

    # salto inválido: intenta regresar rápido
    try:
        conn.write_channel("\x03\n"); time.sleep(0.05)
        conn.write_channel("\n");   time.sleep(0.05)
        conn.clear_buffer()
        manual_session_prep(conn)
    except Exception:
        pass
    return None

# ===================== Elección de puerto (rápida) =====================

def choose_access_or_assume(conn, ports: List[str]) -> Optional[str]:
    for p in ports:
        if port_looks_uplink(p): continue
        if not is_definitely_trunk(conn, p):
            return p
    if len(ports) == 1 and not port_looks_uplink(ports[0]):
        return ports[0]
    return None

# ===================== Quick step en un switch =====================

def quick_step_here(conn, ip: str, mac: str) -> Tuple[Optional[str], List[str]]:
    """Devuelve (puerto_final_o_None, lista_puertos_CAM). No limpia salvo necesidad mínima."""
    ports = cam_lookup_all_ports(conn, mac)
    if not ports:
        # 1 micro refresh súper ligero (no costoso)
        light_refresh(conn, ip, mac)
        ports = cam_lookup_all_ports(conn, mac)

    if not ports:
        return None, []

    access = choose_access_or_assume(conn, ports)
    return access, ports

# ===================== Trazado con rapidez y autorrecuperación =====================

def trace_mac_fast(conn, ip: str, mac: str) -> Tuple[str, str, str]:
    visited_states: Dict[str, Tuple[Tuple[str, ...], int]] = {}
    hops = 0

    while True:
        hops += 1
        if hops > MAX_HOPS:
            raise RuntimeError("Demasiados saltos (posible lazo).")

        this_host = get_hostname(conn)
        this_mgmt_ip = get_mgmt_ip(conn) or "0.0.0.0"

        # QUICK PATH en el switch actual
        access, ports = quick_step_here(conn, ip, mac)
        if access:
            return this_host, this_mgmt_ip, access
        if not ports:
            # Heavy refresh selectivo SOLO si no hay información
            heavy_refresh(conn, ip, mac)
            access, ports = quick_step_here(conn, ip, mac)
            if access:
                return this_host, this_mgmt_ip, access
            if not ports:
                raise RuntimeError(f"No encuentro la MAC {mac} en la CAM de {this_host} ({this_mgmt_ip}).")

        # Detección de estado (anti-bucle)
        fp = tuple(sorted(ports))
        prev = visited_states.get(this_mgmt_ip)
        if prev and prev[0] == fp:
            visited_states[this_mgmt_ip] = (fp, prev[1] + 1)
            if prev[1] + 1 >= LOOP_SAME_STATE_THRESHOLD:
                # Intentos cortos de autorrecuperación rápida para no volver a empezar
                for _ in range(LOOP_AUTO_RECOVERY_TRIES):
                    heavy_refresh(conn, ip, mac)
                    access, ports = quick_step_here(conn, ip, mac)
                    if access:
                        return this_host, this_mgmt_ip, access
                # Si aun así no, seguimos saltando por uplinks (no abortar de inmediato)
        else:
            visited_states[this_mgmt_ip] = (fp, 1)

        # Saltar por uplinks (CDP/LLDP → inferencia)
        jumped = False
        for upl in ports:
            if port_looks_uplink(upl) or is_definitely_trunk(conn, upl):
                nbr_ip = neighbor_ip_from_interface(conn, upl)
                if nbr_ip:
                    new_hn = ssh_to_neighbor_from_device(conn, CORE["username"], CORE["password"], nbr_ip, this_host)
                    if new_hn:
                        jumped = True
                        break
                else:
                    # Inferencia: probar candidatos rápidos
                    cand_ips = candidate_neighbor_ips_by_inference(conn, upl, self_ip=this_mgmt_ip)
                    for ipcand in cand_ips:
                        new_hn = ssh_to_neighbor_from_device(conn, CORE["username"], CORE["password"], ipcand, this_host)
                        if new_hn:
                            jumped = True
                            break
                    if jumped: break
        if not jumped:
            # Sin vecino confiable: si hay 1 solo puerto no uplink, acéptalo.
            if len(ports) == 1 and not port_looks_uplink(ports[0]):
                return this_host, this_mgmt_ip, ports[0]
            # último empujón local y reintento rápido
            heavy_refresh(conn, ip, mac)
            access, ports2 = quick_step_here(conn, ip, mac)
            if access:
                return this_host, this_mgmt_ip, access
            # Si continúa sin vecino ni puerto final:
            raise RuntimeError(
                f"La MAC {mac} aparece en {ports} de {this_host}, sin vecino por CDP/LLDP/Inferencia."
            )

# ===================== Conexión CORE y MAIN =====================

def connect_core_fast(core_params: dict):
    host = core_params.get("host", "")
    port = int(core_params.get("port", 22))
    if not tcp_check(host, port, timeout=2.0):
        raise RuntimeError(f"No hay TCP en {host}:{port} (SSH).")
    conn = ConnectHandler(**core_params)
    manual_session_prep(conn)
    ensure_enable(conn)
    return conn

def main():
    target_ip = input("🔎 ¿Qué IP quieres buscar?: ").strip()
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", target_ip):
        print("IP inválida."); return

    print(f"[i] Conectando al SW-CORE {CORE['host']} ...")
    conn = connect_core_fast(CORE)

    try:
        # Quick path para obtener MAC (sin limpiezas iniciales pesadas)
        print(f"[i] Resolviendo MAC para la IP {target_ip} ...")
        mac = find_mac_for_ip(conn, target_ip)
        if not mac:
            # un empujón breve y segundo intento
            light_refresh(conn, target_ip, None)
            mac = find_mac_for_ip(conn, target_ip)
        if not mac:
            raise RuntimeError("No pude resolver la MAC (DHCP/IDT/ARP).")
        print(f"[✓] MAC detectada: {mac}")

        print("[i] Persiguiendo la MAC (ruta rápida, con refresco selectivo) ...")
        host, mgmt_ip, access_if = trace_mac_fast(conn, target_ip, mac)

        print("\n====== RESULTADO ======")
        print(f"IP consultada:  {target_ip}")
        print(f"MAC del host:   {mac}")
        print(f"Switch:         {host}")
        print(f"IP de gestión:  {mgmt_ip}")
        print(f"Puerto:         {access_if}")
        print("=======================\n")

        if port_looks_uplink(access_if):
            print("⚠️ OJO: salió 47/48 (uplink). Esto NO debería ser host.")
        else:
            print("✅ Puerto de acceso válido.")

    except Exception as e:
        print(f"\n[ERROR] {e}\n")
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass

if __name__ == "__main__":
    main()
