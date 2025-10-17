"""
find_ip_switch.py

Descripción:
------------
Script para localizar en qué switch y puerto está conectada una IP dentro de una red
(Cisco IOS) en VLAN 1. Reporta:
- Switch
- Puerto físico
- MAC
- IP consultada

Estrategia (sin TextFSM, usando regex robustos):
1) Obtener la MAC asociada a la IP consultada utilizando varios comandos en los switches:
   - DHCP Snooping bindings
   - ARP directo/tabla ARP
   - IP Device Tracking (si está habilitado)
2) Con la MAC encontrada, buscar en las tablas de direcciones (show mac address-table)
   de cada switch para determinar el puerto físico de acceso.

Requisitos:
-----------
    pip install netmiko

Notas:
------
- Si algunos "show" requieren privilegios, agrega "secret" a los diccionarios de SWITCHES
  y se realizará "enable()".
- De preferencia corre DHCP Snooping/Device Tracking en el SW-CORE.
- Ajusta la lista SWITCHES a tus credenciales/IPs reales.
"""

from netmiko import ConnectHandler
import re

# ===================== CONFIGURACIÓN =====================
# Lista de switches a consultar. 'host_name' es solo para impresión en consola.
SWITCHES = [
    {"device_type": "cisco_ios", "ip": "192.168.1.11", "username": "cisco", "password": "cisco99", "host_name": "SW1"},
    {"device_type": "cisco_ios", "ip": "192.168.1.1",  "username": "cisco", "password": "cisco99", "host_name": "SW-CORE"},
    {"device_type": "cisco_ios", "ip": "192.168.1.12", "username": "cisco", "password": "cisco99", "host_name": "SW2"},
]
VLAN_OBJETIVO = "1"  # La práctica asume VLAN 1 para todos los dispositivos.

# Si tu equipo requiere enable:
# for s in SWITCHES: s["secret"] = "tu_enable_secret"

# ===================== UTILIDADES =====================
# Patrones para detectar MAC en distintos formatos que arroja IOS:
# - aaaa.bbbb.cccc
# - 00:11:22:33:44:55
# - 001122334455 (plana)
MAC_PATTERNS = [
    r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}",
    r"[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}",
    r"[0-9a-fA-F]{12}"
]

def norm_mac(mac: str) -> str:
    """
    Normaliza una dirección MAC a forma plana en minúsculas (sin separadores).
    Ejemplo:
        'aaaa.bbbb.cccc' -> 'aaaabbbbcccc'
        'AA:BB:CC:DD:EE:FF' -> 'aabbccddeeff'
    """
    return re.sub(r"[^0-9a-fA-F]", "", mac).lower()

def any_mac_in(text: str):
    """
    Busca cualquier MAC en el texto de salida de un comando usando patrones conocidos.
    Devuelve la MAC encontrada (string) o None si no detecta ninguna.
    """
    for pat in MAC_PATTERNS:
        m = re.search(pat, text)
        if m:
            return m.group(0)
    return None

def get_conn(sw: dict):
    """
    Crea y devuelve una conexión Netmiko a un switch Cisco IOS.
    - Aplica 'terminal length 0' para evitar paginación.
    - Si existe 'secret', intenta elevar privilegios con 'enable()'.
    """
    params = {
        "device_type": sw["device_type"],
        "host": sw["ip"],
        "username": sw["username"],
        "password": sw["password"],
        "fast_cli": True,  # acelera envíos de comandos (mejora rendimiento)
    }
    if "secret" in sw and sw["secret"]:
        params["secret"] = sw["secret"]
    conn = ConnectHandler(**params)
    try:
        conn.send_command_timing("terminal length 0", strip_command=False)
    except Exception:
        # No todos los dispositivos aceptan esta orden o el método timing puede fallar sin impacto crítico.
        pass
    if "secret" in sw and sw["secret"]:
        try:
            conn.enable()
        except Exception:
            # Si falla enable(), se continúa en modo usuario (algunos 'show' seguirán funcionando).
            pass
    return conn

def parse_vlan_from_iface(ifname: str) -> str | None:
    """
    Extrae el número de VLAN si la interfaz es de tipo 'VlanX'.
    Ejemplo:
        'Vlan1' -> '1'
        'GigabitEthernet0/1' -> None
    """
    m = re.search(r"[Vv]lan(\d+)", ifname)
    return m.group(1) if m else None

def extract_vlan(text: str) -> str | None:
    """
    Intenta extraer un número de VLAN de una cadena genérica que contenga 'VLAN'/'Vlan'.
    Acepta formatos como:
        'Vlan 1', 'VLAN: 1', 'vlan 1'
    """
    m = re.search(r"[Vv][Ll][Aa][Nn]\s*:?[\s#]*([0-9]+)", text)
    return m.group(1) if m else None

def discover_mac_for_ip(conn, ip: str):
    """
    Dada una IP, intenta resolver la MAC asociada consultando varios orígenes:
      1) DHCP Snooping bindings:
         - 'show ip dhcp snooping binding | include <ip>'
         - 'show ip dhcp snooping binding'
      2) ARP directo por IP:
         - 'show ip arp <ip>'
      3) ARP general:
         - 'show ip arp' / 'show arp'
      4) IP Device Tracking (si está habilitado):
         - 'show ip device tracking all | include <ip>'
         - 'show ip device tracking all'

    Devuelve un dict con:
      {'ip','mac','src'('dhcp'|'arp'|'device-tracking'),'vlan', 'iface'}
    o None si no se encuentra.
    """
    # --- 1) DHCP Snooping ---
    cmds = [
        f"show ip dhcp snooping binding | include {ip}",
        "show ip dhcp snooping binding"
    ]
    for cmd in cmds:
        try:
            out = conn.send_command(cmd, use_textfsm=False)
            if ip in out:
                # Línea típica (campos pueden variar por plataforma):
                # 00:11:22:33:44:55  192.168.1.50  ...  1  Gi0/15
                line = next((l for l in out.splitlines() if ip in l), "")
                mac = any_mac_in(line)
                vlan = None
                iface = None
                # Heurística: número de VLAN seguido de interfaz
                vlan_num = re.search(r"\s(\d+)\s+([A-Za-z]+\d+(?:/\d+)*\S*)", line)
                if vlan_num:
                    vlan = vlan_num.group(1)
                    iface = vlan_num.group(2)
                if not vlan:
                    vlan = extract_vlan(line)
                if not vlan and iface:
                    vlan = parse_vlan_from_iface(iface)
                if mac:
                    return {"ip": ip, "mac": mac, "src": "dhcp", "vlan": vlan, "iface": iface}
        except Exception:
            # Continuar intentando otras fuentes
            pass

    # --- 2) ARP directo por IP ---
    for cmd in (f"show ip arp {ip}",):
        try:
            out = conn.send_command(cmd, use_textfsm=False)
            if ip in out:
                # Típico IOS:
                # "Internet  192.168.1.50  0  aaaa.bbbb.cccc  ARPA  Vlan1"
                line = next((l for l in out.splitlines() if ip in l), "")
                mac = any_mac_in(line)
                iface = None
                vlan = None
                # Interfaz suele ir al final de la línea
                m_if = re.search(r"\s([A-Za-z0-9/\.]+)\s*$", line)
                if m_if:
                    iface = m_if.group(1)
                vlan = parse_vlan_from_iface(iface or "")
                if not vlan:
                    vlan = extract_vlan(line)
                if mac:
                    return {"ip": ip, "mac": mac, "src": "arp", "vlan": vlan, "iface": iface}
        except Exception:
            pass

    # --- 3) ARP genérico (cuando el equipo no soporta consulta directa) ---
    for cmd in ("show ip arp", "show arp"):
        try:
            out = conn.send_command(cmd, use_textfsm=False)
            if ip in out:
                line = next((l for l in out.splitlines() if ip in l), "")
                mac = any_mac_in(line)
                iface = None
                vlan = None
                m_if = re.search(r"\s([A-Za-z0-9/\.]+)\s*$", line)
                if m_if:
                    iface = m_if.group(1)
                vlan = parse_vlan_from_iface(iface or "")
                if not vlan:
                    vlan = extract_vlan(line)
                if mac:
                    return {"ip": ip, "mac": mac, "src": "arp", "vlan": vlan, "iface": iface}
        except Exception:
            pass

    # --- 4) Device Tracking (si está disponible) ---
    for cmd in (f"show ip device tracking all | include {ip}",
                "show ip device tracking all"):
        try:
            out = conn.send_command(cmd, use_textfsm=False)
            if ip in out:
                # Ejemplo de línea:
                # "192.168.1.50  aaaa.bbbb.cccc  Gi0/15 ..."
                line = next((l for l in out.splitlines() if ip in l), "")
                mac = any_mac_in(line)
                iface = None
                vlan = None
                m_if = re.search(r"\s([A-Za-z]+[0-9/\.]+)\s", line)
                if m_if:
                    iface = m_if.group(1)
                # Intento de inferir VLAN desde el texto o la interfaz (si fuera VlanX)
                vlan = extract_vlan(out) or parse_vlan_from_iface(iface or "")
                if mac:
                    return {"ip": ip, "mac": mac, "src": "device-tracking", "vlan": vlan, "iface": iface}
        except Exception:
            pass

    # Si ninguna fuente trajo datos, devolvemos None:
    return None

def find_port_for_mac(conn, mac: str):
    """
    Dada una MAC (en cualquier formato), intenta localizar el puerto y VLAN
    consultando la tabla de direcciones:
        - show mac address-table address <mac>
        - show mac address-table | include <mac>
        - show mac address-table   (barrida completa como último recurso)

    Devuelve:
        {'port': <puerto>, 'vlan': <vlan>, 'type': <tipo>}
    o None si no la encuentra en ese switch.
    """
    mac_clean = norm_mac(mac)
    # Construye variantes de la misma MAC en formatos comunes de IOS:
    mac_variants = {
        "dot": f"{mac_clean[0:4]}.{mac_clean[4:8]}.{mac_clean[8:12]}",
        "colon": ":".join([mac_clean[i:i+2] for i in range(0,12,2)]),
        "plain": mac_clean
    }

    # Secuencia de comandos: específicos -> filtros -> listado general
    cmds = [
        f"show mac address-table address {mac_variants['dot']}",
        f"show mac address-table address {mac_variants['colon']}",
        f"show mac address-table | include {mac_variants['dot']}",
        f"show mac address-table | include {mac_variants['colon']}",
        f"show mac address-table | include {mac_variants['plain']}",
        "show mac address-table"
    ]

    for cmd in cmds:
        try:
            out = conn.send_command(cmd, use_textfsm=False)
            if not out.strip():
                continue

            # Líneas típicas:
            # "  1    aaaa.bbbb.cccc   DYNAMIC  Gi0/15"
            for line in out.splitlines():
                # Verifica si contiene alguna forma de la MAC
                if any(v in line for v in mac_variants.values()):
                    # VLAN: primer número aislado en la línea suele ser la VLAN
                    m_vlan = re.search(r"\s(\d+)\s", line)
                    vlan = m_vlan.group(1) if m_vlan else None
                    # TYPE: DYNAMIC/STATIC/SELF/CPU...
                    m_type = re.search(r"\s(DYNAMIC|STATIC|STATIC_SECURE|SELF|CPU)\s", line, re.IGNORECASE)
                    typ = m_type.group(1) if m_type else "UNKNOWN"
                    # PORT: último token tipo interfaz
                    m_port = re.search(r"([A-Za-z]+\d+(?:/\d+)*\S*)\s*$", line)
                    port = m_port.group(1) if m_port else None

                    if port:
                        return {"port": port, "vlan": vlan, "type": typ}
        except Exception:
            # Si falla un comando (no soportado u otro error), intentamos el siguiente
            continue

    return None

def localizar_ip(ip_buscada: str):
    """
    Flujo principal para localizar una IP:
    1) Recorre los switches y trata de resolver IP -> MAC (DHCP/ARP/Device Tracking).
       Suele existir en el SW-CORE, pero se intentan todos por robustez.
    2) Con la MAC obtenida, recorre todos los switches para encontrar el puerto de acceso
       consultando la tabla MAC. Aplica una heurística simple para preferir:
         - Coincidencia en VLAN objetivo.
         - Puertos que no luzcan como trunks (ej. Port-Channel, TenGig, etc.)
    3) Imprime el resultado final o un aviso si no fue posible localizar el puerto.
    """
    print(f"\n🔎 Buscando la IP {ip_buscada} en la red...\n")

    # 1) Intentar hallar la MAC a partir de la IP
    mac_info = None
    src_sw = None
    for sw in SWITCHES:
        try:
            conn = get_conn(sw)
            info = discover_mac_for_ip(conn, ip_buscada)
            conn.disconnect()
            if info:
                mac_info = info
                src_sw = sw
                print(f"[{sw['host_name']}] IP encontrada -> MAC {info['mac']} (via {info['src']}) IF:{info.get('iface','?')} VLAN:{info.get('vlan','?')}")
                break
            else:
                print(f"[{sw['host_name']}] Sin binding/ARP/DT para {ip_buscada}")
        except Exception as e:
            print(f"[!] Error conectando a {sw['host_name']} ({sw['ip']}): {e}")

    if not mac_info:
        # Si no hay MAC, no es posible continuar con la búsqueda del puerto.
        print("❌ No se encontró la IP en DHCP Snooping, ARP ni Device Tracking en ningún switch.")
        return

    # 2) Con la MAC, buscar en qué switch/puerto aparece en la tabla MAC
    mac = mac_info["mac"]
    best_result = None
    best_switch = None

    for sw in SWITCHES:
        try:
            conn = get_conn(sw)
            loc = find_port_for_mac(conn, mac)
            conn.disconnect()
            if loc:
                # Heurística: preferir
                # - VLAN objetivo (puntaje extra)
                # - Puerto que no parezca trunk/port-channel (penalización si lo es)
                port = loc["port"]
                is_trunkish = bool(re.search(r"Po\d+|Port-Channel|^Gi0/1$|^Gi1/0/1$|^Te|^Fo", port, re.IGNORECASE))
                vlan_score = 2 if (loc["vlan"] == VLAN_OBJETIVO) else 1
                trunk_penalty = 0 if not is_trunkish else -1
                score = vlan_score + trunk_penalty

                if (best_result is None) or (score > best_result.get("score", 0)):
                    best_result = {"port": port, "vlan": loc["vlan"], "type": loc["type"], "score": score}
                    best_switch = sw
        except Exception as e:
            print(f"[!] Error conectando a {sw['host_name']} ({sw['ip']}): {e}")

    if best_result and best_switch:
        # Éxito: se encontró puerto y switch
        print("\n📘 Resultado final:")
        print(f"  ├── Switch:   {best_switch['host_name']}")
        print(f"  ├── IP:       {ip_buscada}")
        print(f"  ├── MAC:      {mac}")
        print(f"  ├── Puerto:   {best_result['port']}")
        print(f"  └── VLAN:     {best_result['vlan'] or mac_info.get('vlan','?')}\n")
        return

    # 3) MAC encontrada pero sin entrada en tablas MAC (posibles causas: aging, MAC aprendida por trunk,
    #    endpoint inactivo, puerto err-disable, topología diferente a lo esperado, etc.)
    print("\n⚠️ Se obtuvo la MAC, pero no aparece en la tabla de direcciones de los switches.")
    print(f"   IP: {ip_buscada} | MAC: {mac} | Origen: {src_sw['host_name']} | VLAN: {mac_info.get('vlan','?')} | IF: {mac_info.get('iface','?')}\n")

# ===================== MAIN =====================
if __name__ == "__main__":
    import sys
    import re as _re

    # Bucle interactivo de consulta
    while True:
        ip = input("\nIngresa la IP que deseas buscar (o 'exit' para salir): ").strip()
        if ip.lower() == "exit":
            break
        # Validación básica de formato IPv4
        if not _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            print("Formato de IP no válido.")
            continue
        try:
            localizar_ip(ip)
        except KeyboardInterrupt:
            print("\nInterrumpido por usuario.")
            sys.exit(0)
