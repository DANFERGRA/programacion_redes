#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rastreador IP -> Switch/Puerto (v3)
- Ruta completa (todos los hops) en consola y CSV.
- Filtro de puertos físicos y límite de 48 puertos para Fa/Gi/Te.
- Vecino por interfaz con fallback robusto.
- SALIDA: 'Ruta completa' ahora en MINI TABLA (no lista).
"""

from netmiko import ConnectHandler
import re, csv
from datetime import datetime
from typing import List, Dict, Optional, Tuple

# ========== CONFIG ==========
SEEDS = [
    {"device_type": "cisco_ios", "ip": "192.168.1.11", "username": "cisco", "password": "cisco99", "secret": "cisco"},
    {"device_type": "cisco_ios", "ip": "192.168.1.12", "username": "cisco", "password": "cisco99", "secret": "cisco"},
    {"device_type": "cisco_ios", "ip": "192.168.1.13", "username": "cisco", "password": "cisco99", "secret": "cisco"},
]
MACS_MUCHAS_UMBRAL = 6
READ_TIMEOUT = 12
TRACE_CSV = "rastro_ip.csv"

# ========== REGEX ==========
RE_HOST = re.compile(r"^(\S+)[>#]\s*$", re.M)
RE_ARP  = re.compile(r"\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f\.]{14})\s+\S+\s+(\S+)", re.I)
RE_DHCP = re.compile(r"^\s*\d+\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f\.]{14})\s+(\d+)\s+(\S+)", re.I)
RE_IPDT = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f\.]{14})\s+(\S+)", re.I)

# MAC table (VLAN, MAC, TYPE, PORT) – ignora CPU/Router
RE_CAM_COLS = re.compile(r"^\s*(\d+)\s+([0-9a-f\.]{14})\s+(\S+)\s+(\S+)\s*$", re.I)

RE_SW_MODE = re.compile(r"(Operational|Administrative)\s+Mode:\s+(\S+)", re.I)
RE_TRUNK_TABLE_LINE = re.compile(r"^(?P<intf>\S+)\s+\S+\s+\S+\s+\S+", re.M)  # columna 1 interfaz

RE_CDP_IP = re.compile(r"IP address:\s+(\d+\.\d+\.\d+\.\d+)", re.I)
RE_LLDP_IP = re.compile(r"Management Address:\s+(\d+\.\d+\.\d+\.\d+)", re.I)
RE_CDP_IF  = re.compile(r"Interface:\s+(\S+),", re.I)
RE_LLDP_IF = re.compile(r"Local Port id:\s+(\S+)", re.I)

# ========== HELPERS ==========
def if_long(name: str) -> str:
    n = name.strip()
    for pfx in ("FastEthernet","GigabitEthernet","TenGigabitEthernet","Port-channel","Vlan","Loopback","Serial"):
        if n.lower().startswith(pfx.lower()):
            return n
    table = {
        "fa": "FastEthernet", "gi": "GigabitEthernet", "te": "TenGigabitEthernet",
        "po": "Port-channel", "vl": "Vlan", "lo": "Loopback", "se": "Serial",
    }
    m = re.match(r"^([A-Za-z]+)(.+)$", n)
    if not m: return n
    pre, rest = m.group(1).lower(), m.group(2)
    pre2 = table.get(pre[:2])
    return f"{pre2}{rest}" if pre2 else n

def is_physical_48(port: str) -> bool:
    """Acepta Fa/Gi/Te con último índice <= 48. Rechaza Vlan/Port-channel/CPU/Router/N/A."""
    p = port.strip()
    if p.upper() in ("CPU", "ROUTER", "N/A"): return False
    if p.lower().startswith(("vlan","port-channel")): return False
    pl = if_long(p)
    # Match Fa#/0/#  Gi#/0/#  Te#/0/#  (último <= 48)
    m = re.search(r"(FastEthernet|GigabitEthernet|TenGigabitEthernet)(\d+)/(\d+)/(\d+)$", pl, re.I)
    if not m:
        # También aceptar formato sin chasis: Gi0/1 (último <= 48)
        m2 = re.search(r"(FastEthernet|GigabitEthernet|TenGigabitEthernet)(\d+)/(\d+)$", pl, re.I)
        if not m2: return False
        last = int(m2.group(3))
        return last <= 48
    last = int(m.group(4))
    return last <= 48

def connect(dev):
    c = ConnectHandler(**dev)
    try: c.enable()
    except Exception: pass
    return c

def run(c, cmd: str) -> str:
    return c.send_command(cmd, use_textfsm=False, read_timeout=READ_TIMEOUT) or ""

def get_hostname(c) -> str:
    out = c.find_prompt()
    m = RE_HOST.search(out)
    return m.group(1) if m else out.strip("#>").strip()

# ========== RESOLVER MAC ==========
def resolve_mac_from_ip(seeds: List[dict], ip: str) -> Tuple[Optional[str], Optional[str]]:
    for dev in seeds:
        try:
            c = connect(dev)
            out = run(c, "show ip dhcp snooping binding")
            for line in out.splitlines():
                m = RE_DHCP.search(line)
                if m and m.group(1) == ip:
                    mac, vlan = m.group(2).lower(), m.group(3); c.disconnect(); return mac, vlan
            out = run(c, f"show ip device tracking all | include {ip}")
            for line in out.splitlines():
                m = RE_IPDT.search(line)
                if m and m.group(1) == ip:
                    mac = m.group(2).lower(); c.disconnect(); return mac, None
            out = run(c, f"show ip arp {ip}")
            for line in out.splitlines():
                m = RE_ARP.search(line)
                if m and m.group(1) == ip:
                    mac = m.group(2).lower(); c.disconnect(); return mac, None
            c.disconnect()
        except Exception:
            continue
    return None, None

# ========== CAM ==========
def find_cam_entries(c, mac: str) -> List[Tuple[str, str]]:
    found = []
    for out in (
        run(c, f"show mac address-table dynamic address {mac}"),
        run(c, f"show mac address-table | include {mac}"),
    ):
        for line in out.splitlines():
            m = RE_CAM_COLS.search(line)
            if not m: continue
            vlan, _mac, typ, port = m.group(1), m.group(2), m.group(3), m.group(4)
            if _mac.lower() != mac.lower(): continue
            if port.upper() in ("CPU","ROUTER"): continue
            port = if_long(port)
            if not is_physical_48(port):  # <<< filtro 48 puertos
                continue
            found.append((vlan, port))
    # dedup
    uniq, seen = [], set()
    for v,p in found:
        k=(v,p)
        if k not in seen: uniq.append(k); seen.add(k)
    return uniq

def count_port_macs(c, port: str) -> int:
    out = run(c, f"show mac address-table interface {port}")
    return sum(1 for ln in out.splitlines() if "DYNAMIC" in ln.upper())

# ========== TRUNK / ACCESS ==========
def is_trunk(c, port: str) -> bool:
    pl = if_long(port)
    sw = run(c, f"show interfaces {pl} switchport")
    for m in RE_SW_MODE.finditer(sw):
        if m.group(2).lower() == "trunk": return True
    trunk = run(c, "show interfaces trunk")
    for m in RE_TRUNK_TABLE_LINE.finditer(trunk):
        if if_long(m.group("intf")) == pl: return True
    return False

def access_vlan(c, port: str) -> Optional[str]:
    pl = if_long(port)
    sw = run(c, f"show interfaces {pl} switchport")
    m = re.search(r"Access Mode VLAN:\s+(\d+)", sw, re.I)
    if m: return m.group(1)
    m = re.search(r"Access VLAN:\s+(\d+)", sw, re.I)
    return m.group(1) if m else None

# ========== VECINO EXACTO ==========
def neighbor_ip_exact(c, port: str) -> Optional[str]:
    pl = if_long(port)
    # 1) CDP por interfaz
    out = run(c, f"show cdp neighbors interface {pl} detail")
    m = RE_CDP_IP.search(out)
    if m: return m.group(1)
    # 2) LLDP por interfaz
    out = run(c, f"show lldp neighbors interface {pl} detail")
    m = RE_LLDP_IP.search(out)
    if m: return m.group(1)
    # 3) Fallback: CDP global, pero filtrando el bloque cuyo Interface coincida EXACTO
    out = run(c, "show cdp neighbors detail")
    blocks = out.split("\n\n")
    for b in blocks:
        m_if = RE_CDP_IF.search(b)
        if m_if and if_long(m_if.group(1)) == pl:
            m_ip = RE_CDP_IP.search(b)
            if m_ip: return m_ip.group(1)
    # 4) Fallback LLDP global
    out = run(c, "show lldp neighbors detail")
    blocks = out.split("\n\n")
    for b in blocks:
        m_if = RE_LLDP_IF.search(b)
        if m_if and if_long(m_if.group(1)) == pl:
            m_ip = RE_LLDP_IP.search(b)
            if m_ip: return m_ip.group(1)
    return None

def should_follow(c, port: str, mac_count: int) -> bool:
    if is_trunk(c, port): return True
    if mac_count >= MACS_MUCHAS_UMBRAL: return True
    if neighbor_ip_exact(c, port): return True
    return False

# ========== TRACE ==========
def trace_ip(ip: str) -> Dict[str, str]:
    mac, vlan_hint = resolve_mac_from_ip(SEEDS, ip)
    if not mac:
        return {"status": "NO_MAC", "detail": f"No se pudo resolver MAC para {ip}"}

    visited_switch_ips = set()
    path: List[Dict[str,str]] = []
    final: Optional[Tuple[str,str,str,str]] = None  # (host, port, vlan, sw_ip)

    queue = SEEDS.copy()
    while queue:
        dev = queue.pop(0)
        if dev["ip"] in visited_switch_ips: continue
        visited_switch_ips.add(dev["ip"])
        try:
            c = connect(dev)
            host = get_hostname(c)
            cams = find_cam_entries(c, mac)
            if not cams:
                c.disconnect(); continue

            for vlan, port in cams:
                macs_here = count_port_macs(c, port)
                trunk = is_trunk(c, port)
                nei = neighbor_ip_exact(c, port)
                accv = access_vlan(c, port) if not trunk else None

                path.append({
                    "hop_hostname": host, "hop_switch_ip": dev["ip"],
                    "vlan": vlan, "port": port, "trunk": "yes" if trunk else "no",
                    "macs_on_port": macs_here, "neighbor_ip": nei or "", "access_vlan": accv or ""
                })

                if should_follow(c, port, macs_here) and nei and nei not in visited_switch_ips:
                    queue.append({
                        "device_type": "cisco_ios", "ip": nei,
                        "username": dev["username"], "password": dev["password"], "secret": dev.get("secret","")
                    })
                else:
                    final = (host, port, vlan, dev["ip"])
                    break

            c.disconnect()
            if final: break
        except Exception:
            continue

    write_trace_csv(ip, mac, vlan_hint, path)

    if not final:
        return {"status": "NOT_FINALIZED", "detail": "No se llegó a un puerto ACCESS inequívoco.", "mac": mac, "path": path}

    host, port, vlan, sw_ip = final
    return {
        "status": "OK", "switch_ip": sw_ip, "switch_hostname": host,
        "port": port, "vlan": vlan, "mac": mac, "path": path
    }

def write_trace_csv(ip: str, mac: str, vlan_hint: Optional[str], rows: List[Dict[str, str]]):
    hdr = ["ts","ip","mac","vlan_hint","hop_hostname","hop_switch_ip","vlan","port","trunk","macs_on_port","neighbor_ip","access_vlan"]
    exists = False
    try:
        with open(TRACE_CSV, "r", encoding="utf-8") as _:
            exists = True
    except Exception:
        pass
    with open(TRACE_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=hdr)
        if not exists: w.writeheader()
        for r in rows:
            w.writerow({
                "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip, "mac": mac, "vlan_hint": vlan_hint or "",
                "hop_hostname": r.get("hop_hostname",""), "hop_switch_ip": r.get("hop_switch_ip",""),
                "vlan": r.get("vlan",""), "port": r.get("port",""),
                "trunk": r.get("trunk",""), "macs_on_port": r.get("macs_on_port",""),
                "neighbor_ip": r.get("neighbor_ip",""), "access_vlan": r.get("access_vlan",""),
            })

# ========== MINI TABLA (render console) ==========
def mini_table(rows: List[List[str]], headers: List[str]) -> str:
    # calcula anchos
    cols = len(headers)
    widths = [len(h) for h in headers]
    for r in rows:
        for i in range(cols):
            widths[i] = max(widths[i], len(str(r[i])))

    def hline(sep_left="+", sep_mid="+", sep_right="+", fill="-"):
        return sep_left + sep_mid.join(fill*(w+2) for w in widths) + sep_right

    def fmt_row(vals: List[str]):
        cells = []
        for i, v in enumerate(vals):
            v = str(v)
            cells.append(" " + v.ljust(widths[i]) + " ")
        return "|" + "|".join(cells) + "|"

    out = []
    out.append(hline())
    out.append(fmt_row(headers))
    out.append(hline("+","+", "+", "="))
    for r in rows:
        out.append(fmt_row(r))
    out.append(hline())
    return "\n".join(out)

# ========== CLI ==========
def main():
    print("=== 🔍 Rastreador IP v3 (ruta completa + filtro 48 puertos) ===")
    while True:
        ip = input("Introduce la IP a localizar (o 'salir'): ").strip()
        if ip.lower() == "salir": break
        if not ip: continue
        res = trace_ip(ip)

        print("\n" + "*"*66)
        print("  🧭 RUTA COMPLETA")
        print("*"*66)
        path = res.get("path", [])

        if path:
            # Construimos filas para la mini tabla
            headers = ["Hop", "Hostname", "Switch IP", "VLAN", "Puerto", "Modo", "MACs", "Vecino IP", "Access VLAN"]
            rows = []
            for i, hop in enumerate(path, 1):
                rows.append([
                    str(i),
                    hop.get("hop_hostname",""),
                    hop.get("hop_switch_ip",""),
                    hop.get("vlan",""),
                    hop.get("port",""),
                    "TRUNK" if hop.get("trunk","no") == "yes" else "ACCESS",
                    str(hop.get("macs_on_port","")),
                    hop.get("neighbor_ip","") or "-",
                    hop.get("access_vlan","") or "-"
                ])
            print(mini_table(rows, headers))
        else:
            print("  (sin hops)")

        print("*"*66)
        if res["status"] == "OK":
            print("  ✅ DESTINO")
            print("*"*66)
            # También mostramos destino en mini tabla
            headers = ["Switch", "Switch IP", "Puerto", "VLAN", "IP", "MAC"]
            rows = [[
                res['switch_hostname'], res['switch_ip'], res['port'],
                res['vlan'], ip, res['mac']
            ]]
            print(mini_table(rows, headers))
        else:
            print("  ⚠️  RASTREO INCONCLUSO")
            print("*"*66)
            headers = ["Motivo", "MAC (si hubo)"]
            rows = [[res.get('detail',''), res.get('mac','-')]]
            print(mini_table(rows, headers))
        print("*"*66 + "\n")

if __name__ == "__main__":
    main()
