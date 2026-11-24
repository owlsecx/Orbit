#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════╗
# ║              ORBIT — Strategic Network Reconnaissance               ║
# ║   ARP Scan | IPv6 NDP Active & Passive | RA Option Extraction       ║
# ║   OS Fingerprint | Vendor Lookup | Port Scan | Export Engine        ║
# ║                                                                      ║
# ║   Author  : khaled.s.haddad                                         ║
# ║   Website : owlsec.org                                              ║
# ║   Version : 1.0                                                     ║
# ╚══════════════════════════════════════════════════════════════════════╝

import os
import sys
import csv
import json
import time
import socket
import struct
import signal
import logging
import datetime
import ipaddress
import threading
import subprocess
from pathlib  import Path
from collections import defaultdict, OrderedDict
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_network, ip_address, IPv6Address

# ── Suppress scapy warnings before import ────────────────────────────
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import (
    ARP, Ether, srp, conf, get_if_hwaddr, get_if_list,
    IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA,
    ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptMTU, ICMPv6NDOptRDNSS, ICMPv6NDOptDNSSL,
    sniff, TCP, UDP, IP, ICMP, sr1
)

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# ═══════════════════════════════════════════════════════════════════════
#  COLOR ENGINE
# ═══════════════════════════════════════════════════════════════════════
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    DIM     = "\033[2m"
    ORANGE  = "\033[38;5;214m"
    PURPLE  = "\033[38;5;135m"
    TEAL    = "\033[38;5;87m"
    GRAY    = "\033[38;5;245m"
    LIME    = "\033[38;5;154m"

def clr(text, *codes):
    return "".join(codes) + str(text) + C.RESET

# ═══════════════════════════════════════════════════════════════════════
#  GLOBALS
# ═══════════════════════════════════════════════════════════════════════
VERSION    = "1.0"
AUTHOR     = "khaled.s.haddad"
WEBSITE    = "owlsec.org"
_STOP_FLAG = threading.Event()

# ═══════════════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════════════
def banner():
    print(clr(r"""
   ██████╗ ██████╗ ██████╗ ██╗████████╗
  ██╔═══██╗██╔══██╗██╔══██╗██║╚══██╔══╝
  ██║   ██║██████╔╝██████╔╝██║   ██║
  ██║   ██║██╔══██╗██╔══██╗██║   ██║
  ╚██████╔╝██║  ██║██████╔╝██║   ██║
   ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝
""", C.CYAN))
    print(clr(f"        Strategic Network Reconnaissance  v{VERSION}", C.MAGENTA, C.BOLD))
    print(clr("   ARP | IPv6 NDP | RA Options | Port Scan | Vendor ID", C.WHITE))
    print()
    print(clr("  Author  : ", C.DIM, C.WHITE) + clr(AUTHOR, C.CYAN) +
          clr("   |   Website : ", C.DIM, C.WHITE) + clr(WEBSITE, C.CYAN))
    print(clr("─" * 68, C.CYAN))
    print()

# ═══════════════════════════════════════════════════════════════════════
#  HELP  (rich, full-featured)
# ═══════════════════════════════════════════════════════════════════════
def show_help():
    W = 66

    def top():    print(clr("╔" + "═"*W + "╗", C.CYAN))
    def bot():    print(clr("╚" + "═"*W + "╝", C.CYAN))
    def div():    print(clr("╠" + "═"*W + "╣", C.CYAN))
    def mid():    print(clr("║" + " "*W + "║", C.CYAN))
    def row(txt, color=C.WHITE, indent=0):
        pad  = " " * indent
        line = pad + txt
        fill = W - len(line)
        if fill < 0:
            line = line[:W]
            fill = 0
        print(clr("║", C.CYAN) + clr(line, color) + " "*fill + clr("║", C.CYAN))
    def hdr(title):
        div()
        row(f"  ◈  {title}", C.YELLOW + C.BOLD)
        mid()

    top()
    title_txt = f"  ORBIT v{VERSION}  —  Help & Usage Reference"
    fill = W - len(title_txt)
    print(clr("║", C.CYAN) + clr(title_txt, C.BOLD + C.CYAN) + " "*max(fill,0) + clr("║", C.CYAN))
    author_txt = f"  {AUTHOR}  |  {WEBSITE}"
    fill2 = W - len(author_txt)
    print(clr("║", C.CYAN) + clr(author_txt, C.DIM + C.WHITE) + " "*max(fill2,0) + clr("║", C.CYAN))
    mid()

    # ── DESCRIPTION ──────────────────────────────────────────
    hdr("DESCRIPTION")
    for line in [
        "ORBIT is a professional-grade network reconnaissance toolkit",
        "designed for authorized network security assessments. It combines",
        "IPv4 ARP scanning, IPv6 NDP probing (active & passive), RA option",
        "extraction, vendor identification, port scanning, and flexible",
        "result export — all within a single TUI-driven interface.",
    ]:
        row(f"    {line}", C.WHITE)
    mid()

    # ── MAIN MENU ─────────────────────────────────────────────
    hdr("MAIN MENU OPTIONS")
    opts = [
        ("[1]", "ARP Scan          ", "Discover IPv4 hosts via ARP broadcast"),
        ("[2]", "NDP Active Scan   ", "Send NS probes to an IPv6 prefix range"),
        ("[3]", "NDP Passive Sniff ", "Listen for NS / NA / RA messages"),
        ("[4]", "Port Scan         ", "TCP/UDP port scan on discovered hosts"),
        ("[5]", "Network Info      ", "Show local interfaces and gateway info"),
        ("[H]", "Help              ", "This help page"),
        ("[0]", "Exit              ", "Quit ORBIT"),
    ]
    for key, name, desc in opts:
        row(f"    {clr(key, C.ORANGE)}{clr('  '+name, C.WHITE)}{clr('— '+desc, C.DIM)}", C.RESET)
    mid()

    # ── ARP SCAN ──────────────────────────────────────────────
    hdr("MODULE 1 — ARP SCAN")
    for line in [
        "Sends Layer-2 ARP broadcast requests across a target IPv4 range.",
        "Returns IP→MAC mapping for all responding hosts, with vendor",
        "OUI lookup (first 3 octets of MAC) when possible.",
        "",
        "  Input   :  CIDR range  (e.g. 192.168.1.0/24)",
        "  Timeout :  Configurable retry timeout (default 3s)",
        "  Extras  :  Reverse DNS, vendor lookup per host",
    ]:
        row(f"    {line}", C.WHITE)
    mid()

    # ── NDP ACTIVE ────────────────────────────────────────────
    hdr("MODULE 2 — NDP ACTIVE SCAN")
    for line in [
        "Sends ICMPv6 Neighbor Solicitation (NS) packets to each host",
        "in a target IPv6 prefix. Parses Neighbor Advertisement (NA)",
        "replies to extract IPv6 addresses and MAC addresses.",
        "",
        "  Input   :  IPv6 prefix  (e.g. 2001:db8::/120)",
        "  Limit   :  First 200 hosts in the prefix",
        "  Extras  :  EUI-64 link-local computation, vendor lookup",
    ]:
        row(f"    {line}", C.WHITE)
    mid()

    # ── NDP PASSIVE ───────────────────────────────────────────
    hdr("MODULE 3 — NDP PASSIVE SNIFF")
    for line in [
        "Passively captures ICMPv6 NDP traffic on the selected interface.",
        "Extracts rich data from Router Advertisements (RA) including:",
        "",
        "  • Advertised Prefixes (with flags, valid/preferred lifetime)",
        "  • Path MTU (with sub-1280 warning per RFC 8200)",
        "  • RDNSS — Recursive DNS server list + lifetimes",
        "  • DNSSL — DNS search domain list + lifetimes",
        "  • Router timers (Reachable time, Retransmit timer)",
        "",
        "  Duration:  Configurable (default 60 seconds)",
        "  Filter  :  BPF icmp6 targeting RA/NS/NA type codes",
    ]:
        row(f"    {line}", C.WHITE)
    mid()

    # ── PORT SCAN ─────────────────────────────────────────────
    hdr("MODULE 4 — PORT SCAN")
    for line in [
        "TCP connect scan against a target host.",
        "Supports custom port ranges or common preset profiles:",
        "",
        "  [T]  Top-20 common ports  (fast recon)",
        "  [W]  Web ports            (80,443,8080,8443,3000,8888)",
        "  [D]  Database ports       (3306,5432,1433,27017,6379)",
        "  [A]  All ports            (1–65535, slow)",
        "  [C]  Custom range         (e.g. 22,80,443 or 1-1024)",
        "",
        "  Each open port shows: port, protocol, banner (if grabbed)",
    ]:
        row(f"    {line}", C.WHITE)
    mid()

    # ── EXPORT ────────────────────────────────────────────────
    hdr("EXPORT OPTIONS  (after each scan)")
    for line in [
        "After every scan you will be prompted to save results.",
        "Choose from the following formats:",
        "",
        "  [1]  TXT   — Human-readable plain text report",
        "  [2]  JSON  — Machine-readable structured data",
        "  [3]  CSV   — Spreadsheet-compatible table",
        "  [4]  All   — Export all three formats simultaneously",
        "  [0]  Skip  — Do not save, return to menu",
        "",
        "  Output path:  Chosen by the user (prompted at runtime)",
    ]:
        row(f"    {line}", C.WHITE)
    mid()

    # ── INTERFACE ─────────────────────────────────────────────
    hdr("INTERFACE SELECTION")
    for line in [
        "Most modules auto-detect the default interface via Scapy.",
        "When multiple interfaces are present, ORBIT presents a",
        "numbered list and lets you choose before scanning.",
    ]:
        row(f"    {line}", C.WHITE)
    mid()

    # ── NOTES ─────────────────────────────────────────────────
    hdr("LEGAL & REQUIREMENTS")
    for line in [
        clr("  ⚠  Requires root / Administrator privileges.",          C.ORANGE),
        clr("  ⚠  Use ONLY on networks you own or are authorized to",  C.ORANGE),
        clr("     test. Unauthorized scanning is illegal.",             C.RED),
        clr("  ✔  Tested on Debian-based Linux distributions.",        C.LIME),
        clr("  ✔  Dependencies: scapy, tqdm  (pip3 install scapy tqdm)", C.LIME),
    ]:
        row(f"    {line}", C.RESET)
    mid()
    bot()
    print()

# ═══════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═══════════════════════════════════════════════════════════════════════
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def pause():
    input(clr("\n  [↩] Press Enter to return to main menu...", C.YELLOW))

def print_header(title):
    print()
    print(clr("─" * 68, C.CYAN))
    print(clr(f"  ◈  {title}", C.BOLD + C.CYAN))
    print(clr("─" * 68, C.CYAN))

def section(title):
    print()
    print(clr(f"  ┌─ {title}", C.YELLOW + C.BOLD))

def info(msg):
    print(clr(f"  [i] {msg}", C.BLUE))

def warn(msg):
    print(clr(f"  [!] {msg}", C.YELLOW))

def err(msg):
    print(clr(f"  [✘] {msg}", C.RED))

def ok(msg):
    print(clr(f"  [✔] {msg}", C.GREEN))

def spinner_start(msg):
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    stop   = threading.Event()
    def _run():
        i = 0
        while not stop.is_set():
            print(f"\r  {clr(frames[i%len(frames)], C.CYAN)} {clr(msg, C.DIM)}", end="", flush=True)
            time.sleep(0.1)
            i += 1
        print("\r" + " " * (len(msg)+8) + "\r", end="", flush=True)
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return stop, t

def spinner_stop(stop, t):
    stop.set()
    t.join()

def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def timestamp_fname():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# ═══════════════════════════════════════════════════════════════════════
#  VENDOR LOOKUP  (offline OUI, first 3 octets)
# ═══════════════════════════════════════════════════════════════════════
_OUI_CACHE: dict = {}

def _load_oui_db():
    """Try to load OUI database from common system paths."""
    candidates = [
        "/usr/share/nmap/nmap-mac-prefixes",
        "/usr/share/arp-scan/ieee-oui.txt",
        "/var/lib/ieee-data/oui.csv",
        "/usr/share/wireshark/manuf",
    ]
    for path in candidates:
        p = Path(path)
        if p.exists():
            try:
                with open(p, "r", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(None, 2)
                        if len(parts) >= 2:
                            key = parts[0].upper().replace("-", "").replace(":", "")[:6]
                            _OUI_CACHE[key] = parts[-1] if len(parts) > 2 else parts[1]
                return True
            except Exception:
                continue
    return False

_OUI_LOADED = _load_oui_db()

def vendor_lookup(mac: str) -> str:
    if not mac or mac in ("??", ""):
        return "Unknown"
    key = mac.upper().replace(":", "").replace("-", "")[:6]
    return _OUI_CACHE.get(key, "Unknown")

# ═══════════════════════════════════════════════════════════════════════
#  INTERFACE PICKER
# ═══════════════════════════════════════════════════════════════════════
def pick_interface() -> str:
    ifaces = get_if_list()
    if not ifaces:
        return conf.iface
    if len(ifaces) == 1:
        return ifaces[0]
    print()
    print(clr("  ┌─ Available Interfaces", C.YELLOW + C.BOLD))
    for i, iface in enumerate(ifaces, 1):
        marker = clr("*", C.GREEN) if iface == conf.iface else " "
        print(f"  │  [{clr(str(i), C.CYAN)}] {marker} {clr(iface, C.WHITE)}")
    print()
    raw = input(clr(f"  [»] Select interface [default: {conf.iface}]: ", C.CYAN)).strip()
    if raw.isdigit():
        idx = int(raw) - 1
        if 0 <= idx < len(ifaces):
            return ifaces[idx]
    return conf.iface

# ═══════════════════════════════════════════════════════════════════════
#  REVERSE DNS
# ═══════════════════════════════════════════════════════════════════════
def rdns(ip: str, timeout=1.0) -> str:
    try:
        old  = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(old)
        return name
    except Exception:
        return ""

# ═══════════════════════════════════════════════════════════════════════
#  EXPORT ENGINE
# ═══════════════════════════════════════════════════════════════════════
def _ask_output_path(default_name: str) -> str:
    """Prompt user for directory and return full file path (without extension)."""
    print()
    print(clr("  ┌─ Save Location", C.YELLOW + C.BOLD))
    cwd = os.getcwd()
    raw = input(clr(f"  │  Output directory [{cwd}]: ", C.CYAN)).strip()
    directory = raw if raw else cwd
    # create if needed
    try:
        os.makedirs(directory, exist_ok=True)
    except Exception as e:
        warn(f"Cannot create directory: {e} — using current directory.")
        directory = cwd
    return os.path.join(directory, default_name)

def _write_txt(path: str, title: str, rows: list, columns: list):
    with open(path + ".txt", "w") as f:
        f.write(f"ORBIT v{VERSION}  —  {title}\n")
        f.write(f"Generated : {ts()}\n")
        f.write(f"Author    : {AUTHOR}  |  {WEBSITE}\n")
        f.write("=" * 80 + "\n\n")
        if not rows:
            f.write("No results captured.\n")
            return
        col_widths = [max(len(str(c)), max((len(str(r.get(c,"") if isinstance(r,dict) else "")) for r in rows), default=0))
                      for c in columns]
        header = "  ".join(str(c).ljust(w) for c, w in zip(columns, col_widths))
        f.write(header + "\n")
        f.write("-" * len(header) + "\n")
        for row in rows:
            if isinstance(row, dict):
                line = "  ".join(str(row.get(c,"")).ljust(w) for c, w in zip(columns, col_widths))
            else:
                line = "  ".join(str(v).ljust(w) for v, w in zip(row, col_widths))
            f.write(line + "\n")

def _write_json(path: str, title: str, rows: list, columns: list):
    payload = {
        "tool"      : f"ORBIT v{VERSION}",
        "module"    : title,
        "generated" : ts(),
        "count"     : len(rows),
        "results"   : rows,
    }
    with open(path + ".json", "w") as f:
        json.dump(payload, f, indent=2, default=str)

def _write_csv(path: str, title: str, rows: list, columns: list):
    with open(path + ".csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            if isinstance(row, dict):
                w.writerow(row)
            else:
                w.writerow(dict(zip(columns, row)))

def _write_html(path: str, title: str, rows: list, columns: list):
    import html as _html
    cells = ""
    head  = "".join(f"<th>{_html.escape(str(c))}</th>" for c in columns)
    for row in rows:
        if isinstance(row, dict):
            vals = [row.get(c, "") for c in columns]
        else:
            vals = list(row)
        cells += "<tr>" + "".join(
            f"<td>{_html.escape(str(v))}</td>" for v in vals
        ) + "</tr>\n"
    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ORBIT v{VERSION} — {_html.escape(title)}</title>
<style>
  body{{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;margin:24px}}
  h1{{color:#58a6ff}} .meta{{color:#8b949e;font-size:12px;margin-bottom:16px}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th{{background:#161b22;color:#58a6ff;padding:8px;text-align:left;border-bottom:2px solid #30363d}}
  td{{padding:6px 8px;border-bottom:1px solid #21262d}}
  tr:hover td{{background:#161b22}}
</style></head><body>
<h1>ORBIT — {_html.escape(title)}</h1>
<div class="meta">Generated: {ts()} &nbsp;|&nbsp; {_html.escape(AUTHOR)} &nbsp;|&nbsp; {_html.escape(WEBSITE)} &nbsp;|&nbsp; {len(rows)} row(s)</div>
<table><tr>{head}</tr>
{cells}</table>
</body></html>"""
    with open(path + ".html", "w", encoding="utf-8") as f:
        f.write(doc)


def prompt_export(title: str, rows: list, columns: list):
    if not rows:
        warn("Nothing to export.")
        return

    print()
    print(clr("  ╔════════════════════════════════════════╗", C.CYAN))
    print(clr("  ║        EXPORT RESULTS                  ║", C.CYAN + C.BOLD))
    print(clr("  ╠════════════════════════════════════════╣", C.CYAN))
    for key, label in [("1","TXT  — Plain text report"),
                        ("2","JSON — Structured data"),
                        ("3","CSV  — Spreadsheet table"),
                        ("5","HTML — Styled report"),
                        ("4","ALL  — Export all formats"),
                        ("0","Skip — Do not save")]:
        print(f"  {clr('║', C.CYAN)}  [{clr(key, C.ORANGE)}]  {clr(label, C.WHITE)}")
    print(clr("  ╚════════════════════════════════════════╝", C.CYAN))
    print()

    choice = input(clr("  [»] Select export format: ", C.CYAN)).strip()
    if choice == "0" or not choice:
        info("Export skipped.")
        return

    fname   = f"orbit_{title.lower().replace(' ', '_').replace('/', '_')}_{timestamp_fname()}"
    basepath = _ask_output_path(fname)
    saved   = []

    if choice in ("1", "4"):
        _write_txt(basepath, title, rows, columns)
        saved.append(basepath + ".txt")
    if choice in ("2", "4"):
        _write_json(basepath, title, rows, columns)
        saved.append(basepath + ".json")
    if choice in ("3", "4"):
        _write_csv(basepath, title, rows, columns)
        saved.append(basepath + ".csv")
    if choice in ("5", "4"):
        _write_html(basepath, title, rows, columns)
        saved.append(basepath + ".html")

    if saved:
        print()
        ok("Saved results:")
        for s in saved:
            print(clr(f"     → {s}", C.TEAL))
    else:
        warn("Unrecognised format choice — export skipped.")

# ═══════════════════════════════════════════════════════════════════════
#  EUI-64 & NDP HELPERS
# ═══════════════════════════════════════════════════════════════════════
def mac_to_eui64_link_local(mac: str) -> str:
    parts = mac.lower().split(":")
    parts.insert(3, "ff")
    parts.insert(4, "fe")
    parts[0] = f"{int(parts[0], 16) ^ 0x02:02x}"
    groups   = [parts[i] + parts[i+1] for i in range(0, 8, 2)]
    return "fe80::" + ":".join(groups)

def solicited_node_multicast(ipv6: str) -> str:
    addr  = IPv6Address(ipv6)
    last3 = addr.packed[-3:]
    return f"ff02::1:ff{last3[0]:02x}:{last3[1]:02x}{last3[2]:02x}"

def solicited_node_dst_mac(ipv6: str) -> str:
    addr  = IPv6Address(ipv6)
    last4 = addr.packed[-4:]
    return f"33:33:{last4[0]:02x}:{last4[1]:02x}:{last4[2]:02x}:{last4[3]:02x}"

def parse_ra_options(pkt):
    prefixes      = []
    mtus          = []
    rdnss_entries = []
    dnssl_entries = []
    src_mac       = None

    layer = pkt[ICMPv6ND_RA].payload
    while layer and layer.name != "NoPayload":
        if isinstance(layer, ICMPv6NDOptPrefixInfo):
            flags = "".join(f for f, attr in [("L","L"),("A","A"),("R","R")]
                            if getattr(layer, attr, 0))
            flags = flags or "—"
            prefixes.append({
                "prefix"   : f"{layer.prefix}/{layer.prefixlen}",
                "valid"    : layer.validlifetime,
                "preferred": layer.preferredlifetime,
                "flags"    : flags,
            })
        elif isinstance(layer, ICMPv6NDOptMTU):
            mtus.append(layer.mtu)
        elif isinstance(layer, ICMPv6NDOptRDNSS):
            rdnss_entries.append(([str(ip) for ip in layer.dns], layer.lifetime))
        elif isinstance(layer, ICMPv6NDOptDNSSL):
            dnssl_entries.append((layer.searchlist, layer.lifetime))
        elif isinstance(layer, ICMPv6NDOptSrcLLAddr):
            src_mac = layer.lladdr
        layer = layer.payload

    return prefixes, mtus, rdnss_entries, dnssl_entries, src_mac

# ═══════════════════════════════════════════════════════════════════════
#  MODULE 1: ARP SCAN
# ═══════════════════════════════════════════════════════════════════════
def module_arp_scan():
    print_header("ARP Scan — IPv4 Host Discovery")

    target = input(clr("\n  [»] IPv4 target/range (e.g. 192.168.1.0/24): ", C.CYAN)).strip()
    if not target:
        err("No target specified.")
        return

    # validate input
    try:
        net = ip_network(target, strict=False)
    except ValueError:
        err(f"Invalid IPv4 target: {target}")
        return

    raw_t = input(clr("  [»] Timeout per probe in seconds [3]: ", C.CYAN)).strip()
    try:
        timeout = float(raw_t) if raw_t else 3.0
    except ValueError:
        timeout = 3.0

    do_rdns   = input(clr("  [»] Perform reverse DNS lookup? [y/N]: ", C.CYAN)).strip().lower() == "y"
    do_vendor = input(clr("  [»] Perform vendor (OUI) lookup? [y/N]: ", C.CYAN)).strip().lower() == "y"

    iface = pick_interface()

    section(f"Launching ARP scan → {target}  iface={iface}")

    arp_req = ARP(pdst=str(net))
    ether   = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet  = ether / arp_req

    stop_sp, t_sp = spinner_start(f"Scanning {target}  …")
    try:
        result  = srp(packet, iface=iface, timeout=timeout, verbose=0, retry=2)[0]
        devices_raw = [{"ip": rcv.psrc, "mac": rcv.hwsrc} for _, rcv in result]
    except Exception as e:
        spinner_stop(stop_sp, t_sp)
        err(f"ARP scan failed: {e}")
        return
    spinner_stop(stop_sp, t_sp)

    if not devices_raw:
        warn("No hosts responded.")
        return

    # enrich
    devices = []
    for d in sorted(devices_raw, key=lambda x: ipaddress.ip_address(x["ip"])):
        entry = {"ip": d["ip"], "mac": d["mac"]}
        if do_vendor:
            entry["vendor"] = vendor_lookup(d["mac"])
        if do_rdns:
            entry["hostname"] = rdns(d["ip"])
        devices.append(entry)

    # display
    section(f"Results — {len(devices)} host(s) found")
    columns = ["ip","mac"]
    header  = f"  {clr('IP Address', C.CYAN):<30} {clr('MAC Address', C.CYAN):<22}"
    if do_vendor:
        header += f" {clr('Vendor', C.CYAN):<30}"
        columns.append("vendor")
    if do_rdns:
        header += f" {clr('Hostname', C.CYAN)}"
        columns.append("hostname")
    print(header)
    print(clr("  " + "─" * (len(header)//2 + 20), C.DIM))

    for d in devices:
        line = f"  {clr(d['ip'], C.WHITE):<30} {clr(d['mac'], C.YELLOW):<22}"
        if do_vendor:
            line += f" {clr(d.get('vendor',''), C.TEAL):<30}"
        if do_rdns:
            line += f" {clr(d.get('hostname',''), C.DIM)}"
        print(line)

    prompt_export("ARP Scan", devices, columns)

# ═══════════════════════════════════════════════════════════════════════
#  MODULE 2: NDP ACTIVE SCAN
# ═══════════════════════════════════════════════════════════════════════
def ndp_scan_single(target_ipv6: str, iface: str, timeout=2) -> dict | None:
    my_mac        = get_if_hwaddr(iface)
    my_link_local = mac_to_eui64_link_local(my_mac)
    sol_node      = solicited_node_multicast(target_ipv6)
    dst_mac       = solicited_node_dst_mac(target_ipv6)

    ns = (
        Ether(dst=dst_mac) /
        IPv6(src=my_link_local, dst=sol_node, hlim=255) /
        ICMPv6ND_NS(tgt=target_ipv6) /
        ICMPv6NDOptSrcLLAddr(lladdr=my_mac)
    )
    try:
        ans, _ = srp(ns, iface=iface, timeout=timeout, verbose=0)
        for _, rcv in ans:
            if ICMPv6ND_NA in rcv:
                src_ip  = rcv[IPv6].src
                src_mac = rcv[ICMPv6NDOptSrcLLAddr].lladdr if rcv.haslayer(ICMPv6NDOptSrcLLAddr) else "??"
                return {"ipv6": src_ip, "mac": src_mac, "vendor": vendor_lookup(src_mac)}
    except Exception:
        pass
    return None

def module_ndp_active():
    print_header("NDP Active Scan — IPv6 Host Discovery")

    target = input(clr("\n  [»] IPv6 prefix (e.g. 2001:db8::/120): ", C.CYAN)).strip()
    if not target:
        err("No prefix specified.")
        return

    try:
        net   = ip_network(target, strict=False)
        hosts = list(net.hosts())[:200]
    except ValueError as e:
        err(f"Invalid IPv6 prefix: {e}")
        return

    raw_t = input(clr(f"  [»] Probe timeout in seconds [1.2]: ", C.CYAN)).strip()
    try:
        probe_timeout = float(raw_t) if raw_t else 1.2
    except ValueError:
        probe_timeout = 1.2

    iface = pick_interface()
    section(f"Scanning {len(hosts)} IPv6 addresses on {iface}")

    results = []
    if HAS_TQDM:
        iterator = tqdm(hosts, ncols=68, bar_format="  {l_bar}{bar}| {n_fmt}/{total_fmt}")
    else:
        iterator = hosts
        info(f"Scanning {len(hosts)} addresses (install tqdm for progress bar)…")

    for ip in iterator:
        res = ndp_scan_single(str(ip), iface, timeout=probe_timeout)
        if res:
            results.append(res)
        time.sleep(0.03)

    if results:
        section(f"Live IPv6 Hosts — {len(results)} found")
        print(f"  {clr('IPv6', C.CYAN):<44} {clr('MAC', C.CYAN):<22} {clr('Vendor', C.CYAN)}")
        print(clr("  " + "─" * 90, C.DIM))
        for r in sorted(results, key=lambda x: x["ipv6"]):
            print(f"  {clr(r['ipv6'], C.WHITE):<44} {clr(r['mac'], C.YELLOW):<22} {clr(r['vendor'], C.TEAL)}")
    else:
        warn("No live hosts found.")

    prompt_export("NDP Active Scan", results, ["ipv6","mac","vendor"])

# ═══════════════════════════════════════════════════════════════════════
#  MODULE 3: NDP PASSIVE SNIFF
# ═══════════════════════════════════════════════════════════════════════
def module_ndp_passive():
    print_header("NDP Passive Sniff — NS / NA / RA Capture")

    raw = input(clr("\n  [»] Sniff duration in seconds [60]: ", C.CYAN)).strip()
    dur = int(raw) if raw.isdigit() else 60

    iface = pick_interface()

    section(f"Passive NDP/RA listening on {clr(iface, C.WHITE)} for {clr(str(dur)+'s', C.WHITE)}")
    print(clr(f"  │  Started at {ts()}", C.DIM))
    print(clr("  │  Waiting for NS / NA / RA messages …  (Ctrl+C to stop early)", C.DIM))
    print()

    discovered     = defaultdict(set)
    prefixes_info  = defaultdict(list)
    mtu_info       = defaultdict(list)
    rdnss_info     = defaultdict(list)
    dnssl_info     = defaultdict(list)
    reachable_info = {}
    retrans_info   = {}
    event_log      = []

    def handle_pkt(pkt):
        if not pkt.haslayer(IPv6):
            return

        ipv6_src = pkt[IPv6].src
        mac_src  = pkt[Ether].src if pkt.haslayer(Ether) else "??"
        msg_type = None

        if ICMPv6ND_NS in pkt:
            tgt = pkt[ICMPv6ND_NS].tgt
            msg_type = f"NS → {tgt}"
            if pkt.haslayer(ICMPv6NDOptSrcLLAddr):
                mac_src = pkt[ICMPv6NDOptSrcLLAddr].lladdr
            discovered[tgt].add(mac_src)
            discovered[ipv6_src].add(mac_src)

        elif ICMPv6ND_NA in pkt:
            tgt = pkt[ICMPv6ND_NA].tgt
            msg_type = f"NA for {tgt}"
            if pkt.haslayer(ICMPv6NDOptSrcLLAddr):
                mac_src = pkt[ICMPv6NDOptSrcLLAddr].lladdr
            discovered[tgt].add(mac_src)
            discovered[ipv6_src].add(mac_src)

        elif ICMPv6ND_RA in pkt:
            msg_type = "RA"
            discovered[ipv6_src].add(mac_src)
            ra = pkt[ICMPv6ND_RA]
            if ra.reachabletime > 0:
                reachable_info[ipv6_src] = ra.reachabletime
            if ra.retranstimer > 0:
                retrans_info[ipv6_src] = ra.retranstimer

            prefixes, mtus, rdnss, dnssl, opt_mac = parse_ra_options(pkt)
            if opt_mac:
                mac_src = opt_mac
                discovered[ipv6_src].add(mac_src)
            if prefixes:  prefixes_info[ipv6_src].extend(prefixes)
            if mtus:      mtu_info[ipv6_src].extend(mtus)
            if rdnss:
                rdnss_info[ipv6_src].extend(rdnss)
                for servers, lt in rdnss:
                    msg_type += f" | RDNSS({lt}s): {', '.join(servers)}"
            if dnssl:
                dnssl_info[ipv6_src].extend(dnssl)
                for domains, lt in dnssl:
                    msg_type += f" | DNSSL({lt}s): {', '.join(domains)}"

        if msg_type:
            now = time.strftime("%H:%M:%S")
            print(f"  {clr(f'[{now}]', C.DIM)} {clr(msg_type, C.WHITE)}")
            print(f"  {clr('│', C.DIM)}  {clr(ipv6_src, C.CYAN):<32}  MAC: {clr(mac_src, C.YELLOW)}")
            event_log.append({"time": now, "type": msg_type, "src": ipv6_src, "mac": mac_src})

    bpf = "icmp6 and (ip6[40] = 134 or ip6[40] = 135 or ip6[40] = 136)"
    try:
        sniff(iface=iface, filter=bpf, prn=handle_pkt,
              timeout=dur, store=False, quiet=True)
    except KeyboardInterrupt:
        warn("Sniff interrupted by user.")
    except Exception as e:
        err(f"Sniff error: {e}")

    # ── Summary tables ───────────────────────────────────────
    has_data = any([discovered, prefixes_info, mtu_info,
                    rdnss_info, dnssl_info, reachable_info, retrans_info])

    if not has_data:
        warn("No NDP/RA messages captured.")
        return

    print()
    print(clr("─" * 68, C.CYAN))
    ok("Passive NDP & RA Summary")

    all_export_rows = []
    all_columns     = ["table","field","value","extra"]

    if discovered:
        section("Live IPv6 → MACs")
        print(f"  {clr('IPv6', C.CYAN):<44} {clr('MACs', C.CYAN):<24} {clr('Vendor', C.CYAN)}")
        print(clr("  " + "─" * 85, C.DIM))
        for ip, macs in sorted(discovered.items()):
            mac_str = ", ".join(sorted(macs))
            v       = vendor_lookup(list(macs)[0]) if macs else ""
            print(f"  {clr(ip, C.WHITE):<44} {clr(mac_str, C.YELLOW):<24} {clr(v, C.TEAL)}")
            all_export_rows.append({"table":"discovered","field":ip,"value":mac_str,"extra":v})

    if prefixes_info:
        section("Advertised Prefixes")
        print(f"  {clr('Router', C.CYAN):<42} {clr('Prefix', C.CYAN):<30} {clr('Flags', C.CYAN):<8} {clr('Valid/Pref (s)', C.CYAN)}")
        print(clr("  " + "─" * 110, C.DIM))
        for r, prefs in sorted(prefixes_info.items()):
            for p in prefs:
                flags_col = clr(p["flags"], C.LIME)
                print(f"  {clr(r, C.WHITE):<42} {clr(p['prefix'], C.YELLOW):<30} {flags_col:<8} {p['valid']}/{p['preferred']}")
                all_export_rows.append({"table":"prefix","field":r,"value":p["prefix"],"extra":f"flags={p['flags']} valid={p['valid']} pref={p['preferred']}"})

    if mtu_info:
        section("Advertised MTU")
        print(f"  {clr('Router', C.CYAN):<42} {clr('MTU', C.CYAN):<16} {clr('Note', C.CYAN)}")
        print(clr("  " + "─" * 80, C.DIM))
        for r, mtus in sorted(mtu_info.items()):
            mtu_set = sorted(set(mtus))
            note    = clr("⚠ below RFC 8200 minimum (1280)", C.RED) if any(m < 1280 for m in mtu_set) else clr("OK", C.LIME)
            print(f"  {clr(r, C.WHITE):<42} {', '.join(map(str, mtu_set)):<16} {note}")
            all_export_rows.append({"table":"mtu","field":r,"value":str(mtu_set),"extra":""})

    if rdnss_info:
        section("Recursive DNS Servers (RDNSS)")
        print(f"  {clr('Router', C.CYAN):<42} {clr('DNS Servers', C.CYAN):<52} {clr('Lifetime', C.CYAN)}")
        print(clr("  " + "─" * 110, C.DIM))
        for r, entries in sorted(rdnss_info.items()):
            for servers, lt in entries:
                print(f"  {clr(r, C.WHITE):<42} {clr(', '.join(servers), C.YELLOW):<52} {lt}s")
                all_export_rows.append({"table":"rdnss","field":r,"value":", ".join(servers),"extra":f"{lt}s"})

    if dnssl_info:
        section("DNS Search Lists (DNSSL)")
        print(f"  {clr('Router', C.CYAN):<42} {clr('Search Domains', C.CYAN):<52} {clr('Lifetime', C.CYAN)}")
        print(clr("  " + "─" * 110, C.DIM))
        for r, entries in sorted(dnssl_info.items()):
            for domains, lt in entries:
                print(f"  {clr(r, C.WHITE):<42} {clr(', '.join(domains), C.YELLOW):<52} {lt}s")
                all_export_rows.append({"table":"dnssl","field":r,"value":", ".join(domains),"extra":f"{lt}s"})

    if reachable_info or retrans_info:
        section("Router Timers")
        print(f"  {clr('Router', C.CYAN):<42} {clr('Reachable (ms)', C.CYAN):<24} {clr('Retrans (ms)', C.CYAN)}")
        print(clr("  " + "─" * 85, C.DIM))
        for r in sorted(set(reachable_info) | set(retrans_info)):
            reach   = reachable_info.get(r, "—")
            retrans = retrans_info.get(r, "—")
            print(f"  {clr(r, C.WHITE):<42} {str(reach):<24} {str(retrans)}")
            all_export_rows.append({"table":"timers","field":r,"value":str(reach),"extra":str(retrans)})

    prompt_export("NDP Passive Sniff", all_export_rows, all_columns)

# ═══════════════════════════════════════════════════════════════════════
#  MODULE 4: PORT SCAN
# ═══════════════════════════════════════════════════════════════════════
_COMMON_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 111:"RPC", 135:"MSRPC", 139:"NetBIOS",
    143:"IMAP", 443:"HTTPS", 445:"SMB", 993:"IMAPS", 995:"POP3S",
    1723:"PPTP", 3306:"MySQL", 3389:"RDP", 5900:"VNC", 8080:"HTTP-Alt",
}
_WEB_PORTS    = [80,443,8080,8443,3000,8888,8008,4443]
_DB_PORTS     = [3306,5432,1433,1521,27017,6379,5984,9200]
_ALL_PORTS    = list(range(1, 65536))

def _grab_banner(host: str, port: int, timeout=2) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(256).decode(errors="ignore").split("\n")[0].strip()
        s.close()
        return banner[:80] if banner else ""
    except Exception:
        return ""

def _tcp_connect_scan(host: str, port: int, timeout: float) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False

def module_port_scan():
    print_header("Port Scan — TCP Connect Scan")

    target = input(clr("\n  [»] Target host/IP: ", C.CYAN)).strip()
    if not target:
        err("No target.")
        return

    # resolve hostname
    try:
        resolved = socket.gethostbyname(target)
    except socket.gaierror:
        err(f"Cannot resolve: {target}")
        return

    if resolved != target:
        info(f"Resolved {target} → {resolved}")

    print()
    print(clr("  ┌─ Port Range Profile", C.YELLOW + C.BOLD))
    profiles = [
        ("T", "Top-20",  "Common services recon"),
        ("W", "Web",     "HTTP/HTTPS variants"),
        ("D", "Database","MySQL, PG, MSSQL …"),
        ("A", "All",     "1–65535 (slow!)"),
        ("C", "Custom",  "Enter ports/range manually"),
    ]
    for k, name, desc in profiles:
        print(f"  │  [{clr(k, C.ORANGE)}]  {clr(name, C.WHITE):<14} {clr('— '+desc, C.DIM)}")
    print()
    profile = input(clr("  [»] Select profile [T]: ", C.CYAN)).strip().upper() or "T"

    if profile == "T":
        ports = list(_COMMON_PORTS.keys())
    elif profile == "W":
        ports = _WEB_PORTS
    elif profile == "D":
        ports = _DB_PORTS
    elif profile == "A":
        ports = _ALL_PORTS
    elif profile == "C":
        raw_ports = input(clr("  [»] Ports (e.g. 22,80,443 or 1-1024): ", C.CYAN)).strip()
        ports = []
        for part in raw_ports.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                try:
                    ports.extend(range(int(a), int(b)+1))
                except ValueError:
                    pass
            elif part.isdigit():
                ports.append(int(part))
    else:
        ports = list(_COMMON_PORTS.keys())

    raw_t   = input(clr("  [»] Connect timeout per port [0.5]: ", C.CYAN)).strip()
    try:
        timeout = float(raw_t) if raw_t else 0.5
    except ValueError:
        timeout = 0.5

    do_banner = input(clr("  [»] Grab service banners? [y/N]: ", C.CYAN)).strip().lower() == "y"

    section(f"Scanning {clr(target, C.WHITE)} ({clr(str(len(ports)), C.ORANGE)} ports)  timeout={timeout}s")

    open_ports = []
    lock       = threading.Lock()

    def scan_port(port):
        if _tcp_connect_scan(resolved, port, timeout):
            svc    = _COMMON_PORTS.get(port, "unknown")
            banner = _grab_banner(resolved, port) if do_banner else ""
            with lock:
                open_ports.append({"port": port, "protocol": "TCP", "service": svc, "banner": banner})
                print(f"  {clr('OPEN', C.LIME):<10} {clr(str(port)+'/TCP', C.WHITE):<16} "
                      f"{clr(svc, C.YELLOW):<16} {clr(banner, C.DIM)}")

    # Concurrent scan with a bounded thread pool (clean join semantics)
    workers = min(200, max(1, len(ports)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(scan_port, ports))

    print()
    if open_ports:
        ok(f"{len(open_ports)} open port(s) found on {target}")
        for entry in sorted(open_ports, key=lambda x: x["port"]):
            entry["host"] = target
        prompt_export("Port Scan", sorted(open_ports, key=lambda x: x["port"]),
                      ["host","port","protocol","service","banner"])
    else:
        warn("No open ports found in scanned range.")

# ═══════════════════════════════════════════════════════════════════════
#  MODULE 5: NETWORK INFO
# ═══════════════════════════════════════════════════════════════════════
def module_network_info():
    print_header("Network Info — Local Interface Overview")

    print()
    ifaces = get_if_list()
    section("Detected Interfaces")
    print(f"  {clr('Interface', C.CYAN):<20} {clr('MAC Address', C.CYAN):<22} {clr('Status', C.CYAN)}")
    print(clr("  " + "─" * 65, C.DIM))
    for iface in ifaces:
        try:
            mac = get_if_hwaddr(iface)
        except Exception:
            mac = "??"
        active = clr("●  active", C.LIME) if iface == conf.iface else clr("○", C.DIM)
        print(f"  {clr(iface, C.WHITE):<20} {clr(mac, C.YELLOW):<22} {active}")

    # Try to get IP via ip addr or ifconfig
    section("IP Addresses (via ip addr)")
    try:
        result = subprocess.run(
            ["ip", "-brief", "addr"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 3:
                    iface  = parts[0]
                    state  = parts[1]
                    addrs  = parts[2:]
                    scolor = C.LIME if state == "UP" else C.RED
                    print(f"  {clr(iface, C.WHITE):<20} {clr(state, scolor):<10} {clr(' '.join(addrs), C.YELLOW)}")
        else:
            warn("ip command failed.")
    except Exception as e:
        warn(f"Could not run 'ip addr': {e}")

    # Default gateway
    section("Default Gateway")
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            print(f"  {clr(result.stdout.strip(), C.YELLOW)}")
        else:
            warn("No default gateway found.")
    except Exception as e:
        warn(f"Could not query route: {e}")

    # DNS servers
    section("DNS Resolvers  (/etc/resolv.conf)")
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    print(f"  {clr('→', C.CYAN)} {clr(line, C.YELLOW)}")
    except Exception:
        warn("Cannot read /etc/resolv.conf")

    print()

# ═══════════════════════════════════════════════════════════════════════
#  MODULE 6: IPv6 / NDP CALCULATOR  (offline address toolkit)
# ═══════════════════════════════════════════════════════════════════════
def _valid_mac(mac: str) -> bool:
    parts = mac.split(":")
    if len(parts) != 6:
        return False
    try:
        return all(0 <= int(p, 16) <= 0xff and len(p) in (1, 2) for p in parts)
    except ValueError:
        return False

def module_ipv6_calc():
    print_header("IPv6 / NDP Calculator — Offline Address Toolkit")
    print()
    print(clr("  [1]  MAC → EUI-64 link-local (+ solicited-node info)", C.WHITE))
    print(clr("  [2]  IPv6 → solicited-node multicast + L2 multicast MAC", C.WHITE))
    print(clr("  [3]  Expand / compress an IPv6 address", C.WHITE))
    print()
    sel = input(clr("  [»] Select [1-3]: ", C.CYAN)).strip()

    if sel == "1":
        mac = input(clr("  [»] MAC address (aa:bb:cc:dd:ee:ff): ", C.CYAN)).strip().lower()
        if not _valid_mac(mac):
            err("Invalid MAC address.")
            return
        mac = ":".join(f"{int(p,16):02x}" for p in mac.split(":"))
        try:
            ll  = mac_to_eui64_link_local(mac)
            snm = solicited_node_multicast(ll)
            dmac = solicited_node_dst_mac(ll)
        except Exception as e:
            err(f"Computation failed: {e}")
            return
        section("Results")
        print(f"  {clr('Input MAC', C.CYAN):<28} {clr(mac, C.WHITE)}")
        print(f"  {clr('EUI-64 link-local', C.CYAN):<28} {clr(ll, C.YELLOW)}")
        print(f"  {clr('Solicited-node mcast', C.CYAN):<28} {clr(snm, C.TEAL)}")
        print(f"  {clr('L2 multicast MAC', C.CYAN):<28} {clr(dmac, C.LIME)}")

    elif sel == "2":
        raw = input(clr("  [»] IPv6 address: ", C.CYAN)).strip()
        try:
            addr = ipaddress.IPv6Address(raw)
        except ValueError:
            err("Invalid IPv6 address.")
            return
        snm  = solicited_node_multicast(str(addr))
        dmac = solicited_node_dst_mac(str(addr))
        section("Results")
        print(f"  {clr('Input', C.CYAN):<28} {clr(str(addr), C.WHITE)}")
        print(f"  {clr('Exploded', C.CYAN):<28} {clr(addr.exploded, C.DIM + C.WHITE)}")
        print(f"  {clr('Solicited-node mcast', C.CYAN):<28} {clr(snm, C.TEAL)}")
        print(f"  {clr('L2 multicast MAC', C.CYAN):<28} {clr(dmac, C.LIME)}")

    elif sel == "3":
        raw = input(clr("  [»] IPv6 address: ", C.CYAN)).strip()
        try:
            addr = ipaddress.IPv6Address(raw)
        except ValueError:
            err("Invalid IPv6 address.")
            return
        section("Results")
        print(f"  {clr('Compressed', C.CYAN):<28} {clr(addr.compressed, C.YELLOW)}")
        print(f"  {clr('Exploded', C.CYAN):<28} {clr(addr.exploded, C.WHITE)}")
        print(f"  {clr('Is link-local', C.CYAN):<28} {clr(str(addr.is_link_local), C.TEAL)}")
        print(f"  {clr('Is multicast', C.CYAN):<28} {clr(str(addr.is_multicast), C.TEAL)}")
        print(f"  {clr('Is private', C.CYAN):<28} {clr(str(addr.is_private), C.TEAL)}")
    else:
        err("Unknown selection.")


# ═══════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ═══════════════════════════════════════════════════════════════════════
def main_menu():
    # Privilege check
    if os.getuid() != 0:
        banner()
        err("ORBIT requires ROOT privileges.  Run with: sudo Orbit")
        sys.exit(1)

    # Suppress scapy conf verbosity
    conf.verb = 0

    signal.signal(signal.SIGINT, lambda s, f: (
        print(clr("\n\n  [✔] ORBIT interrupted. — owlsec.org\n", C.YELLOW)),
        sys.exit(0)
    ))

    while True:
        clear()
        banner()

        items = [
            ("1", "ARP Scan         ", "Discover IPv4 hosts via ARP broadcast",       C.GREEN),
            ("2", "NDP Active Scan  ", "Send NS probes to an IPv6 prefix range",       C.GREEN),
            ("3", "NDP Passive Sniff", "Listen for NS / NA / RA messages",             C.GREEN),
            ("4", "Port Scan        ", "TCP connect scan on a target host",            C.ORANGE),
            ("5", "Network Info     ", "Local interfaces, IPs, gateway, DNS",          C.BLUE),
            ("6", "IPv6/NDP Calc    ", "EUI-64, solicited-node multicast & MAC",       C.BLUE),
        ]
        for num, name, desc, c in items:
            print(f"  {clr(f'[{num}]', c):<8} {clr(name, C.WHITE)} {clr('─ ' + desc, C.DIM)}")
        print()
        print(f"  {clr('[H]', C.YELLOW):<8} {clr('Help             ', C.WHITE)} {clr('─ Full usage & protocol reference', C.DIM)}")
        print(f"  {clr('[0]', C.RED):<8} {clr('Exit', C.WHITE)}")
        print()
        print(clr("─" * 68, C.CYAN))

        choice = input(clr("\n  [»] Select option: ", C.CYAN)).strip().upper()

        if choice == "0":
            print(clr(f"\n  [✔] Thank you for using ORBIT. — {WEBSITE}\n", C.GREEN))
            sys.exit(0)
        elif choice == "H":
            clear(); banner(); show_help(); pause()
        elif choice == "1":
            module_arp_scan();     pause()
        elif choice == "2":
            module_ndp_active();   pause()
        elif choice == "3":
            module_ndp_passive();  pause()
        elif choice == "4":
            module_port_scan();    pause()
        elif choice == "5":
            module_network_info(); pause()
        elif choice == "6":
            module_ipv6_calc();    pause()
        else:
            err("Invalid option. Type H for help.")
            time.sleep(1)

# ═══════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(clr(f"\n\n  [✔] ORBIT stopped by user. — {WEBSITE}\n", C.YELLOW))
    except Exception as e:
        err(f"Unhandled exception: {e}")
        raise
