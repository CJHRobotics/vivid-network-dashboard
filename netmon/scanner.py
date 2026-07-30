"""Network discovery and probing. No UI code lives here.

Discovery strategy:
  1. arp-scan --localnet  (best: IP + MAC + vendor in one pass; needs root or
     cap_net_raw on the arp-scan binary)
  2. fallback: threaded ping sweep of the local /24, then read /proc/net/arp
     for MACs. Works unprivileged, but vendor names are only as good as the
     local OUI file (usually blank without arp-scan).

Everything returns plain Device objects so the GUI never touches a socket.
"""

from __future__ import annotations

import ipaddress
import queue
import re
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


# ----------------------------------------------------------------------------
# Data model
# ----------------------------------------------------------------------------
@dataclass
class Device:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    last_seen: float = field(default_factory=time.time)

    # Filled in on demand by deep_probe()
    latency_ms: Optional[float] = None
    ttl: Optional[int] = None
    os_guess: str = ""
    open_ports: list[tuple[int, str]] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        return self.hostname or self.vendor or self.ip

    @property
    def ip_sortkey(self):
        try:
            return tuple(int(o) for o in self.ip.split("."))
        except ValueError:
            return (999, 999, 999, 999)


# ----------------------------------------------------------------------------
# Small shell helpers
# ----------------------------------------------------------------------------
def _run(cmd, timeout=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )


def get_primary_interface() -> Optional[str]:
    try:
        out = _run(["ip", "route", "show", "default"], timeout=5).stdout
        m = re.search(r"default via \S+ dev (\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    # last resort: first non-loopback iface with an inet addr
    try:
        out = _run(["ip", "-o", "-f", "inet", "addr", "show"], timeout=5).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] != "lo":
                return parts[1]
    except Exception:
        pass
    return None


def get_subnet(iface: str) -> Optional[str]:
    try:
        out = _run(
            ["ip", "-o", "-f", "inet", "addr", "show", "dev", iface], timeout=5
        ).stdout
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


# ----------------------------------------------------------------------------
# Discovery: arp-scan
# ----------------------------------------------------------------------------
_ARP_LINE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:]{17})\s*(.*)")


def discover_arpscan(iface: str) -> Optional[list[Device]]:
    """Return devices via arp-scan, or None if arp-scan can't be used
    (not installed, or no permission) so the caller can fall back."""
    try:
        proc = _run(["arp-scan", "--localnet", "-I", iface], timeout=90)
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return []

    combined = proc.stdout + "\n" + proc.stderr
    if "denied" in combined.lower() or "permission" in combined.lower():
        return None  # needs root / cap_net_raw -> fall back

    devices: dict[str, Device] = {}
    for line in proc.stdout.splitlines():
        m = _ARP_LINE.match(line.strip())
        if not m:
            continue
        ip, mac, vendor = m.group(1), m.group(2).lower(), m.group(3).strip()
        # arp-scan prints "(Unknown)" when the OUI isn't in its table
        if vendor.lower().strip("()") == "unknown":
            vendor = ""
        devices[ip] = Device(ip=ip, mac=mac, vendor=vendor)

    return list(devices.values()) if devices else None


# ----------------------------------------------------------------------------
# Discovery: pure-python fallback (ping sweep + ARP cache)
# ----------------------------------------------------------------------------
def _ping_once(ip: str, timeout_s: float = 0.4) -> bool:
    proc = _run(["ping", "-c", "1", "-W", str(timeout_s), ip], timeout=timeout_s + 2)
    return proc.returncode == 0


def ping_sweep(subnet_cidr: str, workers: int = 96) -> list[str]:
    net = ipaddress.ip_network(subnet_cidr, strict=False)
    if net.num_addresses > 4096:
        # Guard against someone plugging in on a /16. Scan only the /24 the
        # host lives in.
        host = ipaddress.ip_interface(subnet_cidr).ip
        net = ipaddress.ip_network(f"{host}/24", strict=False)

    hosts = [str(h) for h in net.hosts()]
    alive: list[str] = []
    lock = threading.Lock()
    q: queue.Queue = queue.Queue()
    for ip in hosts:
        q.put(ip)

    def worker():
        while True:
            try:
                ip = q.get_nowait()
            except queue.Empty:
                return
            try:
                if _ping_once(ip):
                    with lock:
                        alive.append(ip)
            finally:
                q.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return alive


def read_arp_cache() -> dict[str, str]:
    table: dict[str, str] = {}
    try:
        with open("/proc/net/arp") as f:
            next(f, None)  # header row
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    ip, mac = parts[0], parts[3].lower()
                    if mac != "00:00:00:00:00:00":
                        table[ip] = mac
    except FileNotFoundError:
        pass
    return table


def discover_fallback(subnet_cidr: str) -> list[Device]:
    alive = ping_sweep(subnet_cidr)
    arp = read_arp_cache()
    devices = []
    for ip in alive:
        devices.append(Device(ip=ip, mac=arp.get(ip, "")))
    # Include cached hosts that didn't answer ping but are in the ARP table
    for ip, mac in arp.items():
        if ip not in alive and ipaddress.ip_address(ip) in ipaddress.ip_network(
            subnet_cidr, strict=False
        ):
            devices.append(Device(ip=ip, mac=mac))
    return devices


# ----------------------------------------------------------------------------
# Enrichment
# ----------------------------------------------------------------------------
def reverse_dns(ip: str, timeout: float = 1.0) -> str:
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old)


def enrich_hostnames(devices: list[Device], workers: int = 32) -> None:
    q: queue.Queue = queue.Queue()
    for d in devices:
        if not d.hostname:
            q.put(d)

    def worker():
        while True:
            try:
                d = q.get_nowait()
            except queue.Empty:
                return
            try:
                d.hostname = reverse_dns(d.ip)
            finally:
                q.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


# ----------------------------------------------------------------------------
# Deep probe (detail screen, on demand)
# ----------------------------------------------------------------------------
COMMON_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 515: "Printer", 548: "AFP", 631: "IPP", 1883: "MQTT",
    3306: "MySQL", 3389: "RDP", 5000: "UPnP", 5900: "VNC", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 9100: "JetDirect",
}


def scan_ports(ip: str, timeout: float = 0.6, workers: int = 32) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    lock = threading.Lock()
    q: queue.Queue = queue.Queue()
    for p in COMMON_PORTS:
        q.put(p)

    def worker():
        while True:
            try:
                port = q.get_nowait()
            except queue.Empty:
                return
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                if s.connect_ex((ip, port)) == 0:
                    with lock:
                        found.append((port, COMMON_PORTS[port]))
            except Exception:
                pass
            finally:
                s.close()
                q.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return sorted(found)


def _os_from_ttl(ttl: int) -> str:
    if ttl <= 0:
        return ""
    if ttl <= 64:
        return "Linux / Unix / Android"
    if ttl <= 128:
        return "Windows"
    return "Network device (router/switch)"


def ping_detail(ip: str, count: int = 3) -> tuple[Optional[float], Optional[int]]:
    """Return (avg latency ms, ttl)."""
    proc = _run(["ping", "-c", str(count), "-W", "1", ip], timeout=count + 4)
    out = proc.stdout
    latency = None
    ttl = None
    m = re.search(r"=\s*[\d.]+/([\d.]+)/", out)
    if m:
        latency = float(m.group(1))
    m = re.search(r"ttl=(\d+)", out)
    if m:
        ttl = int(m.group(1))
    return latency, ttl


def deep_probe(device: Device) -> Device:
    latency, ttl = ping_detail(device.ip)
    device.latency_ms = latency
    device.ttl = ttl
    device.os_guess = _os_from_ttl(ttl) if ttl else ""
    device.open_ports = scan_ports(device.ip)
    if not device.hostname:
        device.hostname = reverse_dns(device.ip)
    return device


# ----------------------------------------------------------------------------
# Top-level scanner
# ----------------------------------------------------------------------------
class NetworkScanner:
    def __init__(self):
        self.iface = get_primary_interface()
        self.subnet = get_subnet(self.iface) if self.iface else None
        self.last_method = ""

    def refresh_context(self):
        self.iface = get_primary_interface()
        self.subnet = get_subnet(self.iface) if self.iface else None

    def discover(self, status_cb: Optional[Callable[[str], None]] = None) -> list[Device]:
        def note(msg):
            if status_cb:
                status_cb(msg)

        self.refresh_context()
        if not self.iface or not self.subnet:
            note("No active network interface found")
            return []

        note(f"Scanning {self.subnet} on {self.iface} ...")
        devices = discover_arpscan(self.iface)
        if devices is not None:
            self.last_method = "arp-scan"
        else:
            note("arp-scan unavailable - falling back to ping sweep")
            devices = discover_fallback(self.subnet)
            self.last_method = "ping-sweep"

        note(f"Resolving hostnames for {len(devices)} device(s) ...")
        enrich_hostnames(devices)
        devices.sort(key=lambda d: d.ip_sortkey)
        note(f"{len(devices)} device(s) found via {self.last_method}")
        return devices
