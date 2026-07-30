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
    iface: str = ""     # interface(s) the device was seen on
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


def get_interface_ipmac(iface: str) -> tuple[Optional[str], Optional[str]]:
    """Return (ipv4, mac) for `iface`, or (None, None) if not up."""
    ip = None
    mac = None
    try:
        out = _run(
            ["ip", "-o", "-f", "inet", "addr", "show", "dev", iface], timeout=5
        ).stdout
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/\d+", out)
        if m:
            ip = m.group(1)
    except Exception:
        pass
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            mac = f.read().strip().lower()
    except Exception:
        pass
    return ip, mac


def get_active_interfaces() -> list[tuple[str, str]]:
    """Return [(iface, cidr), ...] for every up non-loopback IPv4 interface.

    We deliberately do NOT restrict to the default-route interface, so that a
    device connected via both ethernet and wifi (potentially on different
    subnets) scans both. Link-local (169.254/16) addresses are skipped.
    """
    seen: dict[tuple[str, str], None] = {}
    try:
        out = _run(["ip", "-o", "-f", "inet", "addr", "show"], timeout=5).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            iface = parts[1]
            cidr = parts[3]
            if iface == "lo":
                continue
            if cidr.startswith("169.254."):
                continue
            if not re.match(r"\d+\.\d+\.\d+\.\d+/\d+$", cidr):
                continue
            seen[(iface, cidr)] = None
    except Exception:
        pass
    return list(seen.keys())


# ----------------------------------------------------------------------------
# Discovery: arp-scan
# ----------------------------------------------------------------------------
_ARP_LINE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:]{17})\s*(.*)")


def discover_arpscan(iface: str) -> Optional[list[Device]]:
    """Return devices via arp-scan, or None if arp-scan can't be used
    (not installed, or no permission) so the caller can fall back."""
    try:
        # --retry=4 catches sleepy wifi clients that ignore the first probe;
        # each extra retry costs ~2s per /24, worth it on a 5-minute rescan.
        proc = _run(
            ["arp-scan", "--localnet", "-I", iface, "--retry=4"], timeout=120
        )
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
# Discovery: nmap host discovery
# ----------------------------------------------------------------------------
# One `Nmap scan report` block per host, MAC on its own line when nmap gets
# ARP replies (root or cap_net_raw). Vendor is in parens after the MAC.
_NMAP_HOST = re.compile(r"Nmap scan report for (?:\S+ \()?(\d+\.\d+\.\d+\.\d+)")
_NMAP_MAC = re.compile(
    r"MAC Address:\s+([0-9A-Fa-f:]{17})(?:\s+\(([^)]*)\))?"
)


def discover_nmap(iface: str, cidr: str) -> Optional[list[Device]]:
    """Run `nmap -sn` against the interface's subnet. Returns None if nmap
    isn't installed or the invocation blew up; returns [] if it ran but
    found nothing."""
    try:
        # -sn: ping scan, no port scan. -PR forces ARP for local hosts.
        # -n: no DNS (we do our own reverse-DNS pass later).
        # --send-eth: raw Ethernet frames (needs cap_net_raw).
        # -e <iface>: pin to the interface we're scanning.
        proc = _run(
            ["nmap", "-sn", "-PR", "-n", "--send-eth", "-e", iface, cidr],
            timeout=180,
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return []

    text = proc.stdout
    if not text.strip():
        return None

    devices: dict[str, Device] = {}
    current_ip: Optional[str] = None
    for line in text.splitlines():
        m = _NMAP_HOST.search(line)
        if m:
            current_ip = m.group(1)
            devices.setdefault(current_ip, Device(ip=current_ip))
            continue
        if current_ip is None:
            continue
        m = _NMAP_MAC.search(line)
        if m:
            mac = m.group(1).lower()
            vendor = (m.group(2) or "").strip()
            devices[current_ip].mac = mac
            if vendor and vendor.lower() != "unknown":
                devices[current_ip].vendor = vendor
    return list(devices.values())


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
        self.interfaces: list[tuple[str, str]] = []
        self.last_method = ""
        self.refresh_context()

    def refresh_context(self):
        self.interfaces = get_active_interfaces()

    # Kept as read-only summaries for the status bar in app.py.
    @property
    def iface(self) -> str:
        return ", ".join(i for i, _ in self.interfaces) or ""

    @property
    def subnet(self) -> str:
        return ", ".join(c for _, c in self.interfaces) or ""

    def discover(self, status_cb: Optional[Callable[[str], None]] = None) -> list[Device]:
        def note(msg):
            if status_cb:
                status_cb(msg)

        self.refresh_context()
        if not self.interfaces:
            note("No active network interface found")
            return []

        # Scan each active interface (ethernet + wifi + anything else up).
        # Devices found on more than one interface are merged by IP, and their
        # `iface` field accumulates the comma-separated list of interfaces.
        merged: dict[str, Device] = {}
        methods: list[str] = []
        for iface, cidr in self.interfaces:
            note(f"Scanning {cidr} on {iface} ...")
            sources: list[str] = []

            arp_devs = discover_arpscan(iface)
            if arp_devs is not None:
                self._merge(merged, arp_devs, iface)
                sources.append("arp-scan")

            nmap_devs = discover_nmap(iface, cidr)
            if nmap_devs is not None:
                self._merge(merged, nmap_devs, iface)
                sources.append("nmap")

            # If neither of the raw-socket scanners was usable, fall back to
            # the pure-python ping sweep so we return _something_.
            if not sources:
                note(f"arp-scan/nmap unavailable on {iface} - ping-sweep fallback")
                self._merge(merged, discover_fallback(cidr), iface)
                sources.append("ping-sweep")
            else:
                # Even when arp-scan/nmap run, some devices (power-saving
                # phones, tight-firewalled hosts) only respond to a direct
                # ICMP echo. Ping every IP nobody's answered for yet.
                note(f"Ping-sweep supplement on {iface} ...")
                known = {ip for ip, d in merged.items() if iface in d.iface.split(",")}
                extra_ips = [ip for ip in ping_sweep(cidr) if ip not in known]
                if extra_ips:
                    arp = read_arp_cache()
                    extras = [Device(ip=ip, mac=arp.get(ip, "")) for ip in extra_ips]
                    self._merge(merged, extras, iface)
                    sources.append("ping")

            methods.append(f"{iface}:{'+'.join(sources)}")

        # Add the Vivid Unit itself — arp-scan/ping never see the host.
        self._add_self(merged)

        devices = list(merged.values())
        self.last_method = " / ".join(methods)
        note(f"Resolving hostnames for {len(devices)} device(s) ...")
        enrich_hostnames(devices)
        devices.sort(key=lambda d: d.ip_sortkey)
        note(f"{len(devices)} device(s) found ({self.last_method})")
        return devices

    @staticmethod
    def _merge(merged: dict[str, Device], devs: list[Device], iface: str) -> None:
        for d in devs:
            d.iface = iface
            existing = merged.get(d.ip)
            if existing is None:
                merged[d.ip] = d
                continue
            if not existing.mac and d.mac:
                existing.mac = d.mac
            if not existing.vendor and d.vendor:
                existing.vendor = d.vendor
            seen_ifaces = existing.iface.split(",") if existing.iface else []
            if iface not in seen_ifaces:
                seen_ifaces.append(iface)
            existing.iface = ",".join(seen_ifaces)

    def _add_self(self, merged: dict[str, Device]) -> None:
        host = socket.gethostname()
        for iface, _cidr in self.interfaces:
            ip, mac = get_interface_ipmac(iface)
            if not ip:
                continue
            existing = merged.get(ip)
            if existing is None:
                merged[ip] = Device(
                    ip=ip, mac=mac or "", vendor="(this device)",
                    hostname=host, iface=iface,
                )
            else:
                if not existing.mac and mac:
                    existing.mac = mac
                if not existing.hostname:
                    existing.hostname = host
                if not existing.vendor:
                    existing.vendor = "(this device)"
                seen_ifaces = existing.iface.split(",") if existing.iface else []
                if iface not in seen_ifaces:
                    seen_ifaces.append(iface)
                    existing.iface = ",".join(seen_ifaces)
