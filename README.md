# Vivid Unit Network Monitor

A fullscreen touchscreen GUI for the UUGear Vivid Unit (RK3399, 1280×720) that
lists every device on your local network and, on tap, shows everything it can
probe about one device.

## What it does

**List view** — a scrollable, touch-friendly list of discovered devices. Each
row shows the best available name (hostname → vendor → IP), the IP, and the MAC.
Tap a row to open the detail view. Auto-rescans every 60 seconds; a **Rescan**
button forces one immediately.

**Detail view** — IP, MAC, vendor, reverse-DNS hostname, and last-seen time.
Tap **Deep Probe** to add:
- ping latency
- TTL-based OS-family guess (Linux/Unix, Windows, or network gear)
- open ports from a scan of ~22 common services (SSH, HTTP, SMB, RDP, VNC, …)

## Install

Copy this folder onto the Vivid Unit, then:

```bash
cd netmon
bash install.sh
```

That installs `python3-tk`, `arp-scan`, and `iputils-ping`, copies the app to
`/opt/netmon`, grants `arp-scan` the `cap_net_raw` capability so the GUI can run
as a normal user, and adds a desktop autostart entry so it launches on login.

Run it right away without rebooting:

```bash
python3 /opt/netmon/run.py
```

Press **Escape** to leave fullscreen.

## How discovery works

1. **arp-scan** (`arp-scan --localnet`) is the primary path — one pass returns
   IP, MAC, and vendor. `install.sh` gives the binary `cap_net_raw+ep` so no
   `sudo` is needed.
2. If arp-scan is missing or unprivileged, it falls back to a **threaded ping
   sweep** of your `/24`, then reads `/proc/net/arp` for MACs. This works
   unprivileged but vendor names may be blank.

Reverse-DNS hostname lookups run in parallel after discovery. All scanning
happens on a worker thread; the Tk UI is only ever touched from the main thread
via a queue, so the screen never freezes mid-scan.

## Files

- `netmon/scanner.py` — all discovery/probe logic, no UI. Swap the GUI without
  touching this.
- `netmon/app.py` — the Tkinter touchscreen UI (list + detail views).
- `run.py` — entry point.
- `install.sh` — dependencies, capability grant, autostart.
- `netmon.service` — optional systemd alternative to desktop autostart.

## Tuning

In `netmon/app.py`: `AUTO_REFRESH_SECONDS`, and the theme colors near the top.
In `netmon/scanner.py`: `COMMON_PORTS` (add ports you care about), ping-sweep
`workers`, and socket `timeout` values.

## Notes

- Discovery only sees devices on the same subnet as the Vivid Unit. Plug it into
  the network segment you want to watch.
- Scanning your own LAN this way is ordinary network administration. Only scan
  networks you own or are authorized to inspect.
