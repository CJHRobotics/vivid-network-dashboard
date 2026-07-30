"""Fullscreen touchscreen GUI for the Vivid Unit (1280x720).

Two views:
  - list view: scrollable rows of discovered devices, tap a row for detail
  - detail view: every field for one device + an on-demand deep probe

The scanner runs on a worker thread; results come back to the Tk main loop
through a queue polled with root.after(). Tkinter is single-threaded, so no
widget is ever touched off the main thread.
"""

from __future__ import annotations

import queue
import signal
import threading
import time
import tkinter as tk
from tkinter import font as tkfont

from .scanner import NetworkScanner, deep_probe, Device

# --- Screen / theme -----------------------------------------------------------
SCREEN_W, SCREEN_H = 1280, 720
AUTO_REFRESH_SECONDS = 60

BG = "#0f1720"          # near-black blue
CARD = "#1b2735"        # row / panel
CARD_HI = "#243449"     # pressed
ACCENT = "#39c0ba"      # teal
ACCENT_DIM = "#2a7d79"
TEXT = "#e7eef5"
MUTED = "#8aa0b4"
GOOD = "#5fd08a"
WARN = "#e0a24a"
DANGER = "#d05f6a"      # exit button


class NetMonApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.scanner = NetworkScanner()
        self.devices: list[Device] = []
        self.msg_q: queue.Queue = queue.Queue()
        self.scanning = False
        self._auto_after_id = None

        root.title("Network Monitor")
        root.configure(bg=BG)
        root.geometry(f"{SCREEN_W}x{SCREEN_H}")
        try:
            root.attributes("-fullscreen", True)
        except tk.TclError:
            pass
        root.bind("<Escape>", lambda e: root.attributes("-fullscreen", False))
        root.protocol("WM_DELETE_WINDOW", self.shutdown)

        self._init_fonts()

        # Container that holds both views; we raise one at a time.
        self.container = tk.Frame(root, bg=BG)
        self.container.pack(fill="both", expand=True)

        self.list_view = tk.Frame(self.container, bg=BG)
        self.detail_view = tk.Frame(self.container, bg=BG)
        for v in (self.list_view, self.detail_view):
            v.place(relx=0, rely=0, relwidth=1, relheight=1)

        self._build_list_view()
        self._build_detail_view()
        self.show_list()

        self.root.after(100, self._poll_queue)
        self.trigger_scan()

    # ---- fonts ---------------------------------------------------------------
    def _init_fonts(self):
        self.f_title = tkfont.Font(family="DejaVu Sans", size=22, weight="bold")
        self.f_row = tkfont.Font(family="DejaVu Sans", size=18, weight="bold")
        self.f_sub = tkfont.Font(family="DejaVu Sans Mono", size=12)
        self.f_btn = tkfont.Font(family="DejaVu Sans", size=15, weight="bold")
        self.f_label = tkfont.Font(family="DejaVu Sans", size=12, weight="bold")
        self.f_value = tkfont.Font(family="DejaVu Sans Mono", size=16)
        self.f_big = tkfont.Font(family="DejaVu Sans", size=26, weight="bold")
        self.f_status = tkfont.Font(family="DejaVu Sans", size=12)

    # ---- reusable touch button ----------------------------------------------
    def _touch_button(self, parent, text, command, bg=ACCENT, fg="#04231f", width=None):
        btn = tk.Label(
            parent, text=text, font=self.f_btn, bg=bg, fg=fg,
            padx=22, pady=14, cursor="hand2",
        )
        if width:
            btn.configure(width=width)

        def on_press(_):
            btn.configure(bg=CARD_HI)

        def on_release(_):
            btn.configure(bg=bg)
            command()

        btn.bind("<ButtonPress-1>", on_press)
        btn.bind("<ButtonRelease-1>", on_release)
        return btn

    # ---- LIST VIEW -----------------------------------------------------------
    def _build_list_view(self):
        header = tk.Frame(self.list_view, bg=BG)
        header.pack(fill="x", padx=18, pady=(14, 8))

        tk.Label(header, text="Network Monitor", font=self.f_title,
                 bg=BG, fg=TEXT).pack(side="left")

        self.rescan_btn = self._touch_button(header, "Rescan", self.trigger_scan)
        self.rescan_btn.pack(side="right")

        self.exit_btn = self._touch_button(
            header, "Exit", self.shutdown, bg=DANGER, fg="#2a0b0f"
        )
        self.exit_btn.pack(side="right", padx=(0, 10))

        self.status_lbl = tk.Label(
            self.list_view, text="Starting up ...", font=self.f_status,
            bg=BG, fg=MUTED, anchor="w",
        )
        self.status_lbl.pack(fill="x", padx=20)

        # Scrollable canvas holding the device rows
        body = tk.Frame(self.list_view, bg=BG)
        body.pack(fill="both", expand=True, padx=12, pady=8)

        self.canvas = tk.Canvas(body, bg=BG, highlightthickness=0)
        self.canvas.pack(side="left", fill="both", expand=True)

        self.rows_frame = tk.Frame(self.canvas, bg=BG)
        self._rows_window = self.canvas.create_window(
            (0, 0), window=self.rows_frame, anchor="nw"
        )

        self.rows_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")),
        )
        self.canvas.bind(
            "<Configure>",
            lambda e: self.canvas.itemconfigure(self._rows_window, width=e.width),
        )

        # Touch drag-to-scroll (capacitive touch arrives as button-1 events)
        self._drag_y = 0
        self.canvas.bind("<ButtonPress-1>", self._on_drag_start)
        self.canvas.bind("<B1-Motion>", self._on_drag_move)
        # Mouse wheel for desktop testing
        self.canvas.bind_all("<Button-4>", lambda e: self.canvas.yview_scroll(-2, "units"))
        self.canvas.bind_all("<Button-5>", lambda e: self.canvas.yview_scroll(2, "units"))

    def _on_drag_start(self, event):
        self._drag_y = event.y
        self.canvas.scan_mark(event.x, event.y)

    def _on_drag_move(self, event):
        self.canvas.scan_dragto(event.x, event.y, gain=1)

    def _render_rows(self):
        for w in self.rows_frame.winfo_children():
            w.destroy()

        if not self.devices:
            tk.Label(
                self.rows_frame,
                text="No devices found yet." if not self.scanning else "Scanning ...",
                font=self.f_row, bg=BG, fg=MUTED, pady=40,
            ).pack(fill="x")
            return

        for dev in self.devices:
            self._render_row(dev)

    def _render_row(self, dev: Device):
        row = tk.Frame(self.rows_frame, bg=CARD, height=76)
        row.pack(fill="x", pady=4, padx=4)
        row.pack_propagate(False)

        left = tk.Frame(row, bg=CARD)
        left.pack(side="left", fill="both", expand=True, padx=16, pady=8)

        tk.Label(left, text=dev.display_name, font=self.f_row, bg=CARD, fg=TEXT,
                 anchor="w").pack(fill="x")
        sub = f"{dev.ip}    {dev.mac or 'MAC unknown'}"
        tk.Label(left, text=sub, font=self.f_sub, bg=CARD, fg=MUTED,
                 anchor="w").pack(fill="x")

        chev = tk.Label(row, text=">", font=self.f_big, bg=CARD, fg=ACCENT)
        chev.pack(side="right", padx=20)

        # Tap anywhere on the row opens detail. Bind on all child widgets so a
        # tap on a label counts too.
        def open_detail(_=None, d=dev):
            self.show_detail(d)

        for w in (row, left, chev, *left.winfo_children()):
            w.bind("<ButtonRelease-1>", open_detail)

    # ---- DETAIL VIEW ---------------------------------------------------------
    def _build_detail_view(self):
        top = tk.Frame(self.detail_view, bg=BG)
        top.pack(fill="x", padx=18, pady=(14, 6))

        self.back_btn = self._touch_button(top, "< Back", self.show_list,
                                           bg=CARD, fg=TEXT)
        self.back_btn.pack(side="left")

        self.probe_btn = self._touch_button(top, "Deep Probe", self._trigger_probe)
        self.probe_btn.pack(side="right")

        self.detail_title = tk.Label(self.detail_view, text="", font=self.f_big,
                                     bg=BG, fg=ACCENT, anchor="w")
        self.detail_title.pack(fill="x", padx=22, pady=(6, 2))

        self.detail_body = tk.Frame(self.detail_view, bg=BG)
        self.detail_body.pack(fill="both", expand=True, padx=22, pady=10)

        self.current_device: Device | None = None

    def _field(self, parent, label, value, value_color=TEXT):
        block = tk.Frame(parent, bg=BG)
        block.pack(fill="x", pady=6, anchor="w")
        tk.Label(block, text=label.upper(), font=self.f_label, bg=BG, fg=MUTED,
                 anchor="w").pack(fill="x")
        tk.Label(block, text=value, font=self.f_value, bg=BG, fg=value_color,
                 anchor="w", justify="left", wraplength=SCREEN_W - 80).pack(fill="x")

    def _render_detail(self):
        for w in self.detail_body.winfo_children():
            w.destroy()
        d = self.current_device
        if not d:
            return

        self.detail_title.configure(text=d.display_name)

        # Two columns of core facts
        cols = tk.Frame(self.detail_body, bg=BG)
        cols.pack(fill="x", anchor="w")
        colL = tk.Frame(cols, bg=BG)
        colL.pack(side="left", fill="both", expand=True)
        colR = tk.Frame(cols, bg=BG)
        colR.pack(side="left", fill="both", expand=True)

        self._field(colL, "IP address", d.ip)
        self._field(colL, "MAC address", d.mac or "unknown")
        self._field(colL, "Vendor", d.vendor or "unknown")
        self._field(colL, "Seen on interface", d.iface or "unknown")
        self._field(colR, "Hostname", d.hostname or "no reverse DNS")
        seen = time.strftime("%H:%M:%S", time.localtime(d.last_seen))
        self._field(colR, "Last seen", seen)

        if d.latency_ms is not None:
            self._field(colR, "Latency", f"{d.latency_ms:.1f} ms", GOOD)
        if d.os_guess:
            self._field(colR, "OS guess (TTL)",
                        f"{d.os_guess}  (ttl={d.ttl})")

        # Open ports
        ports_block = tk.Frame(self.detail_body, bg=BG)
        ports_block.pack(fill="x", anchor="w", pady=(10, 0))
        tk.Label(ports_block, text="OPEN PORTS", font=self.f_label, bg=BG,
                 fg=MUTED, anchor="w").pack(fill="x")

        if d.open_ports:
            txt = "   ".join(f"{p}/{name}" for p, name in d.open_ports)
        elif d.latency_ms is None and not d.os_guess:
            txt = "Tap Deep Probe to scan ports and latency"
        else:
            txt = "None of the common ports are open"
        tk.Label(ports_block, text=txt, font=self.f_value, bg=BG, fg=TEXT,
                 anchor="w", justify="left",
                 wraplength=SCREEN_W - 80).pack(fill="x", pady=(2, 0))

    # ---- view switching ------------------------------------------------------
    def show_list(self):
        self.list_view.tkraise()

    def show_detail(self, dev: Device):
        self.current_device = dev
        self._render_detail()
        self.detail_view.tkraise()

    # ---- scanning ------------------------------------------------------------
    def trigger_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.rescan_btn.configure(text="Scanning...")
        self._cancel_auto_refresh()

        def work():
            devices = self.scanner.discover(
                status_cb=lambda m: self.msg_q.put(("status", m))
            )
            self.msg_q.put(("scan_done", devices))

        threading.Thread(target=work, daemon=True).start()

    def _trigger_probe(self):
        d = self.current_device
        if not d:
            return
        self.probe_btn.configure(text="Probing...")

        def work():
            deep_probe(d)
            self.msg_q.put(("probe_done", d))

        threading.Thread(target=work, daemon=True).start()

    def _schedule_auto_refresh(self):
        self._cancel_auto_refresh()
        self._auto_after_id = self.root.after(
            AUTO_REFRESH_SECONDS * 1000, self.trigger_scan
        )

    def _cancel_auto_refresh(self):
        if self._auto_after_id is not None:
            self.root.after_cancel(self._auto_after_id)
            self._auto_after_id = None

    def shutdown(self, *_):
        """Tear down the Tk root cleanly. Safe to call from a signal handler
        (via root.after) or from the WM close button. Scanner threads are
        daemons and exit with the process."""
        self._cancel_auto_refresh()
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    # ---- queue pump (runs on main thread) ------------------------------------
    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.msg_q.get_nowait()
                if kind == "status":
                    self.status_lbl.configure(text=payload)
                elif kind == "scan_done":
                    self.devices = payload
                    self.scanning = False
                    self.rescan_btn.configure(text="Rescan")
                    self._render_rows()
                    ctx = f"{self.scanner.iface or '?'}  {self.scanner.subnet or ''}"
                    self.status_lbl.configure(
                        text=f"{len(self.devices)} device(s)  |  {ctx}  |  "
                             f"{self.scanner.last_method}  |  "
                             f"{time.strftime('%H:%M:%S')}"
                    )
                    self._schedule_auto_refresh()
                elif kind == "probe_done":
                    self.probe_btn.configure(text="Deep Probe")
                    if self.current_device is payload:
                        self._render_detail()
        except queue.Empty:
            pass
        try:
            self.root.after(150, self._poll_queue)
        except tk.TclError:
            pass  # root already destroyed


def main():
    root = tk.Tk()
    app = NetMonApp(root)

    # Ctrl-C / SIGTERM -> clean exit. Signal handlers only fire between
    # Python bytecode ops, and Tk's mainloop blocks in C, so we bounce the
    # shutdown back onto the Tk main thread via root.after(0, ...). The
    # existing 150ms _poll_queue tick keeps the interpreter warm enough to
    # notice the signal within a fraction of a second.
    def _on_signal(_sig, _frame):
        root.after(0, app.shutdown)

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    try:
        root.mainloop()
    except KeyboardInterrupt:
        app.shutdown()


if __name__ == "__main__":
    main()
