"""
ui_app.py - Main GUI application using customtkinter.

Provides a clean, modern interface for configuring and controlling
the Windows DHCP Tool.
"""

import threading
import time
import logging
from typing import Optional, List, Dict, Any

import customtkinter as ctk
from tkinter import messagebox, ttk
import tkinter as tk

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore

from dhcp_server import DHCPServer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Appearance
# ---------------------------------------------------------------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_network_interfaces() -> List[Dict[str, str]]:
    """
    Enumerate local network interfaces that have an IPv4 address.

    Returns a list of dicts: {"name": ..., "ip": ..., "label": ...}
    """
    interfaces: List[Dict[str, str]] = []
    if psutil is None:
        return interfaces

    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface_name, addr_list in addrs.items():
        # Skip loopback and down interfaces
        stat = stats.get(iface_name)
        if stat and not stat.isup:
            continue

        for addr in addr_list:
            if addr.family == 2:  # AF_INET (IPv4)
                ip = addr.address
                if ip.startswith("127."):
                    continue
                label = f"{iface_name}  [{ip}]"
                interfaces.append({"name": iface_name, "ip": ip, "label": label})
                break  # one IPv4 per interface

    return interfaces


def validate_ip(ip: str) -> bool:
    """Return True if *ip* is a valid dotted-decimal IPv4 address."""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def validate_port_range(start: str, end: str) -> bool:
    """Return True if start and end are valid and start <= end."""
    import struct, socket as _sock
    try:
        s = struct.unpack("!I", _sock.inet_aton(start))[0]
        e = struct.unpack("!I", _sock.inet_aton(end))[0]
        return s <= e
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main Application Window
# ---------------------------------------------------------------------------

class DHCPToolApp(ctk.CTk):
    """Main application window for the Windows DHCP Tool."""

    REFRESH_INTERVAL_MS = 2000  # Lease table refresh every 2 seconds

    def __init__(self) -> None:
        super().__init__()

        self.title("Windows DHCP 分配工具")
        self.geometry("860x620")
        self.minsize(760, 560)
        self.resizable(True, True)

        self._server = DHCPServer()
        self._interfaces: List[Dict[str, str]] = []
        self._refresh_job: Optional[str] = None  # after() job handle

        self._build_ui()
        self._load_interfaces()
        self._schedule_refresh()

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Assemble the main UI layout."""
        # ---------- top bar: interface selector ----------
        top_frame = ctk.CTkFrame(self, corner_radius=8)
        top_frame.pack(fill="x", padx=12, pady=(12, 4))

        ctk.CTkLabel(top_frame, text="网卡：", width=50).pack(
            side="left", padx=(12, 4), pady=8
        )

        self._iface_var = ctk.StringVar(value="")
        self._iface_combo = ctk.CTkComboBox(
            top_frame,
            variable=self._iface_var,
            width=420,
            state="readonly",
            command=self._on_interface_changed,
        )
        self._iface_combo.pack(side="left", padx=4, pady=8)

        ctk.CTkButton(
            top_frame, text="刷新网卡", width=90, command=self._load_interfaces
        ).pack(side="left", padx=8, pady=8)

        # ---------- main content: config (left) + status-indicator (right) ----------
        content_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=12, pady=4)
        content_frame.columnconfigure(0, weight=2)
        content_frame.columnconfigure(1, weight=3)
        content_frame.rowconfigure(0, weight=1)

        # ---------- left: config panel ----------
        self._build_config_panel(content_frame)

        # ---------- right: lease table ----------
        self._build_lease_panel(content_frame)

    def _build_config_panel(self, parent: ctk.CTkFrame) -> None:
        """Build the DHCP configuration input area."""
        cfg_outer = ctk.CTkFrame(parent, corner_radius=8)
        cfg_outer.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=4)

        ctk.CTkLabel(
            cfg_outer, text="DHCP 配置", font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=14, pady=(10, 4))

        cfg_frame = ctk.CTkFrame(cfg_outer, fg_color="transparent")
        cfg_frame.pack(fill="both", expand=True, padx=10, pady=4)

        # Helper to add a labeled entry row
        def add_row(label: str, default: str, attr: str) -> ctk.CTkEntry:
            row = ctk.CTkFrame(cfg_frame, fg_color="transparent")
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=label, width=100, anchor="w").pack(
                side="left", padx=(0, 6)
            )
            entry = ctk.CTkEntry(row, placeholder_text=default)
            entry.insert(0, default)
            entry.pack(side="left", fill="x", expand=True)
            setattr(self, attr, entry)
            return entry

        add_row("起始 IP：", "192.168.100.100", "_entry_start_ip")
        add_row("结束 IP：", "192.168.100.200", "_entry_end_ip")
        add_row("子网掩码：", "255.255.255.0", "_entry_mask")
        add_row("网关：", "", "_entry_gateway")
        add_row("DNS 服务器：", "8.8.8.8", "_entry_dns")
        add_row("租约时间（秒）：", "3600", "_entry_lease")

        # ---------- start / stop buttons + status indicator ----------
        ctrl_frame = ctk.CTkFrame(cfg_outer, fg_color="transparent")
        ctrl_frame.pack(fill="x", padx=10, pady=(8, 12))

        self._btn_start = ctk.CTkButton(
            ctrl_frame,
            text="▶  启动 DHCP",
            fg_color="#2e7d32",
            hover_color="#1b5e20",
            width=130,
            command=self._on_start,
        )
        self._btn_start.pack(side="left", padx=(0, 8))

        self._btn_stop = ctk.CTkButton(
            ctrl_frame,
            text="■  停止 DHCP",
            fg_color="#c62828",
            hover_color="#7f0000",
            width=130,
            state="disabled",
            command=self._on_stop,
        )
        self._btn_stop.pack(side="left", padx=(0, 12))

        # Status indicator (canvas circle)
        self._status_canvas = tk.Canvas(
            ctrl_frame, width=20, height=20,
            bg=self._get_bg_color(), highlightthickness=0
        )
        self._status_canvas.pack(side="left", padx=(0, 6))
        self._status_circle = self._status_canvas.create_oval(
            2, 2, 18, 18, fill="#616161", outline=""
        )

        self._status_label = ctk.CTkLabel(
            ctrl_frame, text="已停止", text_color="#9e9e9e"
        )
        self._status_label.pack(side="left")

    def _build_lease_panel(self, parent: ctk.CTkFrame) -> None:
        """Build the lease/client list table on the right."""
        lease_outer = ctk.CTkFrame(parent, corner_radius=8)
        lease_outer.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=4)

        header = ctk.CTkFrame(lease_outer, fg_color="transparent")
        header.pack(fill="x", padx=14, pady=(10, 4))

        ctk.CTkLabel(
            header, text="已分配客户端", font=ctk.CTkFont(size=14, weight="bold")
        ).pack(side="left")

        self._lease_count_label = ctk.CTkLabel(
            header, text="(0 台)", text_color="#90caf9"
        )
        self._lease_count_label.pack(side="left", padx=8)

        # ttk Treeview (best cross-platform table widget in tkinter)
        tree_frame = ctk.CTkFrame(lease_outer, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "DHCPTable.Treeview",
            background="#1e1e1e",
            foreground="#e0e0e0",
            rowheight=26,
            fieldbackground="#1e1e1e",
            borderwidth=0,
            font=("Consolas", 10),
        )
        style.configure(
            "DHCPTable.Treeview.Heading",
            background="#2d2d2d",
            foreground="#90caf9",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "DHCPTable.Treeview",
            background=[("selected", "#1565c0")],
            foreground=[("selected", "#ffffff")],
        )

        columns = ("mac", "ip", "hostname", "remaining")
        self._tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            style="DHCPTable.Treeview",
            selectmode="browse",
        )

        self._tree.heading("mac", text="MAC 地址")
        self._tree.heading("ip", text="IP 地址")
        self._tree.heading("hostname", text="主机名")
        self._tree.heading("remaining", text="剩余租约")

        self._tree.column("mac", width=150, minwidth=130)
        self._tree.column("ip", width=130, minwidth=110)
        self._tree.column("hostname", width=150, minwidth=100)
        self._tree.column("remaining", width=90, minwidth=80, anchor="center")

        scrollbar = ttk.Scrollbar(
            tree_frame, orient="vertical", command=self._tree.yview
        )
        self._tree.configure(yscrollcommand=scrollbar.set)

        self._tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    # ------------------------------------------------------------------
    # Interface management
    # ------------------------------------------------------------------

    def _load_interfaces(self) -> None:
        """Enumerate network interfaces and populate the combo box."""
        self._interfaces = get_network_interfaces()
        labels = [i["label"] for i in self._interfaces]

        if not labels:
            labels = ["（未找到可用网卡）"]

        self._iface_combo.configure(values=labels)

        if labels:
            self._iface_combo.set(labels[0])
            self._on_interface_changed(labels[0])

    def _on_interface_changed(self, label: str) -> None:
        """Pre-fill gateway with the selected interface's IP."""
        iface = self._get_selected_interface()
        if iface:
            self._entry_gateway.delete(0, "end")
            self._entry_gateway.insert(0, iface["ip"])

    def _get_selected_interface(self) -> Optional[Dict[str, str]]:
        """Return the currently selected interface dict or None."""
        label = self._iface_var.get()
        for iface in self._interfaces:
            if iface["label"] == label:
                return iface
        return None

    # ------------------------------------------------------------------
    # Start / Stop handlers
    # ------------------------------------------------------------------

    def _on_start(self) -> None:
        """Validate config and start the DHCP server."""
        iface = self._get_selected_interface()
        if not iface:
            messagebox.showerror("错误", "请选择一块有效的网卡。")
            return

        start_ip = self._entry_start_ip.get().strip()
        end_ip = self._entry_end_ip.get().strip()
        mask = self._entry_mask.get().strip()
        gateway = self._entry_gateway.get().strip()
        dns = self._entry_dns.get().strip()
        lease_str = self._entry_lease.get().strip()

        # Validation
        errors = []
        for label, val in [
            ("起始 IP", start_ip), ("结束 IP", end_ip),
            ("子网掩码", mask), ("网关", gateway), ("DNS", dns),
        ]:
            if not validate_ip(val):
                errors.append(f"{label} "{val}" 不是合法的 IPv4 地址。")

        try:
            lease_time = int(lease_str)
            if lease_time < 60:
                errors.append("租约时间不能小于 60 秒。")
        except ValueError:
            errors.append(f"租约时间 "{lease_str}" 不是整数。")
            lease_time = 3600

        if not errors and not validate_port_range(start_ip, end_ip):
            errors.append("起始 IP 不能大于结束 IP。")

        if errors:
            messagebox.showerror("配置错误", "\n".join(errors))
            return

        config = {
            "interface_ip": iface["ip"],
            "start_ip": start_ip,
            "end_ip": end_ip,
            "subnet_mask": mask,
            "gateway": gateway,
            "dns": dns,
            "lease_time": lease_time,
        }

        ok = self._server.start(config)
        if not ok:
            messagebox.showerror(
                "启动失败",
                self._server.last_error or "无法启动 DHCP 服务，请检查端口占用和权限。",
            )
            return

        self._set_running_state(True)

    def _on_stop(self) -> None:
        """Stop the DHCP server."""
        self._server.stop()
        self._set_running_state(False)

    def _set_running_state(self, running: bool) -> None:
        """Update button states and status indicator."""
        if running:
            self._btn_start.configure(state="disabled")
            self._btn_stop.configure(state="normal")
            self._status_canvas.itemconfig(self._status_circle, fill="#4caf50")
            self._status_label.configure(text="运行中", text_color="#4caf50")
        else:
            self._btn_start.configure(state="normal")
            self._btn_stop.configure(state="disabled")
            self._status_canvas.itemconfig(self._status_circle, fill="#616161")
            self._status_label.configure(text="已停止", text_color="#9e9e9e")

    # ------------------------------------------------------------------
    # Lease table refresh
    # ------------------------------------------------------------------

    def _schedule_refresh(self) -> None:
        """Schedule periodic lease table refresh."""
        self._refresh_leases()
        self._refresh_job = self.after(self.REFRESH_INTERVAL_MS, self._schedule_refresh)

    def _refresh_leases(self) -> None:
        """Update the lease table with current data from the server."""
        leases = self._server.get_leases()

        # Snapshot current items
        existing_iids = set(self._tree.get_children())
        seen_iids = set()

        for lease in leases:
            iid = lease["mac"].replace(":", "")
            remaining = self._format_remaining(lease["remaining"])
            values = (
                lease["mac"],
                lease["ip"],
                lease.get("hostname") or "—",
                remaining,
            )
            if iid in existing_iids:
                self._tree.item(iid, values=values)
            else:
                self._tree.insert("", "end", iid=iid, values=values)
            seen_iids.add(iid)

        # Remove stale rows
        for iid in existing_iids - seen_iids:
            self._tree.delete(iid)

        self._lease_count_label.configure(text=f"({len(leases)} 台)")

    @staticmethod
    def _format_remaining(seconds: int) -> str:
        """Format remaining seconds as H:MM:SS."""
        h = seconds // 3600
        m = (seconds % 3600) // 60
        s = seconds % 60
        return f"{h}:{m:02d}:{s:02d}"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_bg_color(self) -> str:
        """Return a hex background colour compatible with the current theme."""
        try:
            return self._apply_appearance_mode(
                ctk.ThemeManager.theme["CTkFrame"]["fg_color"]
            )
        except Exception:
            return "#2b2b2b"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_closing(self) -> None:
        """Clean up on window close."""
        if self._refresh_job:
            self.after_cancel(self._refresh_job)
        if self._server.is_running:
            self._server.stop()
        self.destroy()
