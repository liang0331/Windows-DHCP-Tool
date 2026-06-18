"""
main.py - Windows DHCP 分配工具（单文件版）

双击运行或:  python main.py
打包为 exe:   pyinstaller --onefile --windowed --uac-admin --name DHCPTool \
              --collect-all customtkinter --hidden-import psutil main.py

包含 dhcp_server.py 和 ui_app.py 全部内容，避免多文件打包时的模块查找问题。
"""

import os
import sys
import socket
import struct
import subprocess
import threading
import time
import logging
import traceback
from typing import Dict, Optional, Tuple, List, Any

# ---------------------------------------------------------------------------
# Configure logging before any other imports
# 日志同时输出到控制台与文件，方便在 windowed 模式下排查问题
# ---------------------------------------------------------------------------
_LOG_DIR: str
if getattr(sys, "frozen", False):
    _LOG_DIR = os.path.dirname(sys.executable)
else:
    _LOG_DIR = os.path.dirname(os.path.abspath(__file__))
_LOG_FILE: str = os.path.join(_LOG_DIR, "DHCPTool.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(_LOG_FILE, encoding="utf-8"),
    ],
)

logger = logging.getLogger("dhcptool")
logger.info("==== DHCP Tool 启动 ====")
logger.info("日志文件: %s", _LOG_FILE)

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
_MISSING: list = []

try:
    import customtkinter as ctk  # noqa: F401
except ImportError:
    _MISSING.append("customtkinter")

try:
    import psutil  # noqa: F401
except ImportError:
    _MISSING.append("psutil")

if _MISSING:
    msg = (
        "缺少以下 Python 包，请先运行 pip install 安装：\n\n"
        + "\n".join(f"  pip install {pkg}" for pkg in _MISSING)
    )
    try:
        import tkinter
        from tkinter import messagebox
        _root = tkinter.Tk()
        _root.withdraw()
        messagebox.showerror("缺少依赖", msg)
        _root.destroy()
    except Exception:
        print(msg, file=sys.stderr)
    sys.exit(1)

import tkinter as tk
from tkinter import messagebox, ttk


# ===========================================================================
#  配色方案（蓝绿渐变色系 / dark 主题）
# ===========================================================================
COLOR_BG: str = "#1e1e2e"            # 主窗口背景（深蓝灰）
COLOR_CARD: str = "#2b2b3d"          # 卡片背景
COLOR_CARD_INNER: str = "#33334d"    # 内嵌分组卡片背景
COLOR_HEADER: str = "#00838f"        # 顶部 teal 色条
COLOR_HEADER_2: str = "#00bcd4"      # cyan 辅助色
COLOR_ACCENT: str = "#00bcd4"        # 主强调色（青）
COLOR_ACCENT_DARK: str = "#00838f"   # 深强调色
COLOR_SUCCESS: str = "#4caf50"       # 运行中绿
COLOR_SUCCESS_GLOW: str = "#69f0ae"  # LED 高亮绿
COLOR_DANGER: str = "#ef5350"        # 停止红
COLOR_DANGER_DARK: str = "#c62828"
COLOR_TEXT: str = "#e0e0e0"
COLOR_TEXT_DIM: str = "#9e9e9e"
COLOR_ROW_EVEN: str = "#262637"      # 斑马纹偶数行
COLOR_ROW_ODD: str = "#2b2b3d"       # 斑马纹奇数行
COLOR_TABLE_HEAD: str = "#3a3a55"    # 表头


# ===========================================================================
#  dhcp_server.py — DHCPv4 Server Core
# ===========================================================================

# DHCP Constants (RFC 2131 / RFC 2132)
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
BROADCAST_ADDR = "255.255.255.255"
MAGIC_COOKIE = b"\x63\x82\x53\x63"

# DHCP message types (Option 53)
DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPDECLINE = 4
DHCPACK = 5
DHCPNAK = 6
DHCPRELEASE = 7
DHCPINFORM = 8

MSG_TYPE_NAMES = {
    DHCPDISCOVER: "DISCOVER",
    DHCPOFFER: "OFFER",
    DHCPREQUEST: "REQUEST",
    DHCPDECLINE: "DECLINE",
    DHCPACK: "ACK",
    DHCPNAK: "NAK",
    DHCPRELEASE: "RELEASE",
    DHCPINFORM: "INFORM",
}


def ip_to_bytes(ip: str) -> bytes:
    """Convert dotted-decimal IP string to 4 bytes."""
    return socket.inet_aton(ip)


def bytes_to_ip(data: bytes) -> str:
    """Convert 4 bytes to dotted-decimal IP string."""
    return socket.inet_ntoa(data)


def mac_to_str(data: bytes) -> str:
    """Convert 6-byte MAC address to colon-separated hex string."""
    return ":".join(f"{b:02x}" for b in data[:6])


def ip_to_int(ip: str) -> int:
    """Convert dotted-decimal IP string to a 32-bit integer."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def ip_in_range(ip: str, start: str, end: str) -> bool:
    """Return True if *ip* falls within [start, end] (inclusive)."""
    si = ip_to_int(start)
    ei = ip_to_int(end)
    pi = ip_to_int(ip)
    return si <= pi <= ei


def ip_le(a: str, b: str) -> bool:
    """Return True if IP *a* <= IP *b* (numeric comparison)."""
    return ip_to_int(a) <= ip_to_int(b)


def next_ip(ip: str) -> str:
    """Return the IP address that follows *ip*."""
    n = ip_to_int(ip)
    return socket.inet_ntoa(struct.pack("!I", n + 1))


class DHCPPacket:
    """Represents a DHCP packet (RFC 2131 format)."""

    HEADER_FORMAT = "!BBBBIHHIIII16s64s128s4s"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(self) -> None:
        self.op: int = 1
        self.htype: int = 1
        self.hlen: int = 6
        self.hops: int = 0
        self.xid: int = 0
        self.secs: int = 0
        self.flags: int = 0x8000
        self.ciaddr: str = "0.0.0.0"
        self.yiaddr: str = "0.0.0.0"
        self.siaddr: str = "0.0.0.0"
        self.giaddr: str = "0.0.0.0"
        self.chaddr: bytes = b"\x00" * 16
        self.sname: bytes = b"\x00" * 64
        self.file: bytes = b"\x00" * 128
        self.options: Dict[int, bytes] = {}

    @classmethod
    def from_bytes(cls, data: bytes) -> "DHCPPacket":
        if len(data) < cls.HEADER_SIZE + 4:
            raise ValueError("Packet too short")
        pkt = cls()
        vals = struct.unpack(cls.HEADER_FORMAT, data[:cls.HEADER_SIZE])
        (pkt.op, pkt.htype, pkt.hlen, pkt.hops,
         pkt.xid, pkt.secs, pkt.flags,
         ciaddr, yiaddr, siaddr, giaddr,
         chaddr, sname, file_, magic) = vals
        if magic != MAGIC_COOKIE:
            raise ValueError("Invalid DHCP magic cookie")
        pkt.ciaddr = bytes_to_ip(struct.pack("!I", ciaddr))
        pkt.yiaddr = bytes_to_ip(struct.pack("!I", yiaddr))
        pkt.siaddr = bytes_to_ip(struct.pack("!I", siaddr))
        pkt.giaddr = bytes_to_ip(struct.pack("!I", giaddr))
        pkt.chaddr = chaddr
        pkt.sname = sname
        pkt.file = file_
        pkt.options = cls._parse_options(data[cls.HEADER_SIZE:])
        return pkt

    @staticmethod
    def _parse_options(data: bytes) -> Dict[int, bytes]:
        options: Dict[int, bytes] = {}
        i = 0
        while i < len(data):
            code = data[i]
            if code == 255:
                break
            if code == 0:
                i += 1
                continue
            if i + 1 >= len(data):
                break
            length = data[i + 1]
            value = data[i + 2:i + 2 + length]
            options[code] = value
            i += 2 + length
        return options

    def to_bytes(self) -> bytes:
        ciaddr = struct.unpack("!I", ip_to_bytes(self.ciaddr))[0]
        yiaddr = struct.unpack("!I", ip_to_bytes(self.yiaddr))[0]
        siaddr = struct.unpack("!I", ip_to_bytes(self.siaddr))[0]
        giaddr = struct.unpack("!I", ip_to_bytes(self.giaddr))[0]
        header = struct.pack(
            self.HEADER_FORMAT,
            self.op, self.htype, self.hlen, self.hops,
            self.xid, self.secs, self.flags,
            ciaddr, yiaddr, siaddr, giaddr,
            self.chaddr, self.sname, self.file,
            MAGIC_COOKIE,
        )
        options_bytes = self._encode_options()
        return header + options_bytes

    def _encode_options(self) -> bytes:
        result = b""
        for code, value in self.options.items():
            result += bytes([code, len(value)]) + value
        result += b"\xff"
        return result

    def get_message_type(self) -> Optional[int]:
        val = self.options.get(53)
        return val[0] if val else None

    def set_message_type(self, msg_type: int) -> None:
        self.options[53] = bytes([msg_type])

    def get_requested_ip(self) -> Optional[str]:
        val = self.options.get(50)
        return bytes_to_ip(val) if val and len(val) == 4 else None

    def get_hostname(self) -> str:
        val = self.options.get(12)
        try:
            return val.decode("utf-8", errors="replace") if val else ""
        except Exception:
            return ""

    def get_server_identifier(self) -> Optional[str]:
        val = self.options.get(54)
        return bytes_to_ip(val) if val and len(val) == 4 else None

    @property
    def mac_str(self) -> str:
        return mac_to_str(self.chaddr)


class Lease:
    """Represents a single DHCP lease."""

    def __init__(self, ip: str, mac: str, hostname: str, duration: int) -> None:
        self.ip: str = ip
        self.mac: str = mac
        self.hostname: str = hostname
        self.duration: int = duration
        self.expire_time: float = time.time() + duration
        self.assigned_time: float = time.time()

    def renew(self, duration: Optional[int] = None) -> None:
        if duration is not None:
            self.duration = duration
        self.expire_time = time.time() + self.duration

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expire_time

    @property
    def remaining_seconds(self) -> int:
        remaining = int(self.expire_time - time.time())
        return max(0, remaining)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "expire_time": self.expire_time,
            "remaining": self.remaining_seconds,
            "assigned_time": self.assigned_time,
        }


class DHCPServer:
    """
    Pure-Python DHCPv4 server.

    Usage:
        config = {
            "interface_ip": "192.168.100.1",
            "start_ip": "192.168.100.100",
            "end_ip": "192.168.100.200",
            "subnet_mask": "255.255.255.0",
            "gateway": "192.168.100.1",
            "dns": "8.8.8.8",
            "lease_time": 3600,
        }
        server = DHCPServer()
        server.start(config)
        ...
        server.stop()
        leases = server.get_leases()
    """

    def __init__(self) -> None:
        self._running: bool = False
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._lock: threading.Lock = threading.Lock()
        self._leases: Dict[str, Lease] = {}
        self._pending_offers: Dict[str, str] = {}
        self._config: Dict[str, Any] = {}
        self._ip_pool: List[str] = []
        self._allocated_ips: Dict[str, str] = {}
        self.last_error: str = ""

    def start(self, config: Dict[str, Any]) -> bool:
        """Start the DHCP server. Returns True on success, False otherwise.

        所有异常路径都会设置 last_error 并返回 False，确保调用方能拿到错误信息。
        """
        logger.info("DHCPServer.start() 被调用，配置=%s", config)
        if self._running:
            logger.info("服务已在运行，先停止旧实例")
            self.stop()

        self._config = config
        self.last_error = ""
        self._leases.clear()
        self._pending_offers.clear()
        self._allocated_ips.clear()

        # 构建 IP 地址池
        try:
            self._build_ip_pool()
            logger.info("IP 地址池构建完成：%d 个地址 (%s - %s)",
                        len(self._ip_pool),
                        config.get("start_ip"), config.get("end_ip"))
        except Exception as exc:
            self.last_error = f"IP 地址池构建失败：{exc}"
            logger.exception(self.last_error)
            return False

        # 创建并绑定 socket
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self._sock.settimeout(1.0)
            self._sock.bind(("0.0.0.0", DHCP_SERVER_PORT))
            logger.info("UDP socket 已绑定 0.0.0.0:%d", DHCP_SERVER_PORT)
        except PermissionError:
            self.last_error = "无法绑定 UDP 端口 67，请以管理员权限运行此程序。"
            logger.error(self.last_error)
            self._sock = None
            return False
        except OSError as exc:
            self.last_error = f"套接字错误：{exc}"
            logger.error(self.last_error)
            self._sock = None
            return False
        except Exception as exc:
            self.last_error = f"启动时发生未知错误：{exc}"
            logger.exception(self.last_error)
            self._sock = None
            return False

        # 启动服务线程
        try:
            self._running = True
            self._thread = threading.Thread(
                target=self._serve_loop, daemon=True, name="DHCPServerThread"
            )
            self._thread.start()
            logger.info("DHCP 服务线程已启动")
        except Exception as exc:
            self.last_error = f"无法启动服务线程：{exc}"
            logger.exception(self.last_error)
            self._running = False
            try:
                if self._sock:
                    self._sock.close()
            except Exception:
                pass
            self._sock = None
            return False

        logger.info(
            "DHCP server started on %s  pool: %s - %s",
            config.get("interface_ip"), config.get("start_ip"), config.get("end_ip"),
        )
        return True

    def stop(self) -> None:
        """Stop the DHCP server and release the socket."""
        logger.info("DHCPServer.stop() 被调用")
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._thread = None
        logger.info("DHCP server stopped.")

    def get_leases(self) -> List[Dict[str, Any]]:
        """Return a snapshot of all current (non-expired) leases."""
        with self._lock:
            return [lease.to_dict() for mac, lease in self._leases.items() if not lease.is_expired]

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def config(self) -> Dict[str, Any]:
        return dict(self._config)

    def _build_ip_pool(self) -> None:
        """Build the ordered list of IPs in the configured range."""
        self._ip_pool = []
        start_int = ip_to_int(self._config["start_ip"])
        end_int = ip_to_int(self._config["end_ip"])
        for i in range(start_int, end_int + 1):
            self._ip_pool.append(socket.inet_ntoa(struct.pack("!I", i)))

    def _allocate_ip(self, mac: str, requested_ip: Optional[str] = None) -> Optional[str]:
        existing = self._leases.get(mac)
        if existing and not existing.is_expired:
            return existing.ip
        if requested_ip and requested_ip in self._ip_pool:
            if requested_ip not in self._allocated_ips:
                return requested_ip
        for ip in self._ip_pool:
            if ip not in self._allocated_ips and ip not in self._pending_offers.values():
                return ip
        return None

    def _serve_loop(self) -> None:
        """Main receive loop; runs in dedicated thread."""
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                self._cleanup_expired()
                continue
            except OSError:
                break
            try:
                pkt = DHCPPacket.from_bytes(data)
            except Exception as exc:
                logger.debug("Failed to parse DHCP packet: %s", exc)
                continue
            if pkt.op != 1:
                continue
            msg_type = pkt.get_message_type()
            logger.debug(
                "Received %s from %s (%s)",
                MSG_TYPE_NAMES.get(msg_type, str(msg_type)), pkt.mac_str, addr,
            )
            try:
                if msg_type == DHCPDISCOVER:
                    self._handle_discover(pkt)
                elif msg_type == DHCPREQUEST:
                    self._handle_request(pkt)
                elif msg_type == DHCPRELEASE:
                    self._handle_release(pkt)
                elif msg_type == DHCPINFORM:
                    self._handle_inform(pkt)
            except Exception as exc:
                logger.exception("Error handling DHCP message: %s", exc)

    def _handle_discover(self, pkt: DHCPPacket) -> None:
        mac = pkt.mac_str
        requested_ip = pkt.get_requested_ip()
        with self._lock:
            offered_ip = self._allocate_ip(mac, requested_ip)
            if offered_ip is None:
                logger.warning("IP pool exhausted; ignoring DISCOVER from %s", mac)
                return
            self._pending_offers[mac] = offered_ip
        offer = self._build_reply(pkt, DHCPOFFER, offered_ip)
        self._send_reply(offer, pkt)
        logger.debug("OFFER %s -> %s", offered_ip, mac)

    def _handle_request(self, pkt: DHCPPacket) -> None:
        mac = pkt.mac_str
        requested_ip = pkt.get_requested_ip()
        server_id = pkt.get_server_identifier()
        my_ip = self._config["interface_ip"]
        if server_id and server_id != my_ip:
            return
        with self._lock:
            ip_to_ack: Optional[str] = None
            pending = self._pending_offers.get(mac)
            if pending:
                ip_to_ack = pending
            if ip_to_ack is None and requested_ip:
                if requested_ip in self._ip_pool:
                    current_holder = self._allocated_ips.get(requested_ip)
                    if current_holder is None or current_holder == mac:
                        ip_to_ack = requested_ip
            if ip_to_ack is None:
                existing = self._leases.get(mac)
                if existing and not existing.is_expired:
                    ip_to_ack = existing.ip
            if ip_to_ack is None:
                ip_to_ack = self._allocate_ip(mac, requested_ip)
            if ip_to_ack is None:
                nak = self._build_nak(pkt)
                self._send_reply(nak, pkt)
                return
            hostname = pkt.get_hostname()
            lease_time = int(self._config.get("lease_time", 3600))
            existing_lease = self._leases.get(mac)
            if existing_lease and existing_lease.ip == ip_to_ack:
                existing_lease.renew(lease_time)
                existing_lease.hostname = hostname or existing_lease.hostname
            else:
                old_lease = self._leases.get(mac)
                if old_lease:
                    self._allocated_ips.pop(old_lease.ip, None)
                lease = Lease(ip_to_ack, mac, hostname, lease_time)
                self._leases[mac] = lease
                self._allocated_ips[ip_to_ack] = mac
            self._pending_offers.pop(mac, None)
        ack = self._build_reply(pkt, DHCPACK, ip_to_ack)
        self._send_reply(ack, pkt)
        logger.info("ACK %s -> %s (%s)", ip_to_ack, mac, pkt.get_hostname())

    def _handle_release(self, pkt: DHCPPacket) -> None:
        mac = pkt.mac_str
        with self._lock:
            lease = self._leases.pop(mac, None)
            if lease:
                self._allocated_ips.pop(lease.ip, None)
                logger.info("RELEASE %s from %s", lease.ip, mac)

    def _handle_inform(self, pkt: DHCPPacket) -> None:
        ack = self._build_reply(pkt, DHCPACK, pkt.ciaddr, include_lease_time=False)
        self._send_reply(ack, pkt)

    def _build_reply(self, request: DHCPPacket, msg_type: int, offered_ip: str,
                      include_lease_time: bool = True) -> DHCPPacket:
        reply = DHCPPacket()
        reply.op = 2
        reply.htype = request.htype
        reply.hlen = request.hlen
        reply.hops = 0
        reply.xid = request.xid
        reply.secs = 0
        reply.flags = request.flags
        reply.ciaddr = "0.0.0.0"
        reply.yiaddr = offered_ip
        reply.siaddr = self._config["interface_ip"]
        reply.giaddr = request.giaddr
        reply.chaddr = request.chaddr
        reply.sname = b"\x00" * 64
        reply.file = b"\x00" * 128
        opts: Dict[int, bytes] = {}
        opts[53] = bytes([msg_type])
        opts[54] = ip_to_bytes(self._config["interface_ip"])
        if include_lease_time:
            lt = int(self._config.get("lease_time", 3600))
            opts[51] = struct.pack("!I", lt)
            opts[58] = struct.pack("!I", lt // 2)
            opts[59] = struct.pack("!I", lt * 7 // 8)
        opts[1] = ip_to_bytes(self._config["subnet_mask"])
        opts[3] = ip_to_bytes(self._config["gateway"])
        dns_str = self._config.get("dns", "8.8.8.8")
        opts[6] = ip_to_bytes(dns_str)
        reply.options = opts
        return reply

    def _build_nak(self, request: DHCPPacket) -> DHCPPacket:
        nak = DHCPPacket()
        nak.op = 2
        nak.htype = request.htype
        nak.hlen = request.hlen
        nak.hops = 0
        nak.xid = request.xid
        nak.secs = 0
        nak.flags = request.flags
        nak.ciaddr = "0.0.0.0"
        nak.yiaddr = "0.0.0.0"
        nak.siaddr = "0.0.0.0"
        nak.giaddr = request.giaddr
        nak.chaddr = request.chaddr
        nak.sname = b"\x00" * 64
        nak.file = b"\x00" * 128
        nak.options = {53: bytes([DHCPNAK]), 54: ip_to_bytes(self._config["interface_ip"])}
        return nak

    def _send_reply(self, reply: DHCPPacket, request: DHCPPacket) -> None:
        if not self._sock:
            return
        data = reply.to_bytes()
        dest_ip = request.ciaddr if request.ciaddr != "0.0.0.0" else BROADCAST_ADDR
        try:
            self._sock.sendto(data, (dest_ip, DHCP_CLIENT_PORT))
            logger.debug("Sent %d bytes to %s:%d", len(data), dest_ip, DHCP_CLIENT_PORT)
        except OSError as exc:
            logger.error("Failed to send DHCP reply: %s", exc)

    def _cleanup_expired(self) -> None:
        with self._lock:
            expired_macs = [mac for mac, lease in self._leases.items() if lease.is_expired]
            for mac in expired_macs:
                lease = self._leases.pop(mac)
                self._allocated_ips.pop(lease.ip, None)
                logger.debug("Expired lease %s (%s)", lease.ip, mac)


# ===========================================================================
#  ui_app.py — GUI Application
# ===========================================================================

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


def get_network_interfaces() -> List[Dict[str, str]]:
    """Enumerate local network interfaces that have an IPv4 address."""
    interfaces: List[Dict[str, str]] = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for iface_name, addr_list in addrs.items():
        stat = stats.get(iface_name)
        if stat and not stat.isup:
            continue
        for addr in addr_list:
            if addr.family == 2:  # AF_INET
                ip = addr.address
                if ip.startswith("127."):
                    continue
                label = f"{iface_name}  [{ip}]"
                interfaces.append({"name": iface_name, "ip": ip, "label": label})
                break
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


def _gradient_hex(c1: str, c2: str, ratio: float) -> str:
    """Interpolate between two hex colors. ratio 0->c1, 1->c2."""
    r1, g1, b1 = int(c1[1:3], 16), int(c1[3:5], 16), int(c1[5:7], 16)
    r2, g2, b2 = int(c2[1:3], 16), int(c2[3:5], 16), int(c2[5:7], 16)
    r = int(r1 + (r2 - r1) * ratio)
    g = int(g1 + (g2 - g1) * ratio)
    b = int(b1 + (b2 - b1) * ratio)
    return f"#{r:02x}{g:02x}{b:02x}"


class DHCPToolApp(ctk.CTk):
    """Main application window for the Windows DHCP Tool."""

    REFRESH_INTERVAL_MS = 1000

    def __init__(self) -> None:
        super().__init__()
        # 捕获所有未处理回调异常，确保 windowed 模式下也能弹窗提示
        self.report_callback_exception = self._on_tk_exception

        self.title("Windows DHCP 分配工具")
        self.geometry("980x620")
        self.minsize(900, 590)
        self.resizable(True, True)
        self.configure(fg_color=COLOR_BG)

        # 尝试设置窗口图标
        self._set_window_icon()

        self._server = DHCPServer()
        self._interfaces: List[Dict[str, str]] = []
        self._refresh_job: Optional[str] = None
        self._start_time: Optional[float] = None

        self._build_ui()
        self._center_window()
        self._load_interfaces()
        self._schedule_refresh()

        logger.info("GUI 初始化完成")

    # ------------------------------------------------------------------
    # 全局异常兜底：把 tkinter 回调异常以弹窗形式展示
    # ------------------------------------------------------------------
    def _on_tk_exception(self, exc, val, tb) -> None:
        tb_text = "".join(traceback.format_exception(exc, val, tb))
        logger.error("Tkinter 回调异常:\n%s", tb_text)
        try:
            messagebox.showerror("程序异常", f"发生未捕获的异常：\n{val}", parent=self)
        except Exception:
            pass

    def _set_window_icon(self) -> None:
        """尝试用一段简单的 ICO 数据设置窗口图标（失败则忽略）。"""
        try:
            self.iconbitmap(default="")
        except Exception:
            pass

    def _center_window(self) -> None:
        """将窗口居中显示到屏幕中央。"""
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        # 顶部栏：标题 + 网卡选择（合并为一层）
        self._build_topbar()

        # 内容区域：左配置 + 右客户端列表
        content_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=14, pady=(4, 4))
        content_frame.columnconfigure(0, weight=2)
        content_frame.columnconfigure(1, weight=3)
        content_frame.rowconfigure(0, weight=1)

        self._build_config_panel(content_frame)
        self._build_lease_panel(content_frame)

        # 底部状态栏
        self._build_status_bar()

    def _build_topbar(self) -> None:
        """合并顶栏：左侧标题 + 右侧网卡选择与刷新（单层 48px）。"""
        bar = ctk.CTkFrame(self, corner_radius=0, fg_color=COLOR_HEADER, height=48)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)

        ctk.CTkLabel(
            bar, text="DHCP Server",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#ffffff",
        ).pack(side="left", padx=16, pady=8)

        # 网卡选择（靠右）
        ctk.CTkLabel(bar, text="网卡", width=36, anchor="w",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#e0f7fa").pack(side="right", padx=(6, 10), pady=8)

        ctk.CTkButton(
            bar, text="刷新", width=56,
            fg_color="transparent", border_color="#e0f7fa", border_width=1,
            text_color="#ffffff", hover_color=COLOR_HEADER_2,
            command=self._load_interfaces,
        ).pack(side="right", padx=6, pady=8)

        self._iface_var = ctk.StringVar(value="")
        self._iface_combo = ctk.CTkComboBox(
            bar, variable=self._iface_var, width=420,
            state="readonly", command=self._on_interface_changed,
            fg_color=COLOR_CARD_INNER, border_color=COLOR_ACCENT, border_width=1,
            dropdown_fg_color=COLOR_CARD_INNER,
        )
        self._iface_combo.pack(side="right", padx=4, pady=8)

    def _build_config_panel(self, parent: ctk.CTkFrame) -> None:
        """左侧配置面板：6 字段 2×3 grid 平铺 + 启停按钮 + 状态文字。"""
        cfg_outer = ctk.CTkFrame(parent, corner_radius=12, fg_color=COLOR_CARD)
        cfg_outer.grid(row=0, column=0, sticky="nsew", padx=(0, 7), pady=4)

        # 标题
        ctk.CTkLabel(cfg_outer, text="DHCP 配置",
                     font=ctk.CTkFont(size=15, weight="bold"),
                     text_color=COLOR_TEXT).pack(anchor="w", padx=16, pady=(14, 4))

        # 配置字段 grid 容器
        grid_frame = ctk.CTkFrame(cfg_outer, fg_color="transparent")
        grid_frame.pack(fill="x", padx=16, pady=(2, 8))
        grid_frame.columnconfigure(0, weight=1)
        grid_frame.columnconfigure(1, weight=1)

        # 2 列 × 3 行平铺
        self._add_input_field(grid_frame, "起始 IP", "192.168.100.100", "_entry_start_ip", 0, 0)
        self._add_input_field(grid_frame, "结束 IP", "192.168.100.200", "_entry_end_ip", 0, 1)
        self._add_input_field(grid_frame, "子网掩码", "255.255.255.0", "_entry_mask", 1, 0)
        self._add_input_field(grid_frame, "网关", "", "_entry_gateway", 1, 1)
        self._add_input_field(grid_frame, "DNS 服务器", "8.8.8.8", "_entry_dns", 2, 0)
        self._add_input_field(grid_frame, "租约时间（秒）", "3600", "_entry_lease", 2, 1)

        # ---- 控制按钮区 ----
        ctrl_frame = ctk.CTkFrame(cfg_outer, fg_color="transparent")
        ctrl_frame.pack(fill="x", padx=16, pady=(4, 14))

        self._btn_start = ctk.CTkButton(
            ctrl_frame, text="▶  启动 DHCP", fg_color=COLOR_SUCCESS, hover_color="#1b5e20",
            width=150, height=40, corner_radius=10,
            font=ctk.CTkFont(size=14, weight="bold"), text_color="#ffffff",
            command=self._on_start,
        )
        self._btn_start.pack(side="left", padx=(0, 8))

        self._btn_stop = ctk.CTkButton(
            ctrl_frame, text="⏹  停止 DHCP", fg_color=COLOR_DANGER_DARK, hover_color=COLOR_DANGER,
            width=150, height=40, corner_radius=10,
            font=ctk.CTkFont(size=14, weight="bold"), text_color="#ffffff",
            state="disabled", command=self._on_stop,
        )
        self._btn_stop.pack(side="left", padx=(0, 14))

        # 状态文字（替代原 Canvas LED）
        self._status_label = ctk.CTkLabel(
            ctrl_frame, text="○ 已停止", text_color=COLOR_TEXT_DIM,
            font=ctk.CTkFont(size=13),
        )
        self._status_label.pack(side="left")

    def _add_input_field(self, parent: ctk.CTkFrame, label: str,
                         default: str, attr: str, row: int, col: int) -> ctk.CTkEntry:
        """添加一个配置字段（grid 版）：标签在上，输入框在下。"""
        cell = ctk.CTkFrame(parent, fg_color="transparent")
        cell.grid(row=row, column=col, sticky="ew", padx=6, pady=4)
        ctk.CTkLabel(cell, text=label, anchor="w",
                     font=ctk.CTkFont(size=12),
                     text_color=COLOR_TEXT_DIM).pack(anchor="w", padx=2, pady=(0, 2))
        entry = ctk.CTkEntry(
            cell,
            fg_color=COLOR_BG, border_color=COLOR_ACCENT_DARK, border_width=1,
            corner_radius=8, height=32,
        )
        entry.insert(0, default)
        entry.pack(fill="x")
        setattr(self, attr, entry)
        return entry

    def _build_lease_panel(self, parent: ctk.CTkFrame) -> None:
        """右侧客户端列表面板。"""
        lease_outer = ctk.CTkFrame(parent, corner_radius=12, fg_color=COLOR_CARD)
        lease_outer.grid(row=0, column=1, sticky="nsew", padx=(7, 0), pady=4)

        header = ctk.CTkFrame(lease_outer, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(14, 6))
        ctk.CTkLabel(header, text="已分配客户端",
                     font=ctk.CTkFont(size=15, weight="bold"),
                     text_color=COLOR_TEXT).pack(side="left")
        self._lease_count_label = ctk.CTkLabel(
            header, text="(0 台)", text_color=COLOR_ACCENT,
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        self._lease_count_label.pack(side="left", padx=10)

        tree_frame = ctk.CTkFrame(lease_outer, fg_color="transparent")
        tree_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "DHCPTable.Treeview", background=COLOR_ROW_EVEN, foreground=COLOR_TEXT,
            rowheight=28, fieldbackground=COLOR_ROW_EVEN, borderwidth=0,
            font=("Consolas", 10),
        )
        style.configure(
            "DHCPTable.Treeview.Heading", background=COLOR_TABLE_HEAD,
            foreground=COLOR_ACCENT, relief="flat",
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "DHCPTable.Treeview",
            background=[("selected", COLOR_ACCENT_DARK)],
            foreground=[("selected", "#ffffff")],
        )

        columns = ("mac", "ip", "hostname", "remaining")
        self._tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings",
            style="DHCPTable.Treeview", selectmode="browse",
        )
        self._tree.heading("mac", text="MAC 地址")
        self._tree.heading("ip", text="IP 地址")
        self._tree.heading("hostname", text="主机名")
        self._tree.heading("remaining", text="剩余租约")
        self._tree.column("mac", width=160, minwidth=130, anchor="center")
        self._tree.column("ip", width=140, minwidth=110, anchor="center")
        self._tree.column("hostname", width=160, minwidth=100, anchor="w")
        self._tree.column("remaining", width=110, minwidth=90, anchor="center")

        # 斑马纹 tag
        self._tree.tag_configure("evenrow", background=COLOR_ROW_EVEN)
        self._tree.tag_configure("oddrow", background=COLOR_ROW_ODD)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=scrollbar.set)
        self._tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # 空状态提示（覆盖在表格中央）
        self._empty_label = ctk.CTkLabel(
            tree_frame, text="暂无客户端连接，等待 DHCP 请求...",
            text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=13),
        )

    def _build_status_bar(self) -> None:
        """底部状态栏：监听地址 | 防火墙状态 | 运行时间。"""
        bar = ctk.CTkFrame(self, corner_radius=0, fg_color=COLOR_CARD_INNER, height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self._status_listen = ctk.CTkLabel(
            bar, text="监听: — (未运行)", text_color=COLOR_TEXT_DIM,
            font=ctk.CTkFont(size=11),
        )
        self._status_listen.pack(side="left", padx=16, pady=4)

        # 防火墙状态（常驻提示）
        self._status_firewall = ctk.CTkLabel(
            bar, text="防火墙: 未配置", text_color=COLOR_TEXT_DIM,
            font=ctk.CTkFont(size=11),
        )
        self._status_firewall.pack(side="left", padx=16, pady=4)

        self._status_uptime = ctk.CTkLabel(
            bar, text="运行时间: 00:00:00", text_color=COLOR_TEXT_DIM,
            font=ctk.CTkFont(size=11),
        )
        self._status_uptime.pack(side="right", padx=16, pady=4)

    def _set_firewall_status(self, state: str) -> None:
        """更新防火墙状态栏提示。state: pending/ok/fail。"""
        if state == "ok":
            self._status_firewall.configure(
                text="防火墙: 已放行 UDP 67/68", text_color=COLOR_SUCCESS,
            )
        elif state == "fail":
            self._status_firewall.configure(
                text="防火墙: 配置失败，请手动放行", text_color=COLOR_DANGER,
            )
        else:
            self._status_firewall.configure(
                text="防火墙: 未配置", text_color=COLOR_TEXT_DIM,
            )

    # ------------------------------------------------------------------
    # Interface management
    # ------------------------------------------------------------------

    def _load_interfaces(self) -> None:
        logger.info("加载网卡列表")
        self._interfaces = get_network_interfaces()
        labels = [i["label"] for i in self._interfaces]
        if not labels:
            labels = ["（未找到可用网卡）"]
            logger.warning("未找到可用网卡")
        self._iface_combo.configure(values=labels)
        if labels:
            self._iface_combo.set(labels[0])
            self._on_interface_changed(labels[0])

    def _on_interface_changed(self, label: str) -> None:
        iface = self._get_selected_interface()
        if iface:
            logger.info("选中网卡: %s", iface["label"])
            self._entry_gateway.delete(0, "end")
            self._entry_gateway.insert(0, iface["ip"])

    def _get_selected_interface(self) -> Optional[Dict[str, str]]:
        label = self._iface_var.get()
        for iface in self._interfaces:
            if iface["label"] == label:
                return iface
        return None

    # ------------------------------------------------------------------
    # 防火墙自动配置
    # ------------------------------------------------------------------

    @staticmethod
    def _ensure_firewall_rules() -> bool:
        """
        自动添加 Windows 防火墙入站规则，放行 DHCP 所需的 UDP 67/68 端口。
        使用 netsh advfirewall 命令，需要管理员权限（exe 已声明 UAC）。
        返回 True 表示规则已就绪或添加成功，False 表示失败。
        """
        RULE_NAME = "DHCPTool-DHCP-Server"
        try:
            # 先检查是否已有同名规则
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 f"name={RULE_NAME}"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            if RULE_NAME in result.stdout:
                logger.info("防火墙规则 '%s' 已存在，跳过创建", RULE_NAME)
                return True

            # 添加规则：允许 UDP 67/68 入站（DHCP 服务端需要监听 67，客户端回包到 68）
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={RULE_NAME}",
                "dir=in",
                "action=allow",
                "protocol=UDP",
                "localport=67-68",
                "profile=any",
                "description=Windows DHCP 分配工具 - 放行 DHCP 服务端口 (UDP 67/68)",
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            if result.returncode == 0:
                logger.info("防火墙规则 '%s' 添加成功: %s", RULE_NAME, result.stdout.strip())
                return True
            else:
                logger.error("防火墙规则添加失败 (rc=%d): %s", result.returncode, result.stderr.strip())
                return False
        except FileNotFoundError:
            logger.warning("netsh 未找到，跳过防火墙配置")
            return True  # netsh 不存在不算致命错误
        except subprocess.TimeoutExpired:
            logger.error("防火墙命令执行超时")
            return False
        except Exception as exc:
            logger.exception("防火墙自动配置异常: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Start / Stop handlers
    # ------------------------------------------------------------------

    def _on_start(self) -> None:
        """启动 DHCP 服务。整体用 try/except 兜底，任何异常都弹窗提示。"""
        try:
            logger.info("==== 用户点击 [启动 DHCP] ====")
            iface = self._get_selected_interface()
            if not iface:
                logger.warning("未选择有效网卡")
                messagebox.showerror("错误", "请选择一块有效的网卡。", parent=self)
                return

            start_ip = self._entry_start_ip.get().strip()
            end_ip = self._entry_end_ip.get().strip()
            mask = self._entry_mask.get().strip()
            gateway = self._entry_gateway.get().strip()
            dns = self._entry_dns.get().strip()
            lease_str = self._entry_lease.get().strip()
            logger.info("表单输入: start=%s end=%s mask=%s gw=%s dns=%s lease=%s",
                        start_ip, end_ip, mask, gateway, dns, lease_str)

            errors: List[str] = []
            for label_text, val in [("起始 IP", start_ip), ("结束 IP", end_ip),
                                    ("子网掩码", mask), ("网关", gateway), ("DNS", dns)]:
                if not validate_ip(val):
                    errors.append(f'{label_text} "{val}" 不是合法的 IPv4 地址。')
            try:
                lease_time = int(lease_str)
                if lease_time < 60:
                    errors.append("租约时间不能小于 60 秒。")
            except ValueError:
                errors.append(f'租约时间 "{lease_str}" 不是整数。')
                lease_time = 3600

            # 【修复关键点】原代码错误调用 ip_in_range(start_ip, end_ip)（少一个参数）
            # 会导致 TypeError 被静默吞掉，按钮完全没反应。这里改用正确的 ip_le 比较。
            if not errors:
                try:
                    if not ip_le(start_ip, end_ip):
                        errors.append("起始 IP 不能大于结束 IP。")
                except Exception as exc:
                    errors.append(f"起始/结束 IP 比较失败：{exc}")

            if errors:
                logger.warning("配置校验失败: %s", errors)
                messagebox.showerror("配置错误", "\n".join(errors), parent=self)
                return

            config = {
                "interface_ip": iface["ip"], "start_ip": start_ip, "end_ip": end_ip,
                "subnet_mask": mask, "gateway": gateway, "dns": dns, "lease_time": lease_time,
            }

            # 自动配置 Windows 防火墙，放行 UDP 67/68 端口
            logger.info("检查/添加防火墙规则 ...")
            fw_ok = self._ensure_firewall_rules()
            if fw_ok:
                self._set_firewall_status("ok")
            else:
                self._set_firewall_status("fail")
                logger.warning("防火墙规则配置失败，但继续尝试启动 DHCP 服务")
                messagebox.showwarning(
                    "防火墙提示",
                    "自动放行防火墙 UDP 67/68 端口失败。\n"
                    "DHCP 服务仍会尝试启动，但可能无法接收客户端请求。\n\n"
                    "请手动放行 UDP 67/68 端口，或检查防火墙设置。",
                    parent=self,
                )

            logger.info("调用 DHCPServer.start() ...")
            ok = self._server.start(config)
            if not ok:
                err = self._server.last_error or "无法启动 DHCP 服务，请检查端口占用和权限。"
                logger.error("启动失败: %s", err)
                messagebox.showerror("启动失败", err, parent=self)
                return

            self._start_time = time.time()
            self._set_running_state(True)
            logger.info("DHCP 服务已启动，UI 状态已更新")
        except Exception as exc:
            logger.exception("_on_start 发生异常: %s", exc)
            try:
                messagebox.showerror(
                    "启动异常", f"启动过程中发生错误：\n{exc}", parent=self
                )
            except Exception:
                pass

    def _on_stop(self) -> None:
        """停止 DHCP 服务。"""
        try:
            logger.info("==== 用户点击 [停止 DHCP] ====")
            self._server.stop()
            self._start_time = None
            self._set_running_state(False)
            logger.info("DHCP 服务已停止，UI 状态已更新")
        except Exception as exc:
            logger.exception("_on_stop 发生异常: %s", exc)
            try:
                messagebox.showerror("停止异常", f"停止过程中发生错误：\n{exc}", parent=self)
            except Exception:
                pass

    def _set_running_state(self, running: bool) -> None:
        """切换运行/停止状态的 UI 表现（字符圆点，无 Canvas/脉冲）。"""
        if running:
            self._btn_start.configure(state="disabled")
            self._btn_stop.configure(state="normal")
            self._status_label.configure(
                text="● 运行中", text_color=COLOR_SUCCESS,
                font=ctk.CTkFont(size=13, weight="bold"),
            )
        else:
            self._btn_start.configure(state="normal")
            self._btn_stop.configure(state="disabled")
            self._status_label.configure(
                text="○ 已停止", text_color=COLOR_TEXT_DIM,
                font=ctk.CTkFont(size=13),
            )

    # ------------------------------------------------------------------
    # Lease table refresh
    # ------------------------------------------------------------------

    def _schedule_refresh(self) -> None:
        self._refresh_leases()
        self._refresh_job = self.after(self.REFRESH_INTERVAL_MS, self._schedule_refresh)

    def _refresh_leases(self) -> None:
        try:
            leases = self._server.get_leases()
        except Exception as exc:
            logger.debug("获取租约失败: %s", exc)
            leases = []

        existing_iids = set(self._tree.get_children())
        seen_iids: set = set()
        for idx, lease in enumerate(leases):
            iid = lease["mac"].replace(":", "")
            remaining = self._format_remaining(lease["remaining"])
            values = (lease["mac"], lease["ip"], lease.get("hostname") or "—", remaining)
            tag = "evenrow" if idx % 2 == 0 else "oddrow"
            if iid in existing_iids:
                self._tree.item(iid, values=values, tags=(tag,))
            else:
                self._tree.insert("", "end", iid=iid, values=values, tags=(tag,))
            seen_iids.add(iid)
        for iid in existing_iids - seen_iids:
            self._tree.delete(iid)

        count = len(leases)
        self._lease_count_label.configure(text=f"({count} 台)")

        # 空状态提示
        if count == 0:
            self._empty_label.place(relx=0.5, rely=0.5, anchor="center")
            self._empty_label.lift()
        else:
            self._empty_label.place_forget()

        self._update_status_bar()

    @staticmethod
    def _format_remaining(seconds: int) -> str:
        h = seconds // 3600
        m = (seconds % 3600) // 60
        s = seconds % 60
        return f"{h}:{m:02d}:{s:02d}"

    # ------------------------------------------------------------------
    # 底部状态栏更新
    # ------------------------------------------------------------------

    def _update_status_bar(self) -> None:
        try:
            if self._server.is_running:
                cfg = self._server.config
                ip = cfg.get("interface_ip", "?")
                self._status_listen.configure(
                    text=f"监听: 0.0.0.0:67   绑定网卡: {ip}",
                    text_color=COLOR_SUCCESS,
                )
                if self._start_time:
                    uptime = int(time.time() - self._start_time)
                    h = uptime // 3600
                    m = (uptime % 3600) // 60
                    s = uptime % 60
                    self._status_uptime.configure(
                        text=f"运行时间: {h:02d}:{m:02d}:{s:02d}",
                        text_color=COLOR_SUCCESS,
                    )
            else:
                self._status_listen.configure(
                    text="监听: — (未运行)", text_color=COLOR_TEXT_DIM,
                )
                self._status_uptime.configure(
                    text="运行时间: 00:00:00", text_color=COLOR_TEXT_DIM,
                )
        except Exception as exc:
            logger.debug("状态栏更新失败: %s", exc)

    # ------------------------------------------------------------------
    # Helpers / Lifecycle
    # ------------------------------------------------------------------

    def on_closing(self) -> None:
        logger.info("窗口关闭中...")
        if self._refresh_job:
            self.after_cancel(self._refresh_job)
        if self._server.is_running:
            self._server.stop()
        self.destroy()


# ===========================================================================
#  Entry Point
# ===========================================================================

def main() -> None:
    """Create and run the main application window."""
    app = DHCPToolApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()


if __name__ == "__main__":
    main()
