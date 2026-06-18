"""
dhcp_server.py - DHCPv4 server core implementation using raw sockets.

Implements the full DHCP Discover -> Offer -> Request -> Ack flow per RFC 2131.
Thread-safe lease table management with support for lease renewal.
"""

import socket
import struct
import threading
import time
import logging
from typing import Dict, Optional, Tuple, List, Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DHCP Constants (RFC 2131 / RFC 2132)
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def ip_to_bytes(ip: str) -> bytes:
    """Convert dotted-decimal IP string to 4 bytes."""
    return socket.inet_aton(ip)


def bytes_to_ip(data: bytes) -> str:
    """Convert 4 bytes to dotted-decimal IP string."""
    return socket.inet_ntoa(data)


def mac_to_str(data: bytes) -> str:
    """Convert 6-byte MAC address to colon-separated hex string."""
    return ":".join(f"{b:02x}" for b in data[:6])


def ip_in_range(ip: str, start: str, end: str) -> bool:
    """Return True if *ip* falls within [start, end] (inclusive)."""
    return (
        struct.unpack("!I", socket.inet_aton(ip))[0]
        >= struct.unpack("!I", socket.inet_aton(start))[0]
        and struct.unpack("!I", socket.inet_aton(ip))[0]
        <= struct.unpack("!I", socket.inet_aton(end))[0]
    )


def next_ip(ip: str) -> str:
    """Return the IP address that follows *ip*."""
    n = struct.unpack("!I", socket.inet_aton(ip))[0]
    return socket.inet_ntoa(struct.pack("!I", n + 1))


# ---------------------------------------------------------------------------
# DHCP packet parser / builder
# ---------------------------------------------------------------------------

class DHCPPacket:
    """Represents a DHCP packet (RFC 2131 format)."""

    HEADER_FORMAT = "!BBBBIHHIIII16s64s128s4s"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 236 bytes

    def __init__(self) -> None:
        self.op: int = 1           # 1=BOOTREQUEST, 2=BOOTREPLY
        self.htype: int = 1        # hardware type (Ethernet = 1)
        self.hlen: int = 6         # hardware address length
        self.hops: int = 0
        self.xid: int = 0          # transaction id
        self.secs: int = 0
        self.flags: int = 0x8000   # broadcast flag
        self.ciaddr: str = "0.0.0.0"   # client IP address
        self.yiaddr: str = "0.0.0.0"   # 'your' (client) IP address
        self.siaddr: str = "0.0.0.0"   # next server IP address
        self.giaddr: str = "0.0.0.0"   # relay agent IP address
        self.chaddr: bytes = b"\x00" * 16   # client hardware address
        self.sname: bytes = b"\x00" * 64    # server host name
        self.file: bytes = b"\x00" * 128    # boot file name
        self.options: Dict[int, bytes] = {}

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @classmethod
    def from_bytes(cls, data: bytes) -> "DHCPPacket":
        """Parse raw bytes into a DHCPPacket; returns None on failure."""
        if len(data) < cls.HEADER_SIZE + 4:
            raise ValueError("Packet too short")

        pkt = cls()
        (
            pkt.op, pkt.htype, pkt.hlen, pkt.hops,
            pkt.xid, pkt.secs, pkt.flags,
            ciaddr, yiaddr, siaddr, giaddr,
            chaddr, sname, file_, magic,
        ) = struct.unpack(cls.HEADER_FORMAT, data[:cls.HEADER_SIZE])

        if magic != MAGIC_COOKIE:
            raise ValueError("Invalid DHCP magic cookie")

        pkt.ciaddr = bytes_to_ip(struct.pack("!I", ciaddr))
        pkt.yiaddr = bytes_to_ip(struct.pack("!I", yiaddr))
        pkt.siaddr = bytes_to_ip(struct.pack("!I", siaddr))
        pkt.giaddr = bytes_to_ip(struct.pack("!I", giaddr))
        pkt.chaddr = chaddr
        pkt.sname = sname
        pkt.file = file_

        # Parse options (TLV after magic cookie)
        pkt.options = cls._parse_options(data[cls.HEADER_SIZE:])
        return pkt

    @staticmethod
    def _parse_options(data: bytes) -> Dict[int, bytes]:
        options: Dict[int, bytes] = {}
        i = 0
        while i < len(data):
            code = data[i]
            if code == 255:  # END
                break
            if code == 0:    # PAD
                i += 1
                continue
            if i + 1 >= len(data):
                break
            length = data[i + 1]
            value = data[i + 2: i + 2 + length]
            options[code] = value
            i += 2 + length
        return options

    # ------------------------------------------------------------------
    # Building
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Serialize the packet to raw bytes."""
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
        result += b"\xff"  # END option
        # Pad to minimum 300 bytes total
        return result

    # ------------------------------------------------------------------
    # Convenience getters / setters
    # ------------------------------------------------------------------

    def get_message_type(self) -> Optional[int]:
        """Return DHCP message type (option 53) or None."""
        val = self.options.get(53)
        return val[0] if val else None

    def set_message_type(self, msg_type: int) -> None:
        self.options[53] = bytes([msg_type])

    def get_requested_ip(self) -> Optional[str]:
        """Return requested IP address (option 50) or None."""
        val = self.options.get(50)
        return bytes_to_ip(val) if val and len(val) == 4 else None

    def get_hostname(self) -> str:
        """Return hostname (option 12) or empty string."""
        val = self.options.get(12)
        try:
            return val.decode("utf-8", errors="replace") if val else ""
        except Exception:
            return ""

    def get_server_identifier(self) -> Optional[str]:
        """Return server identifier (option 54) or None."""
        val = self.options.get(54)
        return bytes_to_ip(val) if val and len(val) == 4 else None

    @property
    def mac_str(self) -> str:
        return mac_to_str(self.chaddr)


# ---------------------------------------------------------------------------
# Lease record
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# DHCP Server
# ---------------------------------------------------------------------------

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

        # Lease table: MAC string -> Lease
        self._leases: Dict[str, Lease] = {}
        # Pending offers: MAC string -> offered IP (before ACK)
        self._pending_offers: Dict[str, str] = {}

        self._config: Dict[str, Any] = {}
        self._ip_pool: List[str] = []
        self._allocated_ips: Dict[str, str] = {}  # ip -> mac

        self.last_error: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, config: Dict[str, Any]) -> bool:
        """
        Start the DHCP server with the given configuration.

        Args:
            config: dict with keys: interface_ip, start_ip, end_ip,
                    subnet_mask, gateway, dns, lease_time.

        Returns:
            True if started successfully, False otherwise (check last_error).
        """
        if self._running:
            self.stop()

        self._config = config
        self.last_error = ""
        self._leases.clear()
        self._pending_offers.clear()
        self._allocated_ips.clear()
        self._build_ip_pool()

        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self._sock.settimeout(1.0)
            # Bind to the interface IP on port 67
            self._sock.bind(("0.0.0.0", DHCP_SERVER_PORT))
        except PermissionError:
            self.last_error = (
                "无法绑定 UDP 端口 67，请以管理员权限运行此程序。"
            )
            logger.error(self.last_error)
            return False
        except OSError as exc:
            self.last_error = f"套接字错误：{exc}"
            logger.error(self.last_error)
            return False

        self._running = True
        self._thread = threading.Thread(
            target=self._serve_loop, daemon=True, name="DHCPServerThread"
        )
        self._thread.start()
        logger.info(
            "DHCP server started on %s  pool: %s - %s",
            config.get("interface_ip"),
            config.get("start_ip"),
            config.get("end_ip"),
        )
        return True

    def stop(self) -> None:
        """Stop the DHCP server and release the socket."""
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
            result = []
            for mac, lease in self._leases.items():
                if not lease.is_expired:
                    result.append(lease.to_dict())
            return result

    @property
    def is_running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_ip_pool(self) -> None:
        """Build the ordered list of IPs in the configured range."""
        self._ip_pool = []
        ip = self._config["start_ip"]
        end = self._config["end_ip"]
        start_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        end_int = struct.unpack("!I", socket.inet_aton(end))[0]
        for i in range(start_int, end_int + 1):
            self._ip_pool.append(socket.inet_ntoa(struct.pack("!I", i)))

    def _allocate_ip(self, mac: str, requested_ip: Optional[str] = None) -> Optional[str]:
        """
        Allocate an IP for *mac*.  Prefer *requested_ip* if it is free
        and within the pool.  Returns None if the pool is exhausted.
        """
        # Check if mac already has a valid lease
        existing = self._leases.get(mac)
        if existing and not existing.is_expired:
            return existing.ip

        # Honor requested IP if available
        if requested_ip and requested_ip in self._ip_pool:
            if requested_ip not in self._allocated_ips:
                return requested_ip

        # Find next free IP
        for ip in self._ip_pool:
            if ip not in self._allocated_ips:
                # Double-check no pending offer claimed it
                if ip not in self._pending_offers.values():
                    return ip
        return None

    # ------------------------------------------------------------------
    # Serve loop
    # ------------------------------------------------------------------

    def _serve_loop(self) -> None:
        """Main receive loop; runs in dedicated thread."""
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                # Clean up expired leases periodically
                self._cleanup_expired()
                continue
            except OSError:
                break

            try:
                pkt = DHCPPacket.from_bytes(data)
            except Exception as exc:
                logger.debug("Failed to parse DHCP packet: %s", exc)
                continue

            if pkt.op != 1:  # Only handle BOOTREQUEST
                continue

            msg_type = pkt.get_message_type()
            logger.debug(
                "Received %s from %s (%s)",
                MSG_TYPE_NAMES.get(msg_type, str(msg_type)),
                pkt.mac_str,
                addr,
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

    # ------------------------------------------------------------------
    # DHCP message handlers
    # ------------------------------------------------------------------

    def _handle_discover(self, pkt: DHCPPacket) -> None:
        """Respond to DHCPDISCOVER with DHCPOFFER."""
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
        """Respond to DHCPREQUEST with DHCPACK or DHCPNAK."""
        mac = pkt.mac_str
        requested_ip = pkt.get_requested_ip()
        server_id = pkt.get_server_identifier()
        my_ip = self._config["interface_ip"]

        # If there's a server identifier and it's not us, ignore
        if server_id and server_id != my_ip:
            return

        with self._lock:
            # Determine which IP we should ACK
            ip_to_ack: Optional[str] = None

            # 1. Use IP from pending offer
            pending = self._pending_offers.get(mac)
            if pending:
                ip_to_ack = pending

            # 2. Use requested IP if it's in our pool and not taken
            if ip_to_ack is None and requested_ip:
                if requested_ip in self._ip_pool:
                    current_holder = self._allocated_ips.get(requested_ip)
                    if current_holder is None or current_holder == mac:
                        ip_to_ack = requested_ip

            # 3. Renew existing lease
            if ip_to_ack is None:
                existing = self._leases.get(mac)
                if existing and not existing.is_expired:
                    ip_to_ack = existing.ip

            # 4. Try to allocate fresh
            if ip_to_ack is None:
                ip_to_ack = self._allocate_ip(mac, requested_ip)

            if ip_to_ack is None:
                # NAK — no IP available
                nak = self._build_nak(pkt)
                self._send_reply(nak, pkt)
                return

            # Commit the lease
            hostname = pkt.get_hostname()
            lease_time = int(self._config.get("lease_time", 3600))
            existing_lease = self._leases.get(mac)
            if existing_lease and existing_lease.ip == ip_to_ack:
                existing_lease.renew(lease_time)
                existing_lease.hostname = hostname or existing_lease.hostname
            else:
                # Release any old IP held by this MAC
                old_lease = self._leases.get(mac)
                if old_lease:
                    self._allocated_ips.pop(old_lease.ip, None)

                lease = Lease(ip_to_ack, mac, hostname, lease_time)
                self._leases[mac] = lease
                self._allocated_ips[ip_to_ack] = mac

            # Clear pending offer
            self._pending_offers.pop(mac, None)

        ack = self._build_reply(pkt, DHCPACK, ip_to_ack)
        self._send_reply(ack, pkt)
        logger.info("ACK %s -> %s (%s)", ip_to_ack, mac, pkt.get_hostname())

    def _handle_release(self, pkt: DHCPPacket) -> None:
        """Handle DHCPRELEASE — remove lease."""
        mac = pkt.mac_str
        with self._lock:
            lease = self._leases.pop(mac, None)
            if lease:
                self._allocated_ips.pop(lease.ip, None)
                logger.info("RELEASE %s from %s", lease.ip, mac)

    def _handle_inform(self, pkt: DHCPPacket) -> None:
        """Handle DHCPINFORM — send ACK with config but no lease."""
        ack = self._build_reply(pkt, DHCPACK, pkt.ciaddr, include_lease_time=False)
        self._send_reply(ack, pkt)

    # ------------------------------------------------------------------
    # Packet builders
    # ------------------------------------------------------------------

    def _build_reply(
        self,
        request: DHCPPacket,
        msg_type: int,
        offered_ip: str,
        include_lease_time: bool = True,
    ) -> DHCPPacket:
        """Build an OFFER or ACK reply packet."""
        reply = DHCPPacket()
        reply.op = 2  # BOOTREPLY
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
        opts[54] = ip_to_bytes(self._config["interface_ip"])  # server identifier
        if include_lease_time:
            lease_time = int(self._config.get("lease_time", 3600))
            opts[51] = struct.pack("!I", lease_time)           # lease time
            opts[58] = struct.pack("!I", lease_time // 2)      # renewal time
            opts[59] = struct.pack("!I", lease_time * 7 // 8)  # rebind time
        opts[1] = ip_to_bytes(self._config["subnet_mask"])     # subnet mask
        opts[3] = ip_to_bytes(self._config["gateway"])         # router
        dns_str = self._config.get("dns", "8.8.8.8")
        opts[6] = ip_to_bytes(dns_str)                         # DNS server

        reply.options = opts
        return reply

    def _build_nak(self, request: DHCPPacket) -> DHCPPacket:
        """Build a DHCPNAK packet."""
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
        nak.options = {
            53: bytes([DHCPNAK]),
            54: ip_to_bytes(self._config["interface_ip"]),
        }
        return nak

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    def _send_reply(self, reply: DHCPPacket, request: DHCPPacket) -> None:
        """Send *reply* to the appropriate destination."""
        if not self._sock:
            return

        data = reply.to_bytes()

        # Unicast if client knows its IP; otherwise broadcast
        if request.ciaddr != "0.0.0.0":
            dest_ip = request.ciaddr
        else:
            dest_ip = BROADCAST_ADDR

        try:
            self._sock.sendto(data, (dest_ip, DHCP_CLIENT_PORT))
            logger.debug(
                "Sent %s bytes to %s:%d",
                len(data), dest_ip, DHCP_CLIENT_PORT,
            )
        except OSError as exc:
            logger.error("Failed to send DHCP reply: %s", exc)

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def _cleanup_expired(self) -> None:
        """Remove expired leases from the tables (called from serve loop)."""
        with self._lock:
            expired_macs = [
                mac for mac, lease in self._leases.items() if lease.is_expired
            ]
            for mac in expired_macs:
                lease = self._leases.pop(mac)
                self._allocated_ips.pop(lease.ip, None)
                logger.debug("Expired lease %s (%s)", lease.ip, mac)
