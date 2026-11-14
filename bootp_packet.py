"""
BOOTP Packet Encoder / Decoder (RFC 951 & RFC 1048 / RFC 2132)
Strict 300-byte fixed-size binary packet format:
- 236-byte base header (RFC 951)
- 64-byte vendor extensions area (RFC 1048 magic cookie + TLV options)
"""

import struct
import socket
import random

# Fixed binary format string:
# op (1B), htype (1B), hlen (1B), hops (1B),
# xid (4B uint32), secs (2B uint16), flags (2B uint16),
# ciaddr (4B), yiaddr (4B), siaddr (4B), giaddr (4B),
# chaddr (16B), sname (64B), file (128B), vend (64B)
BOOTP_FORMAT = "!BBBBIHH4s4s4s4s16s64s128s64s"
BOOTP_PACKET_SIZE = 300  # 236 + 64

# RFC 1048 Magic Cookie (0x63825363)
MAGIC_COOKIE = b"\x63\x82\x53\x63"

# Operation codes
BOOTREQUEST = 1
BOOTREPLY = 2

# Hardware types
HTYPE_ETHERNET = 1
HLEN_ETHERNET = 6

# Flags
FLAG_BROADCAST = 0x8000
FLAG_UNICAST = 0x0000

# RFC 1048 / 2132 Option Codes
OPT_PAD = 0
OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_HOSTNAME = 12
OPT_END = 255


def mac_to_bytes(mac_str: str) -> bytes:
    """Convert 'AA:BB:CC:DD:EE:FF' or 'aa-bb-cc-dd-ee-ff' to 6 bytes."""
    clean_mac = mac_str.replace(":", "").replace("-", "")
    if len(clean_mac) != 12:
        raise ValueError(f"Invalid MAC address string: {mac_str}")
    return bytes.fromhex(clean_mac)


def bytes_to_mac(b: bytes) -> str:
    """Convert 6 bytes into 'aa:bb:cc:dd:ee:ff'."""
    return ":".join(f"{x:02x}" for x in b[:6])


def pack_vendor_options(options: dict) -> bytes:
    """
    Encode vendor options into a 64-byte field starting with RFC 1048 Magic Cookie.
    Supported options:
    - subnet_mask (str)
    - router / gateway (str)
    - dns (str or list of str)
    - hostname (str)
    """
    buf = bytearray(MAGIC_COOKIE)

    # Option 1: Subnet Mask (4 bytes)
    if "subnet_mask" in options and options["subnet_mask"]:
        buf.extend(bytes([OPT_SUBNET_MASK, 4]))
        buf.extend(socket.inet_aton(options["subnet_mask"]))

    # Option 3: Router / Default Gateway (4 bytes)
    router_val = options.get("router") or options.get("gateway")
    if router_val:
        buf.extend(bytes([OPT_ROUTER, 4]))
        buf.extend(socket.inet_aton(router_val))

    # Option 6: DNS Server (4 bytes per server)
    if "dns" in options and options["dns"]:
        dns_list = options["dns"] if isinstance(options["dns"], list) else [options["dns"]]
        dns_bytes = b"".join(socket.inet_aton(d) for d in dns_list)
        buf.extend(bytes([OPT_DNS, len(dns_bytes)]))
        buf.extend(dns_bytes)

    # Option 12: Host Name
    if "hostname" in options and options["hostname"]:
        h_bytes = options["hostname"].encode("ascii", errors="ignore")[:32]
        buf.extend(bytes([OPT_HOSTNAME, len(h_bytes)]))
        buf.extend(h_bytes)

    # Option 255: End marker
    buf.append(OPT_END)

    # Pad with zeros to exactly 64 bytes
    if len(buf) < 64:
        buf.extend(b"\x00" * (64 - len(buf)))
    return bytes(buf[:64])


def unpack_vendor_options(buf: bytes) -> dict:
    """
    Parse the 64-byte vendor field.
    Returns a dict with parsed options.
    """
    options = {}
    if len(buf) < 4:
        return options

    if buf[:4] != MAGIC_COOKIE:
        options["raw_vendor"] = buf.hex()
        return options

    options["has_magic_cookie"] = True
    i = 4
    while i < len(buf):
        opt = buf[i]
        if opt == OPT_PAD:
            i += 1
            continue
        if opt == OPT_END:
            break
        if i + 1 >= len(buf):
            break
        length = buf[i + 1]
        val = buf[i + 2 : i + 2 + length]

        if opt == OPT_SUBNET_MASK and length == 4:
            options["subnet_mask"] = socket.inet_ntoa(val)
        elif opt == OPT_ROUTER and length >= 4:
            options["router"] = socket.inet_ntoa(val[:4])
            options["gateway"] = options["router"]
        elif opt == OPT_DNS and length >= 4:
            dns_servers = [
                socket.inet_ntoa(val[k : k + 4]) for k in range(0, length, 4) if k + 4 <= length
            ]
            options["dns"] = dns_servers[0] if len(dns_servers) == 1 else dns_servers
        elif opt == OPT_HOSTNAME:
            options["hostname"] = val.decode("ascii", errors="ignore")
        else:
            options[f"option_{opt}"] = val.hex()

        i += 2 + length

    return options


class BOOTPPacket:
    """
    Represents an RFC 951 / RFC 1048 BOOTP packet.
    """

    def __init__(
        self,
        op: int = BOOTREQUEST,
        htype: int = HTYPE_ETHERNET,
        hlen: int = HLEN_ETHERNET,
        hops: int = 0,
        xid: int = None,
        secs: int = 0,
        flags: int = FLAG_BROADCAST,
        ciaddr: str = "0.0.0.0",
        yiaddr: str = "0.0.0.0",
        siaddr: str = "0.0.0.0",
        giaddr: str = "0.0.0.0",
        chaddr: str = "00:00:00:00:00:00",
        sname: str = "",
        file: str = "",
        options: dict = None,
    ):
        self.op = op
        self.htype = htype
        self.hlen = hlen
        self.hops = hops
        self.xid = random.randint(1, 0xFFFFFFFF) if xid is None else xid
        self.secs = secs
        self.flags = flags
        self.ciaddr = ciaddr
        self.yiaddr = yiaddr
        self.siaddr = siaddr
        self.giaddr = giaddr
        self.chaddr = chaddr
        self.sname = sname
        self.file = file
        self.options = options or {}

    @property
    def is_broadcast(self) -> bool:
        """Returns True if the broadcast flag is set."""
        return bool(self.flags & FLAG_BROADCAST)

    @property
    def op_name(self) -> str:
        if self.op == BOOTREQUEST:
            return "BOOTREQUEST (1)"
        elif self.op == BOOTREPLY:
            return "BOOTREPLY (2)"
        return f"UNKNOWN ({self.op})"

    def pack(self) -> bytes:
        """Serializes the BOOTP packet into 300 bytes."""
        ci_b = socket.inet_aton(self.ciaddr)
        yi_b = socket.inet_aton(self.yiaddr)
        si_b = socket.inet_aton(self.siaddr)
        gi_b = socket.inet_aton(self.giaddr)

        # chaddr: 16 bytes (6-byte MAC followed by 10 null bytes)
        mac_raw = mac_to_bytes(self.chaddr)
        chaddr_b = mac_raw.ljust(16, b"\x00")

        # sname: 64 bytes null-padded
        sname_b = self.sname.encode("ascii", errors="ignore")[:63].ljust(64, b"\x00")

        # file: 128 bytes null-padded
        file_b = self.file.encode("ascii", errors="ignore")[:127].ljust(128, b"\x00")

        # vend: 64 bytes
        vend_b = pack_vendor_options(self.options)

        packet = struct.pack(
            BOOTP_FORMAT,
            self.op,
            self.htype,
            self.hlen,
            self.hops,
            self.xid,
            self.secs,
            self.flags,
            ci_b,
            yi_b,
            si_b,
            gi_b,
            chaddr_b,
            sname_b,
            file_b,
            vend_b,
        )
        assert len(packet) == BOOTP_PACKET_SIZE, f"Packet size is {len(packet)}, expected {BOOTP_PACKET_SIZE}"
        return packet

    @classmethod
    def unpack(cls, data: bytes) -> "BOOTPPacket":
        """Deserializes bytes into a BOOTPPacket object."""
        if len(data) < BOOTP_PACKET_SIZE:
            # Pad if packet is at least 236 bytes but shorter than 300
            if len(data) >= 236:
                data = data.ljust(BOOTP_PACKET_SIZE, b"\x00")
            else:
                raise ValueError(f"Packet too short for BOOTP: {len(data)} bytes (minimum 236 required)")

        unpacked = struct.unpack(BOOTP_FORMAT, data[:BOOTP_PACKET_SIZE])
        (
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ci_b,
            yi_b,
            si_b,
            gi_b,
            chaddr_b,
            sname_b,
            file_b,
            vend_b,
        ) = unpacked

        ciaddr = socket.inet_ntoa(ci_b)
        yiaddr = socket.inet_ntoa(yi_b)
        siaddr = socket.inet_ntoa(si_b)
        giaddr = socket.inet_ntoa(gi_b)

        chaddr = bytes_to_mac(chaddr_b[:hlen])
        sname = sname_b.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        file = file_b.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        options = unpack_vendor_options(vend_b)

        return cls(
            op=op,
            htype=htype,
            hlen=hlen,
            hops=hops,
            xid=xid,
            secs=secs,
            flags=flags,
            ciaddr=ciaddr,
            yiaddr=yiaddr,
            siaddr=siaddr,
            giaddr=giaddr,
            chaddr=chaddr,
            sname=sname,
            file=file,
            options=options,
        )

    def format_details(self, transmission_mode: str = "BROADCAST") -> str:
        """Produces a clean terminal breakdown of the packet."""
        tag = f"[{transmission_mode.upper()}]"
        lines = [
            f"+----------------------------------------------------------------+",
            f"| BOOTP Message: {self.op_name:<28} {tag:>17} |",
            f"+----------------------------------------------------------------+",
            f"| Hardware Type (htype): {self.htype:<5} | HW Addr Len (hlen): {self.hlen:<14} |",
            f"| Hops:                  {self.hops:<5} | Secs Elapsed:       {self.secs:<14} |",
            f"| Transaction ID (xid):  0x{self.xid:08x} ({self.xid})",
            f"| Flags:                 0x{self.flags:04x} ({'BROADCAST' if self.is_broadcast else 'UNICAST'})",
            f"| Client MAC (chaddr):   {self.chaddr}",
            f"| Client IP  (ciaddr):   {self.ciaddr}",
            f"| Your IP    (yiaddr):   {self.yiaddr}",
            f"| Server IP  (siaddr):   {self.siaddr}",
            f"| Gateway IP (giaddr):   {self.giaddr}",
            f"| Server Hostname:       {self.sname or '(none)'}",
            f"| Boot File:             {self.file or '(none)'}",
            f"+----------------------------------------------------------------+",
            f"| Vendor Extensions (RFC 1048 Options):                          |",
        ]
        if self.options:
            for k, v in self.options.items():
                if k not in ("has_magic_cookie", "raw_vendor"):
                    lines.append(f"|   * {k:<18}: {str(v)}")
        else:
            lines.append(f"|   (none)")
        lines.append(f"+----------------------------------------------------------------+")
        return "\n".join(lines)
