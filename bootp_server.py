#!/usr/bin/env python3
"""
BOOTP Server (Bootstrap Protocol - RFC 951 & RFC 1048)
Cross-platform implementation for Linux, macOS, and Windows.

Features:
- Fixed 300-byte binary packet structure compatible with Wireshark.
- Static MAC-to-IP mapping loaded from bootptab.json.
- Supports standard UDP port 67 (with sudo) or unprivileged high ports (e.g. 6767 via --dev).
- Distinguishes and logs [BROADCAST] vs [UNICAST] transmissions.
- Displays active static address mapping table.
"""

import argparse
import json
import os
import socket
import sys
import time
from datetime import datetime

from bootp_packet import (
    BOOTPPacket,
    BOOTREQUEST,
    BOOTREPLY,
    FLAG_BROADCAST,
    BOOTP_PACKET_SIZE,
)
import network_utils


def load_config(config_path: str) -> dict:
    """Loads static mappings and server config from JSON."""
    if not os.path.exists(config_path):
        print(f"[-] Configuration file '{config_path}' not found!")
        sys.exit(1)

    with open(config_path, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[-] Error parsing JSON in '{config_path}': {e}")
            sys.exit(1)

    # Normalize all MAC keys to lowercase colon-separated
    normalized_mappings = {}
    for mac, entry in data.get("mappings", {}).items():
        try:
            norm_mac = network_utils.normalize_mac(mac)
            normalized_mappings[norm_mac] = entry
        except ValueError:
            print(f"[!] Warning: Skipping invalid MAC format in config: '{mac}'")

    data["mappings"] = normalized_mappings
    return data


def print_mappings_table(mappings: dict, server_name: str, port: int, client_port: int):
    """Displays the current BOOTP static address mappings."""
    print("=" * 80)
    print(f"   BOOTP SERVER: '{server_name}' (Listening on UDP Port {port} -> Client Port {client_port})")
    print("=" * 80)
    print(f"{'Client Hardware MAC':<20} | {'Assigned IP':<16} | {'Hostname':<18} | {'Boot File'}")
    print("-" * 80)
    for mac, entry in mappings.items():
        ip = entry.get("ip", "N/A")
        hostname = entry.get("hostname", "-")
        boot_file = entry.get("boot_file", "-")
        print(f"{mac:<20} | {ip:<16} | {hostname:<18} | {boot_file}")
    print("=" * 80)
    print()


def get_local_ip(interface: str = None) -> str:
    """Determines the server's own IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually send data
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def run_server(
    config_file: str,
    port: int,
    client_port: int,
    bind_ip: str = "0.0.0.0",
    broadcast_ip: str = "255.255.255.255",
):
    config = load_config(config_file)
    mappings = config.get("mappings", {})
    srv_cfg = config.get("server_config", {})
    server_name = srv_cfg.get("server_name", "bootp-srv")
    server_ip = get_local_ip()

    print_mappings_table(mappings, server_name, port, client_port)

    # Initialize UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    try:
        sock.bind((bind_ip, port))
        print(f"[+] Server socket bound to {bind_ip}:{port} on {network_utils.get_os_type().upper()}")
        print(f"[+] Server IP: {server_ip} | Awaiting incoming BOOTREQUEST packets...\n")
    except PermissionError:
        print(f"\n[-] Permission denied: Cannot bind to privileged port {port}.")
        print(f"    * On Linux/macOS: Run with 'sudo python3 bootp_server.py --port {port}'")
        print(f"    * Or run in unprivileged dev mode: 'python3 bootp_server.py --dev'\n")
        sys.exit(1)
    except OSError as e:
        print(f"[-] Failed to bind socket: {e}")
        sys.exit(1)

    while True:
        try:
            data, client_addr = sock.recvfrom(4096)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if len(data) < 236:
                print(f"[{timestamp}] [!] Received undersized packet ({len(data)} bytes) from {client_addr}. Ignoring.")
                continue

            try:
                request = BOOTPPacket.unpack(data)
            except Exception as e:
                print(f"[{timestamp}] [!] Failed to unpack packet from {client_addr}: {e}")
                continue

            if request.op != BOOTREQUEST:
                print(f"[{timestamp}] [!] Non-BOOTREQUEST op={request.op} received from {client_addr}. Ignoring.")
                continue

            # Determine transmission mode of request
            req_mode = "BROADCAST" if request.is_broadcast or client_addr[0] in ("0.0.0.0", "255.255.255.255") else "UNICAST"
            print("*" * 68)
            print(f"[{timestamp}] RECEIVED BOOTREQUEST from {client_addr[0]}:{client_addr[1]}")
            print(request.format_details(req_mode))

            client_mac = request.chaddr.lower()
            if client_mac not in mappings:
                print(f"\n[!] REJECTED: MAC address '{client_mac}' is not in static bootptab table!")
                print(f"    No IP assigned. (Static BOOTP policy requires pre-configured MAC)\n")
                print("*" * 68 + "\n")
                continue

            # Mapping found
            client_conf = mappings[client_mac]
            allotted_ip = client_conf["ip"]
            subnet_mask = client_conf.get("subnet_mask", srv_cfg.get("default_subnet_mask", "255.255.255.0"))
            gateway = client_conf.get("gateway", srv_cfg.get("default_gateway", server_ip))
            dns = client_conf.get("dns", srv_cfg.get("default_dns", "8.8.8.8"))
            boot_file = client_conf.get("boot_file", srv_cfg.get("default_boot_file", "pxelinux.0"))
            hostname = client_conf.get("hostname", "")

            # Construct BOOTREPLY
            reply_options = {
                "subnet_mask": subnet_mask,
                "router": gateway,
                "dns": dns,
                "hostname": hostname,
            }

            reply = BOOTPPacket(
                op=BOOTREPLY,
                htype=request.htype,
                hlen=request.hlen,
                hops=0,
                xid=request.xid,
                secs=0,
                flags=request.flags,
                ciaddr=request.ciaddr,
                yiaddr=allotted_ip,
                siaddr=server_ip,
                giaddr=request.giaddr,
                chaddr=client_mac,
                sname=server_name,
                file=boot_file,
                options=reply_options,
            )

            reply_bytes = reply.pack()

            # Determine reply destination (RFC 951 / RFC 1542 logic)
            # If client set the broadcast flag (0x8000), reply via broadcast.
            # If client set flags to 0x0000 (unicast), reply via unicast directly to client.
            if request.is_broadcast:
                reply_mode = "BROADCAST"
                target_dest_ip = "127.0.0.1" if client_addr[0] == "127.0.0.1" else broadcast_ip
                dest_addr = (target_dest_ip, client_port)
            else:
                reply_mode = "UNICAST"
                target_dest_ip = "127.0.0.1" if client_addr[0] == "127.0.0.1" else (request.ciaddr if request.ciaddr != "0.0.0.0" else allotted_ip)
                dest_addr = (target_dest_ip, client_port)

            sock.sendto(reply_bytes, dest_addr)

            print(f"\n[{timestamp}] TRANSMITTING BOOTREPLY to {dest_addr[0]}:{dest_addr[1]}")
            print(reply.format_details(reply_mode))
            print(f"[+] Allotted IP {allotted_ip} to client {client_mac} ({hostname})")
            print("*" * 68 + "\n")

        except KeyboardInterrupt:
            print("\n[*] BOOTP Server stopped by user.")
            break
        except Exception as e:
            print(f"[-] Server loop error: {e}")

    sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="Cross-Platform BOOTP Server (RFC 951 & RFC 1048)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Standard mode (Requires sudo / admin privileges):
    sudo python3 bootp_server.py
    sudo python3 bootp_server.py --port 67 --client-port 68

  Development / Testing mode without sudo:
    python3 bootp_server.py --dev
    python3 bootp_server.py --port 6767 --client-port 6868
        """,
    )
    parser.add_argument("--config", default="bootptab.json", help="Path to JSON configuration file (default: bootptab.json)")
    parser.add_argument("--port", type=int, default=67, help="Server listening UDP port (default: 67)")
    parser.add_argument("--client-port", type=int, default=68, help="Client destination UDP port (default: 68)")
    parser.add_argument("--bind-ip", default="0.0.0.0", help="IP address to bind server socket (default: 0.0.0.0)")
    parser.add_argument("--broadcast-ip", default="255.255.255.255", help="Broadcast IP to use (default: 255.255.255.255)")
    parser.add_argument("--dev", action="store_true", help="Quick flag: use unprivileged ports (server: 6767, client: 6868)")

    args = parser.parse_args()

    if args.dev:
        args.port = 6767
        args.client_port = 6868

    run_server(
        config_file=args.config,
        port=args.port,
        client_port=args.client_port,
        bind_ip=args.bind_ip,
        broadcast_ip=args.broadcast_ip,
    )


if __name__ == "__main__":
    main()
