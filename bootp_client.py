#!/usr/bin/env python3
"""
BOOTP Client (Bootstrap Protocol - RFC 951 & RFC 1048)
Cross-platform implementation for Linux, macOS, and Windows.

Features:
- Auto-detects local host MAC address or accepts mock MAC via --mac.
- Fixed 300-byte binary packet structure compatible with Wireshark.
- Supports standard UDP port 68 (with sudo) or unprivileged high ports (e.g. 6868 via --dev).
- Distinguishes and logs [BROADCAST] vs [UNICAST] transmissions.
- Applies allotted IP to network interface cross-platform for ping testing (--apply-ip).
- Built-in ping verification (--ping <target_ip>).
"""

import argparse
import os
import signal
import socket
import sys
import time
from datetime import datetime

from bootp_packet import (
    BOOTPPacket,
    BOOTREQUEST,
    BOOTREPLY,
    FLAG_BROADCAST,
    FLAG_UNICAST,
)
import network_utils


# Global tracking for clean exit
_allotted_ip = None
_subnet_mask = None
_target_interface = None
_ip_applied = False


def cleanup_on_exit(signum=None, frame=None):
    global _allotted_ip, _subnet_mask, _target_interface, _ip_applied
    if _ip_applied and _allotted_ip:
        print(f"\n[*] Cleaning up allotted IP {_allotted_ip} from interface '{_target_interface or 'default'}'...")
        network_utils.remove_interface_ip(_allotted_ip, _subnet_mask, _target_interface)
        _ip_applied = False
    print("[*] BOOTP Client terminated.")
    sys.exit(0)


signal.signal(signal.SIGINT, cleanup_on_exit)
signal.signal(signal.SIGTERM, cleanup_on_exit)


def run_client(
    mac_address: str,
    port: int,
    server_port: int,
    server_ip: str,
    interface: str = None,
    apply_ip: bool = False,
    ping_ip: str = None,
    timeout: float = 4.0,
    max_retries: int = 3,
    use_broadcast_flag: bool = True,
):
    global _allotted_ip, _subnet_mask, _target_interface, _ip_applied

    _target_interface = interface or network_utils.get_default_interface()
    norm_mac = network_utils.normalize_mac(mac_address)
    os_name = network_utils.get_os_type().upper()

    print("=" * 68)
    print(f"   BOOTP CLIENT on {os_name}")
    print("=" * 68)
    print(f"Hardware MAC Address:    {norm_mac}")
    print(f"Network Interface:       {_target_interface or 'default'}")
    print(f"Listening Client Port:   UDP {port}")
    print(f"Target Server Address:   {server_ip}:{server_port}")
    print(f"Flag Mode:               {'BROADCAST (0x8000)' if use_broadcast_flag else 'UNICAST (0x0000)'}")
    print("=" * 68 + "\n")

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    try:
        # Bind to client port on all interfaces
        sock.bind(("0.0.0.0", port))
    except PermissionError:
        print(f"[-] Permission denied: Cannot bind to privileged port {port}.")
        print(f"    * On Linux/macOS: Run with 'sudo python3 bootp_client.py'")
        print(f"    * Or run in unprivileged dev mode: 'python3 bootp_client.py --dev'\n")
        sys.exit(1)
    except OSError as e:
        print(f"[-] Failed to bind socket to port {port}: {e}")
        sys.exit(1)

    sock.settimeout(timeout)

    flags = FLAG_BROADCAST if use_broadcast_flag else FLAG_UNICAST
    reply_received = False
    allotted_ip = None
    allotted_mask = "255.255.255.0"
    gateway = None

    for attempt in range(1, max_retries + 1):
        # Generate new packet for each attempt sequence
        req_packet = BOOTPPacket(
            op=BOOTREQUEST,
            flags=flags,
            ciaddr="0.0.0.0",
            yiaddr="0.0.0.0",
            siaddr="0.0.0.0",
            giaddr="0.0.0.0",
            chaddr=norm_mac,
            secs=(attempt - 1) * int(timeout),
        )

        req_bytes = req_packet.pack()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"[{timestamp}] Attempt {attempt}/{max_retries}: Sending BOOTREQUEST to {server_ip}:{server_port}...")
        print(req_packet.format_details("BROADCAST" if use_broadcast_flag else "UNICAST"))

        try:
            sock.sendto(req_bytes, (server_ip, server_port))
        except OSError as e:
            print(f"[-] Send error: {e}")
            break

        # Await reply
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                data, srv_addr = sock.recvfrom(4096)
                if len(data) < 236:
                    continue

                reply = BOOTPPacket.unpack(data)

                # Verify that reply matches this client
                if reply.op != BOOTREPLY:
                    continue
                if reply.xid != req_packet.xid:
                    # Packet belongs to another transaction/client
                    continue
                if reply.chaddr.lower() != norm_mac.lower():
                    continue

                # Valid BOOTREPLY matched!
                reply_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                rep_mode = "BROADCAST" if reply.is_broadcast else "UNICAST"
                print("\n" + "=" * 68)
                print(f"[{reply_ts}] RECEIVED BOOTREPLY FROM SERVER {srv_addr[0]}:{srv_addr[1]}")
                print(reply.format_details(rep_mode))
                print("=" * 68)

                allotted_ip = reply.yiaddr
                allotted_mask = reply.options.get("subnet_mask", "255.255.255.0")
                gateway = reply.options.get("gateway") or reply.options.get("router")
                reply_received = True
                break

            except socket.timeout:
                break
            except Exception as e:
                print(f"[!] Error receiving packet: {e}")
                break

        if reply_received:
            break
        else:
            print(f"[!] Timeout waiting for reply (attempt {attempt}). Retrying...")

    sock.close()

    if not reply_received:
        print("\n[-] BOOTP address acquisition failed: No response from server.")
        sys.exit(1)

    print(f"\n[+] SUCCESS: IP Address {allotted_ip} successfully leased from BOOTP Server!")

    # Check if user wants to apply IP for ping connectivity
    _allotted_ip = allotted_ip
    _subnet_mask = allotted_mask

    if apply_ip:
        success = network_utils.apply_interface_ip(allotted_ip, allotted_mask, _target_interface)
        if success:
            _ip_applied = True
            print(f"[+] Device is now active on {allotted_ip}. Other devices can ping this IP.")

    # Execute ping test if requested
    if ping_ip:
        network_utils.ping_target(ping_ip)
    elif gateway and gateway != "0.0.0.0" and server_ip != "127.0.0.1":
        # Prompt or offer pinging gateway
        print(f"\n[*] Tip: You can test connectivity by pinging the gateway ({gateway}) or another client.")

    if _ip_applied:
        print(f"\n[i] Client will keep running to maintain the assigned IP address.")
        print(f"    Press Ctrl+C at any time to clean up and exit.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            cleanup_on_exit()


def main():
    parser = argparse.ArgumentParser(
        description="Cross-Platform BOOTP Client (RFC 951 & RFC 1048)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Standard mode (with real MAC address):
    sudo python3 bootp_client.py

  Specify custom/mock MAC:
    python3 bootp_client.py --dev --mac aa:bb:cc:dd:ee:01

  Apply IP to interface for pinging and ping target:
    sudo python3 bootp_client.py --apply-ip --ping 192.168.1.151

  Development loopback mode without sudo:
    python3 bootp_client.py --dev
        """,
    )
    parser.add_argument("--mac", default=None, help="Hardware MAC address (default: auto-detected host MAC)")
    parser.add_argument("--interface", default=None, help="Network interface name (e.g. eth0, wlo1, en0)")
    parser.add_argument("--port", type=int, default=68, help="Client listening UDP port (default: 68)")
    parser.add_argument("--server-port", type=int, default=67, help="Server destination UDP port (default: 67)")
    parser.add_argument("--server-ip", default="255.255.255.255", help="Target server / broadcast IP (default: 255.255.255.255)")
    parser.add_argument("--dev", action="store_true", help="Quick flag: use unprivileged ports on localhost (client: 6868, server: 6767, server-ip: 127.0.0.1)")
    parser.add_argument("--unicast", action="store_true", help="Request unicast reply (sets flags=0x0000 instead of broadcast 0x8000)")
    parser.add_argument("--apply-ip", action="store_true", help="Apply allotted IP to interface using OS command (enables ICMP ping from other devices)")
    parser.add_argument("--ping", dest="ping_ip", default=None, help="Target IP address to ping after receiving lease")
    parser.add_argument("--timeout", type=float, default=3.0, help="Socket timeout in seconds (default: 3.0)")
    parser.add_argument("--retries", type=int, default=3, help="Max retry attempts (default: 3)")

    args = parser.parse_args()

    # Resolve MAC address
    if not args.mac:
        args.mac = network_utils.get_mac_address(args.interface)
        print(f"[*] Auto-detected host MAC: {args.mac}")
    else:
        print(f"[*] Using user-supplied MAC: {args.mac}")

    if args.dev:
        args.port = 6868
        args.server_port = 6767
        if args.server_ip == "255.255.255.255":
            args.server_ip = "127.0.0.1"

    run_client(
        mac_address=args.mac,
        port=args.port,
        server_port=args.server_port,
        server_ip=args.server_ip,
        interface=args.interface,
        apply_ip=args.apply_ip,
        ping_ip=args.ping_ip,
        timeout=args.timeout,
        max_retries=args.retries,
        use_broadcast_flag=not args.unicast,
    )


if __name__ == "__main__":
    main()
