#!/usr/bin/env python3
"""
BOOTP Server (Bootstrap Protocol - RFC 951 & RFC 1048)
Cross-platform implementation for Linux, macOS, and Windows.

Features:
- Fixed 300-byte binary packet structure compatible with Wireshark.
- Static MAC-to-IP mapping loaded from bootptab.json.
- Runs on high ports 6767 (server) / 6868 (client) by default (no root/sudo needed).
- Supports standard ports 67/68 via --standard-ports (requires sudo).
- Interactive Management CLI:
  * View current mappings
  * Add new mapping
  * Edit existing mapping
  * Remove a mapping
  * Remove all mappings
  * Reload or save to bootptab.json
- Distinguishes and logs [BROADCAST] vs [UNICAST] transmissions.
"""

import argparse
import ipaddress
import json
import os
import socket
import sys
import threading
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
        print(f"[-] Configuration file '{config_path}' not found! Creating default skeleton...")
        default_data = {
            "server_config": {
                "server_name": "bootp-primary-srv",
                "default_gateway": "192.168.1.1",
                "default_subnet_mask": "255.255.255.0",
                "default_dns": "8.8.8.8",
                "default_boot_file": "pxelinux.0",
            },
            "mappings": {},
        }
        save_config(config_path, default_data)
        return default_data

    with open(config_path, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[-] Error parsing JSON in '{config_path}': {e}")
            sys.exit(1)

    normalized_mappings = {}
    for mac, entry in data.get("mappings", {}).items():
        try:
            norm_mac = network_utils.normalize_mac(mac)
            normalized_mappings[norm_mac] = entry
        except ValueError:
            print(f"[!] Warning: Skipping invalid MAC format in config: '{mac}'")

    data["mappings"] = normalized_mappings
    return data


def save_config(config_path: str, data: dict):
    """Saves static mappings and server config back to JSON."""
    try:
        with open(config_path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[-] Failed to save config to '{config_path}': {e}")


def print_mappings_table(mappings: dict, server_name: str = "", port: int = 0, client_port: int = 0):
    """Displays the current BOOTP static address mappings."""
    print("=" * 82)
    if server_name:
        print(f"   BOOTP SERVER: '{server_name}' (Port {port} -> Client Port {client_port})")
        print("=" * 82)
    print(f"{'#':<3} | {'Client Hardware MAC':<19} | {'Assigned IP':<15} | {'Hostname':<18} | {'Boot File'}")
    print("-" * 82)
    if not mappings:
        print("    (No mappings configured. Use 'add' command in CLI to add mappings)")
    else:
        for idx, (mac, entry) in enumerate(mappings.items(), start=1):
            ip = entry.get("ip", "N/A")
            hostname = entry.get("hostname", "-")
            boot_file = entry.get("boot_file", "-")
            print(f"{idx:<3} | {mac:<19} | {ip:<15} | {hostname:<18} | {boot_file}")
    print("=" * 82)


def get_local_ip(interface: str = None) -> str:
    """Determines the server's own IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def is_valid_ip(ip_str: str) -> bool:
    try:
        ipaddress.IPv4Address(ip_str.strip())
        return True
    except Exception:
        return False


def server_packet_loop(sock: socket.socket, state: dict):
    """Background worker processing BOOTP requests and replies."""
    client_port = state["client_port"]
    broadcast_ip = state["broadcast_ip"]
    server_ip = state["server_ip"]
    srv_cfg = state["config"].get("server_config", {})
    server_name = srv_cfg.get("server_name", "bootp-srv")

    while state["running"]:
        try:
            data, client_addr = sock.recvfrom(4096)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if len(data) < 236:
                print(f"\n[{timestamp}] [!] Received undersized packet ({len(data)} bytes) from {client_addr}. Ignoring.")
                print("bootp-admin> ", end="", flush=True)
                continue

            try:
                request = BOOTPPacket.unpack(data)
            except Exception as e:
                print(f"\n[{timestamp}] [!] Failed to unpack packet from {client_addr}: {e}")
                print("bootp-admin> ", end="", flush=True)
                continue

            if request.op != BOOTREQUEST:
                print(f"\n[{timestamp}] [!] Non-BOOTREQUEST op={request.op} received from {client_addr}. Ignoring.")
                print("bootp-admin> ", end="", flush=True)
                continue

            req_mode = "BROADCAST" if request.is_broadcast or client_addr[0] in ("0.0.0.0", "255.255.255.255") else "UNICAST"
            print("\n" + "*" * 68)
            print(f"[{timestamp}] RECEIVED BOOTREQUEST from {client_addr[0]}:{client_addr[1]}")
            print(request.format_details(req_mode))

            client_mac = request.chaddr.lower()
            with state["lock"]:
                mappings = state["config"].get("mappings", {})
                client_conf = mappings.get(client_mac)

            if not client_conf:
                print(f"\n[!] REJECTED: MAC address '{client_mac}' is not in static bootptab table!")
                print(f"    No IP assigned. (Use CLI 'add' to register this client MAC)\n")
                print("*" * 68 + "\n")
                print("bootp-admin> ", end="", flush=True)
                continue

            allotted_ip = client_conf["ip"]
            subnet_mask = client_conf.get("subnet_mask", srv_cfg.get("default_subnet_mask", "255.255.255.0"))
            gateway = client_conf.get("gateway", srv_cfg.get("default_gateway", server_ip))
            dns = client_conf.get("dns", srv_cfg.get("default_dns", "8.8.8.8"))
            boot_file = client_conf.get("boot_file", srv_cfg.get("default_boot_file", "pxelinux.0"))
            hostname = client_conf.get("hostname", "")

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
            print("bootp-admin> ", end="", flush=True)

        except (socket.timeout, BlockingIOError):
            continue
        except OSError:
            if not state["running"]:
                break
        except Exception as e:
            if state["running"]:
                print(f"\n[-] Server packet processing error: {e}")
                print("bootp-admin> ", end="", flush=True)


def cli_loop(state: dict):
    """Operator interactive CLI loop."""
    config_file = state["config_file"]
    srv_cfg = state["config"].get("server_config", {})

    print("\n" + "=" * 68)
    print("      BOOTP Server Operator CLI is active.")
    print("      Type 'help' or '?' for available commands.")
    print("=" * 68 + "\n")

    while state["running"]:
        try:
            cmd_line = input("bootp-admin> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Exiting server...")
            state["running"] = False
            break

        if not cmd_line:
            continue

        parts = cmd_line.split()
        cmd = parts[0].lower()

        if cmd in ("help", "?"):
            print("""
Available Operator Commands:
  show, list, ls          Display current MAC-to-IP mappings table
  add                     Interactively add a new client MAC mapping
  edit <mac>              Edit an existing mapping by MAC address
  remove <mac>, rm <mac>  Remove a specific mapping
  remove-all, clear       Remove all mappings
  reload                  Reload mappings from bootptab.json file
  save                    Save current in-memory mappings to bootptab.json
  info                    Show server details and listening ports
  exit, quit              Stop the server and exit
""")

        elif cmd in ("show", "list", "ls"):
            with state["lock"]:
                mappings = dict(state["config"].get("mappings", {}))
            print_mappings_table(mappings)

        elif cmd == "add":
            print("\n--- Add New Client Mapping ---")
            raw_mac = input("Enter Client MAC Address (e.g. 00:11:22:33:44:55): ").strip()
            try:
                norm_mac = network_utils.normalize_mac(raw_mac)
            except ValueError as e:
                print(f"[-] {e}")
                continue

            with state["lock"]:
                if norm_mac in state["config"].get("mappings", {}):
                    print(f"[!] Warning: MAC '{norm_mac}' is already registered with IP '{state['config']['mappings'][norm_mac]['ip']}'.")
                    overwrite = input("Overwrite? [y/N]: ").strip().lower()
                    if overwrite not in ("y", "yes"):
                        print("[*] Aborted.")
                        continue

            ip = input("Enter Allocated IPv4 Address (e.g. 192.168.1.155): ").strip()
            if not is_valid_ip(ip):
                print(f"[-] Invalid IPv4 address format: '{ip}'")
                continue

            def_mask = srv_cfg.get("default_subnet_mask", "255.255.255.0")
            mask = input(f"Enter Subnet Mask [default {def_mask}]: ").strip() or def_mask

            def_gw = srv_cfg.get("default_gateway", state["server_ip"])
            gw = input(f"Enter Gateway IP [default {def_gw}]: ").strip() or def_gw

            def_dns = srv_cfg.get("default_dns", "8.8.8.8")
            dns = input(f"Enter DNS Server IP [default {def_dns}]: ").strip() or def_dns

            host = input(f"Enter Hostname (optional): ").strip() or f"host-{norm_mac.replace(':', '')[-4:]}"
            def_boot = srv_cfg.get("default_boot_file", "pxelinux.0")
            boot_file = input(f"Enter Boot File [default {def_boot}]: ").strip() or def_boot

            new_entry = {
                "ip": ip,
                "subnet_mask": mask,
                "gateway": gw,
                "dns": dns,
                "hostname": host,
                "boot_file": boot_file,
            }

            with state["lock"]:
                state["config"].setdefault("mappings", {})[norm_mac] = new_entry
                save_config(config_file, state["config"])

            print(f"[+] Successfully added mapping: {norm_mac} -> {ip} ({host}) and saved to {config_file}\n")

        elif cmd == "edit":
            if len(parts) < 2:
                print("Usage: edit <MAC_ADDRESS>")
                continue

            try:
                target_mac = network_utils.normalize_mac(parts[1])
            except ValueError as e:
                print(f"[-] {e}")
                continue

            with state["lock"]:
                mappings = state["config"].setdefault("mappings", {})
                if target_mac not in mappings:
                    print(f"[-] MAC address '{target_mac}' not found in mappings table.")
                    continue
                cur = dict(mappings[target_mac])

            print(f"\n--- Editing mapping for {target_mac} (Press Enter to keep current value) ---")
            new_ip = input(f"Allocated IP [{cur.get('ip')}]: ").strip() or cur.get("ip")
            if not is_valid_ip(new_ip):
                print("[-] Invalid IP address. Edit cancelled.")
                continue

            new_mask = input(f"Subnet Mask [{cur.get('subnet_mask')}]: ").strip() or cur.get("subnet_mask")
            new_gw = input(f"Gateway [{cur.get('gateway')}]: ").strip() or cur.get("gateway")
            new_dns = input(f"DNS Server [{cur.get('dns')}]: ").strip() or cur.get("dns")
            new_host = input(f"Hostname [{cur.get('hostname')}]: ").strip() or cur.get("hostname")
            new_boot = input(f"Boot File [{cur.get('boot_file')}]: ").strip() or cur.get("boot_file")

            updated_entry = {
                "ip": new_ip,
                "subnet_mask": new_mask,
                "gateway": new_gw,
                "dns": new_dns,
                "hostname": new_host,
                "boot_file": new_boot,
            }

            with state["lock"]:
                mappings[target_mac] = updated_entry
                save_config(config_file, state["config"])

            print(f"[+] Updated mapping for {target_mac} -> {new_ip} and saved to {config_file}\n")

        elif cmd in ("remove", "rm"):
            if len(parts) < 2:
                print("Usage: remove <MAC_ADDRESS>")
                continue

            try:
                target_mac = network_utils.normalize_mac(parts[1])
            except ValueError as e:
                print(f"[-] {e}")
                continue

            with state["lock"]:
                mappings = state["config"].setdefault("mappings", {})
                if target_mac in mappings:
                    removed = mappings.pop(target_mac)
                    save_config(config_file, state["config"])
                    print(f"[+] Removed mapping for MAC '{target_mac}' (was {removed.get('ip')}). Saved to {config_file}\n")
                else:
                    print(f"[-] MAC '{target_mac}' not found in mappings.")

        elif cmd in ("remove-all", "clear"):
            confirm = input("Are you sure you want to remove ALL mappings? [y/N]: ").strip().lower()
            if confirm in ("y", "yes"):
                with state["lock"]:
                    count = len(state["config"].get("mappings", {}))
                    state["config"]["mappings"] = {}
                    save_config(config_file, state["config"])
                print(f"[+] Removed all {count} mappings from table and {config_file}\n")
            else:
                print("[*] Operation cancelled.")

        elif cmd == "reload":
            new_cfg = load_config(config_file)
            with state["lock"]:
                state["config"] = new_cfg
            print(f"[+] Reloaded configuration from {config_file} ({len(new_cfg.get('mappings', {}))} mappings active).\n")

        elif cmd == "save":
            with state["lock"]:
                save_config(config_file, state["config"])
            print(f"[+] Saved active configuration to {config_file}\n")

        elif cmd == "info":
            print(f"Server Name: {srv_cfg.get('server_name', 'bootp-srv')}")
            print(f"Server IP:   {state['server_ip']}")
            print(f"Listening:   Port {state['port']} (Client reply port: {state['client_port']})")
            print(f"Config File: {config_file}")
            with state["lock"]:
                print(f"Mappings:    {len(state['config'].get('mappings', {}))} registered clients")
            print()

        elif cmd in ("exit", "quit"):
            print("[*] Stopping server...")
            state["running"] = False
            break

        else:
            print(f"[-] Unknown command '{cmd}'. Type 'help' for options.")


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
    sock.settimeout(0.5)

    try:
        sock.bind((bind_ip, port))
        print(f"[+] Server socket bound to {bind_ip}:{port} on {network_utils.get_os_type().upper()}")
        print(f"[+] Server IP: {server_ip} | Awaiting incoming BOOTREQUEST packets...")
    except PermissionError:
        print(f"\n[-] Permission denied: Cannot bind to privileged port {port}.")
        print(f"    * On Linux/macOS: Run with 'sudo python3 bootp_server.py --port {port}'")
        print(f"    * Or omit --standard-ports to run on default high ports (6767/6868)\n")
        sys.exit(1)
    except OSError as e:
        print(f"[-] Failed to bind socket: {e}")
        sys.exit(1)

    state = {
        "running": True,
        "config": config,
        "config_file": config_file,
        "port": port,
        "client_port": client_port,
        "broadcast_ip": broadcast_ip,
        "server_ip": server_ip,
        "lock": threading.Lock(),
    }

    # Start network packet handling in background daemon thread
    pkt_thread = threading.Thread(target=server_packet_loop, args=(sock, state), daemon=True)
    pkt_thread.start()

    # Run operator CLI on main thread
    try:
        cli_loop(state)
    except KeyboardInterrupt:
        print("\n[*] Server interrupted.")
    finally:
        state["running"] = False
        pkt_thread.join(timeout=1.0)
        sock.close()
        print("[*] Server shutdown complete.")


def main():
    parser = argparse.ArgumentParser(
        description="Cross-Platform BOOTP Server (RFC 951 & RFC 1048) with Interactive CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Default mode (High ports 6767/6868, no sudo required):
    python3 bootp_server.py

  Standard BOOTP mode (Ports 67/68, requires sudo / admin):
    sudo python3 bootp_server.py --standard-ports

  Custom port overrides:
    python3 bootp_server.py --port 9000 --client-port 9001
        """,
    )
    parser.add_argument("--config", default="bootptab.json", help="Path to JSON configuration file (default: bootptab.json)")
    parser.add_argument("--port", type=int, default=6767, help="Server listening UDP port (default: 6767; 67 when --standard-ports is used)")
    parser.add_argument("--client-port", type=int, default=6868, help="Client destination UDP port (default: 6868; 68 when --standard-ports is used)")
    parser.add_argument("--bind-ip", default="0.0.0.0", help="IP address to bind server socket (default: 0.0.0.0)")
    parser.add_argument("--broadcast-ip", default="255.255.255.255", help="Broadcast IP to use (default: 255.255.255.255)")
    parser.add_argument("--standard-ports", action="store_true", help="Use standard privileged BOOTP ports (server: 67, client: 68). Requires root/sudo.")
    parser.add_argument("--dev", action="store_true", help="Alias for running on high ports 6767/6868 (now the default)")

    args = parser.parse_args()

    # Apply standard-ports if requested and user didn't explicitly override port/client-port
    if args.standard_ports:
        if args.port == 6767:
            args.port = 67
        if args.client_port == 6868:
            args.client_port = 68

    run_server(
        config_file=args.config,
        port=args.port,
        client_port=args.client_port,
        bind_ip=args.bind_ip,
        broadcast_ip=args.broadcast_ip,
    )


if __name__ == "__main__":
    main()
