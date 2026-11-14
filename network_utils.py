"""
Cross-Platform Network Utilities for BOOTP
Supports Linux, macOS (Darwin), and Windows.
Handles:
- MAC address auto-detection
- Active interface and broadcast IP resolution
- Network interface IP assignment (for pingability) and cleanup
- Cross-platform ICMP ping execution
"""

import sys
import os
import platform
import subprocess
import socket
import uuid
import re
import ipaddress


def get_os_type() -> str:
    """Returns 'linux', 'darwin' (macOS), or 'windows'."""
    sys_name = platform.system().lower()
    if "linux" in sys_name:
        return "linux"
    elif "darwin" in sys_name or "mac" in sys_name:
        return "darwin"
    elif "windows" in sys_name or sys_name.startswith("win"):
        return "windows"
    return sys_name


def normalize_mac(mac_str: str) -> str:
    """Normalizes MAC to lowercase colon-separated format: aa:bb:cc:dd:ee:ff."""
    clean = re.sub(r"[^0-9a-fA-F]", "", mac_str).lower()
    if len(clean) != 12:
        raise ValueError(f"Invalid MAC address: '{mac_str}' (expected 12 hex digits)")
    return ":".join(clean[i : i + 2] for i in range(0, 12, 2))


def get_default_interface() -> str | None:
    """
    Detects the primary active network interface cross-platform.
    Returns interface name or None.
    """
    os_type = get_os_type()

    if os_type == "linux":
        try:
            with open("/proc/net/route", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[1] == "00000000":
                        return parts[0]
        except Exception:
            pass

    elif os_type == "darwin":
        try:
            res = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True)
            for line in res.stdout.splitlines():
                if "interface:" in line:
                    return line.split(":")[1].strip()
        except Exception:
            pass

    elif os_type == "windows":
        try:
            res = subprocess.run(["netsh", "interface", "ipv4", "show", "interfaces"], capture_output=True, text=True)
            for line in res.stdout.splitlines():
                if "connected" in line.lower():
                    parts = line.strip().split()
                    return parts[-1]
        except Exception:
            pass

    return None


def get_mac_address(interface: str = None) -> str:
    """
    Auto-detects MAC address of the host machine across Linux, macOS, and Windows.
    If interface is specified, attempts to read MAC of that specific interface.
    """
    os_type = get_os_type()

    if os_type == "linux":
        if not interface:
            interface = get_default_interface()
        if interface:
            path = f"/sys/class/net/{interface}/address"
            if os.path.isfile(path):
                try:
                    with open(path, "r") as f:
                        mac = f.read().strip()
                        if mac and mac != "00:00:00:00:00:00":
                            return normalize_mac(mac)
                except Exception:
                    pass

    elif os_type == "darwin":
        if not interface:
            interface = get_default_interface() or "en0"
        try:
            res = subprocess.run(["ifconfig", interface], capture_output=True, text=True)
            for line in res.stdout.splitlines():
                if "ether" in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        return normalize_mac(parts[1])
        except Exception:
            pass

    # Universal fallback using uuid.getnode() (works on Linux, macOS, and Windows)
    node = uuid.getnode()
    mac = ":".join(f"{(node >> shift) & 0xFF:02x}" for shift in range(40, -1, -8))
    return normalize_mac(mac)


def get_broadcast_address(interface: str = None) -> str:
    """
    Returns the network broadcast IP address.
    Defaults to 255.255.255.255.
    """
    return "255.255.255.255"


def is_root() -> bool:
    """Checks if the script is running with administrative / root privileges."""
    os_type = get_os_type()
    if os_type == "windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def apply_interface_ip(ip: str, subnet_mask: str = "255.255.255.0", interface: str = None) -> bool:
    """
    Assigns the allotted IP address to the local network interface so that
    the operating system can respond to ARP and ICMP ping requests from other devices.

    Supported platforms:
    - Linux: `ip addr add <ip>/<prefix> dev <interface>`
    - macOS: `ifconfig <interface> alias <ip> netmask <subnet_mask>`
    - Windows: `netsh interface ipv4 add address "<interface>" <ip> <subnet_mask>`
    """
    os_type = get_os_type()
    if not interface:
        interface = get_default_interface()

    try:
        net = ipaddress.IPv4Network(f"{ip}/{subnet_mask}", strict=False)
        prefix = net.prefixlen
    except Exception:
        prefix = 24

    print(f"\n[*] Applying allotted IP {ip}/{prefix} to interface '{interface or 'default'}' for pingability...")

    if not is_root():
        print(f"[!] Warning: Elevated privileges required to configure network interface IP.")
        print(f"[!] Manual commands to apply this IP on your OS:")
        if os_type == "linux":
            print(f"      sudo ip addr add {ip}/{prefix} dev {interface or 'eth0'}")
        elif os_type == "darwin":
            print(f"      sudo ifconfig {interface or 'en0'} alias {ip} netmask {subnet_mask}")
        elif os_type == "windows":
            print(f"      netsh interface ipv4 add address \"{interface or 'Ethernet'}\" {ip} {subnet_mask}")
        return False

    try:
        if os_type == "linux":
            if not interface:
                print("[-] Could not determine interface to apply IP on Linux.")
                return False
            cmd = ["ip", "addr", "add", f"{ip}/{prefix}", "dev", interface]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0 or "File exists" in res.stderr:
                print(f"[+] Successfully configured IP {ip}/{prefix} on {interface}.")
                return True
            else:
                print(f"[-] Failed to set IP on Linux: {res.stderr.strip()}")
                return False

        elif os_type == "darwin":
            iface = interface or "en0"
            cmd = ["ifconfig", iface, "alias", ip, "netmask", subnet_mask]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                print(f"[+] Successfully configured IP alias {ip} on {iface}.")
                return True
            else:
                print(f"[-] Failed to set IP on macOS: {res.stderr.strip()}")
                return False

        elif os_type == "windows":
            iface = interface or "Wi-Fi"
            cmd = ["netsh", "interface", "ipv4", "add", "address", iface, ip, subnet_mask]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                print(f"[+] Successfully configured IP {ip} on interface '{iface}'.")
                return True
            else:
                print(f"[-] Failed to set IP on Windows: {res.stderr.strip()}")
                return False

    except Exception as e:
        print(f"[-] Exception while applying IP: {e}")
        return False

    return False


def remove_interface_ip(ip: str, subnet_mask: str = "255.255.255.0", interface: str = None) -> bool:
    """
    Removes the IP alias when client shuts down, keeping the interface clean.
    """
    os_type = get_os_type()
    if not interface:
        interface = get_default_interface()

    try:
        net = ipaddress.IPv4Network(f"{ip}/{subnet_mask}", strict=False)
        prefix = net.prefixlen
    except Exception:
        prefix = 24

    if not is_root():
        return False

    try:
        if os_type == "linux":
            if interface:
                cmd = ["ip", "addr", "del", f"{ip}/{prefix}", "dev", interface]
                subprocess.run(cmd, capture_output=True, text=True)
                return True
        elif os_type == "darwin":
            iface = interface or "en0"
            cmd = ["ifconfig", iface, "-alias", ip]
            subprocess.run(cmd, capture_output=True, text=True)
            return True
        elif os_type == "windows":
            iface = interface or "Wi-Fi"
            cmd = ["netsh", "interface", "ipv4", "delete", "address", iface, ip]
            subprocess.run(cmd, capture_output=True, text=True)
            return True
    except Exception:
        pass
    return False


def ping_target(target_ip: str, count: int = 3, timeout_sec: int = 2) -> bool:
    """
    Cross-platform ICMP ping execution.
    Prints real-time ping output and returns True if host responded.
    """
    os_type = get_os_type()
    print(f"\n[*] Pinging target host {target_ip} ({count} packets)...")

    if os_type == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout_sec * 1000)), target_ip]
    elif os_type == "darwin":
        cmd = ["ping", "-c", str(count), "-W", str(int(timeout_sec * 1000)), target_ip]
    else:  # Linux
        cmd = ["ping", "-c", str(count), "-W", str(timeout_sec), target_ip]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        print(res.stdout)
        if res.returncode == 0:
            print(f"[+] PING SUCCESSFUL: Host {target_ip} is reachable!")
            return True
        else:
            print(f"[-] PING FAILED: Host {target_ip} did not respond.")
            if res.stderr:
                print(res.stderr)
            return False
    except Exception as e:
        print(f"[-] Error executing ping: {e}")
        return False
