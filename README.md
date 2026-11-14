# BOOTP (Bootstrap Protocol) Implementation

A standards-compliant, cross-platform implementation of **BOOTP (Bootstrap Protocol)** following **RFC 951** and **RFC 1048 / RFC 2132**, built in Python using UDP socket programming.

Compatible across **Linux**, **macOS**, and **Windows**.

---

## 1. Key Features & RFC Compliance

* **RFC 951 300-Byte Packet Structure:** Full binary memory layout using Python `struct`:
  * Base Header: `op`, `htype`, `hlen`, `hops`, `xid`, `secs`, `flags`, `ciaddr`, `yiaddr`, `siaddr`, `giaddr`, `chaddr` (16 bytes), `sname` (64 bytes), `file` (128 bytes).
  * Vendor Specific Area (64 bytes): Starts with RFC 1048 Magic Cookie `0x63825363`, followed by standard TLV options (Subnet Mask, Router/Default Gateway, DNS, Hostname, and End marker `0xFF`).
  * **Wireshark Compatible:** Traced and dissected directly in Wireshark as standard BOOTP.
* **Cross-Platform Support:** Works seamlessly on Linux, macOS (Darwin), and Windows.
* **Dual Port Modes:**
  * **Default Mode (High Ports):** Runs on unprivileged UDP ports **6767** (Server) and **6868** (Client) by default without requiring `sudo` / Administrator permissions.
  * **Standard BOOTP Mode (`--standard-ports`):** Uses RFC standard UDP ports **67** (Server) and **68** (Client) with `sudo` / Administrator.
* **Interactive Server Operator CLI:** Manage the server live while it runs:
  * View current table of mappings (`show` / `list`)
  * Add a new MAC-to-IP mapping (`add`)
  * Edit an existing mapping (`edit <mac>`)
  * Remove a mapping (`remove <mac>`)
  * Clear all mappings (`remove-all`)
  * Save / reload configuration (`save`, `reload`)
  * Real-time packet inspection (displays incoming `BOOTREQUEST` and outgoing `BOOTREPLY` packets as they occur).
* **Automatic & Mock Hardware Addressing:** Client auto-detects active network interface MAC or accepts arbitrary mock MAC addresses via `--mac`.
* **Broadcast vs Unicast Distinction:** Clear terminal markers showing `[BROADCAST]` vs `[UNICAST]` transmissions.
* **Inter-Device Ping Connectivity:** Includes `--apply-ip` to assign the allotted IP alias to the network interface, enabling connected devices to ping each other. Supports `--ping <target_ip>` for instant ICMP verification.

---

## 2. Project File Structure

| File | Description |
| :--- | :--- |
| `bootp_packet.py` | RFC 951 & RFC 1048 packet encoder/decoder and binary serialization. |
| `network_utils.py` | Cross-platform utilities for MAC detection, IP assignment, and ping execution. |
| `bootp_server.py` | BOOTP server with interactive CLI and background request handler. |
| `bootp_client.py` | BOOTP client broadcasting requests and acquiring IP leases. |
| `bootptab.json` | Configuration file containing static MAC-to-IP and network mappings. |

---

## 3. Quick Start (Single Machine / Demo)

By default, both server and client use high ports (**6767/6868**), so **no `sudo` or root permissions are required**:

### Step 1: Start the Server
```bash
python3 bootp_server.py
```
*The server will display its banner, current mappings, and drop into the interactive `bootp-admin>` CLI while listening in the background.*

### Step 2: Run a Client (In another terminal)
```bash
# Auto-detects local network MAC (or uses loopback):
python3 bootp_client.py --dev

# Or specify a pre-configured mock MAC:
python3 bootp_client.py --dev --mac aa:bb:cc:dd:ee:01
```

### Step 3: Run Additional Clients with Inter-Client Ping
```bash
# Client 2 (allots 127.0.0.52 and tests pinging Client 1 at 127.0.0.51):
python3 bootp_client.py --dev --mac aa:bb:cc:dd:ee:02 --ping 127.0.0.51
```

---

## 4. Server Operator CLI Commands

While `bootp_server.py` is running, the operator can interact with the server console at the `bootp-admin>` prompt:

| Command | Description |
| :--- | :--- |
| `show` / `list` | Display table of all registered client MAC-to-IP mappings. |
| `add` | Interactively register a new MAC address, IP, mask, gateway, DNS, and hostname. |
| `edit <mac>` | Edit parameters for an existing MAC address. |
| `remove <mac>` | Delete a specific client mapping from the table. |
| `remove-all` | Clear all client mappings from the table. |
| `reload` | Reload mappings from `bootptab.json`. |
| `save` | Save the in-memory mappings back to `bootptab.json`. |
| `info` | View server status, IP, port bindings, and mapping count. |
| `help` | List available commands. |
| `exit` / `quit` | Gracefully shut down the server. |

> Incoming `BOOTREQUEST` and outgoing `BOOTREPLY` packets continue to stream on screen in real time without interrupting the CLI prompt.

---

## 5. Multi-Device Setup (Wi-Fi Hotspot / Real LAN Mode)

To run across different laptops connected to a Wi-Fi hotspot or switch:

### Option A: Using Default High Ports (Recommended, No `sudo` Needed)
1. **Machine 1 (Server):**
   ```bash
   python3 bootp_server.py
   ```
2. **Machine 2 (Client):**
   Point the client to the server's LAN IP (e.g. `192.168.1.100`):
   ```bash
   python3 bootp_client.py --server-ip 192.168.1.100
   ```
   *(Or broadcast across the subnet using `255.255.255.255`)*.

---

### Option B: Using Standard RFC Privileged Ports 67 & 68 (`--standard-ports`)
1. **Machine 1 (Server):**
   ```bash
   sudo python3 bootp_server.py --standard-ports
   ```
2. **Machine 2 (Client):**
   ```bash
   sudo python3 bootp_client.py --standard-ports --apply-ip --ping 192.168.1.150
   ```

> **Note on Ping (`--apply-ip`):**
> When `--apply-ip` is specified, the client script automatically configures the network interface:
> * **Linux:** `sudo ip addr add <allotted_ip>/<cidr> dev <interface>`
> * **macOS:** `sudo ifconfig <interface> alias <allotted_ip> netmask <subnet_mask>`
> * **Windows:** `netsh interface ipv4 add address "<interface>" <allotted_ip> <subnet_mask>`
>
> This enables the OS kernel to respond to ARP and ICMP Echo requests, allowing laptops to ping each other. Press `Ctrl+C` to cleanly remove the assigned IP upon termination.

---

## 6. Wireshark Tracing Guide

1. Open Wireshark and select your active network interface (`wlo1`, `eth0`, `Wi-Fi`, or `Loopback: lo`).
2. If using `--standard-ports` (67/68), set the display filter to:
   ```text
   bootp
   ```
3. If using default high ports (6767/6868):
   * In Wireshark, right-click any captured UDP packet on port 6767 or 6868.
   * Select **Decode As...** $\rightarrow$ Set Current to **BOOTP/DHCP** $\rightarrow$ Click **Save**.
4. You can inspect:
   * **Message type:** Boot Request (1) or Boot Reply (2)
   * **Transaction ID:** Matches between request and reply
   * **Client MAC address**
   * **Your (client) IP address (`yiaddr`)**
   * **RFC 1048 Vendor Extensions:** Magic Cookie `0x63825363`, Subnet Mask, Gateway Router, DNS Server, Hostname, and End Option (`0xFF`).

---

## 7. Command-Line Reference

### Server Options (`bootp_server.py`)
```text
--config PATH           Path to JSON configuration (default: bootptab.json)
--port PORT             Server UDP port (default: 6767; 67 with --standard-ports)
--client-port PORT      Client UDP port (default: 6868; 68 with --standard-ports)
--bind-ip IP            IP to bind server (default: 0.0.0.0)
--broadcast-ip IP       Broadcast IP to use (default: 255.255.255.255)
--standard-ports        Use standard privileged ports 67/68 (requires sudo)
--dev                   Alias for high ports (now the default)
```

### Client Options (`bootp_client.py`)
```text
--mac MAC               Hardware MAC address (default: auto-detected host MAC)
--interface IFACE       Network interface name (e.g. eth0, wlo1, en0)
--port PORT             Client UDP port (default: 6868; 68 with --standard-ports)
--server-port PORT      Server UDP port (default: 6767; 67 with --standard-ports)
--server-ip IP          Server / Broadcast IP (default: 255.255.255.255)
--standard-ports        Use standard privileged ports 68/67 (requires sudo)
--dev                   Development shortcut (uses localhost 127.0.0.1)
--unicast               Request unicast reply (flags=0x0000)
--apply-ip              Configure OS interface with allotted IP for pinging
--ping IP               Target IP address to ping after receiving IP
--timeout SEC           Timeout in seconds (default: 3.0)
--retries N             Number of attempts (default: 3)
```
