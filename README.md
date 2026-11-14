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
  * **Standard Mode:** Uses privileged UDP ports **67** (Server) and **68** (Client) with `sudo` / Administrator.
  * **Development Mode (`--dev`):** Uses unprivileged high UDP ports **6767** (Server) and **6868** (Client) on localhost for instant testing without `sudo`.
* **JSON-Based Static Table:** Server loads MAC-to-IP static mappings from `bootptab.json`.
* **Automatic & Mock Hardware Addressing:** Client auto-detects active network interface MAC or accepts arbitrary mock MAC addresses via `--mac`.
* **Broadcast vs Unicast Distinction:** Clear terminal markers showing `[BROADCAST]` vs `[UNICAST]` transmissions.
* **Inter-Device Ping Connectivity:** Includes `--apply-ip` to assign the allotted IP alias to the network interface, enabling connected devices to ping each other. Supports `--ping <target_ip>` for instant ICMP verification.

---

## 2. Project File Structure

| File | Description |
| :--- | :--- |
| `bootp_packet.py` | RFC 951 & RFC 1048 packet encoder/decoder and binary serialization. |
| `network_utils.py` | Cross-platform utilities for MAC detection, IP assignment, and ping execution. |
| `bootp_server.py` | BOOTP server listening for requests and returning static leases. |
| `bootp_client.py` | BOOTP client broadcasting requests and acquiring IP leases. |
| `bootptab.json` | Configuration file containing static MAC-to-IP and network mappings. |

---

## 3. Quick Start (Development / Localhost Mode)

Run both client and server on a single machine without root/`sudo` privileges using `--dev`:

### Step 1: Start the Server
```bash
python3 bootp_server.py --dev
```

### Step 2: Run a Client (Auto-detected Host MAC)
Open a second terminal:
```bash
python3 bootp_client.py --dev
```

### Step 3: Run Additional Clients with Mock MACs
```bash
# Client 1 (allots 127.0.0.51)
python3 bootp_client.py --dev --mac aa:bb:cc:dd:ee:01

# Client 2 (allots 127.0.0.52 and tests pinging Client 1)
python3 bootp_client.py --dev --mac aa:bb:cc:dd:ee:02 --ping 127.0.0.51
```

---

## 4. Multi-Device Setup (Wi-Fi Hotspot / Real LAN Mode)

To run between multiple laptops connected to a Wi-Fi hotspot or switch:

### Step 1: Configure `bootptab.json`
Add the MAC addresses of your group members' laptops to `bootptab.json`:
```json
{
  "mappings": {
    "36:f2:ac:55:88:00": {
      "ip": "192.168.1.150",
      "subnet_mask": "255.255.255.0",
      "gateway": "192.168.1.1",
      "dns": "8.8.8.8",
      "hostname": "laptop-1"
    },
    "b8:27:eb:11:22:33": {
      "ip": "192.168.1.151",
      "subnet_mask": "255.255.255.0",
      "gateway": "192.168.1.1",
      "dns": "8.8.8.8",
      "hostname": "laptop-2"
    }
  }
}
```

### Step 2: Run the Server (Laptop A)
Using standard ports (67/68):
* **Linux / macOS:**
  ```bash
  sudo python3 bootp_server.py
  ```
* **Windows (Administrator Command Prompt / PowerShell):**
  ```powershell
  python bootp_server.py
  ```

### Step 3: Run the Clients (Laptop B, Laptop C, etc.)
* **Linux / macOS:**
  ```bash
  sudo python3 bootp_client.py --apply-ip --ping 192.168.1.150
  ```
* **Windows (Run as Administrator):**
  ```powershell
  python bootp_client.py --apply-ip --ping 192.168.1.150
  ```

> **Note on Ping (`--apply-ip`):**
> When `--apply-ip` is specified, the client script automatically configures the network interface:
> * **Linux:** `sudo ip addr add <allotted_ip>/<cidr> dev <interface>`
> * **macOS:** `sudo ifconfig <interface> alias <allotted_ip> netmask <subnet_mask>`
> * **Windows:** `netsh interface ipv4 add address "<interface>" <allotted_ip> <subnet_mask>`
>
> This enables the OS kernel to respond to ARP and ICMP Echo requests, allowing laptops to ping each other. Press `Ctrl+C` to cleanly remove the assigned IP upon termination.

---

## 5. Wireshark Tracing Guide

1. Open Wireshark and select your active network interface (`wlo1`, `eth0`, `Wi-Fi`, or `Loopback: lo`).
2. Set the display filter to:
   ```text
   bootp
   ```
3. Run the client and server.
4. If testing on custom ports (`--dev`, port 6767/6868):
   * In Wireshark, right-click any captured UDP packet on port 6767/6868.
   * Select **Decode As...** -> Set Current to **BOOTP/DHCP** -> Click **Save**.
5. You can inspect:
   * **Message type:** Boot Request (1) or Boot Reply (2)
   * **Transaction ID:** Matches between request and reply
   * **Client MAC address**
   * **Your (client) IP address**
   * **RFC 1048 Vendor Extensions:** Magic Cookie `0x63825363`, Subnet Mask, Gateway Router, DNS Server.

---

## 6. Command-Line Reference

### Server Options (`bootp_server.py`)
```text
--config PATH           Path to JSON configuration (default: bootptab.json)
--port PORT             Server UDP port (default: 67)
--client-port PORT      Client UDP port (default: 68)
--bind-ip IP            IP to bind server (default: 0.0.0.0)
--broadcast-ip IP       Broadcast IP to use (default: 255.255.255.255)
--dev                   Development shortcut (server: 6767, client: 6868)
```

### Client Options (`bootp_client.py`)
```text
--mac MAC               Hardware MAC address (default: auto-detected host MAC)
--interface IFACE       Network interface name (e.g. eth0, wlo1, en0)
--port PORT             Client UDP port (default: 68)
--server-port PORT      Server UDP port (default: 67)
--server-ip IP          Server / Broadcast IP (default: 255.255.255.255)
--dev                   Development shortcut (client: 6868, server: 6767 on 127.0.0.1)
--unicast               Request unicast reply (flags=0x0000)
--apply-ip              Configure OS interface with allotted IP for pinging
--ping IP               Target IP address to ping after receiving IP
--timeout SEC           Timeout in seconds (default: 3.0)
--retries N             Number of attempts (default: 3)
```
