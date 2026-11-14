# Computer Networks Group Project: Socket Programming Protocols

## 1. Project Overview & Constraints
* **Objective:** Implement one protocol from three specific baskets (BOOTP, DHCP, FTP) using TCP/UDP socket programming.
* **Architecture:** Client-Server model for each protocol.
* **Scope Definition:** This is strictly an **Application/Transport layer** implementation. 
  * We will use standard OS-provided TCP and UDP sockets.
  * We **DO NOT** need to simulate lower layers (Data Link/Physical) or bit-level error injection (unlike previous assignments). 
  * The OS handles IP routing, Ethernet framing, and physical transmission.

PLEASE MAKE SURE THAT THE PACKETS ACTUALLY FOLLOW THE ACTUAL FORMATS (BOOTP/DHCP/FTP packets) so that they can be traced using wireshark or similar utility programmes.  
  

## 2. Environment & Network Setup Strategy
To run and test both Client and Server on the same network without interfering with system configurations, we will use one of two approaches:
1. **Localhost (Development):** Run both on `127.0.0.1`. Use unprivileged high ports (e.g., Server on 6767, Client on 6868) to bypass `sudo` requirements. Clients will send UDP requests directly to the server's loopback port.
2. **Local LAN/Hotspot (Testing/Demo):** Connect all group laptops to a single Wi-Fi hotspot. Enable the `SO_BROADCAST` socket option for BOOTP/DHCP clients to send true broadcasts (e.g., `255.255.255.255`).

*Note: The Server will maintain a virtual IP pool internally (in variables or a file) to track leases. We will not actually reconfigure our laptops' OS network interfaces.*

## 3. Language Selection Notes
* **C/C++:** Ideal for memory-mapping exact RFC binary structures using `__attribute__((packed))` structs. Harder string parsing for FTP.
* **Python:** Fastest development speed. Easy binary packing via the `struct` module. Easiest string and file I/O handling for FTP.

---

## 4. Implementation Breakdowns

### Protocol A: BOOTP (Bootstrap Protocol)
* **Transport:** UDP (Connectionless).
* **Concept:** Static mapping of MAC addresses to IP addresses.
* **Server State:** A hardcoded static table (e.g., dictionary or file) mapping mock MAC addresses to specific IPs.
* **Data Structure:** A fixed-length binary payload representing the BOOTP packet (op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file, vend).
* **Execution Flow:**
  1. **Client (`BOOTREQUEST`):** Sets `op=1`, generates a random transaction ID (`xid`), inserts a mock MAC into `chaddr`, and sends a UDP datagram to the server.
  2. **Server (`BOOTREPLY`):** Receives datagram, parses `chaddr`, looks it up in the static table, sets `op=2`, fills `yiaddr` (Your IP) with the matched IP, and sends it back.

### Protocol B: DHCP (Dynamic Host Configuration Protocol)
* **Transport:** UDP (Connectionless).
* **Concept:** Dynamic IP allocation built on top of the BOOTP packet structure.
* **Server State:** An IP pool tracker (e.g., arrays or objects marking IPs as `AVAILABLE`, `OFFERED`, or `LEASED` with expiration timers).
* **Data Structure:** The BOOTP packet + DHCP Magic Cookie (`0x63825363`) + variable-length DHCP Options array (Message Type, Subnet Mask, Lease Time).
* **Execution Flow (The DORA Handshake):**
  1. **Client (`DHCPDISCOVER`):** UDP broadcast, Message Type Option = 1.
  2. **Server (`DHCPOFFER`):** Finds available IP, marks `OFFERED`, sends reply with Message Type = 2 and IP in `yiaddr`.
  3. **Client (`DHCPREQUEST`):** Receives offer, broadcasts Message Type = 3 to officially request the offered IP.
  4. **Server (`DHCPACK`):** Marks IP as `LEASED`, sends Message Type = 5 containing final lease data (subnet, time).

### Protocol C: FTP (File Transfer Protocol)
* **Transport:** TCP (Connection-oriented).
* **Concept:** Dual-channel architecture (Control + Data).
* **Execution Flow:**
  1. **Control Channel:** 
     * Server opens a listening TCP socket. Client connects.
     * Persistent connection where text commands (`USER`, `PASS`, `LIST`, `RETR`, `QUIT`) are sent by the client.
     * Server replies with numeric status codes (e.g., `220`, `200`, `550`).
  2. **Data Channel (Active Mode using `PORT`):**
     * Client sends `PORT h1,h2,h3,h4,p1,p2` (IP and calculated port).
     * Client opens a local listening socket on that port.
     * Server actively `connect()`s to the client's IP/port to establish a temporary Data Channel.
  3. **File Transfer (`RETR` / `STOR`):**
     * File bytes are read in chunks and streamed over the Data Channel socket.
     * Data Channel is immediately closed upon EOF. Control channel sends `226 Transfer complete`.

for BOOTP/DHCP
- broadcast setup required (disabling firewall and allowing LAN broadcast)
- show which packets are broadcast and unicast in terminal output
- facility for multiple DHCP servers on the same network
- show differences between DHCP and BOOTP
- show only current addresses for BOOTP
- show current address mappings and available addresses for DHCP
- show DORA handshake steps 

for FTP
- no need for broadcast setup
- file chunking and byte streaming
- show NVT/ASCII control connection contents if possible
