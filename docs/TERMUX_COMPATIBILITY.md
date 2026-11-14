# GOJO INFINITY SECURITY — TERMUX COMPATIBILITY SPECIFICATION

## 1. Operating Environment
- **Platform:** Android 7.0+ (ARM64, ARMv7, x86_64) via Termux environment.
- **Root Status:** **NON-ROOT**. Every capability in Gojo Infinity Security is designed and tested to execute inside the unprivileged Android sandbox UID (`u0_a...`).

## 2. Capabilities & Constraints Matrix

| Feature | Android Standard Constraint | Gojo Infinity Engineered Solution |
|---|---|---|
| **Host Discovery** | `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` requires root UID 0 | 1. TCP-connect probes against common ports (80, 443, 22, 8080, 53).<br>2. Subprocess wrapper executing Termux `/system/bin/ping -c 1` (which has setuid or capability in modern Android for basic ICMP echo).<br>3. ARP cache inspection via `/proc/net/arp` (accessible on older Android, gracefully handles PermissionDenied on Android 10+). |
| **Port Scanning** | SYN scan (`-sS`) requires raw socket privileges | High-speed asynchronous TCP Connect scanning (`socket.connect_ex` with strict non-blocking timeouts in `asyncio`). Capable of 100+ concurrent ports per second in Termux without kernel penalties. |
| **Firewall & Traffic Filtering** | `iptables` / `nftables` requires root | **INFINITY SHIELD Application Firewall:** Operates at the application & reverse-proxy layer (ASGI middleware). Filters HTTP/HTTPS requests, enforces token bucket rate limiting, blocks offending IPs, mitigates directory traversal, XSS, and SQL injection payloads targeting local or proxied web services. |
| **Background Daemons** | Android battery optimizer kills background apps | `start.sh` executes `termux-wake-lock` if the `termux-api` package is present, keeps background workers alive via standard PID files (`logs/gojo.pid`), and writes to `logs/engine.log`. |
| **Storage & Persistence** | External SD card permissions require `SAF` | Uses Termux native home directory (`$HOME/gojo-infinity`) and local SQLite database (`database/gojo_infinity.db`), providing isolated, high-speed, and crash-resilient storage. |
| **DNS Intelligence** | `/etc/resolv.conf` may not exist in Android | Uses fallback upstream DNS resolvers (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`) via pure Python DNS client, or system Android `getaddrinfo` resolution. |

## 3. Package Requirements in Termux
Minimal footprint without heavy dependencies:
```bash
pkg update -y
pkg install -y python git curl wget openssl clang libffi make binutils
pip install -r requirements.txt
```
All chosen Python libraries are either pure Python or have pre-built wheels / compile seamlessly in Termux Clang.
