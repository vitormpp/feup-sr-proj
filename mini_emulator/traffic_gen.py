#!/usr/bin/env python3
"""
Diverse traffic generator for the SEED emulator.

Mounted into each host container at /traffic_gen.py.  Runs as a background
process alongside the existing node services.  Generates realistic HTTP, DNS,
Telnet, and ICMP traffic between emulator hosts — no extra packages required.

Each instance acts as both **server** (listens on protocol ports) and
**client** (randomly connects to other hosts).  Protocol exchanges are
realistic enough for Zeek / Suricata to classify them correctly.

Configuration via environment variables:
    TRAFFIC_DELAY_MIN  — minimum seconds between client actions (default 1)
    TRAFFIC_DELAY_MAX  — maximum seconds between client actions (default 10)
    TRAFFIC_TARGETS    — comma-separated IPs to contact (auto-detected if empty)
"""

import os
import sys
import socket
import struct
import random
import threading
import subprocess
import time
import logging

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DELAY_MIN = float(os.environ.get("TRAFFIC_DELAY_MIN", "1"))
DELAY_MAX = float(os.environ.get("TRAFFIC_DELAY_MAX", "10"))

# All host IPs in the emulator (static topology).
ALL_HOSTS = [
    "10.160.0.71", "10.160.0.72", "10.160.0.73",  # AS 160
    "10.161.0.71", "10.161.0.72", "10.161.0.73",  # AS 161
    "10.162.0.71", "10.162.0.72", "10.162.0.73", "10.162.0.74",  # AS 162
]

# Protocol selection weights (no SSH)
PROTOCOLS = ["http", "dns", "telnet", "icmp"]
WEIGHTS   = [  45,    25,     15,      15  ]

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [traffic-gen] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("traffic_gen")

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _get_local_ips():
    """Return the set of IPs assigned to this host."""
    ips = set()
    try:
        # Works on Linux — parse all interfaces
        output = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show"], text=True, stderr=subprocess.DEVNULL
        )
        for line in output.splitlines():
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "inet" and i + 1 < len(parts):
                    ips.add(parts[i + 1].split("/")[0])
    except Exception:
        pass
    ips.add("127.0.0.1")
    return ips


def _pick_target(local_ips):
    """Choose a random remote host IP."""
    targets = os.environ.get("TRAFFIC_TARGETS", "")
    pool = [a.strip() for a in targets.split(",") if a.strip()] if targets else ALL_HOSTS
    remote = [ip for ip in pool if ip not in local_ips]
    return random.choice(remote) if remote else None

# ---------------------------------------------------------------------------
# DNS helpers  (build / parse minimal DNS packets)
# ---------------------------------------------------------------------------

_DOMAINS = [
    "example.com", "google.com", "github.com", "wikipedia.org",
    "stackoverflow.com", "python.org", "reddit.com", "amazon.com",
    "cloudflare.com", "mozilla.org", "linux.org", "kernel.org",
    "arxiv.org", "ieee.org", "debian.org", "ubuntu.com",
]


def _build_dns_query(domain):
    """Build a minimal DNS A-record query packet."""
    tx_id = random.randint(0, 0xFFFF)
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 0)
    qname = b""
    for label in domain.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    question = qname + struct.pack("!HH", 1, 1)  # A record, IN class
    return tx_id, header + question


def _build_dns_response(query_data):
    """Given raw query bytes, craft a synthetic A-record response."""
    if len(query_data) < 12:
        return None
    tx_id = query_data[:2]
    flags = struct.pack("!H", 0x8180)  # standard response, no error
    counts = struct.pack("!HHHH", 1, 1, 0, 0)
    question = query_data[12:]  # qname + qtype + qclass
    # answer: pointer to name in question (0xC00C), A record, IN, TTL 300, 4-byte IP
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHI", 1, 1, 300)
        + struct.pack("!H", 4)
        + socket.inet_aton(f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}")
    )
    return tx_id + flags + counts + question + answer

# ---------------------------------------------------------------------------
# HTTP content
# ---------------------------------------------------------------------------

_HTTP_PATHS = [
    "/", "/index.html", "/about", "/contact", "/api/v1/status",
    "/api/v1/users", "/login", "/dashboard", "/search?q=network",
    "/static/js/app.js", "/static/css/style.css", "/images/logo.png",
    "/docs/getting-started", "/blog/2026/05/update", "/healthz",
]

_HTTP_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "curl/8.5.0",
    "python-requests/2.31.0",
    "Wget/1.21.4",
]

_HTML_BODIES = [
    "<html><head><title>Welcome</title></head><body><h1>Hello World</h1><p>This is a sample page.</p></body></html>",
    "<html><head><title>Dashboard</title></head><body><h1>System Status</h1><p>All systems operational.</p><ul><li>CPU: 42%</li><li>MEM: 67%</li></ul></body></html>",
    '{"status":"ok","uptime":123456,"version":"1.2.3"}',
    "<html><head><title>Not Found</title></head><body><h1>404</h1><p>Page not found.</p></body></html>",
    "<html><head><title>Blog</title></head><body><h1>Latest Post</h1><p>Network emulation is fascinating.</p></body></html>",
]

# ---------------------------------------------------------------------------
# Telnet content
# ---------------------------------------------------------------------------

_TELNET_COMMANDS = [
    "ls -la\r\n",
    "whoami\r\n",
    "cat /etc/hostname\r\n",
    "uptime\r\n",
    "ps aux\r\n",
    "df -h\r\n",
    "free -m\r\n",
    "ip addr show\r\n",
    "netstat -tlnp\r\n",
    "uname -a\r\n",
    "date\r\n",
    "echo hello world\r\n",
    "exit\r\n",
]

_TELNET_RESPONSES = [
    "total 48\r\ndrwxr-xr-x  2 root root 4096 May  1 12:00 .\r\ndrwxr-xr-x 18 root root 4096 May  1 12:00 ..\r\n-rw-r--r--  1 root root  220 May  1 12:00 .bash_logout\r\n",
    "root\r\n",
    "emulator-node\r\n",
    " 10:23:45 up 2 days,  3:42,  1 user,  load average: 0.12, 0.08, 0.05\r\n",
    "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\nroot         1  0.0  0.1  18384  3200 ?        Ss   May01   0:03 /sbin/init\r\n",
    "Filesystem      Size  Used Avail Use% Mounted on\r\n/dev/sda1        50G   12G   36G  25% /\r\n",
    "              total        used        free      shared  buff/cache   available\r\nMem:           7982        1234        5432         123        1316        6432\r\n",
]

# ---------------------------------------------------------------------------
# Server threads
# ---------------------------------------------------------------------------

def _run_tcp_server(port, handler, name):
    """Generic TCP server — one thread per accepted connection."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
    except OSError as e:
        log.warning("Cannot bind %s server on port %d: %s", name, port, e)
        return
    srv.listen(8)
    srv.settimeout(None)
    log.info("Server %s listening on :%d", name, port)
    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=handler, args=(conn, addr), daemon=True)
            t.start()
        except Exception as e:
            log.debug("Server %s accept error: %s", name, e)


def http_server_handler(conn, addr):
    """Handle one HTTP connection: read request, send response."""
    try:
        conn.settimeout(10)
        data = conn.recv(4096)
        if not data:
            return
        # Parse first line to log it
        first_line = data.split(b"\r\n")[0].decode(errors="replace")
        log.debug("HTTP request from %s: %s", addr[0], first_line)

        body = random.choice(_HTML_BODIES)
        content_type = "application/json" if body.startswith("{") else "text/html"
        status = "404 Not Found" if "404" in body else "200 OK"
        response = (
            f"HTTP/1.1 {status}\r\n"
            f"Content-Type: {content_type}; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Server: SeedEmu-TrafficGen/1.0\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )
        conn.sendall(response.encode())
    except Exception:
        pass
    finally:
        conn.close()


def telnet_server_handler(conn, addr):
    """Handle one Telnet connection: option negotiation + command/response."""
    try:
        conn.settimeout(15)
        # Send Telnet option negotiation (DO ECHO, WILL ECHO, DO SGA)
        conn.sendall(b"\xff\xfd\x01\xff\xfb\x01\xff\xfd\x03")
        # Read client negotiation
        try:
            conn.recv(256)
        except socket.timeout:
            pass
        # Send login prompt
        conn.sendall(b"SeedEmu login: ")
        try:
            conn.recv(256)  # username
        except socket.timeout:
            pass
        conn.sendall(b"Password: ")
        try:
            conn.recv(256)  # password
        except socket.timeout:
            pass
        conn.sendall(b"\r\nWelcome to SeedEmu node.\r\n$ ")
        # Exchange a few commands
        for _ in range(random.randint(1, 4)):
            try:
                cmd = conn.recv(1024)
                if not cmd:
                    break
            except socket.timeout:
                break
            resp = random.choice(_TELNET_RESPONSES)
            conn.sendall(resp.encode() + b"$ ")
            time.sleep(random.uniform(0.2, 1.0))
        conn.sendall(b"logout\r\n")
    except Exception:
        pass
    finally:
        conn.close()


def dns_server_loop():
    """UDP DNS server — respond to A-record queries."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", 53))
    except OSError as e:
        log.warning("Cannot bind DNS server on port 53: %s", e)
        return
    log.info("Server DNS listening on :53/udp")
    while True:
        try:
            data, addr = srv.recvfrom(512)
            resp = _build_dns_response(data)
            if resp:
                srv.sendto(resp, addr)
        except Exception as e:
            log.debug("DNS server error: %s", e)

# ---------------------------------------------------------------------------
# Client functions
# ---------------------------------------------------------------------------

def http_client(target):
    """Send a realistic HTTP GET request to target:80."""
    path = random.choice(_HTTP_PATHS)
    ua = random.choice(_HTTP_USER_AGENTS)
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        f"Accept-Language: en-US,en;q=0.5\r\n"
        f"Accept-Encoding: gzip, deflate\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(8)
    try:
        sock.connect((target, 80))
        sock.sendall(request.encode())
        resp = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
        status_line = resp.split(b"\r\n")[0].decode(errors="replace") if resp else "(empty)"
        log.info("HTTP  %s%s → %s", target, path, status_line)
    except Exception as e:
        log.debug("HTTP client to %s failed: %s", target, e)
    finally:
        sock.close()


def dns_client(target):
    """Send a DNS A-record query to target:53."""
    domain = random.choice(_DOMAINS)
    tx_id, packet = _build_dns_query(domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(packet, (target, 53))
        resp, _ = sock.recvfrom(512)
        log.info("DNS   %s → query %s (got %d bytes)", target, domain, len(resp))
    except Exception as e:
        log.debug("DNS client to %s failed: %s", target, e)
    finally:
        sock.close()


def telnet_client(target):
    """Open a Telnet-style connection to target:23."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    try:
        sock.connect((target, 23))
        # Read server negotiation + prompt
        try:
            sock.recv(512)
        except socket.timeout:
            pass
        # Send Telnet option replies (WILL ECHO, DO ECHO)
        sock.sendall(b"\xff\xfb\x01\xff\xfd\x01")
        time.sleep(0.3)
        # Send username
        sock.sendall(b"admin\r\n")
        try:
            sock.recv(512)
        except socket.timeout:
            pass
        time.sleep(0.3)
        # Send password
        sock.sendall(b"password123\r\n")
        try:
            sock.recv(1024)
        except socket.timeout:
            pass
        time.sleep(0.3)
        # Send a few commands
        num_cmds = random.randint(1, 4)
        for _ in range(num_cmds):
            cmd = random.choice(_TELNET_COMMANDS)
            sock.sendall(cmd.encode())
            time.sleep(random.uniform(0.3, 1.5))
            try:
                sock.recv(2048)
            except socket.timeout:
                pass
        sock.sendall(b"exit\r\n")
        log.info("TELNET %s → sent %d commands", target, num_cmds)
    except Exception as e:
        log.debug("Telnet client to %s failed: %s", target, e)
    finally:
        sock.close()


def icmp_client(target):
    """Ping target a few times."""
    count = random.randint(1, 5)
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", "2", target],
            capture_output=True, text=True, timeout=15,
        )
        # Extract summary line
        lines = result.stdout.strip().splitlines()
        summary = lines[-1] if lines else "(no output)"
        log.info("ICMP  %s → %d pings: %s", target, count, summary)
    except Exception as e:
        log.debug("ICMP client to %s failed: %s", target, e)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

CLIENT_DISPATCH = {
    "http":   http_client,
    "dns":    dns_client,
    "telnet": telnet_client,
    "icmp":   icmp_client,
}


def main():
    local_ips = _get_local_ips()
    hostname = socket.gethostname()
    log.info("Starting traffic generator on %s (local IPs: %s)", hostname, local_ips)
    log.info("Delay range: %.1f–%.1fs  |  Protocols: %s", DELAY_MIN, DELAY_MAX, PROTOCOLS)

    # --- Start server threads ---
    threading.Thread(
        target=_run_tcp_server,
        args=(80, http_server_handler, "HTTP"),
        daemon=True,
    ).start()

    threading.Thread(
        target=_run_tcp_server,
        args=(23, telnet_server_handler, "Telnet"),
        daemon=True,
    ).start()

    threading.Thread(target=dns_server_loop, daemon=True).start()

    # Give servers a moment to bind
    time.sleep(1)

    # --- Client loop ---
    while True:
        target = _pick_target(local_ips)
        if target is None:
            log.warning("No remote targets available, sleeping...")
            time.sleep(10)
            continue

        protocol = random.choices(PROTOCOLS, weights=WEIGHTS, k=1)[0]
        client_fn = CLIENT_DISPATCH[protocol]

        try:
            client_fn(target)
        except Exception as e:
            log.debug("Client %s to %s error: %s", protocol, target, e)

        delay = random.uniform(DELAY_MIN, DELAY_MAX)
        time.sleep(delay)


if __name__ == "__main__":
    main()
