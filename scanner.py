"""
scanner.py
Henry Nettey

Scans a small list of TCP ports and returns open ones.
This file assumes the target IP has already been validated elsewhere.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    161, 389, 443, 445, 1433, 3306, 3389, 5432,
    6379, 8080, 8443, 9200, 27017
]

HTTP_PROBE_PORTS = {80, 8080, 8443}


def prepare_ports(ports=None):
    """Returns a clean list of ports to scan."""
    if ports is None:
        return COMMON_PORTS.copy()

    cleaned_ports = sorted(set(ports))

    for port in cleaned_ports:
        if not isinstance(port, int):
            raise ValueError("Ports must be integers.")
        if port < 1 or port > 65535:
            raise ValueError(f"Port {port} is outside the valid range 1-65535.")

    return cleaned_ports


def grab_banner(ip_address, port, timeout=1.5):
    """Tries to read a short banner from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip_address, port))

            if port in HTTP_PROBE_PORTS:
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                except OSError:
                    pass

            data = sock.recv(128)

            if not data:
                return "No banner received"

            text = data.decode("utf-8", errors="ignore").strip()

            if not text:
                return "No banner received"

            return text[:100]

    except (socket.timeout, TimeoutError, OSError):
        return "No banner received"


def scan_port(ip_address, port, timeout=1.0):
    """Checks one TCP port and returns a result only if it is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip_address, port))

            if result == 0:
                return {
                    "port": port,
                    "state": "open",
                    "banner": grab_banner(ip_address, port, timeout)
                }

    except (socket.timeout, TimeoutError, OSError):
        return None

    return None


def scan_target(ip_address, ports=None, timeout=1.0):
    """Sequential scan. Start with this version first."""
    ports_to_scan = prepare_ports(ports)
    findings = []

    for port in ports_to_scan:
        result = scan_port(ip_address, port, timeout)

        if result is not None:
            findings.append(result)

    return findings


def scan_target_threaded(ip_address, ports=None, timeout=1.0, max_workers=15):
    """Optional: faster version using threads."""
    ports_to_scan = prepare_ports(ports)
    findings = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(scan_port, ip_address, port, timeout)
            for port in ports_to_scan
        ]

        for future in as_completed(futures):
            result = future.result()

            if result is not None:
                findings.append(result)

    return sorted(findings, key=lambda item: item["port"])

def run_scan(ip_address: str) -> list[dict]:
    """Runs the scan on the selected common ports."""
    return scan_target(ip_address)
