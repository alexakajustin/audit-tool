"""
Native TCP Port Scanner — Fast, multi-threaded pure Python port scanner.

Scans common ports without requiring external dependencies (no Nmap binary needed).
Works on all platforms (Windows, Linux, macOS) without administrator privileges.
Performs service banner grabbing and protocol identification.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import time
from typing import Callable, Optional

from core.base import BaseScanner
from core.models import (
    Device,
    DeviceStatus,
    PortInfo,
    ScanCapabilities,
    ScanResult,
    ScanState,
    ScanTarget,
)
from network.mac_lookup import lookup_vendor


# Well-known service port mappings
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    1883: "MQTT",
    1900: "UPnP",
    2049: "NFS",
    3000: "Node/Dev",
    3306: "MySQL",
    3389: "RDP",
    5000: "Flask/Dev",
    5357: "WSDAPI",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    7547: "TR-069",
    8000: "HTTP-Alt",
    8008: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8081: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "Portainer/Sonar",
    9090: "Cockpit/Admin",
    9100: "JetDirect/Print",
    27017: "MongoDB",
}

# Top 25 priority ports for fast sweeps
TOP_25_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 995, 1433, 3306, 3389, 5000,
    5432, 5900, 6379, 8000, 8080, 8443, 8888,
]


class PortScanner(BaseScanner):
    """
    High-speed, multi-threaded native TCP port scanner.
    Discovers live hosts and their open ports with service detection.
    """

    @property
    def name(self) -> str:
        return "port_scanner"

    @property
    def display_name(self) -> str:
        return "TCP Port Scanner"

    @property
    def description(self) -> str:
        return (
            "Fast native Python TCP port scanner. Discovers open ports, "
            "web servers, database services, remote desktop, and SSH without Nmap."
        )

    def get_capabilities(self) -> ScanCapabilities:
        return ScanCapabilities(
            can_discover_hosts=True,
            can_detect_ports=True,
            can_detect_os=False,
            can_detect_services=True,
            can_detect_hostnames=True,
            requires_admin=False,
            is_passive=False,
            layer=3,
        )

    def is_available(self) -> bool:
        """Native scanner — always available."""
        return True

    def scan(
        self,
        target: ScanTarget,
        on_device_found: Optional[Callable[[Device], None]] = None,
    ) -> ScanResult:
        result = ScanResult(scanner_name=self.name, state=ScanState.RUNNING)
        result.start_time = time.time()

        opts = target.options or {}
        scan_profile = opts.get("scan_type", "fast")

        # Determine ports to scan
        if scan_profile == "full":
            ports_to_scan = sorted(list(COMMON_PORTS.keys()))
        elif scan_profile in ("ports", "top100"):
            ports_to_scan = sorted(list(COMMON_PORTS.keys()))
        else:  # "fast" or "discovery"
            ports_to_scan = TOP_25_PORTS

        # Extract target IPs
        target_ips = self._resolve_target_ips(target.subnet)
        if not target_ips:
            result.state = ScanState.COMPLETE
            result.end_time = time.time()
            return result

        # Scan hosts concurrently
        max_workers = min(64, max(4, len(target_ips) * 4))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {
                executor.submit(self._scan_single_host, ip, ports_to_scan): ip
                for ip in target_ips
            }

            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    device = future.result()
                    if device:
                        result.devices.append(device)
                        if on_device_found:
                            try:
                                on_device_found(device)
                            except Exception:
                                pass
                except Exception as e:
                    result.errors.append(f"Error scanning {ip}: {e}")

        result.state = ScanState.COMPLETE
        result.end_time = time.time()
        return result

    def _resolve_target_ips(self, subnet_str: str) -> list[str]:
        """Resolve subnet strings (CIDRs or IPs) to a list of IPv4 address strings."""
        ips = []
        for token in subnet_str.split():
            token = token.strip()
            if not token:
                continue
            try:
                if "/" in token:
                    net = ipaddress.IPv4Network(token, strict=False)
                    # Limit scan to max 512 hosts per range for performance
                    hosts = list(net.hosts())[:512]
                    ips.extend([str(h) for h in hosts])
                else:
                    ipaddress.IPv4Address(token)
                    ips.append(token)
            except Exception:
                pass
        return ips

    def _scan_single_host(self, ip: str, ports: list[int]) -> Optional[Device]:
        """Scan a single host for open ports and return Device if any port is open."""
        open_ports: list[PortInfo] = []

        for port in ports:
            is_open, banner = self._probe_port(ip, port)
            if is_open:
                service = COMMON_PORTS.get(port, "unknown")
                open_ports.append(PortInfo(
                    port=port,
                    protocol="tcp",
                    state="open",
                    service=service,
                    version=banner,
                ))

        if not open_ports:
            return None

        # Resolve hostname via reverse DNS
        hostname = ""
        try:
            hostname = socket.getfqdn(ip)
            if hostname == ip:
                hostname = ""
        except Exception:
            pass

        return Device(
            mac=f"ROUTED-{ip}",
            ip=ip,
            hostname=hostname,
            ports=open_ports,
            status=DeviceStatus.ONLINE,
            discovery_methods=[self.name],
        )

    def _probe_port(self, ip: str, port: int, timeout: float = 0.35) -> tuple[bool, str]:
        """Attempt to connect to a TCP port and grab service banner if open."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            res = s.connect_ex((ip, port))
            if res == 0:
                banner = ""
                # Try simple banner grab
                try:
                    s.settimeout(0.4)
                    if port in (80, 8080, 8000, 8888, 5000, 3000):
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    elif port in (21, 22, 25, 110):
                        pass  # Service sends greeting on connect
                    
                    data = s.recv(256)
                    if data:
                        lines = data.decode("utf-8", errors="ignore").splitlines()
                        for line in lines:
                            line = line.strip()
                            if line.startswith("Server:") or line.startswith("SSH-") or line.startswith("220 "):
                                banner = line[:60]
                                break
                        if not banner and lines:
                            banner = lines[0][:60]
                except Exception:
                    pass
                return True, banner
            return False, ""
        except Exception:
            return False, ""
        finally:
            try:
                s.close()
            except Exception:
                pass
