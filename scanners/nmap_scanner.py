"""
Nmap Scanner — L3 discovery with port scanning, OS and service detection.

Uses python-nmap as a wrapper around the Nmap binary.
Handles both known networks and stealth discovery of non-responsive hosts.
"""

from __future__ import annotations

import shutil
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


class NmapScanner(BaseScanner):
    """
    Nmap-based scanner for port scanning, OS/service detection.
    Supports multiple scan profiles via target.options.
    """

    @property
    def name(self) -> str:
        return "nmap_discovery"

    @property
    def display_name(self) -> str:
        return "Nmap Scanner"

    @property
    def description(self) -> str:
        return (
            "Uses Nmap for L3 host discovery, port scanning, service version "
            "detection, and OS fingerprinting. Handles hosts that don't respond to ping."
        )

    def get_capabilities(self) -> ScanCapabilities:
        return ScanCapabilities(
            can_discover_hosts=True,
            can_detect_ports=True,
            can_detect_os=True,
            can_detect_services=True,
            can_detect_hostnames=True,
            requires_admin=False,  # Basic scans work without admin
            is_passive=False,
            layer=3,
        )

    def is_available(self) -> bool:
        """Check if nmap binary is installed."""
        return shutil.which("nmap") is not None

    def scan(
        self,
        target: ScanTarget,
        on_device_found: Optional[Callable[[Device], None]] = None,
    ) -> ScanResult:
        result = ScanResult(scanner_name=self.name, state=ScanState.RUNNING)
        result.start_time = time.time()

        try:
            import nmap

            nm = nmap.PortScanner()
            arguments = self._build_arguments(target)

            nm.scan(hosts=target.subnet, arguments=arguments)

            for host in nm.all_hosts():
                device = self._parse_host(nm, host)
                result.devices.append(device)
                if on_device_found:
                    on_device_found(device)

            result.state = ScanState.COMPLETE

        except ImportError:
            result.errors.append(
                "python-nmap is not installed. Install with: pip install python-nmap"
            )
            result.state = ScanState.FAILED
        except nmap.PortScannerError as e:
            result.errors.append(f"Nmap error: {e}")
            result.state = ScanState.FAILED
        except Exception as e:
            result.errors.append(f"Nmap scan failed: {e}")
            result.state = ScanState.FAILED

        result.end_time = time.time()
        return result

    def _build_arguments(self, target: ScanTarget) -> str:
        """
        Build Nmap CLI arguments from scan options.

        Options:
            scan_type: "discovery" | "ports" | "full" (default: "discovery")
            top_ports: int (default: 100)
            os_detection: bool (default: False)
            skip_ping: bool (default: False) — for hosts that don't respond to ping
            service_detection: bool (default: False)
        """
        opts = target.options
        scan_type = opts.get("scan_type", "discovery")

        if scan_type == "discovery":
            # Host discovery only — fast
            args = "-sn"
        elif scan_type == "ports":
            # Port scan with top N ports
            top_ports = opts.get("top_ports", 100)
            args = f"-sS --top-ports {top_ports}"
        elif scan_type == "full":
            # Full scan: ports + service + OS
            top_ports = opts.get("top_ports", 100)
            args = f"-sS -sV --top-ports {top_ports}"
        else:
            args = "-sn"

        # Skip ping for hosts that don't respond to ICMP
        if opts.get("skip_ping", False):
            args += " -Pn"

        # OS detection (requires admin on most systems)
        if opts.get("os_detection", False):
            args += " -O"

        # Service version detection
        if opts.get("service_detection", False) and "-sV" not in args:
            args += " -sV"

        # Timing template (T3 = normal, T4 = aggressive)
        args += " -T4"

        return args

    def _parse_host(self, nm, host: str) -> Device:
        """Parse Nmap results for a single host into a Device."""
        host_data = nm[host]

        # MAC address (Nmap only gets this on local network or with admin)
        mac = ""
        vendor = ""
        if "mac" in host_data.get("addresses", {}):
            mac = host_data["addresses"]["mac"].upper()
            vendor = lookup_vendor(mac)
        if not vendor and "vendor" in host_data:
            # Nmap sometimes provides vendor directly
            vendors = host_data.get("vendor", {})
            if vendors:
                vendor = list(vendors.values())[0]

        # If no MAC from Nmap, generate a placeholder from IP
        if not mac:
            mac = f"UNKNOWN-{host.replace('.', '-')}"

        # Hostname
        hostname = ""
        hostnames = host_data.get("hostnames", [])
        if hostnames and hostnames[0].get("name"):
            hostname = hostnames[0]["name"]

        # OS detection results
        os_name = ""
        if "osmatch" in host_data:
            os_matches = host_data["osmatch"]
            if os_matches:
                os_name = os_matches[0].get("name", "")

        # Status
        state = host_data.get("status", {}).get("state", "up")
        status = DeviceStatus.ONLINE if state == "up" else DeviceStatus.OFFLINE

        # Ports
        ports = []
        for proto in ["tcp", "udp"]:
            if proto in host_data:
                for port_num, port_data in host_data[proto].items():
                    ports.append(PortInfo(
                        port=port_num,
                        protocol=proto,
                        state=port_data.get("state", ""),
                        service=port_data.get("name", ""),
                        version=port_data.get("version", ""),
                    ))

        return Device(
            mac=mac,
            ip=host,
            vendor=vendor,
            hostname=hostname,
            os=os_name,
            ports=ports,
            status=status,
            discovery_methods=[self.name],
        )
