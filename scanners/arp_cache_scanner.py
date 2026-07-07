"""
ARP Cache Scanner — reads the local OS ARP table.

Zero network traffic, zero privileges needed.
Great as a fast, non-intrusive first pass.
"""

from __future__ import annotations

import re
import subprocess
import time
from typing import Callable, Optional

from core.base import BaseScanner
from core.models import (
    Device,
    DeviceStatus,
    ScanCapabilities,
    ScanResult,
    ScanState,
    ScanTarget,
)
from network.mac_lookup import lookup_vendor


class ArpCacheScanner(BaseScanner):
    """Reads the local ARP cache — no packets sent, no admin needed."""

    @property
    def name(self) -> str:
        return "arp_cache"

    @property
    def display_name(self) -> str:
        return "ARP Cache Reader"

    @property
    def description(self) -> str:
        return (
            "Reads your OS ARP table (arp -a) to find devices your machine "
            "already knows about. Zero network traffic, no admin required."
        )

    def get_capabilities(self) -> ScanCapabilities:
        return ScanCapabilities(
            can_discover_hosts=True,
            can_detect_ports=False,
            can_detect_os=False,
            can_detect_services=False,
            can_detect_hostnames=False,
            requires_admin=False,
            is_passive=True,
            layer=2,
        )

    def scan(
        self,
        target: ScanTarget,
        on_device_found: Optional[Callable[[Device], None]] = None,
    ) -> ScanResult:
        result = ScanResult(scanner_name=self.name, state=ScanState.RUNNING)
        result.start_time = time.time()

        try:
            entries = self._read_arp_table()

            for ip, mac in entries:
                # Skip incomplete entries
                if not mac or mac == "ff:ff:ff:ff:ff:ff":
                    continue

                device = Device(
                    mac=mac.upper(),
                    ip=ip,
                    vendor=lookup_vendor(mac),
                    status=DeviceStatus.ONLINE,
                    discovery_methods=[self.name],
                )

                result.devices.append(device)
                if on_device_found:
                    on_device_found(device)

            result.state = ScanState.COMPLETE

        except Exception as e:
            result.errors.append(str(e))
            result.state = ScanState.FAILED

        result.end_time = time.time()
        return result

    def _read_arp_table(self) -> list[tuple[str, str]]:
        """
        Parse the OS ARP table. Returns [(ip, mac), ...].
        Handles both Windows and Linux output formats.
        """
        entries = []

        try:
            # Windows: arp -a
            proc = subprocess.run(
                ["arp", "-a"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )

            for line in proc.stdout.splitlines():
                # Windows format: "  192.168.1.1    aa-bb-cc-dd-ee-ff    dynamic"
                # Linux format:   "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
                match = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+"
                    r"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}"
                    r"[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})",
                    line,
                )
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace("-", ":").upper()
                    entries.append((ip, mac))

        except Exception:
            pass

        return entries
