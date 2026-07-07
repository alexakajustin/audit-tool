"""
WiFi Scanner — discovers nearby wireless networks (SSIDs, BSSIDs, signals).

Uses the native Windows 'netsh wlan' API.
Zero network connection required. Does not require admin privileges.
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


class WifiScanner(BaseScanner):
    """Scans for nearby wireless access points using native OS commands."""

    @property
    def name(self) -> str:
        return "wifi_scanner"

    @property
    def display_name(self) -> str:
        return "Wi-Fi AP Scanner"

    @property
    def description(self) -> str:
        return (
            "Scans for nearby wireless networks (SSIDs, BSSIDs, signal levels, "
            "and security types) using your Wi-Fi card. No connection required."
        )

    def get_capabilities(self) -> ScanCapabilities:
        return ScanCapabilities(
            can_discover_hosts=True,
            can_detect_ports=False,
            can_detect_os=False,
            can_detect_services=False,
            can_detect_hostnames=True,  # SSID acts as hostname
            requires_admin=False,
            is_passive=True,            # Passive relative to IP network
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
            # Call Windows Netsh command to list visible BSSIDs
            proc = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )

            if proc.returncode != 0:
                # If command fails, perhaps Wi-Fi is disabled or not present
                result.errors.append("Wi-Fi interface may be disabled or missing.")
                result.state = ScanState.FAILED
                result.end_time = time.time()
                return result

            devices = self._parse_netsh_output(proc.stdout)

            for device in devices:
                result.devices.append(device)
                if on_device_found:
                    on_device_found(device)

            result.state = ScanState.COMPLETE

        except Exception as e:
            result.errors.append(f"Wi-Fi scan failed: {e}")
            result.state = ScanState.FAILED

        result.end_time = time.time()
        return result

    def _parse_netsh_output(self, output: str) -> list[Device]:
        """Parses the output of 'netsh wlan show networks mode=bssid'."""
        devices = []
        
        # Split by SSID blocks
        networks = output.split("SSID ")
        if len(networks) <= 1:
            return []

        for net_block in networks[1:]:
            lines = net_block.splitlines()
            if not lines:
                continue

            # Extract SSID name
            first_line = lines[0].strip()
            ssid_match = re.match(r"\d+\s*:\s*(.*)", first_line)
            ssid = ssid_match.group(1).strip() if ssid_match else "Hidden Network"
            if not ssid:
                ssid = "Hidden Network"

            # Parse authentication
            auth = "Unknown"
            for line in lines:
                if "Authentication" in line:
                    auth = line.split(":", 1)[1].strip()
                    break

            # Now find all BSSID sub-blocks in this network block
            bssid_blocks = net_block.split("BSSID ")
            if len(bssid_blocks) <= 1:
                continue

            for bss_block in bssid_blocks[1:]:
                bss_lines = bss_block.splitlines()
                if not bss_lines:
                    continue

                # Extract BSSID (MAC Address)
                mac_line = bss_lines[0].strip()
                mac_match = re.match(r"\d+\s*:\s*([0-9a-fA-F:]{17}|[0-9a-fA-F-]{17})", mac_line)
                if not mac_match:
                    continue

                mac = mac_match.group(1).upper().replace("-", ":")
                
                # Parse signal, channel, etc.
                signal = "—"
                channel = "—"
                for line in bss_lines[1:]:
                    if "Signal" in line:
                        signal = line.split(":", 1)[1].strip()
                    elif "Channel" in line:
                        channel = line.split(":", 1)[1].strip()

                notes = f"SSID: {ssid} | Auth: {auth} | Signal: {signal} | Channel: {channel}"
                
                device = Device(
                    mac=mac,
                    ip="", # Not connected
                    vendor=lookup_vendor(mac),
                    hostname=ssid,
                    status=DeviceStatus.ONLINE,
                    discovery_methods=[self.name],
                    notes=notes
                )
                devices.append(device)

        return devices
