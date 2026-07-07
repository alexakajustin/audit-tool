"""
ARP Sweep Scanner — active L2 discovery via Scapy.

Sends ARP who-has requests to every IP in the subnet.
Works with or without DHCP. Requires admin privileges.
"""

from __future__ import annotations

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


class ArpScanner(BaseScanner):
    """Active ARP sweep — discovers all L2 devices in a subnet."""

    @property
    def name(self) -> str:
        return "arp_sweep"

    @property
    def display_name(self) -> str:
        return "ARP Sweep"

    @property
    def description(self) -> str:
        return (
            "Sends ARP requests to every IP in the subnet to discover "
            "devices at Layer 2. Works with or without DHCP. Requires admin."
        )

    def get_capabilities(self) -> ScanCapabilities:
        return ScanCapabilities(
            can_discover_hosts=True,
            can_detect_ports=False,
            can_detect_os=False,
            can_detect_services=False,
            can_detect_hostnames=False,
            requires_admin=True,
            is_passive=False,
            layer=2,
        )

    def is_available(self) -> bool:
        """Check if Scapy is importable."""
        try:
            import scapy.all  # noqa: F401
            return True
        except ImportError:
            return False

    def scan(
        self,
        target: ScanTarget,
        on_device_found: Optional[Callable[[Device], None]] = None,
    ) -> ScanResult:
        result = ScanResult(scanner_name=self.name, state=ScanState.RUNNING)
        result.start_time = time.time()

        timeout = target.options.get("timeout", 3)

        try:
            from scapy.all import ARP, Ether, srp, conf

            # Suppress Scapy warnings
            conf.verb = 0

            # Set interface if specified
            if target.interface:
                conf.iface = target.interface

            # Build ARP request: broadcast Ether + ARP who-has
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target.subnet)

            # Send and receive
            answered, _ = srp(arp_request, timeout=timeout, retry=1, verbose=0)

            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc.upper()

                # Calculate response time
                resp_time = (received.time - sent.sent_time) * 1000  # ms

                device = Device(
                    mac=mac,
                    ip=ip,
                    vendor=lookup_vendor(mac),
                    status=DeviceStatus.ONLINE,
                    discovery_methods=[self.name],
                    response_time_ms=round(resp_time, 2),
                )

                result.devices.append(device)
                if on_device_found:
                    on_device_found(device)

            result.state = ScanState.COMPLETE

        except PermissionError:
            result.errors.append(
                "ARP scanning requires administrator privileges. "
                "Run the tool as Administrator."
            )
            result.state = ScanState.FAILED
        except ImportError:
            result.errors.append("Scapy is not installed. Install with: pip install scapy")
            result.state = ScanState.FAILED
        except Exception as e:
            result.errors.append(f"ARP scan failed: {e}")
            result.state = ScanState.FAILED

        result.end_time = time.time()
        return result
