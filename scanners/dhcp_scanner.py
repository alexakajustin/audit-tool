"""
DHCP Scanner — passive DHCP traffic sniffer.

Captures DHCP Discover/Offer/Request/ACK packets to map
device assignments. Only useful on networks with DHCP;
gracefully does nothing on static-only networks (YAGNI).
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


class DhcpScanner(BaseScanner):
    """Passively sniffs DHCP traffic to discover device assignments."""

    @property
    def name(self) -> str:
        return "dhcp_sniff"

    @property
    def display_name(self) -> str:
        return "DHCP Sniffer"

    @property
    def description(self) -> str:
        return (
            "Passively captures DHCP packets (Discover/Offer/Request/ACK) "
            "to map IP assignments, hostnames, and lease info. Only works "
            "on networks with DHCP. Requires admin."
        )

    def get_capabilities(self) -> ScanCapabilities:
        return ScanCapabilities(
            can_discover_hosts=True,
            can_detect_ports=False,
            can_detect_os=False,
            can_detect_services=False,
            can_detect_hostnames=True,
            requires_admin=True,
            is_passive=True,
            layer=2,
        )

    def is_available(self) -> bool:
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

        # How long to listen for DHCP traffic
        timeout = target.options.get("timeout", 30)
        discovered: dict[str, Device] = {}

        try:
            from scapy.all import sniff, DHCP, BOOTP, Ether, conf

            conf.verb = 0
            if target.interface:
                conf.iface = target.interface

            def process_dhcp(pkt):
                """Process a single DHCP packet."""
                if not pkt.haslayer(DHCP):
                    return

                dhcp_options = {
                    opt[0]: opt[1]
                    for opt in pkt[DHCP].options
                    if isinstance(opt, tuple) and len(opt) >= 2
                }

                msg_type = dhcp_options.get("message-type", 0)
                mac = ""
                ip = ""
                hostname = ""

                # Extract MAC from Ethernet layer
                if pkt.haslayer(Ether):
                    mac = pkt[Ether].src.upper()

                # Extract offered/assigned IP from BOOTP
                if pkt.haslayer(BOOTP):
                    bootp = pkt[BOOTP]
                    if bootp.yiaddr and bootp.yiaddr != "0.0.0.0":
                        ip = bootp.yiaddr
                    elif bootp.ciaddr and bootp.ciaddr != "0.0.0.0":
                        ip = bootp.ciaddr

                # Extract hostname from DHCP options
                raw_hostname = dhcp_options.get("hostname", b"")
                if isinstance(raw_hostname, bytes):
                    hostname = raw_hostname.decode("utf-8", errors="ignore")
                elif isinstance(raw_hostname, str):
                    hostname = raw_hostname

                # Only track if we got something useful
                if mac and mac != "FF:FF:FF:FF:FF:FF":
                    if mac not in discovered:
                        device = Device(
                            mac=mac,
                            ip=ip,
                            vendor=lookup_vendor(mac),
                            hostname=hostname,
                            status=DeviceStatus.ONLINE,
                            discovery_methods=[self.name],
                        )
                        discovered[mac] = device
                        if on_device_found:
                            on_device_found(device)
                    else:
                        # Update existing
                        dev = discovered[mac]
                        if ip:
                            dev.ip = ip
                        if hostname:
                            dev.hostname = hostname
                        dev.last_seen = time.time()

            # Sniff for DHCP traffic (UDP ports 67/68)
            sniff(
                filter="udp and (port 67 or port 68)",
                prn=process_dhcp,
                timeout=timeout,
                store=0,
            )

            result.devices = list(discovered.values())
            result.state = ScanState.COMPLETE

        except PermissionError:
            result.errors.append(
                "DHCP sniffing requires administrator privileges."
            )
            result.state = ScanState.FAILED
        except ImportError:
            result.errors.append("Scapy is not installed.")
            result.state = ScanState.FAILED
        except Exception as e:
            result.errors.append(f"DHCP scan failed: {e}")
            result.state = ScanState.FAILED

        result.end_time = time.time()
        return result
