"""
Data models for the audit tool.
Pure data classes — no behavior, no dependencies, serializable.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class DeviceStatus(Enum):
    """Device reachability status."""
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class ScanType(Enum):
    """Available scan types."""
    ARP_SWEEP = "arp_sweep"
    ARP_CACHE = "arp_cache"
    NMAP_DISCOVERY = "nmap_discovery"
    NMAP_FULL = "nmap_full"
    DHCP_SNIFF = "dhcp_sniff"
    PASSIVE_DISCOVERY = "passive_discovery"


class ScanState(Enum):
    """Scan lifecycle state."""
    PENDING = "pending"
    RUNNING = "running"
    MERGING = "merging"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# Device
# ---------------------------------------------------------------------------

@dataclass
class PortInfo:
    """A single open port on a device."""
    port: int
    protocol: str = "tcp"         # tcp / udp
    state: str = "open"           # open / closed / filtered
    service: str = ""             # e.g. "http", "ssh"
    version: str = ""             # e.g. "Apache 2.4.41"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Device:
    """
    A discovered network device.
    Single source of truth for device identity — keyed by MAC address.
    """
    mac: str                                    # Primary key
    ip: str = ""
    vendor: str = ""
    hostname: str = ""
    os: str = ""
    ports: list[PortInfo] = field(default_factory=list)
    status: DeviceStatus = DeviceStatus.UNKNOWN
    discovery_methods: list[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    response_time_ms: Optional[float] = None
    notes: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict:
        """Serialize to plain dict for JSON responses."""
        return {
            "id": self.id,
            "mac": self.mac,
            "ip": self.ip,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "os": self.os,
            "ports": [p.to_dict() for p in self.ports],
            "status": self.status.value,
            "discovery_methods": self.discovery_methods,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "response_time_ms": self.response_time_ms,
            "notes": self.notes,
        }

    def merge(self, other: Device) -> None:
        """
        Merge another Device's data into this one.
        Keeps the richest information from both.
        """
        if other.ip:
            self.ip = other.ip
        if other.vendor and not self.vendor:
            self.vendor = other.vendor
        if other.hostname and not self.hostname:
            self.hostname = other.hostname
        if other.os and not self.os:
            self.os = other.os
        if other.response_time_ms is not None:
            self.response_time_ms = other.response_time_ms

        # Merge ports — keep unique by (port, protocol)
        existing = {(p.port, p.protocol) for p in self.ports}
        for port in other.ports:
            if (port.port, port.protocol) not in existing:
                self.ports.append(port)
                existing.add((port.port, port.protocol))

        # Merge discovery methods
        for method in other.discovery_methods:
            if method not in self.discovery_methods:
                self.discovery_methods.append(method)

        # Update timestamps
        self.first_seen = min(self.first_seen, other.first_seen)
        self.last_seen = max(self.last_seen, other.last_seen)
        self.status = other.status if other.status != DeviceStatus.UNKNOWN else self.status


# ---------------------------------------------------------------------------
# Scan configuration & results
# ---------------------------------------------------------------------------

@dataclass
class ScanTarget:
    """What to scan and how."""
    subnet: str                                  # e.g. "192.168.1.0/24"
    interface: str = ""                          # Network interface name
    scanner_names: list[str] = field(default_factory=list)  # Which scanners to use
    options: dict = field(default_factory=dict)   # Scanner-specific options

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanCapabilities:
    """What a scanner can detect — used by registry for capability queries."""
    can_discover_hosts: bool = False
    can_detect_ports: bool = False
    can_detect_os: bool = False
    can_detect_services: bool = False
    can_detect_hostnames: bool = False
    requires_admin: bool = False
    is_passive: bool = False                     # True = doesn't inject packets
    layer: int = 3                               # 2 = L2 (ARP), 3 = L3 (IP)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    """Output from a single scanner run."""
    scanner_name: str
    devices: list[Device] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    errors: list[str] = field(default_factory=list)
    state: ScanState = ScanState.PENDING

    @property
    def duration(self) -> float:
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return 0.0

    @property
    def device_count(self) -> int:
        return len(self.devices)

    def to_dict(self) -> dict:
        return {
            "scanner_name": self.scanner_name,
            "devices": [d.to_dict() for d in self.devices],
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "device_count": self.device_count,
            "errors": self.errors,
            "state": self.state.value,
        }


# ---------------------------------------------------------------------------
# Packet / Sniffer
# ---------------------------------------------------------------------------

@dataclass
class PacketInfo:
    """A single captured packet — lightweight summary for streaming."""
    timestamp: float
    protocol: str               # ARP, DNS, HTTP, TCP, UDP, ICMP, etc.
    src: str                    # Source IP or MAC
    dst: str                    # Destination IP or MAC
    size: int                   # Bytes
    summary: str                # Human-readable one-line summary
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    src_mac: str = ""           # Source MAC address (L2)
    dst_mac: str = ""           # Destination MAC address (L2)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CaptureResult:
    """Summary of a sniffer capture session."""
    total_packets: int = 0
    duration: float = 0.0
    protocols: dict[str, int] = field(default_factory=dict)  # protocol -> count
    unique_hosts: set[str] = field(default_factory=set)
    pcap_path: str = ""

    def to_dict(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "duration": self.duration,
            "protocols": self.protocols,
            "unique_hosts": list(self.unique_hosts),
            "pcap_path": self.pcap_path,
        }


# ---------------------------------------------------------------------------
# VLAN / Subnet / Switch Intelligence
# ---------------------------------------------------------------------------

@dataclass
class VLANInfo:
    """A discovered VLAN on the network."""
    vlan_id: int                                # 802.1Q VLAN ID (1-4094)
    name: str = ""                              # VLAN name (from VTP/CDP/LLDP)
    subnet: str = ""                            # Associated subnet CIDR if known
    source_protocol: str = ""                   # How it was discovered: cdp, lldp, dot1q, vtp, ospf, etc.
    source_switch: str = ""                     # Switch hostname that advertised it
    is_native: bool = False                     # True if this is the native/untagged VLAN
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SubnetInfo:
    """An inferred or discovered subnet."""
    cidr: str                                   # e.g. "10.20.30.0/24"
    gateway: str = ""                           # Gateway IP if known
    dhcp_server: str = ""                       # DHCP server IP if detected
    vlan_id: Optional[int] = None               # Associated VLAN ID if known
    device_count: int = 0                       # Number of devices seen in this subnet
    source_protocol: str = ""                   # How it was discovered
    source_router: str = ""                     # Router that advertised it
    metric: int = 0                             # Routing metric if learned from a protocol
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SwitchInfo:
    """A network switch or router discovered via CDP/LLDP."""
    device_id: str                              # Switch hostname / device ID (primary key)
    management_ip: str = ""                     # Management IP address
    platform: str = ""                          # Hardware model (e.g. "WS-C3750-48P")
    software_version: str = ""                  # Firmware / IOS version string
    local_port: str = ""                        # Port YOU are connected to (e.g. "GigabitEthernet0/1")
    native_vlan: Optional[int] = None           # Native VLAN on that port
    capabilities: list[str] = field(default_factory=list)  # e.g. ["Router", "Switch", "IGMP"]
    vlans_advertised: list[int] = field(default_factory=list)  # VLANs seen from this switch
    source_protocol: str = ""                   # "cdp" or "lldp"
    source_mac: str = ""                        # MAC address of the switch port
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RoutingEntry:
    """A route learned passively from a routing protocol."""
    destination: str                            # Destination subnet CIDR
    next_hop: str = ""                          # Next-hop IP
    metric: int = 0                             # Route metric
    protocol: str = ""                          # "ospf", "eigrp", "rip"
    advertising_router: str = ""                # Router ID that advertised this route
    area: str = ""                              # OSPF area ID (if applicable)
    as_number: int = 0                          # EIGRP AS number (if applicable)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)
