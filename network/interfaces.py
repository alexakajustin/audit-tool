"""
Network interface detection and subnet utilities.
Uses psutil for cross-platform interface enumeration.
"""

from __future__ import annotations

import ipaddress
import socket
import subprocess
import re
from dataclasses import dataclass, asdict
from typing import Optional

import psutil


@dataclass
class InterfaceInfo:
    """Represents a network interface with its addresses and subnet."""
    name: str
    ip: str
    netmask: str
    mac: str
    subnet: str              # CIDR notation, e.g. "192.168.1.0/24"
    gateway: str = ""
    is_up: bool = True
    is_loopback: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def get_interfaces() -> list[InterfaceInfo]:
    """
    List all active network interfaces with IPv4 addresses.
    Filters out loopback and interfaces without IP assignments.
    """
    interfaces = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for iface_name, addr_list in addrs.items():
        iface_stat = stats.get(iface_name)
        is_up = iface_stat.isup if iface_stat else False

        # Exclude loopback, virtual, VPN, and software interfaces (but keep if they contain "wi-fi" or "wifi")
        exclude_keywords = ["vmware", "virtualbox", "vethernet", "zerotier", "vpn", "wsl", "loopback", "host-only", "tap-", "tun-"]
        if any(keyword in iface_name.lower() for keyword in exclude_keywords):
            if "wi-fi" not in iface_name.lower() and "wifi" not in iface_name.lower():
                continue

        # Keep only physical Ethernet or Wi-Fi adapters
        include_keywords = ["ethernet", "wi-fi", "wifi", "wireless", "local area connection"]
        if not any(keyword in iface_name.lower() for keyword in include_keywords):
            continue

        ipv4 = None
        mac = ""

        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ipv4 = addr
            elif addr.family == psutil.AF_LINK:
                mac = addr.address

        ipv4_address = ""
        ipv4_netmask = ""
        is_loopback = False
        if ipv4:
            ipv4_address = ipv4.address
            ipv4_netmask = ipv4.netmask
            is_loopback = ipv4.address.startswith("127.")

        if is_loopback:
            continue

        # Calculate subnet in CIDR notation if IPv4 exists
        subnet = ""
        if ipv4_address and ipv4_netmask:
            try:
                network = ipaddress.IPv4Network(
                    f"{ipv4_address}/{ipv4_netmask}", strict=False
                )
                subnet = str(network)
            except (ValueError, TypeError):
                pass

        interfaces.append(InterfaceInfo(
            name=iface_name,
            ip=ipv4_address,
            netmask=ipv4_netmask,
            mac=mac,
            subnet=subnet,
            is_up=is_up,
            is_loopback=is_loopback,
        ))

    # Try to detect default gateway
    gateway = _detect_gateway()
    if gateway:
        for iface in interfaces:
            net = ipaddress.IPv4Network(iface.subnet, strict=False)
            try:
                if ipaddress.IPv4Address(gateway) in net:
                    iface.gateway = gateway
                    break
            except ValueError:
                continue

    return interfaces


def get_best_interface() -> Optional[InterfaceInfo]:
    """
    Auto-select the most likely "useful" interface.
    Prefers: has gateway > private IP > first available.
    """
    interfaces = get_interfaces()
    if not interfaces:
        return None

    # Prefer interface with a gateway
    with_gateway = [i for i in interfaces if i.gateway]
    if with_gateway:
        return with_gateway[0]

    # Prefer private IP ranges
    private = [
        i for i in interfaces
        if ipaddress.IPv4Address(i.ip).is_private
    ]
    if private:
        return private[0]

    return interfaces[0]


def _detect_gateway() -> str:
    """Detect the default gateway IP (Windows & Linux)."""
    try:
        # Windows
        result = subprocess.run(
            ["ipconfig"],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW
            if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        # Look for "Default Gateway" lines
        for line in result.stdout.splitlines():
            if "Default Gateway" in line or "Gateway" in line:
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    return match.group(1)
    except Exception:
        pass

    try:
        # Linux fallback
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass

    return ""


def get_subnet_hosts(subnet: str) -> list[str]:
    """Get all host IPs in a subnet (excluding network and broadcast)."""
    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []
