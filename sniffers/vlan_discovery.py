"""
VLAN Discovery Engine — discovers VLANs, subnets, switches, and routing
topology using both passive protocol sniffing AND active non-admin probing.

Passive (requires admin): CDP, LLDP, 802.1Q, OSPF, EIGRP, RIP, STP, HSRP/VRRP.
Active  (NO admin needed): SNMP queries, gateway sweep, cross-VLAN reachability,
                           router fingerprinting, ARP gateway MAC analysis.

The active probes are the primary discovery method — they work without
admin rights and can discover remote VLANs beyond the local subnet.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import struct
import subprocess
import threading
import time
from typing import Callable, Optional

from core.models import VLANInfo, SubnetInfo, SwitchInfo, RoutingEntry, Device, DeviceStatus


class VLANDiscovery:
    """
    Passively discovers network infrastructure by sniffing
    CDP, LLDP, 802.1Q, routing protocols, and STP.
    """

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._probe_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._start_time: float = 0.0

        # Discovered intelligence
        self._vlans: dict[int, VLANInfo] = {}                  # VLAN ID -> VLANInfo
        self._subnets: dict[str, SubnetInfo] = {}              # CIDR -> SubnetInfo
        self._switches: dict[str, SwitchInfo] = {}             # device_id -> SwitchInfo
        self._routes: dict[str, RoutingEntry] = {}             # "dest|nexthop" -> RoutingEntry
        self._observed_ips: dict[str, set[str]] = {}           # Subnet prefix -> set of IPs
        self._traceroute_hops: list[str] = []                  # Ordered list of upstream router IPs

        # Protocol packet counters
        self._protocol_counts: dict[str, int] = {}
        self._total_packets: int = 0

        # Active probe results
        self._security_findings: list[dict] = []               # Security audit findings
        self._probe_status: str = "idle"                       # idle / running / complete
        self._probed_gateways: set[str] = set()                # IPs already probed
        self._snmp_communities_found: dict[str, str] = {}      # IP -> working community
        self._reachable_gateways: dict[str, dict] = {}         # IP -> {ports, method}
        self._cross_vlan_hosts: list[dict] = []                 # Hosts found on remote VLANs

        # Callbacks
        self._on_switch_found: Optional[Callable[[SwitchInfo], None]] = None
        self._on_vlan_found: Optional[Callable[[VLANInfo], None]] = None

    @property
    def is_running(self) -> bool:
        return self._running

    def start(
        self,
        interface: str = "",
        on_switch_found: Optional[Callable[[SwitchInfo], None]] = None,
        on_vlan_found: Optional[Callable[[VLANInfo], None]] = None,
    ) -> None:
        """Start the VLAN discovery sniffer."""
        if self._running:
            return

        self._running = True
        self._start_time = time.time()
        self._on_switch_found = on_switch_found
        self._on_vlan_found = on_vlan_found

        # Immediately seed baseline intelligence from local adapters and inventory
        self._seed_local_network_intelligence()

        # Thread 1: Passive infrastructure sniffer (requires admin, fails gracefully)
        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(interface,),
            daemon=True,
        )
        self._thread.start()

        # Thread 2: OS-level discovery (route table, ARP, traceroute — no admin)
        threading.Thread(
            target=self._run_traceroute_discovery,
            daemon=True,
        ).start()

        # Thread 3: Active probes (SNMP, gateway sweep, cross-VLAN — no admin)
        self._probe_thread = threading.Thread(
            target=self._run_active_probes,
            daemon=True,
        )
        self._probe_thread.start()

    def _seed_local_network_intelligence(self) -> None:
        """Seed local adapter subnets, default gateway, and central inventory into VLAN discovery."""
        try:
            from network.interfaces import get_interfaces
            ifaces = get_interfaces()
            for iface in ifaces:
                if iface.subnet:
                    self._register_subnet(
                        cidr=iface.subnet,
                        gateway=iface.gateway,
                        source_protocol="local_adapter",
                        source_router=iface.gateway or "Local Host",
                    )
                    self._register_vlan(
                        vlan_id=1,
                        name="Default / Native VLAN",
                        subnet=iface.subnet,
                        source_protocol="local_adapter",
                        is_native=True,
                    )
                    if iface.gateway:
                        self._inject_device_to_inventory(
                            ip=iface.gateway,
                            hostname=f"Gateway-{iface.gateway}",
                            method="LOCAL_GATEWAY"
                        )
        except Exception as e:
            print(f"[VLANDiscovery] Local adapter seeding error: {e}")

        # Sync known devices from central inventory if available
        try:
            import api
            if hasattr(api, 'inventory') and api.inventory:
                devices = api.inventory.get_all_devices()
                for dev in devices:
                    if dev.ip and not dev.ip.startswith("127."):
                        self._track_ip_for_subnet(dev.ip, "inventory")
        except Exception:
            pass

    def _run_traceroute_discovery(self) -> None:
        """Use native OS commands to discover routers, subnets, and cross-subnet devices."""
        import subprocess
        import re
        import json

        print("[VLANDiscovery] Running OS-level network intelligence (route + arp + tracert) ...")

        # ── 1. PowerShell / Windows Get-NetRoute ──────────────────────
        try:
            if hasattr(subprocess, "CREATE_NO_WINDOW"):
                try:
                    ps_cmd = (
                        "Get-NetRoute -AddressFamily IPv4 | "
                        "Select-Object DestinationPrefix, NextHop | "
                        "ConvertTo-Json -Compress"
                    )
                    proc = subprocess.run(
                        ["powershell", "-NoProfile", "-Command", ps_cmd],
                        capture_output=True, text=True, timeout=8,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    if proc.returncode == 0 and proc.stdout.strip():
                        routes_data = json.loads(proc.stdout)
                        if isinstance(routes_data, dict):
                            routes_data = [routes_data]
                        for r in routes_data:
                            prefix = r.get("DestinationPrefix", "")
                            next_hop = r.get("NextHop", "")
                            if not prefix:
                                continue
                            if prefix == "0.0.0.0/0":
                                if next_hop and next_hop != "0.0.0.0" and not next_hop.startswith("::"):
                                    try:
                                        gw_ip = ipaddress.IPv4Address(next_hop)
                                        if gw_ip.is_private:
                                            net = ipaddress.IPv4Network(f"{next_hop}/24", strict=False)
                                            self._register_subnet(cidr=str(net), gateway=next_hop, source_protocol="default_route", source_router="local_os")
                                            self._inject_device_to_inventory(ip=next_hop, hostname=f"Gateway-{next_hop}", method="DEFAULT_ROUTE")
                                    except Exception:
                                        pass
                                continue
                            try:
                                net = ipaddress.IPv4Network(prefix, strict=False)
                                if net.prefixlen <= 29 and not net.is_loopback and not net.is_multicast:
                                    gw_str = next_hop if (next_hop and next_hop != "0.0.0.0" and not next_hop.startswith("::")) else ""
                                    self._register_subnet(
                                        cidr=str(net),
                                        gateway=gw_str,
                                        source_protocol="route_table",
                                        source_router="local_os"
                                    )
                                    if gw_str:
                                        self._inject_device_to_inventory(ip=gw_str, hostname=f"Router-{gw_str}", method="ROUTE_TABLE")
                            except Exception:
                                pass
                except Exception:
                    pass
        except Exception:
            pass

        # ── 2. Windows 'route print' fallback ─────────────────────────
        try:
            proc = subprocess.run(
                ["route", "print"],
                capture_output=True, text=True, timeout=8,
                creationflags=subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            for line in proc.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4:
                    dest, mask, gw = parts[0], parts[1], parts[2]
                    if dest in ("127.0.0.0", "127.0.0.1", "224.0.0.0", "255.255.255.255") or mask == "255.255.255.255":
                        continue
                    if dest == "0.0.0.0" and gw != "On-link":
                        try:
                            gw_ip = ipaddress.IPv4Address(gw)
                            if gw_ip.is_private:
                                net = ipaddress.IPv4Network(f"{gw}/24", strict=False)
                                self._register_subnet(cidr=str(net), gateway=gw, source_protocol="default_route", source_router="local_os")
                                self._inject_device_to_inventory(ip=gw, hostname=f"Gateway-{gw}", method="ROUTE_TABLE")
                        except Exception:
                            pass
                        continue
                    try:
                        net_dest = ipaddress.IPv4Address(dest)
                        if net_dest.is_private and not net_dest.is_loopback:
                            cidr = str(ipaddress.IPv4Network(f"{dest}/{mask}", strict=False))
                            gw_str = gw if gw != "On-link" and gw != "0.0.0.0" else ""
                            self._register_subnet(
                                cidr=cidr,
                                gateway=gw_str,
                                source_protocol="route_table",
                                source_router="local_os"
                            )
                            if gw_str:
                                self._inject_device_to_inventory(ip=gw_str, hostname=f"Router-{gw_str}", method="ROUTE_TABLE")
                    except Exception:
                        continue
        except Exception as e:
            print(f"[VLANDiscovery] route print failed: {e}")

        # ── 3. Full 'arp -a' discovery ─────────────────────────────────
        try:
            proc = subprocess.run(
                ["arp", "-a"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            arp_re = re.compile(
                r"(\d+\.\d+\.\d+\.\d+)\s+"
                r"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}"
                r"[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})"
            )
            for line in proc.stdout.splitlines():
                m = arp_re.search(line)
                if not m:
                    continue
                ip_str = m.group(1)
                mac_str = m.group(2).replace("-", ":").upper()
                if mac_str in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                    continue
                try:
                    ip = ipaddress.IPv4Address(ip_str)
                    if ip.is_private and not ip.is_loopback and not ip.is_multicast:
                        net = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
                        self._register_subnet(
                            cidr=str(net),
                            source_protocol="arp_table",
                        )
                        self._inject_device_to_inventory(
                            ip=ip_str,
                            mac=mac_str,
                            method="ARP_TABLE_GLOBAL"
                        )
                except Exception:
                    continue
        except Exception as e:
            print(f"[VLANDiscovery] arp -a failed: {e}")

        # ── 4. Windows 'tracert' for upstream hops ────────────────────
        try:
            proc = subprocess.run(
                ["tracert", "-d", "-w", "400", "-h", "6", "8.8.8.8"],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            hops = []
            for line in proc.stdout.splitlines():
                match = re.search(r"^\s*\d+\s+.*?(\d+\.\d+\.\d+\.\d+)\s*$", line.strip())
                if match:
                    ip_str = match.group(1)
                    try:
                        ip = ipaddress.IPv4Address(ip_str)
                        if ip.is_private:
                            hops.append(ip_str)
                            net = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
                            self._register_subnet(
                                cidr=str(net),
                                gateway=ip_str,
                                source_protocol="traceroute",
                                source_router="tracert"
                            )
                            self._inject_device_to_inventory(
                                ip=ip_str,
                                hostname=f"Router-{ip_str}",
                                method="TRACEROUTE"
                            )
                    except Exception:
                        continue

            with self._lock:
                self._traceroute_hops = hops

        except Exception as e:
            print(f"[VLANDiscovery] tracert failed: {e}")

        print(f"[VLANDiscovery] OS-level discovery complete. Known subnets: {len(self._subnets)}")

    # ── Active Probes (No Admin Required) ────────────────────────

    def _run_active_probes(self) -> None:
        """
        Continuous active probing thread — runs discovery once, then enters
        a tight sweep loop that re-scans discovered VLAN subnets every 5s.
        Acts like a persistent sniffer for cross-VLAN traffic.
        """
        with self._lock:
            self._probe_status = "running"

        print("[VLANDiscovery] Active probes starting (no admin required)...")

        # Wait for OS-level discovery to populate gateways
        time.sleep(4)

        try:
            # ── Initial Discovery (runs once) ──────────────────────

            # Phase 1: Collect known gateway IPs
            gateway_ips = self._collect_gateway_targets()
            print(f"[VLANDiscovery] Active probes: {len(gateway_ips)} gateway targets collected")

            # Phase 2: SNMP query all known gateways
            for gw_ip in gateway_ips:
                if not self._running:
                    return
                self._probe_snmp_router(gw_ip)

            # Phase 3: Gateway subnet sweep
            if self._running:
                self._probe_gateway_sweep()

            # Phase 4: SNMP query newly discovered gateways
            new_gateways = set(self._reachable_gateways.keys()) - self._probed_gateways
            for gw_ip in new_gateways:
                if not self._running:
                    return
                self._probe_snmp_router(gw_ip)

            # Phase 5: Router fingerprinting
            if self._running:
                self._probe_router_fingerprint()

            # Phase 6: Cross-VLAN reachability testing
            if self._running:
                self._probe_cross_vlan_reachability()

            # Phase 7: ARP gateway MAC analysis
            if self._running:
                self._probe_arp_gateway_analysis()

            # Phase 8: First host sweep
            if self._running:
                self._probe_remote_subnet_hosts()

            print(f"[VLANDiscovery] Initial discovery complete. "
                  f"Entering continuous sweep mode (every 5s)...")

            # ── Continuous Sweep Loop ──────────────────────────────
            # Re-sweep discovered subnets every 5s to catch new devices.
            # Re-run gateway discovery every 60s to find new VLANs.

            sweep_count = 0
            last_gateway_rescan = time.time()

            while self._running:
                time.sleep(5)
                if not self._running:
                    break

                sweep_count += 1

                # Re-run gateway discovery every 60 seconds to find new VLANs
                now = time.time()
                if now - last_gateway_rescan > 60:
                    last_gateway_rescan = now
                    print(f"[VLANDiscovery] Re-scanning for new gateways...")
                    self._probe_gateway_sweep()
                    # SNMP probe any new ones
                    new_gw = set(self._reachable_gateways.keys()) - self._probed_gateways
                    for gw_ip in new_gw:
                        if not self._running:
                            break
                        self._probe_snmp_router(gw_ip)

                # Sweep all discovered remote subnets for live hosts
                if self._running:
                    self._probe_remote_subnet_hosts()

                if sweep_count % 12 == 0:  # Log every ~60s
                    with self._lock:
                        host_count = len(self._cross_vlan_hosts)
                    print(f"[VLANDiscovery] Sweep #{sweep_count} complete. "
                          f"Total cross-VLAN hosts: {host_count}")

        except Exception as e:
            print(f"[VLANDiscovery] Active probes error: {e}")
        finally:
            with self._lock:
                self._probe_status = "complete"
            print(f"[VLANDiscovery] Active probes stopped. Findings: {len(self._security_findings)}, "
                  f"VLANs: {len(self._vlans)}, Subnets: {len(self._subnets)}, "
                  f"Switches: {len(self._switches)}, Cross-VLAN hosts: {len(self._cross_vlan_hosts)}")

    def _collect_gateway_targets(self) -> list[str]:
        """Collect all known gateway IPs from subnets, routes, and local adapters."""
        targets = set()

        with self._lock:
            for subnet in self._subnets.values():
                if subnet.gateway and subnet.gateway != "0.0.0.0":
                    targets.add(subnet.gateway)
                if subnet.dhcp_server and subnet.dhcp_server != "0.0.0.0":
                    targets.add(subnet.dhcp_server)

        # Also try the local gateway
        try:
            from network.interfaces import get_best_interface
            best = get_best_interface()
            if best and best.gateway:
                targets.add(best.gateway)
        except Exception:
            pass

        return list(targets)

    def _add_finding(self, severity: str, finding_type: str, target: str, message: str, details: str = "") -> None:
        """Register a security audit finding (thread-safe)."""
        finding = {
            "severity": severity,       # critical / high / medium / low / info
            "type": finding_type,       # snmp_open, cross_vlan_access, mgmt_exposed, etc.
            "target": target,           # IP address involved
            "message": message,
            "details": details,
            "timestamp": time.time(),
        }
        with self._lock:
            # Deduplicate by (type, target)
            key = (finding_type, target)
            for existing in self._security_findings:
                if (existing["type"], existing["target"]) == key:
                    return
            self._security_findings.append(finding)

    # ── SNMP Router Probe ────────────────────────────────────────

    def _probe_snmp_router(self, ip: str) -> None:
        """
        Query a gateway/router via SNMP to discover all VLANs, interfaces,
        ARP entries, and routes. This is the most powerful discovery method.
        """
        if ip in self._probed_gateways:
            return
        self._probed_gateways.add(ip)

        self._record_hit("SNMP_PROBE")

        try:
            from network.snmp_client import (
                snmp_test_community,
                snmp_get_system_info,
                snmp_get_interfaces,
                snmp_get_arp_table,
                snmp_get_routes,
            )
        except ImportError:
            print("[VLANDiscovery] SNMP client module not available")
            return

        # Try common community strings
        communities = ["public", "private"]
        working_community = None

        for community in communities:
            if not self._running:
                return
            try:
                if snmp_test_community(ip, community, timeout=2.0):
                    working_community = community
                    break
            except Exception:
                continue

        if not working_community:
            return

        print(f"[VLANDiscovery] SNMP SUCCESS: {ip} responds to community '{working_community}'")

        with self._lock:
            self._snmp_communities_found[ip] = working_community

        # Security finding: SNMP with default community is open
        self._add_finding(
            severity="high",
            finding_type="snmp_open",
            target=ip,
            message=f"SNMP accessible with default community string '{working_community}' on {ip}",
            details=f"The router/switch at {ip} responds to SNMPv2c queries with the "
                    f"'{working_community}' community string. This exposes the entire network "
                    f"topology, all VLANs, ARP tables, and routing information to any device "
                    f"on the network without authentication."
        )

        # ── Get System Info ──
        try:
            sys_info = snmp_get_system_info(ip, working_community, timeout=2.0)

            device_id = sys_info.get("sys_name", "") or f"Router-{ip}"
            platform = sys_info.get("sys_descr", "")

            if device_id:
                self._register_switch(
                    device_id=str(device_id),
                    management_ip=ip,
                    platform=str(platform)[:120] if platform else "",
                    software_version="",
                    source_protocol="snmp",
                    capabilities=["Router"],
                )
                print(f"[VLANDiscovery] SNMP: Device '{device_id}' — {str(platform)[:80]}")

        except Exception as e:
            print(f"[VLANDiscovery] SNMP system info error: {e}")

        # ── Get Interfaces (discovers VLANs!) ──
        try:
            interfaces = snmp_get_interfaces(ip, working_community, timeout=2.0)
            vlan_count = 0

            for iface in interfaces:
                name = iface.get("name", "")
                iface_ip = iface.get("ip", "")
                iface_mask = iface.get("netmask", "")
                iface_type = iface.get("type", 0)

                # Detect VLAN interfaces by name pattern or type
                vlan_id = None
                name_lower = name.lower() if name else ""

                # Match patterns: "vlan7", "vlan 7", "VLAN0007", "Vlan7"
                vlan_match = re.search(r'vlan\s*0*(\d+)', name_lower)
                if vlan_match:
                    vlan_id = int(vlan_match.group(1))
                # Also match by interface type (53=propVirtual, 135=l2vlan, 136=l3ipvlan)
                elif iface_type in (53, 135, 136):
                    # Try to extract VLAN ID from interface index
                    idx = iface.get("index", 0)
                    if 1 <= idx <= 4094:
                        vlan_id = idx

                if vlan_id and 1 <= vlan_id <= 4094:
                    vlan_count += 1
                    subnet_cidr = ""
                    if iface_ip and iface_mask:
                        try:
                            net = ipaddress.IPv4Network(f"{iface_ip}/{iface_mask}", strict=False)
                            subnet_cidr = str(net)
                            self._register_subnet(
                                cidr=subnet_cidr,
                                gateway=iface_ip,
                                source_protocol="snmp",
                                source_router=str(sys_info.get("sys_name", ip)) if sys_info else ip,
                                vlan_id=vlan_id,
                            )
                        except Exception:
                            pass

                    self._register_vlan(
                        vlan_id=vlan_id,
                        name=name or f"VLAN {vlan_id}",
                        subnet=subnet_cidr,
                        source_protocol="snmp",
                        source_switch=str(sys_info.get("sys_name", ip)) if sys_info else ip,
                    )

                    print(f"[VLANDiscovery] SNMP: VLAN {vlan_id} — '{name}', IP: {iface_ip}/{iface_mask}")

                elif iface_ip and iface_mask and not iface_ip.startswith("127."):
                    # Non-VLAN interface with IP — still register the subnet
                    try:
                        net = ipaddress.IPv4Network(f"{iface_ip}/{iface_mask}", strict=False)
                        self._register_subnet(
                            cidr=str(net),
                            gateway=iface_ip,
                            source_protocol="snmp",
                            source_router=str(sys_info.get("sys_name", ip)) if sys_info else ip,
                        )
                    except Exception:
                        pass

            if vlan_count:
                print(f"[VLANDiscovery] SNMP: {vlan_count} VLANs discovered on {ip}")

        except Exception as e:
            print(f"[VLANDiscovery] SNMP interfaces error: {e}")

        # ── Get ARP Table (devices on ALL VLANs!) ──
        try:
            arp_entries = snmp_get_arp_table(ip, working_community, timeout=2.0)
            arp_count = 0

            for entry in arp_entries:
                arp_ip = entry.get("ip", "")
                arp_mac = entry.get("mac", "")
                if arp_ip and not arp_ip.startswith("127."):
                    arp_count += 1
                    self._track_ip_for_subnet(arp_ip, "snmp_arp")
                    self._inject_device_to_inventory(
                        ip=arp_ip,
                        mac=arp_mac,
                        method="SNMP_ARP"
                    )

            if arp_count:
                print(f"[VLANDiscovery] SNMP: {arp_count} ARP entries from {ip} (devices on all VLANs)")

        except Exception as e:
            print(f"[VLANDiscovery] SNMP ARP table error: {e}")

        # ── Get Routing Table ──
        try:
            routes = snmp_get_routes(ip, working_community, timeout=2.0)
            route_count = 0

            for route in routes:
                dest = route.get("destination", "")
                mask = route.get("netmask", "")
                next_hop = route.get("next_hop", "")

                if not dest or dest == "0.0.0.0":
                    continue

                try:
                    dest_ip = ipaddress.IPv4Address(dest)
                    if dest_ip.is_loopback or dest_ip.is_multicast:
                        continue

                    cidr = str(ipaddress.IPv4Network(f"{dest}/{mask}", strict=False)) if mask else f"{dest}/32"

                    proto_map = {2: "local", 3: "static", 8: "rip", 13: "ospf", 14: "bgp"}
                    proto_name = proto_map.get(route.get("protocol", 0), "other")

                    self._register_route(
                        destination=cidr,
                        next_hop=next_hop if next_hop != "0.0.0.0" else "",
                        protocol=f"snmp_{proto_name}",
                        advertising_router=ip,
                    )
                    self._register_subnet(
                        cidr=cidr,
                        gateway=next_hop if next_hop != "0.0.0.0" else "",
                        source_protocol="snmp_route",
                        source_router=ip,
                    )
                    route_count += 1

                except Exception:
                    continue

            if route_count:
                print(f"[VLANDiscovery] SNMP: {route_count} routes from {ip}")

        except Exception as e:
            print(f"[VLANDiscovery] SNMP routes error: {e}")

    # ── Gateway Subnet Sweep ─────────────────────────────────────

    def _probe_gateway_sweep(self) -> None:
        """
        TCP connect scan to common gateway addresses (.1) across private subnets.
        Finds reachable gateways on remote VLANs — proves inter-VLAN routing exists.
        No admin rights needed (uses standard TCP sockets).
        """
        print("[VLANDiscovery] Starting gateway subnet sweep...")
        self._record_hit("GATEWAY_SWEEP")

        # Build target list: 192.168.X.1 for X=1-254, 10.0.X.1 for common, 172.16-31.X.1
        targets = []

        # 192.168.X.1 — most common for small/medium VLAN setups
        for x in range(1, 255):
            targets.append(f"192.168.{x}.1")

        # 10.0.X.1 for common office subnets
        for x in range(0, 20):
            targets.append(f"10.0.{x}.1")
        for x in range(0, 20):
            targets.append(f"10.10.{x}.1")

        # 172.16-31.X.1
        for second in range(16, 32):
            for x in range(0, 5):
                targets.append(f"172.{second}.{x}.1")

        # Filter out IPs we already know about from local subnets
        known_ips = set()
        with self._lock:
            for subnet in self._subnets.values():
                if subnet.gateway:
                    known_ips.add(subnet.gateway)

        # Test ports: 80(HTTP), 443(HTTPS), 22(SSH), 8291(WinBox), 53(DNS)
        test_ports = [80, 443, 22, 8291, 53]
        found = 0

        for target_ip in targets:
            if not self._running:
                break

            # Skip IPs we already know about
            if target_ip in known_ips or target_ip in self._reachable_gateways:
                continue

            # Quick TCP connect probe
            open_ports = []
            for port in test_ports:
                if not self._running:
                    break
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.25)
                    result = sock.connect_ex((target_ip, port))
                    sock.close()
                    if result == 0:
                        open_ports.append(port)
                except Exception:
                    pass

            if open_ports:
                found += 1
                with self._lock:
                    self._reachable_gateways[target_ip] = {
                        "ports": open_ports,
                        "method": "gateway_sweep"
                    }

                # Register as a subnet + router
                try:
                    net = ipaddress.IPv4Network(f"{target_ip}/24", strict=False)
                    self._register_subnet(
                        cidr=str(net),
                        gateway=target_ip,
                        source_protocol="gateway_sweep",
                        source_router=target_ip,
                    )
                except Exception:
                    pass

                self._inject_device_to_inventory(
                    ip=target_ip,
                    hostname=f"Gateway-{target_ip}",
                    method="GATEWAY_SWEEP",
                    ports=open_ports,
                )

                # Infer a VLAN from the third octet
                parts = target_ip.split(".")
                if parts[0] == "192" and parts[1] == "168":
                    vlan_id = int(parts[2])
                    if 1 <= vlan_id <= 4094:
                        self._register_vlan(
                            vlan_id=vlan_id,
                            name=f"VLAN {vlan_id} (Inferred)",
                            subnet=f"192.168.{vlan_id}.0/24",
                            source_protocol="gateway_sweep",
                        )

                print(f"[VLANDiscovery] GATEWAY SWEEP: {target_ip} is REACHABLE (ports: {open_ports})")

        print(f"[VLANDiscovery] Gateway sweep complete. {found} new reachable gateways found.")

    # ── Cross-VLAN Reachability ───────────────────────────────────

    def _probe_cross_vlan_reachability(self) -> None:
        """
        Test if devices/gateways on remote VLANs are reachable from our VLAN.
        Reachability = missing inter-VLAN ACLs = security finding.
        """
        print("[VLANDiscovery] Testing cross-VLAN reachability...")
        self._record_hit("CROSS_VLAN_TEST")

        # Determine our local subnet
        local_subnet = None
        try:
            from network.interfaces import get_best_interface
            best = get_best_interface()
            if best and best.subnet:
                local_subnet = ipaddress.IPv4Network(best.subnet, strict=False)
        except Exception:
            return

        if not local_subnet:
            return

        # Test reachability to each discovered remote gateway
        remote_gateways = []
        with self._lock:
            for subnet in self._subnets.values():
                if subnet.gateway and subnet.gateway != "0.0.0.0":
                    try:
                        gw_ip = ipaddress.IPv4Address(subnet.gateway)
                        if gw_ip not in local_subnet and gw_ip.is_private:
                            remote_gateways.append((subnet.gateway, subnet.cidr, subnet.source_protocol))
                    except Exception:
                        continue

        for gw_ip, cidr, source in remote_gateways:
            if not self._running:
                break

            # Ping test (subprocess, no admin needed)
            reachable = False
            try:
                proc = subprocess.run(
                    ["ping", "-n", "1", "-w", "500", gw_ip],
                    capture_output=True, text=True, timeout=3,
                    creationflags=subprocess.CREATE_NO_WINDOW
                    if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
                )
                if "TTL=" in proc.stdout or "ttl=" in proc.stdout:
                    reachable = True
            except Exception:
                pass

            # TCP fallback check
            if not reachable:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((gw_ip, 80))
                    sock.close()
                    if result == 0:
                        reachable = True
                except Exception:
                    pass

            if reachable:
                self._add_finding(
                    severity="high",
                    finding_type="cross_vlan_access",
                    target=gw_ip,
                    message=f"Cross-VLAN routing to {gw_ip} ({cidr}) has no ACL restrictions",
                    details=f"From your VLAN ({local_subnet}), the gateway {gw_ip} on "
                            f"remote subnet {cidr} (discovered via {source}) is fully reachable. "
                            f"This means inter-VLAN traffic is not filtered by access control lists. "
                            f"Any device on your VLAN can communicate with devices on {cidr}."
                )
                print(f"[VLANDiscovery] CROSS-VLAN: {gw_ip} ({cidr}) is REACHABLE from {local_subnet} — NO ACL!")

    # ── Router Fingerprinting ────────────────────────────────────

    def _probe_router_fingerprint(self) -> None:
        """
        Probe well-known management ports on discovered gateways to identify
        router brands and flag exposed management interfaces.
        """
        print("[VLANDiscovery] Fingerprinting routers...")
        self._record_hit("ROUTER_FINGERPRINT")

        # Collect all unique gateway IPs
        gw_ips = set()
        with self._lock:
            for subnet in self._subnets.values():
                if subnet.gateway and subnet.gateway != "0.0.0.0":
                    gw_ips.add(subnet.gateway)
            for ip in self._reachable_gateways:
                gw_ips.add(ip)

        # Management port signatures
        port_sigs = {
            8291: ("MikroTik WinBox", "MikroTik"),
            8728: ("MikroTik API", "MikroTik"),
            8729: ("MikroTik API-SSL", "MikroTik"),
            4786: ("Cisco Smart Install", "Cisco"),
            80:   ("HTTP Management", ""),
            443:  ("HTTPS Management", ""),
            22:   ("SSH Management", ""),
            23:   ("Telnet Management", ""),
            161:  ("SNMP", ""),
        }

        for gw_ip in gw_ips:
            if not self._running:
                break

            open_mgmt_ports = []
            detected_vendor = ""

            for port, (service_name, vendor) in port_sigs.items():
                if not self._running:
                    break

                # UDP check for SNMP (port 161)
                if port == 161:
                    try:
                        from network.snmp_client import snmp_test_community
                        if snmp_test_community(gw_ip, "public", timeout=1.5):
                            open_mgmt_ports.append((port, service_name))
                            if not detected_vendor:
                                detected_vendor = vendor
                    except Exception:
                        pass
                    continue

                # TCP check for other ports
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((gw_ip, port))
                    sock.close()
                    if result == 0:
                        open_mgmt_ports.append((port, service_name))
                        if vendor and not detected_vendor:
                            detected_vendor = vendor
                except Exception:
                    pass

            if open_mgmt_ports:
                # Update switch record with vendor info
                if detected_vendor:
                    self._register_switch(
                        device_id=f"{detected_vendor}-{gw_ip}",
                        management_ip=gw_ip,
                        platform=detected_vendor,
                        source_protocol="fingerprint",
                        capabilities=["Router"],
                    )

                # Flag exposed management ports
                port_list = ", ".join(f"{p}({s})" for p, s in open_mgmt_ports)
                dangerous_ports = [p for p, s in open_mgmt_ports if p in (23, 80, 8291, 4786, 161)]

                if dangerous_ports:
                    self._add_finding(
                        severity="medium",
                        finding_type="mgmt_exposed",
                        target=gw_ip,
                        message=f"Router {gw_ip} exposes management interfaces: {port_list}",
                        details=f"The router at {gw_ip} has the following management ports open "
                                f"and accessible from user VLANs: {port_list}. "
                                f"Management access should be restricted to a dedicated management VLAN "
                                f"or filtered by ACLs."
                    )

                print(f"[VLANDiscovery] FINGERPRINT: {gw_ip} — {detected_vendor or 'Unknown'}, "
                      f"Ports: {port_list}")

    # ── ARP Gateway MAC Analysis ─────────────────────────────────

    def _probe_arp_gateway_analysis(self) -> None:
        """
        Enhanced ARP cache analysis: groups ARP entries by MAC address.
        If one MAC serves as gateway for IPs on different subnets,
        this confirms inter-VLAN routing through a shared router.
        """
        print("[VLANDiscovery] Analyzing ARP gateway MACs...")
        self._record_hit("ARP_ANALYSIS")

        try:
            proc = subprocess.run(
                ["arp", "-a"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )

            arp_re = re.compile(
                r"(\d+\.\d+\.\d+\.\d+)\s+"
                r"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}"
                r"[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})"
            )

            # Parse all ARP entries
            mac_to_ips: dict[str, list[str]] = {}
            for line in proc.stdout.splitlines():
                m = arp_re.search(line)
                if not m:
                    continue
                ip_str = m.group(1)
                mac_str = m.group(2).replace("-", ":").upper()
                if mac_str in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                    continue
                if mac_str not in mac_to_ips:
                    mac_to_ips[mac_str] = []
                mac_to_ips[mac_str].append(ip_str)

            # Find MACs that appear with IPs on different /24 subnets
            for mac, ips in mac_to_ips.items():
                subnets = set()
                for ip_str in ips:
                    try:
                        net = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
                        subnets.add(str(net))
                    except Exception:
                        continue

                if len(subnets) > 1:
                    # Same MAC, different subnets — this is a router doing inter-VLAN routing
                    subnet_list = ", ".join(sorted(subnets))
                    self._add_finding(
                        severity="info",
                        finding_type="inter_vlan_router",
                        target=mac,
                        message=f"MAC {mac} serves as gateway across multiple subnets: {subnet_list}",
                        details=f"The device with MAC address {mac} appears in the ARP table as the "
                                f"gateway for IPs across {len(subnets)} different subnets ({subnet_list}). "
                                f"This confirms inter-VLAN routing is performed by this device."
                    )
                    print(f"[VLANDiscovery] ARP ANALYSIS: MAC {mac} routes across {len(subnets)} subnets: {subnet_list}")

        except Exception as e:
            print(f"[VLANDiscovery] ARP analysis error: {e}")

    def run_manual_probe(self) -> dict:
        """Trigger active probes or an immediate sweep if already running."""
        if self._probe_status == "running":
            # Already in continuous mode — trigger an immediate host sweep
            threading.Thread(
                target=self._probe_remote_subnet_hosts,
                daemon=True,
            ).start()
            return {"status": "immediate_sweep_triggered"}

        self._probe_thread = threading.Thread(
            target=self._run_active_probes,
            daemon=True,
        )
        self._probe_thread.start()
        return {"status": "probes_started"}

    def sweep_subnet(self, cidr: str) -> dict:
        """Sweep a specific subnet for live hosts (callable from API)."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
        except Exception:
            return {"error": f"Invalid CIDR: {cidr}"}

        if net.prefixlen < 22:
            return {"error": "Subnet too large (max /22)"}

        hosts = [str(h) for h in net.hosts()]
        if len(hosts) > 254:
            hosts = hosts[:254]

        print(f"[VLANDiscovery] On-demand sweep of {net} ({len(hosts)} hosts)...")

        def _check_host(ip_str: str) -> dict | None:
            try:
                proc = subprocess.run(
                    ["ping", "-n", "1", "-w", "300", ip_str],
                    capture_output=True, text=True, timeout=2,
                    creationflags=subprocess.CREATE_NO_WINDOW
                    if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
                )
                if "TTL=" in proc.stdout or "ttl=" in proc.stdout:
                    ttl = 0
                    m = re.search(r'TTL=(\d+)', proc.stdout, re.IGNORECASE)
                    if m:
                        ttl = int(m.group(1))
                    return {"ip": ip_str, "ttl": ttl, "method": "ping"}
            except Exception:
                pass
            for port in [80, 443, 22, 554, 8080, 8291]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.3)
                    result = sock.connect_ex((ip_str, port))
                    sock.close()
                    if result == 0:
                        return {"ip": ip_str, "port": port, "method": "tcp"}
                except Exception:
                    pass
            return None

        found = []
        with ThreadPoolExecutor(max_workers=40) as pool:
            futures = {pool.submit(_check_host, ip): ip for ip in hosts}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    ip_str = result["ip"]
                    ttl = result.get("ttl", 0)
                    os_hint = ""
                    if ttl > 0:
                        if ttl <= 64:
                            os_hint = "Linux/macOS/IoT"
                        elif ttl <= 128:
                            os_hint = "Windows"
                        else:
                            os_hint = "Network Device"

                    entry = {
                        "ip": ip_str,
                        "subnet": str(net),
                        "ttl": ttl,
                        "os_hint": os_hint,
                        "method": result.get("method", "ping"),
                        "open_port": result.get("port"),
                        "timestamp": time.time(),
                    }
                    found.append(entry)

                    with self._lock:
                        if not any(h["ip"] == ip_str for h in self._cross_vlan_hosts):
                            self._cross_vlan_hosts.append(entry)

                    self._inject_device_to_inventory(
                        ip=ip_str,
                        hostname=f"{os_hint}-{ip_str}" if os_hint else "",
                        method="SUBNET_SWEEP"
                    )
                    print(f"[VLANDiscovery] SWEEP: {ip_str} on {net} (TTL={ttl}, {os_hint})")

        print(f"[VLANDiscovery] On-demand sweep of {net} complete: {len(found)} hosts found.")
        return {"subnet": str(net), "hosts_found": len(found), "hosts": found}


    # ── Remote Subnet Host Sweep ─────────────────────────────────

    def _probe_remote_subnet_hosts(self) -> None:
        """
        Ping/TCP sweep all discovered remote subnets to find live host IPs.
        Uses concurrent threads for speed. No admin required.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        print("[VLANDiscovery] Sweeping remote subnets for live hosts...")
        self._record_hit("HOST_SWEEP")

        # Determine local subnet
        local_subnet = None
        try:
            from network.interfaces import get_best_interface
            best = get_best_interface()
            if best and best.subnet:
                local_subnet = ipaddress.IPv4Network(best.subnet, strict=False)
        except Exception:
            pass

        # Collect remote subnets to sweep — ONLY those confirmed reachable
        remote_subnets = []
        with self._lock:
            for subnet_info in self._subnets.values():
                try:
                    net = ipaddress.IPv4Network(subnet_info.cidr, strict=False)
                    # Skip local subnet, loopback, link-local, huge subnets
                    if net.prefixlen < 22:
                        continue
                    if net.is_loopback or net.is_link_local or net.is_multicast:
                        continue
                    if not net.is_private:
                        continue
                    if local_subnet and net == local_subnet:
                        continue
                    # ONLY sweep subnets where we confirmed the gateway is actually
                    # reachable — gateway_sweep and snmp both verify connectivity.
                    # DO NOT sweep traceroute subnets — those are ISP transit hops
                    # that will waste minutes timing out on 254 unreachable hosts.
                    src = subnet_info.source_protocol or ""
                    if any(kw in src for kw in ("snmp", "gateway_sweep")):
                        remote_subnets.append(net)
                except Exception:
                    continue

        if not remote_subnets:
            print("[VLANDiscovery] No confirmed-reachable remote subnets to sweep.")
            return

        # Prioritize 192.168.x.x subnets (most common for VLAN setups)
        remote_subnets.sort(key=lambda n: (0 if str(n).startswith("192.168.") else 1, str(n)))

        print(f"[VLANDiscovery] Sweeping {len(remote_subnets)} confirmed-reachable subnet(s): "
              f"{', '.join(str(s) for s in remote_subnets)}")


        def _ping_host(ip_str: str) -> dict | None:
            """Ping a single host. Returns info dict if alive, None otherwise."""
            if not self._running:
                return None
            try:
                proc = subprocess.run(
                    ["ping", "-n", "1", "-w", "300", ip_str],
                    capture_output=True, text=True, timeout=2,
                    creationflags=subprocess.CREATE_NO_WINDOW
                    if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
                )
                if "TTL=" in proc.stdout or "ttl=" in proc.stdout:
                    # Extract TTL for fingerprinting
                    ttl = 0
                    ttl_match = re.search(r'TTL=(\d+)', proc.stdout, re.IGNORECASE)
                    if ttl_match:
                        ttl = int(ttl_match.group(1))
                    return {"ip": ip_str, "ttl": ttl, "method": "ping"}
            except Exception:
                pass

            # TCP fallback: try common ports
            for port in [80, 443, 22, 554, 8080, 8291]:
                if not self._running:
                    return None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.3)
                    result = sock.connect_ex((ip_str, port))
                    sock.close()
                    if result == 0:
                        return {"ip": ip_str, "port": port, "method": "tcp"}
                except Exception:
                    pass
            return None

        total_found = 0
        for subnet in remote_subnets:
            if not self._running:
                break

            # Generate host IPs (skip .0 network and .255 broadcast)
            hosts = [str(h) for h in subnet.hosts()]
            if len(hosts) > 254:
                hosts = hosts[:254]  # Cap at /24 size

            print(f"[VLANDiscovery] Sweeping {subnet} ({len(hosts)} hosts)...")

            with ThreadPoolExecutor(max_workers=40) as pool:
                futures = {pool.submit(_ping_host, ip): ip for ip in hosts}
                for future in as_completed(futures):
                    if not self._running:
                        break
                    result = future.result()
                    if result:
                        ip_str = result["ip"]
                        total_found += 1

                        # Determine OS hint from TTL
                        ttl = result.get("ttl", 0)
                        os_hint = ""
                        if ttl > 0:
                            if ttl <= 64:
                                os_hint = "Linux/macOS/IoT"
                            elif ttl <= 128:
                                os_hint = "Windows"
                            else:
                                os_hint = "Network Device"

                        host_entry = {
                            "ip": ip_str,
                            "subnet": str(subnet),
                            "ttl": ttl,
                            "os_hint": os_hint,
                            "method": result.get("method", "ping"),
                            "open_port": result.get("port"),
                            "timestamp": time.time(),
                        }

                        with self._lock:
                            # Deduplicate
                            if not any(h["ip"] == ip_str for h in self._cross_vlan_hosts):
                                self._cross_vlan_hosts.append(host_entry)

                        # Inject into central inventory
                        self._inject_device_to_inventory(
                            ip=ip_str,
                            hostname=f"{os_hint}-{ip_str}" if os_hint else "",
                            method="CROSS_VLAN_SWEEP"
                        )

                        print(f"[VLANDiscovery] HOST FOUND: {ip_str} on {subnet} "
                              f"(TTL={ttl}, {os_hint}, via {result.get('method')})")

        print(f"[VLANDiscovery] Host sweep complete. {total_found} live hosts found on remote VLANs.")

        if total_found > 0:
            self._add_finding(
                severity="high",
                finding_type="cross_vlan_hosts",
                target=f"{total_found} hosts",
                message=f"{total_found} devices on remote VLANs are directly reachable",
                details=f"A ping/TCP sweep of remote subnets found {total_found} live hosts that are "
                        f"directly reachable from your VLAN ({local_subnet}). This confirms that "
                        f"inter-VLAN routing has no ACL restrictions. All discovered hosts can be "
                        f"directly attacked from any device on your VLAN."
            )


    def _inject_device_to_inventory(self, ip: str, mac: str = "", hostname: str = "", method: str = "", ports: list[int] = None) -> None:
        """Helper to inject a discovered device into the central inventory."""
        try:
            import api
            if hasattr(api, 'inventory') and api.inventory:
                from network.mac_lookup import lookup_vendor
                from core.models import PortInfo
                actual_mac = mac if mac else f"ROUTED-{ip}"
                port_objs = []
                if ports:
                    svc_names = {80: "HTTP", 443: "HTTPS", 22: "SSH", 23: "Telnet", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 53: "DNS"}
                    for p in ports:
                        if isinstance(p, int):
                            port_objs.append(PortInfo(port=p, protocol="tcp", state="open", service=svc_names.get(p, "unknown")))
                        elif isinstance(p, PortInfo):
                            port_objs.append(p)

                api.inventory.upsert_device(Device(
                    mac=actual_mac,
                    ip=ip,
                    hostname=hostname,
                    vendor=lookup_vendor(actual_mac) if mac else "",
                    status=DeviceStatus.ONLINE if mac else DeviceStatus.UNKNOWN,
                    ports=port_objs,
                    discovery_methods=[method] if method else ["VLAN_DISCOVERY"]
                ))
        except Exception:
            pass

    def stop(self) -> dict:
        """Stop the VLAN discovery sniffer and return summary."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        return self.get_status()

    def get_status(self) -> dict:
        """Get current discovery status and all intelligence."""
        with self._lock:
            return {
                "is_running": self._running,
                "duration": time.time() - self._start_time if self._start_time else 0,
                "total_packets": self._total_packets,
                "protocol_counts": dict(self._protocol_counts),
                "vlans_count": len(self._vlans),
                "subnets_count": len(self._subnets),
                "switches_count": len(self._switches),
                "routes_count": len(self._routes),
                "probe_status": self._probe_status,
                "findings_count": len(self._security_findings),
            }

    def get_vlans(self) -> list[dict]:
        with self._lock:
            return [v.to_dict() for v in self._vlans.values()]

    def get_subnets(self) -> list[dict]:
        with self._lock:
            return [s.to_dict() for s in self._subnets.values()]

    def get_switches(self) -> list[dict]:
        with self._lock:
            return [s.to_dict() for s in self._switches.values()]

    def get_routes(self) -> list[dict]:
        with self._lock:
            return [r.to_dict() for r in self._routes.values()]

    def get_traceroute_hops(self) -> list[str]:
        with self._lock:
            return list(self._traceroute_hops)

    def get_security_findings(self) -> list[dict]:
        """Get all security audit findings from active probes."""
        with self._lock:
            return list(self._security_findings)

    def get_cross_vlan_hosts(self) -> list[dict]:
        """Get all live hosts discovered on remote VLANs."""
        with self._lock:
            return list(self._cross_vlan_hosts)

    def get_full_intelligence(self) -> dict:
        """Get all discovered intelligence in one response."""
        with self._lock:
            return {
                "status": {
                    "is_running": self._running,
                    "duration": time.time() - self._start_time if self._start_time else 0,
                    "total_packets": self._total_packets,
                    "protocol_counts": dict(self._protocol_counts),
                    "probe_status": self._probe_status,
                    "findings_count": len(self._security_findings),
                },
                "vlans": [v.to_dict() for v in sorted(self._vlans.values(), key=lambda v: v.vlan_id)],
                "subnets": [s.to_dict() for s in self._subnets.values()],
                "switches": [s.to_dict() for s in self._switches.values()],
                "routes": [r.to_dict() for r in self._routes.values()],
                "findings": list(self._security_findings),
                "cross_vlan_hosts": list(self._cross_vlan_hosts),
            }

    # ── Capture Loop ─────────────────────────────────────────────

    def _capture_loop(self, interface: str) -> None:
        """Background thread — sniffs infrastructure protocols."""
        try:
            from scapy.all import sniff, conf, load_contrib

            conf.verb = 0

            # Load Scapy contrib modules for CDP, LLDP, OSPF, EIGRP
            for module in ["cdp", "lldp", "ospf", "eigrp"]:
                try:
                    load_contrib(module)
                except Exception:
                    pass

            # BPF filter targeting infrastructure protocols
            bpf = (
                "ether host 01:00:0c:cc:cc:cc or "       # CDP / VTP
                "ether host 01:80:c2:00:00:0e or "       # LLDP
                "ether host 01:80:c2:00:00:00 or "       # STP
                "proto 89 or "                             # OSPF
                "proto 88 or "                             # EIGRP
                "(udp and port 520) or "                   # RIP
                "(udp and port 1985) or "                  # HSRP
                "proto 112 or "                            # VRRP
                "(udp and (port 67 or port 68))"           # DHCP (Option 82/121/3)
            )

            print(f"[VLANDiscovery] Starting on '{interface or 'default'}' ...")
            print(f"[VLANDiscovery] Listening for CDP, LLDP, 802.1Q, OSPF, EIGRP, RIP, STP, HSRP/VRRP, DHCP ...")

            sniff(
                iface=interface if interface else None,
                filter=bpf,
                prn=self._process_packet,
                store=0,
                promisc=True,
                stop_filter=lambda _: not self._running,
            )

        except Exception as e:
            print(f"\n[VLANDiscovery] ERROR: {e}")
            print("[VLANDiscovery] Hint: Requires admin privileges and Npcap on Windows.")
            import traceback
            traceback.print_exc()
        finally:
            self._running = False

    def _process_packet(self, pkt) -> None:
        """Route each packet to the appropriate protocol parser."""
        if not self._running:
            return

        with self._lock:
            self._total_packets += 1

        try:
            from scapy.all import Ether, Dot1Q, IP, UDP

            # ── 802.1Q Tagged Frames ────────────────────────────
            if pkt.haslayer(Dot1Q):
                self._process_dot1q(pkt)

            # ── CDP ─────────────────────────────────────────────
            if pkt.haslayer(Ether):
                dst_mac = pkt[Ether].dst.lower()
                if dst_mac == "01:00:0c:cc:cc:cc":
                    self._process_cdp(pkt)
                    return

            # ── LLDP ────────────────────────────────────────────
            if pkt.haslayer(Ether):
                eth = pkt[Ether]
                if eth.dst.lower() == "01:80:c2:00:00:0e" or eth.type == 0x88CC:
                    self._process_lldp(pkt)
                    return

            # ── STP ─────────────────────────────────────────────
            if pkt.haslayer(Ether):
                if pkt[Ether].dst.lower() == "01:80:c2:00:00:00":
                    self._process_stp(pkt)
                    return

            # ── OSPF ────────────────────────────────────────────
            if pkt.haslayer(IP) and pkt[IP].proto == 89:
                self._process_ospf(pkt)
                return

            # ── EIGRP ───────────────────────────────────────────
            if pkt.haslayer(IP) and pkt[IP].proto == 88:
                self._process_eigrp(pkt)
                return

            # ── RIP ─────────────────────────────────────────────
            if pkt.haslayer(UDP):
                udp = pkt[UDP]
                if udp.dport == 520 or udp.sport == 520:
                    self._process_rip(pkt)
                    return

            # ── HSRP ────────────────────────────────────────────
            if pkt.haslayer(UDP):
                udp = pkt[UDP]
                if udp.dport == 1985 or udp.sport == 1985:
                    self._process_hsrp(pkt)
                    return

            # ── VRRP ────────────────────────────────────────────
            if pkt.haslayer(IP) and pkt[IP].proto == 112:
                self._process_vrrp(pkt)
                return

            # ── DHCP ────────────────────────────────────────────
            if pkt.haslayer(UDP):
                udp = pkt[UDP]
                if udp.dport in (67, 68) or udp.sport in (67, 68):
                    self._process_dhcp(pkt)
                    return

        except Exception:
            pass

    # ── Protocol Parsers ─────────────────────────────────────────

    def _process_cdp(self, pkt) -> None:
        """Parse CDP packets for switch/VLAN intelligence."""
        try:
            self._record_hit("CDP")

            device_id = ""
            platform = ""
            software = ""
            local_port = ""
            mgmt_ip = ""
            native_vlan = None
            capabilities_list = []
            src_mac = ""

            if pkt.haslayer("Ether"):
                src_mac = pkt["Ether"].src.upper()

            # Walk through CDP TLVs
            if pkt.haslayer("CDPMsgDeviceID"):
                raw_val = pkt["CDPMsgDeviceID"].val
                device_id = raw_val.decode("utf-8", errors="ignore") if isinstance(raw_val, bytes) else str(raw_val)

            if pkt.haslayer("CDPMsgPlatform"):
                raw_val = pkt["CDPMsgPlatform"].val
                platform = raw_val.decode("utf-8", errors="ignore") if isinstance(raw_val, bytes) else str(raw_val)

            if pkt.haslayer("CDPMsgSoftwareVersion"):
                raw_val = pkt["CDPMsgSoftwareVersion"].val
                software = raw_val.decode("utf-8", errors="ignore") if isinstance(raw_val, bytes) else str(raw_val)

            if pkt.haslayer("CDPMsgPortID"):
                raw_val = pkt["CDPMsgPortID"].iface
                local_port = raw_val.decode("utf-8", errors="ignore") if isinstance(raw_val, bytes) else str(raw_val)

            if pkt.haslayer("CDPMsgNativeVLAN"):
                native_vlan = pkt["CDPMsgNativeVLAN"].vlan

            if pkt.haslayer("CDPMsgAddr"):
                try:
                    addr_layer = pkt["CDPMsgAddr"]
                    if hasattr(addr_layer, "addr") and addr_layer.addr:
                        for a in addr_layer.addr:
                            if hasattr(a, "addr"):
                                raw = a.addr
                                if isinstance(raw, bytes) and len(raw) == 4:
                                    mgmt_ip = f"{raw[0]}.{raw[1]}.{raw[2]}.{raw[3]}"
                                    break
                                elif isinstance(raw, str):
                                    mgmt_ip = raw
                                    break
                except Exception:
                    pass

            if pkt.haslayer("CDPMsgCapabilities"):
                try:
                    cap_val = pkt["CDPMsgCapabilities"].cap
                    cap_int = int(cap_val) if not isinstance(cap_val, int) else cap_val
                    cap_map = {
                        0x01: "Router", 0x02: "Transparent Bridge",
                        0x04: "Source-Route Bridge", 0x08: "Switch",
                        0x10: "Host", 0x20: "IGMP", 0x40: "Repeater",
                    }
                    for bit, name in cap_map.items():
                        if cap_int & bit:
                            capabilities_list.append(name)
                except Exception:
                    pass

            if device_id:
                self._register_switch(
                    device_id=device_id,
                    management_ip=mgmt_ip,
                    platform=platform,
                    software_version=software,
                    local_port=local_port,
                    native_vlan=native_vlan,
                    capabilities=capabilities_list,
                    source_protocol="cdp",
                    source_mac=src_mac,
                )

                # Register native VLAN
                if native_vlan is not None:
                    self._register_vlan(
                        vlan_id=native_vlan,
                        source_protocol="cdp",
                        source_switch=device_id,
                        is_native=True,
                    )

                if mgmt_ip and mgmt_ip != "0.0.0.0":
                    try:
                        net = ipaddress.IPv4Network(f"{mgmt_ip}/24", strict=False)
                        self._register_subnet(
                            cidr=str(net),
                            gateway=mgmt_ip,
                            source_protocol="cdp",
                            source_router=device_id
                        )
                    except Exception:
                        pass

                print(f"[VLANDiscovery] CDP: Switch '{device_id}' ({platform}), Port: {local_port}, Native VLAN: {native_vlan}, Mgmt IP: {mgmt_ip}")

        except Exception as e:
            print(f"[VLANDiscovery] CDP parse error: {e}")

    def _process_lldp(self, pkt) -> None:
        """Parse LLDP packets for switch/VLAN intelligence."""
        try:
            self._record_hit("LLDP")

            device_id = ""
            port_desc = ""
            mgmt_ip = ""
            sys_desc = ""
            vlan_id = None
            capabilities_list = []
            src_mac = ""

            if pkt.haslayer("Ether"):
                src_mac = pkt["Ether"].src.upper()

            # LLDP System Name
            if pkt.haslayer("LLDPDUSystemName"):
                try:
                    raw = pkt["LLDPDUSystemName"].system_name
                    device_id = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else str(raw)
                except Exception:
                    pass

            # LLDP Port Description
            if pkt.haslayer("LLDPDUPortDescription"):
                try:
                    raw = pkt["LLDPDUPortDescription"].description
                    port_desc = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else str(raw)
                except Exception:
                    pass

            # LLDP Port ID (fallback for port info)
            if not port_desc and pkt.haslayer("LLDPDUPortID"):
                try:
                    raw = pkt["LLDPDUPortID"].id
                    port_desc = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else str(raw)
                except Exception:
                    pass

            # LLDP System Description
            if pkt.haslayer("LLDPDUSystemDescription"):
                try:
                    raw = pkt["LLDPDUSystemDescription"].description
                    sys_desc = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else str(raw)
                except Exception:
                    pass

            # LLDP Management Address
            if pkt.haslayer("LLDPDUManagementAddress"):
                try:
                    ma = pkt["LLDPDUManagementAddress"]
                    if hasattr(ma, "management_address"):
                        raw = ma.management_address
                        if isinstance(raw, bytes) and len(raw) == 4:
                            mgmt_ip = f"{raw[0]}.{raw[1]}.{raw[2]}.{raw[3]}"
                        elif isinstance(raw, str):
                            mgmt_ip = raw
                except Exception:
                    pass

            # LLDP System Capabilities
            if pkt.haslayer("LLDPDUSystemCapabilities"):
                try:
                    sc = pkt["LLDPDUSystemCapabilities"]
                    cap_val = sc.capabilities if hasattr(sc, "capabilities") else 0
                    cap_int = int(cap_val)
                    cap_map = {
                        0x0002: "Repeater", 0x0004: "Bridge",
                        0x0008: "WLAN AP", 0x0010: "Router",
                        0x0020: "Telephone", 0x0040: "DOCSIS",
                        0x0080: "Station", 0x0100: "C-VLAN",
                    }
                    for bit, name in cap_map.items():
                        if cap_int & bit:
                            capabilities_list.append(name)
                except Exception:
                    pass

            # LLDP 802.1 Port VLAN ID
            if pkt.haslayer("LLDPDot1PortVlanId"):
                try:
                    vlan_id = pkt["LLDPDot1PortVlanId"].vlan
                except Exception:
                    pass

            # Fallback device_id from Chassis ID
            if not device_id and pkt.haslayer("LLDPDUChassisID"):
                try:
                    raw = pkt["LLDPDUChassisID"].id
                    device_id = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else str(raw)
                except Exception:
                    device_id = src_mac or "Unknown LLDP Device"

            if device_id:
                self._register_switch(
                    device_id=device_id,
                    management_ip=mgmt_ip,
                    platform=sys_desc[:120] if sys_desc else "",
                    software_version="",
                    local_port=port_desc,
                    native_vlan=vlan_id,
                    capabilities=capabilities_list,
                    source_protocol="lldp",
                    source_mac=src_mac,
                )

                if vlan_id is not None:
                    self._register_vlan(
                        vlan_id=vlan_id,
                        source_protocol="lldp",
                        source_switch=device_id,
                        is_native=True,
                    )

                if mgmt_ip and mgmt_ip != "0.0.0.0":
                    try:
                        net = ipaddress.IPv4Network(f"{mgmt_ip}/24", strict=False)
                        self._register_subnet(
                            cidr=str(net),
                            gateway=mgmt_ip,
                            source_protocol="lldp",
                            source_router=device_id
                        )
                    except Exception:
                        pass

                print(f"[VLANDiscovery] LLDP: Switch '{device_id}', Port: {port_desc}, VLAN: {vlan_id}, Mgmt IP: {mgmt_ip}")

        except Exception as e:
            print(f"[VLANDiscovery] LLDP parse error: {e}")

    def _process_dot1q(self, pkt) -> None:
        """Extract VLAN IDs from 802.1Q tagged frames."""
        try:
            from scapy.all import Dot1Q, IP

            self._record_hit("802.1Q")

            vlan_id = pkt[Dot1Q].vlan
            if vlan_id and 1 <= vlan_id <= 4094:
                self._register_vlan(
                    vlan_id=vlan_id,
                    source_protocol="dot1q",
                )

                # If there's an IP layer inside, track the subnet
                if pkt.haslayer(IP):
                    src_ip = pkt[IP].src
                    if src_ip and src_ip != "0.0.0.0":
                        self._track_ip_for_subnet(src_ip, f"vlan_{vlan_id}")

            # Check for double-tagging (Q-in-Q)
            try:
                inner = pkt[Dot1Q:2]
                if inner:
                    inner_vlan = inner.vlan
                    if inner_vlan and 1 <= inner_vlan <= 4094:
                        self._register_vlan(
                            vlan_id=inner_vlan,
                            source_protocol="dot1q_inner",
                        )
            except (IndexError, Exception):
                pass

        except Exception:
            pass

    def _process_ospf(self, pkt) -> None:
        """Parse OSPF Hello packets for router and area discovery."""
        try:
            from scapy.all import IP

            self._record_hit("OSPF")

            src_ip = pkt[IP].src if pkt.haslayer(IP) else ""

            # Try to access OSPF Hello layer
            if pkt.haslayer("OSPF_Hello"):
                hello = pkt["OSPF_Hello"]
                hdr = pkt["OSPF_Hdr"] if pkt.haslayer("OSPF_Hdr") else None

                router_id = ""
                area_id = ""
                network_mask = ""

                if hdr:
                    router_id = str(hdr.src) if hasattr(hdr, "src") else ""
                    area_id = str(hdr.area) if hasattr(hdr, "area") else ""

                if hasattr(hello, "mask"):
                    network_mask = str(hello.mask)

                # Register the router's own subnet from the Hello mask
                if src_ip and network_mask and network_mask != "0.0.0.0":
                    try:
                        network = ipaddress.IPv4Network(
                            f"{src_ip}/{network_mask}", strict=False
                        )
                        self._register_subnet(
                            cidr=str(network),
                            gateway=src_ip,
                            source_protocol="ospf",
                            source_router=router_id or src_ip,
                        )
                    except (ValueError, TypeError):
                        pass

                # Extract neighbor IPs
                if hasattr(hello, "neighbors") and hello.neighbors:
                    neighbors = hello.neighbors
                    if isinstance(neighbors, list):
                        for n in neighbors:
                            neighbor_ip = str(n)
                            self._track_ip_for_subnet(neighbor_ip, "ospf")

                print(f"[VLANDiscovery] OSPF Hello: Router {router_id or src_ip}, Area {area_id}, Mask {network_mask}")

            # OSPF LSA updates may contain route advertisements
            elif pkt.haslayer("OSPF_Hdr"):
                hdr = pkt["OSPF_Hdr"]
                router_id = str(hdr.src) if hasattr(hdr, "src") else src_ip
                area_id = str(hdr.area) if hasattr(hdr, "area") else ""

                # Register the router as an OSPF speaker
                self._register_route(
                    destination=f"{src_ip}/32",
                    next_hop=src_ip,
                    protocol="ospf",
                    advertising_router=router_id,
                    area=area_id,
                )

        except Exception as e:
            print(f"[VLANDiscovery] OSPF parse error: {e}")

    def _process_eigrp(self, pkt) -> None:
        """Parse EIGRP packets for AS and route discovery."""
        try:
            from scapy.all import IP

            self._record_hit("EIGRP")

            src_ip = pkt[IP].src if pkt.haslayer(IP) else ""
            as_number = 0

            if pkt.haslayer("EIGRP"):
                eigrp = pkt["EIGRP"]
                if hasattr(eigrp, "asn"):
                    as_number = eigrp.asn

                # Look for internal route TLVs
                if pkt.haslayer("EIGRPIntRoute"):
                    try:
                        route = pkt["EIGRPIntRoute"]
                        if hasattr(route, "dst") and hasattr(route, "prefixlen"):
                            dest = f"{route.dst}/{route.prefixlen}"
                            nexthop = str(route.nexthop) if hasattr(route, "nexthop") else src_ip
                            metric_val = int(route.delay) if hasattr(route, "delay") else 0

                            self._register_route(
                                destination=dest,
                                next_hop=nexthop,
                                metric=metric_val,
                                protocol="eigrp",
                                advertising_router=src_ip,
                                as_number=as_number,
                            )

                            self._register_subnet(
                                cidr=dest,
                                source_protocol="eigrp",
                                source_router=src_ip,
                                metric=metric_val,
                            )
                    except Exception:
                        pass

                print(f"[VLANDiscovery] EIGRP: Router {src_ip}, AS {as_number}")

        except Exception as e:
            print(f"[VLANDiscovery] EIGRP parse error: {e}")

    def _process_rip(self, pkt) -> None:
        """Parse RIP v1/v2 packets for route advertisements."""
        try:
            from scapy.all import IP, UDP, Raw

            self._record_hit("RIP")

            src_ip = pkt[IP].src if pkt.haslayer(IP) else ""

            # RIP uses a simple fixed-format: 4-byte header + 20-byte route entries
            if pkt.haslayer(Raw):
                raw = bytes(pkt[Raw].load)
                if len(raw) < 4:
                    return

                command = raw[0]    # 1=Request, 2=Response
                version = raw[1]    # 1 or 2

                if command == 2 and len(raw) >= 24:  # Response with at least one route
                    offset = 4  # Skip header
                    routes_found = 0
                    while offset + 20 <= len(raw) and routes_found < 50:
                        # Each RIP entry: 2B AFI, 2B route_tag, 4B IP, 4B mask, 4B next_hop, 4B metric
                        entry = raw[offset:offset + 20]
                        afi = struct.unpack("!H", entry[0:2])[0]

                        if afi == 2:  # AF_INET
                            route_ip = f"{entry[4]}.{entry[5]}.{entry[6]}.{entry[7]}"
                            route_mask = f"{entry[8]}.{entry[9]}.{entry[10]}.{entry[11]}"
                            next_hop_bytes = entry[12:16]
                            next_hop = f"{next_hop_bytes[0]}.{next_hop_bytes[1]}.{next_hop_bytes[2]}.{next_hop_bytes[3]}"
                            metric_val = struct.unpack("!I", entry[16:20])[0]

                            if next_hop == "0.0.0.0":
                                next_hop = src_ip

                            try:
                                if version == 1 and route_mask == "0.0.0.0":
                                    # RIPv1: classful, infer mask
                                    net = ipaddress.IPv4Network(f"{route_ip}/24", strict=False)
                                else:
                                    net = ipaddress.IPv4Network(f"{route_ip}/{route_mask}", strict=False)
                                cidr = str(net)

                                if metric_val < 16:  # 16 = infinity / unreachable
                                    self._register_route(
                                        destination=cidr,
                                        next_hop=next_hop,
                                        metric=metric_val,
                                        protocol=f"rip_v{version}",
                                        advertising_router=src_ip,
                                    )
                                    self._register_subnet(
                                        cidr=cidr,
                                        gateway=next_hop,
                                        source_protocol=f"rip_v{version}",
                                        source_router=src_ip,
                                        metric=metric_val,
                                    )
                                    routes_found += 1
                            except (ValueError, TypeError):
                                pass

                        offset += 20

                    if routes_found:
                        print(f"[VLANDiscovery] RIPv{version}: {routes_found} routes from {src_ip}")

        except Exception as e:
            print(f"[VLANDiscovery] RIP parse error: {e}")

    def _process_stp(self, pkt) -> None:
        """Parse STP (Spanning Tree Protocol) for bridge topology."""
        try:
            self._record_hit("STP")

            # STP BPDU is carried as LLC/SNAP payload
            if pkt.haslayer("STP"):
                stp = pkt["STP"]
                root_id = str(stp.rootid) if hasattr(stp, "rootid") else ""
                bridge_id = str(stp.bridgeid) if hasattr(stp, "bridgeid") else ""
                root_mac = str(stp.rootmac) if hasattr(stp, "rootmac") else ""
                bridge_mac = str(stp.bridgemac) if hasattr(stp, "bridgemac") else ""

                # We can detect the root bridge and local bridge from STP
                if bridge_mac:
                    device_id = f"STP-Bridge-{bridge_mac.upper()}"
                    self._register_switch(
                        device_id=device_id,
                        source_protocol="stp",
                        source_mac=bridge_mac.upper(),
                        capabilities=["Bridge"],
                    )
        except Exception:
            pass

    def _process_hsrp(self, pkt) -> None:
        """Parse HSRP packets to discover virtual gateway IPs."""
        try:
            from scapy.all import IP, Raw

            self._record_hit("HSRP")

            src_ip = pkt[IP].src if pkt.haslayer(IP) else ""

            if pkt.haslayer(Raw):
                raw = bytes(pkt[Raw].load)
                if len(raw) >= 20:
                    # HSRP v1 format: version(1), opcode(1), state(1), hellotime(1),
                    # holdtime(1), priority(1), group(1), reserved(1), auth(8), virtual_ip(4)
                    group = raw[6]
                    state = raw[2]
                    priority = raw[5]
                    virtual_ip_bytes = raw[16:20]
                    virtual_ip = f"{virtual_ip_bytes[0]}.{virtual_ip_bytes[1]}.{virtual_ip_bytes[2]}.{virtual_ip_bytes[3]}"

                    state_map = {0: "Initial", 1: "Learn", 2: "Listen", 4: "Speak", 8: "Standby", 16: "Active"}
                    state_name = state_map.get(state, f"State-{state}")

                    # Register the virtual gateway as a subnet gateway
                    if virtual_ip and virtual_ip != "0.0.0.0":
                        try:
                            net = ipaddress.IPv4Network(f"{virtual_ip}/24", strict=False)
                            self._register_subnet(
                                cidr=str(net),
                                gateway=virtual_ip,
                                source_protocol="hsrp",
                                source_router=src_ip,
                            )
                        except (ValueError, TypeError):
                            pass

                    print(f"[VLANDiscovery] HSRP: Group {group}, VIP {virtual_ip}, {state_name}, Priority {priority}, From {src_ip}")

        except Exception as e:
            print(f"[VLANDiscovery] HSRP parse error: {e}")

    def _process_vrrp(self, pkt) -> None:
        """Parse VRRP packets to discover virtual gateway IPs."""
        try:
            from scapy.all import IP, Raw

            self._record_hit("VRRP")

            src_ip = pkt[IP].src if pkt.haslayer(IP) else ""

            if pkt.haslayer(Raw):
                raw = bytes(pkt[Raw].load)
                if len(raw) >= 16:
                    # VRRP format: version/type(1), vrid(1), priority(1), count(1), ...
                    vrid = raw[1]
                    priority = raw[2]
                    addr_count = raw[3]

                    # Virtual IPs start at offset 8 (after auth type + adver interval)
                    for i in range(min(addr_count, 4)):
                        offset = 8 + (i * 4)
                        if offset + 4 <= len(raw):
                            vip = f"{raw[offset]}.{raw[offset+1]}.{raw[offset+2]}.{raw[offset+3]}"
                            if vip and vip != "0.0.0.0":
                                try:
                                    net = ipaddress.IPv4Network(f"{vip}/24", strict=False)
                                    self._register_subnet(
                                        cidr=str(net),
                                        gateway=vip,
                                        source_protocol="vrrp",
                                        source_router=src_ip,
                                    )
                                except (ValueError, TypeError):
                                    pass

                    print(f"[VLANDiscovery] VRRP: VRID {vrid}, Priority {priority}, From {src_ip}")

        except Exception as e:
            print(f"[VLANDiscovery] VRRP parse error: {e}")

    def _process_dhcp(self, pkt) -> None:
        """Parse DHCP / BOOTP options (Option 82 Relay Agent, Option 121 Classless Routes, Option 3 Gateway)."""
        try:
            from scapy.all import DHCP, IP

            if not pkt.haslayer(DHCP):
                return

            self._record_hit("DHCP")
            options = pkt[DHCP].options
            opt_dict = {}
            for item in options:
                if isinstance(item, tuple) and len(item) >= 2:
                    opt_dict[item[0]] = item[1]

            gateway_ip = ""
            if "router" in opt_dict:
                r = opt_dict["router"]
                gateway_ip = str(r[0]) if isinstance(r, list) and r else str(r)

            subnet_mask = ""
            if "subnet_mask" in opt_dict:
                subnet_mask = str(opt_dict["subnet_mask"])

            dhcp_server = ""
            if "server_id" in opt_dict:
                dhcp_server = str(opt_dict["server_id"])

            src_ip = pkt[IP].src if pkt.haslayer(IP) else ""

            if gateway_ip and subnet_mask:
                try:
                    net = ipaddress.IPv4Network(f"{gateway_ip}/{subnet_mask}", strict=False)
                    self._register_subnet(
                        cidr=str(net),
                        gateway=gateway_ip,
                        dhcp_server=dhcp_server or src_ip,
                        source_protocol="dhcp",
                        source_router=dhcp_server or gateway_ip
                    )
                except Exception:
                    pass

            # Parse Option 82 if present
            relay_info = opt_dict.get("relay_agent_Information") or opt_dict.get(82)
            if relay_info:
                self._parse_dhcp_option_82(relay_info)

        except Exception as e:
            print(f"[VLANDiscovery] DHCP parse error: {e}")

    def _parse_dhcp_option_82(self, raw_data) -> None:
        """Extract VLAN ID and Switch info from DHCP Option 82 (Relay Agent Info)."""
        try:
            if not isinstance(raw_data, bytes):
                raw_data = bytes(raw_data)

            vlan_id = None
            switch_mac = ""
            circuit_id_str = ""

            offset = 0
            while offset + 2 <= len(raw_data):
                sub_opt = raw_data[offset]
                sub_len = raw_data[offset + 1]
                val = raw_data[offset + 2 : offset + 2 + sub_len]
                offset += 2 + sub_len

                if sub_opt == 1:  # Circuit ID (VLAN / Port)
                    if len(val) >= 4 and val[0:2] == b"\x00\x04":
                        vlan_id = struct.unpack("!H", val[2:4])[0]
                    else:
                        circuit_id_str = val.decode("utf-8", errors="ignore")
                        import re
                        m = re.search(r"vlan\s*(\d+)", circuit_id_str, re.IGNORECASE)
                        if m:
                            vlan_id = int(m.group(1))

                elif sub_opt == 2:  # Remote ID (Switch MAC / Chassis)
                    if len(val) == 6:
                        switch_mac = ":".join(f"{b:02X}" for b in val)
                    elif len(val) == 8 and val[0:2] == b"\x00\x06":
                        switch_mac = ":".join(f"{b:02X}" for b in val[2:8])

            if vlan_id and 1 <= vlan_id <= 4094:
                self._register_vlan(
                    vlan_id=vlan_id,
                    name=f"VLAN {vlan_id} (DHCP Option 82)",
                    source_protocol="dhcp_opt82",
                )

            if switch_mac:
                device_id = f"Switch-{switch_mac.replace(':', '')}"
                self._register_switch(
                    device_id=device_id,
                    native_vlan=vlan_id,
                    source_protocol="dhcp_opt82",
                    source_mac=switch_mac,
                )
        except Exception:
            pass

    # ── Registration Helpers ─────────────────────────────────────

    def _register_vlan(
        self,
        vlan_id: int,
        name: str = "",
        subnet: str = "",
        source_protocol: str = "",
        source_switch: str = "",
        is_native: bool = False,
    ) -> None:
        """Register or update a discovered VLAN."""
        if not (1 <= vlan_id <= 4094):
            return

        with self._lock:
            if vlan_id in self._vlans:
                existing = self._vlans[vlan_id]
                existing.last_seen = time.time()
                if name and not existing.name:
                    existing.name = name
                if subnet and not existing.subnet:
                    existing.subnet = subnet
                if source_switch and not existing.source_switch:
                    existing.source_switch = source_switch
                if is_native:
                    existing.is_native = True
            else:
                vlan = VLANInfo(
                    vlan_id=vlan_id,
                    name=name or f"VLAN {vlan_id}",
                    subnet=subnet,
                    source_protocol=source_protocol,
                    source_switch=source_switch,
                    is_native=is_native,
                )
                self._vlans[vlan_id] = vlan

                # Notify callback
                if self._on_vlan_found:
                    try:
                        self._on_vlan_found(vlan)
                    except Exception:
                        pass

    def _register_subnet(
        self,
        cidr: str,
        gateway: str = "",
        dhcp_server: str = "",
        source_protocol: str = "",
        source_router: str = "",
        metric: int = 0,
        vlan_id: Optional[int] = None,
    ) -> None:
        """Register or update a discovered subnet."""
        try:
            # Normalize the CIDR
            net = ipaddress.IPv4Network(cidr, strict=False)
            cidr = str(net)
        except (ValueError, TypeError):
            return

        with self._lock:
            if cidr in self._subnets:
                existing = self._subnets[cidr]
                existing.last_seen = time.time()
                if gateway and not existing.gateway:
                    existing.gateway = gateway
                if dhcp_server and not existing.dhcp_server:
                    existing.dhcp_server = dhcp_server
                if vlan_id is not None and existing.vlan_id is None:
                    existing.vlan_id = vlan_id
            else:
                self._subnets[cidr] = SubnetInfo(
                    cidr=cidr,
                    gateway=gateway,
                    dhcp_server=dhcp_server,
                    vlan_id=vlan_id,
                    source_protocol=source_protocol,
                    source_router=source_router,
                    metric=metric,
                )



    def _register_switch(
        self,
        device_id: str,
        management_ip: str = "",
        platform: str = "",
        software_version: str = "",
        local_port: str = "",
        native_vlan: Optional[int] = None,
        capabilities: list[str] = None,
        source_protocol: str = "",
        source_mac: str = "",
    ) -> None:
        """Register or update a discovered switch."""
        if not device_id:
            return

        is_new = False
        with self._lock:
            if device_id in self._switches:
                existing = self._switches[device_id]
                existing.last_seen = time.time()
                if management_ip and not existing.management_ip:
                    existing.management_ip = management_ip
                if platform and not existing.platform:
                    existing.platform = platform
                if software_version and not existing.software_version:
                    existing.software_version = software_version
                if local_port:
                    existing.local_port = local_port
                if native_vlan is not None:
                    existing.native_vlan = native_vlan
                    if native_vlan not in existing.vlans_advertised:
                        existing.vlans_advertised.append(native_vlan)
                if capabilities:
                    for cap in capabilities:
                        if cap not in existing.capabilities:
                            existing.capabilities.append(cap)
            else:
                is_new = True
                self._switches[device_id] = SwitchInfo(
                    device_id=device_id,
                    management_ip=management_ip,
                    platform=platform,
                    software_version=software_version,
                    local_port=local_port,
                    native_vlan=native_vlan,
                    capabilities=capabilities or [],
                    vlans_advertised=[native_vlan] if native_vlan is not None else [],
                    source_protocol=source_protocol,
                    source_mac=source_mac,
                )

        # Notify callback (outside lock)
        if is_new and self._on_switch_found:
            try:
                self._on_switch_found(self._switches[device_id])
            except Exception:
                pass

        # Register switch/router in central inventory
        try:
            import api
            if hasattr(api, 'inventory') and api.inventory and management_ip and management_ip != "0.0.0.0":
                api.inventory.upsert_device(Device(
                    mac=source_mac.lower() if source_mac else f"ROUTED-{management_ip}",
                    ip=management_ip,
                    hostname=device_id,
                    vendor=platform,
                    os=software_version,
                    discovery_methods=[f"VLAN_{source_protocol.upper()}" if source_protocol else "VLAN_DISCOVERY"]
                ))
        except Exception:
            pass

    def _register_route(
        self,
        destination: str,
        next_hop: str = "",
        metric: int = 0,
        protocol: str = "",
        advertising_router: str = "",
        area: str = "",
        as_number: int = 0,
    ) -> None:
        """Register or update a routing entry."""
        key = f"{destination}|{next_hop}"

        with self._lock:
            if key in self._routes:
                self._routes[key].last_seen = time.time()
                if metric:
                    self._routes[key].metric = metric
            else:
                self._routes[key] = RoutingEntry(
                    destination=destination,
                    next_hop=next_hop,
                    metric=metric,
                    protocol=protocol,
                    advertising_router=advertising_router,
                    area=area,
                    as_number=as_number,
                )

        # Register routing nodes in central inventory
        try:
            import api
            if hasattr(api, 'inventory') and api.inventory:
                if advertising_router and advertising_router != "0.0.0.0":
                    api.inventory.upsert_device(Device(
                        mac=f"ROUTED-{advertising_router}",
                        ip=advertising_router,
                        discovery_methods=[f"VLAN_ROUTE_{protocol.upper()}" if protocol else "VLAN_ROUTE"]
                    ))
                if next_hop and next_hop != "0.0.0.0":
                    api.inventory.upsert_device(Device(
                        mac=f"ROUTED-{next_hop}",
                        ip=next_hop,
                        discovery_methods=[f"VLAN_ROUTE_{protocol.upper()}" if protocol else "VLAN_ROUTE"]
                    ))
        except Exception:
            pass

    def _track_ip_for_subnet(self, ip_str: str, context: str = "") -> None:
        """Track an observed IP to eventually infer subnets."""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            if ip.is_multicast or ip.is_reserved or ip.is_loopback:
                return

            # Group by /24 as a heuristic
            net = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
            prefix = str(net)

            with self._lock:
                if prefix not in self._observed_ips:
                    self._observed_ips[prefix] = set()
                self._observed_ips[prefix].add(ip_str)

                # Once we see enough IPs in a /24, register as a subnet
                if len(self._observed_ips[prefix]) >= 2:
                    if prefix not in self._subnets:
                        self._register_subnet(
                            cidr=prefix,
                            source_protocol=f"traffic_analysis ({context})",
                        )
                    else:
                        self._subnets[prefix].device_count = len(self._observed_ips[prefix])

        except (ValueError, TypeError):
            pass

    def _record_hit(self, protocol: str) -> None:
        """Record a protocol packet hit for statistics."""
        with self._lock:
            self._protocol_counts[protocol] = self._protocol_counts.get(protocol, 0) + 1
