"""
Passive Discovery Engine — mines broadcast/multicast traffic to discover
ALL devices on the LAN without sending a single packet.

On a switched network, unicast traffic between other devices never reaches
your port. But EVERY device constantly leaks its identity through broadcast
protocols: ARP, DHCP, mDNS, SSDP, LLMNR, NetBIOS.

This engine captures that broadcast traffic and automatically builds
the device inventory — no active scanning required.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from core.models import Device, DeviceStatus
from network.mac_lookup import lookup_vendor


class PassiveDiscovery:
    """
    Passively discovers devices by analyzing broadcast/multicast traffic.

    Runs a background Scapy sniffer that only captures broadcast traffic
    and extracts device information from multiple protocols.
    """

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._devices: dict[str, Device] = {}   # MAC -> Device
        self._lock = threading.Lock()
        self._start_time: float = 0.0
        self._protocol_hits: dict[str, int] = {}  # protocol -> discovery count
        self._on_device_found: Optional[Callable[[Device], None]] = None
        self._total_broadcast_packets: int = 0

    @property
    def is_running(self) -> bool:
        return self._running

    def start(
        self,
        interface: str = "",
        on_device_found: Optional[Callable[[Device], None]] = None,
    ) -> None:
        """Start passive discovery on the given interface."""
        if self._running:
            return

        self._running = True
        self._start_time = time.time()
        self._on_device_found = on_device_found

        self._thread = threading.Thread(
            target=self._discovery_loop,
            args=(interface,),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> dict:
        """Stop passive discovery and return summary."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

        return self.get_status()

    def get_status(self) -> dict:
        """Get current passive discovery status."""
        with self._lock:
            return {
                "is_running": self._running,
                "devices_found": len(self._devices),
                "broadcast_packets": self._total_broadcast_packets,
                "protocol_hits": dict(self._protocol_hits),
                "duration": time.time() - self._start_time if self._start_time else 0,
                "devices": [d.to_dict() for d in self._devices.values()],
            }

    def get_discovered_devices(self) -> list[Device]:
        """Get all passively discovered devices."""
        with self._lock:
            return list(self._devices.values())

    def _discovery_loop(self, interface: str) -> None:
        """Background thread — captures broadcast/multicast traffic."""
        try:
            from scapy.all import sniff, conf

            conf.verb = 0

            # BPF filter: capture broadcast/multicast traffic + ARP
            # This captures:
            # - All ARP packets (broadcast by nature)
            # - DHCP (UDP ports 67/68)
            # - mDNS (UDP port 5353, multicast 224.0.0.251)
            # - LLMNR (UDP port 5355, multicast 224.0.0.252)
            # - NetBIOS (UDP ports 137/138)
            # - SSDP/UPnP (UDP port 1900, multicast 239.255.255.250)
            # - IPv6 multicast
            bpf = (
                "arp or "
                "(udp and (port 67 or port 68)) or "       # DHCP
                "(udp and port 5353) or "                    # mDNS
                "(udp and port 5355) or "                    # LLMNR
                "(udp and (port 137 or port 138)) or "       # NetBIOS
                "(udp and port 1900) or "                    # SSDP
                "(dst host 255.255.255.255) or "             # IPv4 broadcast
                "(ether broadcast) or "                      # L2 broadcast
                "(ether multicast)"                          # L2 multicast
            )

            print(f"[PassiveDiscovery] Starting on '{interface or 'default'}' ...")
            print(f"[PassiveDiscovery] Listening for ARP, DHCP, mDNS, LLMNR, NetBIOS, SSDP ...")

            sniff(
                iface=interface if interface else None,
                filter=bpf,
                prn=self._process_packet,
                store=0,
                promisc=True,
                stop_filter=lambda _: not self._running,
            )

        except Exception as e:
            print(f"\n[PassiveDiscovery] ERROR: {e}")
            print("[PassiveDiscovery] Hint: Requires admin privileges and Npcap on Windows.")
            import traceback
            traceback.print_exc()
        finally:
            self._running = False

    def _process_packet(self, pkt) -> None:
        """Process a single broadcast/multicast packet for device discovery."""
        if not self._running:
            return

        with self._lock:
            self._total_broadcast_packets += 1

        try:
            from scapy.all import ARP, IP, UDP, DHCP, BOOTP, DNS, Ether, IPv6

            # ── ARP ─────────────────────────────────────────────
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                self._record_hit("ARP")

                # Sender always reveals IP+MAC
                if arp.psrc and arp.psrc != "0.0.0.0" and arp.hwsrc:
                    self._register_device(
                        mac=arp.hwsrc,
                        ip=arp.psrc,
                        method="arp",
                    )

                # ARP reply: target also reveals IP+MAC
                if arp.op == 2 and arp.pdst and arp.pdst != "0.0.0.0" and arp.hwdst:
                    self._register_device(
                        mac=arp.hwdst,
                        ip=arp.pdst,
                        method="arp",
                    )

            # ── DHCP ────────────────────────────────────────────
            elif pkt.haslayer(DHCP):
                self._record_hit("DHCP")
                self._process_dhcp(pkt)

            # ── mDNS (port 5353) ────────────────────────────────
            elif pkt.haslayer(UDP) and pkt.haslayer(DNS):
                udp = pkt[UDP]
                if udp.dport == 5353 or udp.sport == 5353:
                    self._record_hit("mDNS")
                    self._process_mdns(pkt)
                elif udp.dport == 5355 or udp.sport == 5355:
                    self._record_hit("LLMNR")
                    self._process_llmnr(pkt)
                else:
                    self._record_hit("DNS")

            # ── LLMNR (port 5355) without DNS layer ─────────────
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                if udp.dport == 5355 or udp.sport == 5355:
                    self._record_hit("LLMNR")
                    self._process_llmnr(pkt)
                elif udp.dport == 137 or udp.sport == 137 or udp.dport == 138 or udp.sport == 138:
                    self._record_hit("NetBIOS")
                    self._process_netbios(pkt)
                elif udp.dport == 1900 or udp.sport == 1900:
                    self._record_hit("SSDP")
                    self._process_ssdp(pkt)
                elif udp.dport == 67 or udp.dport == 68:
                    self._record_hit("DHCP")

            # ── Any IP packet with Ethernet → register the MAC+IP ──
            if pkt.haslayer(IP) and pkt.haslayer(Ether):
                ip = pkt[IP]
                eth = pkt[Ether]
                src_mac = eth.src
                src_ip = ip.src
                if (
                    src_mac
                    and src_mac.lower() != "ff:ff:ff:ff:ff:ff"
                    and src_ip
                    and src_ip != "0.0.0.0"
                    and not src_ip.startswith("224.")
                    and not src_ip.startswith("239.")
                    and src_ip != "255.255.255.255"
                ):
                    self._register_device(mac=src_mac, ip=src_ip, method="broadcast")

        except Exception:
            pass

    def _process_dhcp(self, pkt) -> None:
        """Extract device info from DHCP packets."""
        try:
            from scapy.all import DHCP, BOOTP, Ether

            dhcp_options = {}
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and len(opt) >= 2:
                    dhcp_options[opt[0]] = opt[1]

            mac = ""
            ip = ""
            hostname = ""

            # MAC from Ethernet
            if pkt.haslayer(Ether):
                mac = pkt[Ether].src

            # IP from BOOTP
            if pkt.haslayer(BOOTP):
                bootp = pkt[BOOTP]
                if bootp.yiaddr and bootp.yiaddr != "0.0.0.0":
                    ip = bootp.yiaddr
                elif bootp.ciaddr and bootp.ciaddr != "0.0.0.0":
                    ip = bootp.ciaddr

            # Hostname from DHCP options
            raw_hostname = dhcp_options.get("hostname", b"")
            if isinstance(raw_hostname, bytes):
                hostname = raw_hostname.decode("utf-8", errors="ignore")
            elif isinstance(raw_hostname, str):
                hostname = raw_hostname

            if mac and mac.lower() != "ff:ff:ff:ff:ff:ff":
                self._register_device(
                    mac=mac, ip=ip, hostname=hostname, method="dhcp",
                )

        except Exception:
            pass

    def _process_mdns(self, pkt) -> None:
        """Extract device info from mDNS packets."""
        try:
            from scapy.all import DNS, IP, Ether

            dns = pkt[DNS]
            mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
            ip = pkt[IP].src if pkt.haslayer(IP) else ""

            hostname = ""

            # mDNS responses contain answers with device hostnames
            if dns.ancount and dns.ancount > 0:
                for i in range(dns.ancount):
                    try:
                        rr = dns.an[i] if hasattr(dns, 'an') and dns.an else None
                        if rr:
                            rrname = rr.rrname
                            if isinstance(rrname, bytes):
                                rrname = rrname.decode("utf-8", errors="ignore")
                            # Extract hostname from .local names
                            if ".local." in str(rrname) or ".local" in str(rrname):
                                hostname = str(rrname).replace(".local.", "").replace(".local", "").split(".")[0]
                                if hostname.startswith("_"):
                                    hostname = ""  # Skip service type records
                    except Exception:
                        continue

            # Also check query names
            if not hostname and dns.qd:
                try:
                    qname = dns.qd.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="ignore")
                    if ".local." in str(qname) or ".local" in str(qname):
                        name = str(qname).replace(".local.", "").replace(".local", "").split(".")[0]
                        if not name.startswith("_"):
                            hostname = name
                except Exception:
                    pass

            if mac and mac.lower() != "ff:ff:ff:ff:ff:ff":
                self._register_device(
                    mac=mac, ip=ip, hostname=hostname, method="mdns",
                )

        except Exception:
            pass

    def _process_llmnr(self, pkt) -> None:
        """Extract device info from LLMNR packets (Windows hostname resolution)."""
        try:
            from scapy.all import DNS, IP, Ether

            mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
            ip = pkt[IP].src if pkt.haslayer(IP) else ""
            hostname = ""

            # LLMNR uses the same DNS packet format
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qd:
                    qname = dns.qd.qname
                    if isinstance(qname, bytes):
                        hostname = qname.decode("utf-8", errors="ignore").rstrip(".")
                    else:
                        hostname = str(qname).rstrip(".")

            if mac and mac.lower() != "ff:ff:ff:ff:ff:ff":
                self._register_device(
                    mac=mac, ip=ip, hostname=hostname, method="llmnr",
                )

        except Exception:
            pass

    def _process_netbios(self, pkt) -> None:
        """Extract device info from NetBIOS packets."""
        try:
            from scapy.all import IP, Ether

            mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
            ip = pkt[IP].src if pkt.haslayer(IP) else ""

            # Try to extract NetBIOS name from the payload
            hostname = ""
            try:
                raw = bytes(pkt[IP].payload.payload) if pkt.haslayer(IP) else b""
                if len(raw) > 56:
                    # NetBIOS name service query — name starts at offset 13
                    # Encoded as pairs of chars (A=0x41+nibble)
                    encoded = raw[13:45]
                    decoded = ""
                    for i in range(0, len(encoded) - 1, 2):
                        c1 = encoded[i] - 0x41
                        c2 = encoded[i + 1] - 0x41
                        char = chr((c1 << 4) | c2)
                        if char.isprintable() and char != " ":
                            decoded += char
                    if decoded and len(decoded) >= 2:
                        hostname = decoded.strip()
            except Exception:
                pass

            if mac and mac.lower() != "ff:ff:ff:ff:ff:ff":
                self._register_device(
                    mac=mac, ip=ip, hostname=hostname, method="netbios",
                )

        except Exception:
            pass

    def _process_ssdp(self, pkt) -> None:
        """Extract device info from SSDP/UPnP packets."""
        try:
            from scapy.all import IP, Ether

            mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
            ip = pkt[IP].src if pkt.haslayer(IP) else ""

            # Extract device info from SSDP payload
            notes = ""
            try:
                raw = bytes(pkt[IP].payload.payload) if pkt.haslayer(IP) else b""
                if raw:
                    text = raw.decode("utf-8", errors="ignore")
                    for line in text.split("\r\n"):
                        upper = line.upper()
                        if upper.startswith("SERVER:"):
                            notes = line[7:].strip()
                            break
                        elif upper.startswith("NT:") or upper.startswith("ST:"):
                            if not notes:
                                notes = line.split(":", 1)[1].strip()
            except Exception:
                pass

            if mac and mac.lower() != "ff:ff:ff:ff:ff:ff":
                self._register_device(
                    mac=mac, ip=ip, method="ssdp",
                    notes=f"SSDP: {notes}" if notes else "",
                )

        except Exception:
            pass

    def _register_device(
        self,
        mac: str,
        ip: str = "",
        hostname: str = "",
        method: str = "passive",
        notes: str = "",
    ) -> None:
        """Register or update a discovered device."""
        mac = mac.upper().replace("-", ":")

        # Skip broadcast/multicast MACs
        if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            return
        # Skip multicast MACs (first byte odd)
        try:
            first_octet = int(mac.split(":")[0], 16)
            if first_octet & 1:  # Multicast bit set
                return
        except (ValueError, IndexError):
            return

        discovery_method = f"passive_{method}"
        is_new = False

        with self._lock:
            if mac in self._devices:
                dev = self._devices[mac]
                if ip and ip != "0.0.0.0":
                    dev.ip = ip
                if hostname and not dev.hostname:
                    dev.hostname = hostname
                if notes and not dev.notes:
                    dev.notes = notes
                if discovery_method not in dev.discovery_methods:
                    dev.discovery_methods.append(discovery_method)
                dev.last_seen = time.time()
                dev.status = DeviceStatus.ONLINE
            else:
                is_new = True
                dev = Device(
                    mac=mac,
                    ip=ip if ip and ip != "0.0.0.0" else "",
                    vendor=lookup_vendor(mac),
                    hostname=hostname,
                    status=DeviceStatus.ONLINE,
                    discovery_methods=[discovery_method],
                    notes=notes,
                )
                self._devices[mac] = dev

        # Notify callback (outside the lock to avoid deadlocks)
        if is_new and self._on_device_found:
            try:
                self._on_device_found(dev)
            except Exception:
                pass

    def _record_hit(self, protocol: str) -> None:
        """Record a protocol hit for statistics."""
        with self._lock:
            self._protocol_hits[protocol] = self._protocol_hits.get(protocol, 0) + 1
