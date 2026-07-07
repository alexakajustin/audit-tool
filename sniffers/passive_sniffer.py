"""
Passive Network Sniffer — captures and analyzes traffic without injection.

Runs in a background thread. Yields PacketInfo objects for real-time
streaming via WebSocket. Supports BPF filters and PCAP import/export.

Enhanced protocol identification: mDNS, LLMNR, SSDP, NetBIOS, NDP.
Tracks DNS queries, security observations, and network intelligence.
"""

from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict
from typing import Callable, Optional

from core.base import BaseSniffer
from core.models import CaptureResult, PacketInfo


class PassiveSniffer(BaseSniffer):
    """Passive packet capture with protocol analysis and network intelligence."""

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._packets: list[PacketInfo] = []
        self._stats: dict[str, int] = {}       # protocol -> count
        self._unique_hosts: set[str] = set()
        self._start_time: float = 0.0
        self._on_packet: Optional[Callable[[PacketInfo], None]] = None
        self._raw_packets = []                   # Raw Scapy packets for pcap export
        self._lock = threading.Lock()

        # ── Network Intelligence tracking ───────────────────────
        self._dns_queries: OrderedDict[str, int] = OrderedDict()   # domain -> count
        self._host_connections: dict[str, set] = {}                 # IP -> set of IPs it talks to
        self._mac_to_ip: dict[str, str] = {}                       # MAC -> IP mapping
        self._services_seen: dict[str, set] = {}                   # IP -> set of services
        self._security_alerts: list[dict] = []                     # cleartext, etc.
        self._http_hosts: set[str] = set()                         # HTTP Host headers seen
        self._data_volume: dict[str, int] = {}                     # IP -> total bytes
        self._local_ip: str = ""                                   # The user's own IP (to exclude)
        self._ip_to_mac: dict[str, str] = {}                       # IP -> MAC mapping for ARP spoofing
        self._dhcp_servers: set[str] = set()                       # Set of detected DHCP servers
        self._tcp_syn_scans: dict[str, set[int]] = {}              # IP -> set of destination ports scanned
        self._alerts_triggered: set[str] = set()                   # Avoid duplicate alerts for the same event

    @property
    def name(self) -> str:
        return "passive_sniffer"

    @property
    def is_running(self) -> bool:
        return self._running

    def start(
        self,
        interface: str,
        bpf_filter: str = "",
        on_packet: Optional[Callable[[PacketInfo], None]] = None,
    ) -> None:
        if self._running:
            return

        self._running = True
        self._packets = []
        self._raw_packets = []
        self._stats = {}
        self._unique_hosts = set()
        self._start_time = time.time()
        self._on_packet = on_packet
        self._dns_queries = OrderedDict()
        self._host_connections = {}
        self._mac_to_ip = {}
        self._services_seen = {}
        self._security_alerts = []
        self._http_hosts = set()
        self._data_volume = {}
        self._ip_to_mac = {}
        self._dhcp_servers = set()
        self._tcp_syn_scans = {}
        self._alerts_triggered = set()

        # Detect local IP for this interface
        self._local_ip = self._detect_local_ip(interface)

        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(interface, bpf_filter),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> CaptureResult:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

        duration = time.time() - self._start_time if self._start_time else 0

        return CaptureResult(
            total_packets=len(self._packets),
            duration=duration,
            protocols=dict(self._stats),
            unique_hosts=set(self._unique_hosts),
        )

    def get_stats(self) -> dict:
        with self._lock:
            # Top DNS queries (most popular domains being browsed)
            dns_top = list(self._dns_queries.items())[-50:]
            dns_top.sort(key=lambda x: x[1], reverse=True)

            # Security alerts (last 20)
            alerts = self._security_alerts[-20:]

            # Services seen per host
            services_summary = {}
            for ip, svcs in self._services_seen.items():
                services_summary[ip] = list(svcs)

            # Data volume top talkers
            vol_sorted = sorted(self._data_volume.items(), key=lambda x: x[1], reverse=True)[:20]

            # Host connections (who talks to whom)
            connections = {}
            for ip, peers in self._host_connections.items():
                connections[ip] = list(peers)[:10]

            return {
                "is_running": self._running,
                "total_packets": len(self._packets),
                "duration": time.time() - self._start_time if self._start_time else 0,
                "protocols": dict(self._stats),
                "unique_hosts_count": len(self._unique_hosts),
                "unique_hosts": list(self._unique_hosts),
                "local_ip": self._local_ip,
                "packets_per_second": (
                    len(self._packets) / (time.time() - self._start_time)
                    if self._start_time and time.time() > self._start_time
                    else 0
                ),
                # Network Intelligence
                "dns_queries": dns_top[:30],
                "http_hosts": list(self._http_hosts)[:30],
                "security_alerts": alerts,
                "services": services_summary,
                "top_talkers": vol_sorted,
                "connections": connections,
                "mac_map": dict(self._mac_to_ip),
            }

    def get_recent_packets(self, count: int = 50) -> list[dict]:
        """Get the most recent N packets as dicts."""
        with self._lock:
            return [p.to_dict() for p in self._packets[-count:]]

    def export_pcap(self, filepath: str) -> str:
        try:
            from scapy.all import wrpcap
            if self._raw_packets:
                wrpcap(filepath, self._raw_packets)
            return filepath
        except Exception as e:
            raise RuntimeError(f"Failed to export PCAP: {e}")

    def import_pcap(self, filepath: str) -> CaptureResult:
        try:
            from scapy.all import rdpcap
            packets = rdpcap(filepath)

            self._packets = []
            self._stats = {}
            self._unique_hosts = set()

            for pkt in packets:
                info = self._parse_packet(pkt)
                if info:
                    with self._lock:
                        self._packets.append(info)
                        self._stats[info.protocol] = self._stats.get(info.protocol, 0) + 1
                        self._unique_hosts.add(info.src)
                        self._unique_hosts.add(info.dst)

            return CaptureResult(
                total_packets=len(self._packets),
                duration=0,
                protocols=dict(self._stats),
                unique_hosts=set(self._unique_hosts),
                pcap_path=filepath,
            )
        except Exception as e:
            raise RuntimeError(f"Failed to import PCAP: {e}")

    def _detect_local_ip(self, interface: str) -> str:
        """Detect the local IP address for the given interface."""
        try:
            from network.interfaces import get_interfaces, get_best_interface
            if interface:
                for iface in get_interfaces():
                    if iface.name == interface and iface.ip:
                        return iface.ip
            best = get_best_interface()
            return best.ip if best else ""
        except Exception:
            return ""

    def _capture_loop(self, interface: str, bpf_filter: str) -> None:
        """Background capture thread — runs Scapy sniff()."""
        try:
            from scapy.all import sniff, conf
            import traceback

            conf.verb = 0

            def process(pkt):
                if not self._running:
                    return

                info = self._parse_packet(pkt)
                if info:
                    with self._lock:
                        self._packets.append(info)
                        self._raw_packets.append(pkt)
                        self._stats[info.protocol] = self._stats.get(info.protocol, 0) + 1
                        if info.src:
                            self._unique_hosts.add(info.src)
                        if info.dst:
                            self._unique_hosts.add(info.dst)

                        # ── Track network intelligence ──────────
                        self._track_intelligence(pkt, info)

                    if self._on_packet:
                        try:
                            self._on_packet(info)
                        except Exception:
                            pass

            print(f"[Sniffer] Starting passive capture on '{interface}' (filter: '{bpf_filter}')")
            if self._local_ip:
                print(f"[Sniffer] Local IP detected: {self._local_ip}")
            sniff(
                iface=interface if interface else None,
                filter=bpf_filter if bpf_filter else None,
                prn=process,
                store=0,
                promisc=True,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            print(f"\n[Sniffer] FATAL ERROR: {e}")
            print("[Sniffer] Hint: On Windows, Scapy requires Npcap (https://npcap.com/) to be installed.")
            import traceback
            traceback.print_exc()
        finally:
            self._running = False

    def _track_intelligence(self, pkt, info: PacketInfo) -> None:
        """Extract network intelligence from packets (called inside the lock)."""
        try:
            from scapy.all import IP, TCP, UDP, DNS, Ether, Raw

            # Track data volume per host
            if info.src:
                self._data_volume[info.src] = self._data_volume.get(info.src, 0) + info.size
            if info.dst:
                self._data_volume[info.dst] = self._data_volume.get(info.dst, 0) + info.size

            # Track connections (who talks to whom)
            if info.src and info.dst:
                if info.src not in self._host_connections:
                    self._host_connections[info.src] = set()
                self._host_connections[info.src].add(info.dst)

            # Track MAC to IP mapping
            if info.src_mac and info.src and not info.src.startswith("ff:"):
                self._mac_to_ip[info.src_mac] = info.src

            # Track DNS queries (what sites are being browsed)
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qr == 0 and dns.qd:  # Query
                    qname = dns.qd.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="ignore")
                    qname = str(qname).rstrip(".")
                    if qname and len(qname) > 3 and "." in qname:
                        self._dns_queries[qname] = self._dns_queries.get(qname, 0) + 1

            # Track services per host by port
            if info.dst_port and info.dst:
                port_services = {
                    80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
                    25: "SMTP", 53: "DNS", 110: "POP3", 143: "IMAP",
                    3389: "RDP", 445: "SMB", 139: "NetBIOS",
                    3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
                    6379: "Redis", 1433: "MSSQL", 5900: "VNC",
                    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
                    23: "Telnet", 161: "SNMP", 69: "TFTP",
                }
                svc = port_services.get(info.dst_port)
                if svc:
                    if info.dst not in self._services_seen:
                        self._services_seen[info.dst] = set()
                    self._services_seen[info.dst].add(svc)

            # ── Security alerts ──────────────────────────────
            # Cleartext HTTP traffic
            if info.protocol == "HTTP" and pkt.haslayer(Raw):
                raw = bytes(pkt[Raw].load)
                # Check for HTTP Host header
                try:
                    text = raw.decode("utf-8", errors="ignore")
                    for line in text.split("\r\n"):
                        if line.upper().startswith("HOST:"):
                            host = line[5:].strip()
                            self._http_hosts.add(host)
                            if len(self._security_alerts) < 200:
                                self._security_alerts.append({
                                    "type": "cleartext_http",
                                    "severity": "warning",
                                    "message": f"Cleartext HTTP to {host}",
                                    "src": info.src,
                                    "dst": info.dst,
                                    "timestamp": info.timestamp,
                                })
                            break
                except Exception:
                    pass

            # FTP traffic (credentials in cleartext)
            if info.protocol == "FTP" and pkt.haslayer(Raw):
                try:
                    raw_text = bytes(pkt[Raw].load).decode("utf-8", errors="ignore").strip()
                    if raw_text.upper().startswith(("USER ", "PASS ")):
                        if len(self._security_alerts) < 200:
                            self._security_alerts.append({
                                "type": "cleartext_credentials",
                                "severity": "critical",
                                "message": f"FTP credentials in cleartext: {raw_text[:40]}",
                                "src": info.src,
                                "dst": info.dst,
                                "timestamp": info.timestamp,
                            })
                except Exception:
                    pass

            # Telnet traffic
            if info.dst_port == 23 or info.src_port == 23:
                if len(self._security_alerts) < 200:
                    existing = [a for a in self._security_alerts if a["type"] == "telnet" and a["dst"] == info.dst]
                    if not existing:
                        self._security_alerts.append({
                            "type": "telnet",
                            "severity": "critical",
                            "message": f"Telnet session detected (unencrypted remote access)",
                            "src": info.src,
                            "dst": info.dst,
                            "timestamp": info.timestamp,
                        })

            # SNMP community string exposure
            if info.protocol == "SNMP" and pkt.haslayer(Raw):
                if len(self._security_alerts) < 200:
                    self._security_alerts.append({
                        "type": "snmp_exposed",
                        "severity": "warning",
                        "message": f"SNMP traffic detected (potential community string exposure)",
                        "src": info.src,
                        "dst": info.dst,
                        "timestamp": info.timestamp,
                    })

            # ARP Spoofing / Poisoning detection
            if info.src and info.src_mac and not info.src.startswith("ff") and not info.src.startswith("fe80") and not info.src.startswith("224.") and not info.src.startswith("239.") and info.src != "0.0.0.0" and info.src != "255.255.255.255":
                src_ip = info.src
                src_mac = info.src_mac.upper()
                if src_mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00") and not src_mac.startswith("01:00:5E") and not src_mac.startswith("33:33"):
                    if src_ip in self._ip_to_mac:
                        old_mac = self._ip_to_mac[src_ip]
                        if old_mac != src_mac:
                            alert_key = f"arp_spoof:{src_ip}"
                            if alert_key not in self._alerts_triggered:
                                self._alerts_triggered.add(alert_key)
                                if len(self._security_alerts) < 200:
                                    self._security_alerts.append({
                                        "type": "arp_spoofing",
                                        "severity": "critical",
                                        "message": f"Potential ARP Spoofing: IP {src_ip} changed MAC from {old_mac} to {src_mac}",
                                        "src": src_ip,
                                        "dst": "Broadcast",
                                        "timestamp": info.timestamp,
                                    })
                    else:
                        self._ip_to_mac[src_ip] = src_mac

            # Rogue / Multiple DHCP Servers detection
            if info.protocol == "DHCP" and pkt.haslayer(UDP):
                udp = pkt[UDP]
                if udp.sport == 67 and info.src:
                    server_ip = info.src
                    server_mac = info.src_mac.upper() if info.src_mac else "Unknown MAC"
                    if server_ip not in self._dhcp_servers:
                        self._dhcp_servers.add(server_ip)
                        if len(self._dhcp_servers) > 1:
                            alert_key = f"rogue_dhcp:{server_ip}"
                            if alert_key not in self._alerts_triggered:
                                self._alerts_triggered.add(alert_key)
                                first_server = list(self._dhcp_servers)[0]
                                if len(self._security_alerts) < 200:
                                    self._security_alerts.append({
                                        "type": "rogue_dhcp",
                                        "severity": "critical",
                                        "message": f"Multiple DHCP Servers: IP {server_ip} ({server_mac}) active beside {first_server}",
                                        "src": server_ip,
                                        "dst": "Broadcast",
                                        "timestamp": info.timestamp,
                                    })

            # Deprecated/Weak TLS version detection
            if pkt.haslayer(Raw) and (info.src_port == 443 or info.dst_port == 443):
                payload = bytes(pkt[Raw].load)
                if len(payload) >= 11:
                    # Check if Handshake Record (0x16) and Server Hello (0x02) at offset 5
                    if payload[0] == 0x16 and payload[5] == 0x02:
                        version_num = (payload[9] << 8) | payload[10]
                        version_map = {
                            0x0300: "SSL 3.0",
                            0x0301: "TLS 1.0",
                            0x0302: "TLS 1.1"
                        }
                        if version_num in version_map:
                            version_name = version_map[version_num]
                            alert_key = f"weak_tls:{info.src}:{version_name}"
                            if alert_key not in self._alerts_triggered:
                                self._alerts_triggered.add(alert_key)
                                if len(self._security_alerts) < 200:
                                    self._security_alerts.append({
                                        "type": "weak_tls",
                                        "severity": "warning",
                                        "message": f"Weak SSL/TLS protocol ({version_name}) negotiated by server",
                                        "src": info.src,
                                        "dst": info.dst,
                                        "timestamp": info.timestamp,
                                    })

            # TCP SYN Port Scan detection
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                # SYN set, ACK not set
                is_syn_only = False
                if hasattr(tcp, "flags"):
                    if isinstance(tcp.flags, str):
                        is_syn_only = (tcp.flags == "S")
                    else:
                        is_syn_only = (int(tcp.flags) == 2)
                if is_syn_only:
                    src_ip = info.src
                    dst_port = info.dst_port
                    if src_ip and dst_port:
                        if src_ip not in self._tcp_syn_scans:
                            self._tcp_syn_scans[src_ip] = set()
                        self._tcp_syn_scans[src_ip].add(dst_port)
                        scanned_count = len(self._tcp_syn_scans[src_ip])
                        if scanned_count >= 15:
                            alert_key = f"port_scan:{src_ip}"
                            if alert_key not in self._alerts_triggered or (scanned_count % 20 == 0):
                                self._alerts_triggered.add(alert_key)
                                if len(self._security_alerts) < 200:
                                    self._security_alerts.append({
                                        "type": "port_scan",
                                        "severity": "warning",
                                        "message": f"Host performing TCP port scan ({scanned_count} unique ports probed)",
                                        "src": src_ip,
                                        "dst": "Multiple Ports",
                                        "timestamp": info.timestamp,
                                    })

            # Cleartext Email Credentials
            if pkt.haslayer(Raw) and info.dst_port in (25, 110, 143):
                try:
                    raw_text = bytes(pkt[Raw].load).decode("utf-8", errors="ignore").strip()
                    raw_upper = raw_text.upper()
                    is_leak = False
                    msg = ""
                    if info.dst_port == 110 and (raw_upper.startswith("USER ") or raw_upper.startswith("PASS ")):
                        is_leak = True
                        msg = f"POP3 credentials sent in cleartext: {raw_text[:40]}"
                    elif info.dst_port == 143 and " LOGIN " in raw_upper:
                        is_leak = True
                        msg = f"IMAP credentials sent in cleartext: {raw_text[:40]}"
                    elif info.dst_port == 25 and (raw_upper.startswith("AUTH PLAIN") or raw_upper.startswith("AUTH LOGIN")):
                        is_leak = True
                        msg = f"SMTP authentication initiated in cleartext"
                    if is_leak:
                        alert_key = f"cleartext_email_cred:{info.src}:{info.dst_port}"
                        if alert_key not in self._alerts_triggered:
                            self._alerts_triggered.add(alert_key)
                            if len(self._security_alerts) < 200:
                                self._security_alerts.append({
                                    "type": "cleartext_credentials",
                                    "severity": "critical",
                                    "message": msg,
                                    "src": info.src,
                                    "dst": info.dst,
                                    "timestamp": info.timestamp,
                                })
                except Exception:
                    pass

            # Direct DNS Request bypassing local resolver
            if info.protocol == "DNS" and pkt.haslayer(UDP):
                udp = pkt[UDP]
                if udp.dport == 53 and info.dst:
                    public_dns = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222", "208.67.220.220"}
                    if info.dst in public_dns:
                        alert_key = f"public_dns:{info.src}:{info.dst}"
                        if alert_key not in self._alerts_triggered:
                            self._alerts_triggered.add(alert_key)
                            if len(self._security_alerts) < 200:
                                self._security_alerts.append({
                                    "type": "dns_bypass",
                                    "severity": "warning",
                                    "message": f"Direct DNS query bypassing local resolver to {info.dst}",
                                    "src": info.src,
                                    "dst": info.dst,
                                    "timestamp": info.timestamp,
                                })

        except Exception:
            pass

    def _parse_packet(self, pkt) -> Optional[PacketInfo]:
        """Parse a Scapy packet into a PacketInfo summary with enhanced protocol detection."""
        try:
            from scapy.all import IP, TCP, UDP, ARP, ICMP, DNS, DHCP, Ether, IPv6

            ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
            size = len(pkt)
            src = ""
            dst = ""
            src_port = None
            dst_port = None
            src_mac = ""
            dst_mac = ""
            protocol = "OTHER"
            summary = ""

            # Extract L2 MAC addresses from Ethernet header
            if pkt.haslayer(Ether):
                src_mac = pkt[Ether].src.upper() if pkt[Ether].src else ""
                dst_mac = pkt[Ether].dst.upper() if pkt[Ether].dst else ""

            # Layer 2 — ARP
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                protocol = "ARP"
                src = arp.psrc
                dst = arp.pdst
                op = "who-has" if arp.op == 1 else "is-at"
                summary = f"ARP {op} {dst} → {arp.hwsrc}"

            # Layer 3 — IP based
            elif pkt.haslayer(IP):
                ip = pkt[IP]
                src = ip.src
                dst = ip.dst

                if pkt.haslayer(DHCP):
                    protocol = "DHCP"
                    summary = f"DHCP {src} → {dst}"

                elif pkt.haslayer(DNS):
                    dns = pkt[DNS]
                    qname = ""
                    if dns.qd:
                        qname = dns.qd.qname.decode("utf-8", errors="ignore") if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)

                    # Distinguish mDNS (port 5353) from regular DNS
                    is_mdns = False
                    if pkt.haslayer(UDP):
                        udp = pkt[UDP]
                        src_port = udp.sport
                        dst_port = udp.dport
                        if dst_port == 5353 or src_port == 5353:
                            is_mdns = True

                    if is_mdns:
                        protocol = "mDNS"
                        summary = f"mDNS {'Query' if dns.qr == 0 else 'Response'}: {qname}"
                    else:
                        protocol = "DNS"
                        summary = f"DNS {'Query' if dns.qr == 0 else 'Response'}: {qname}"

                elif pkt.haslayer(ICMP):
                    protocol = "ICMP"
                    icmp = pkt[ICMP]
                    icmp_types = {0: "Reply", 8: "Request", 3: "Unreachable", 11: "TTL Exceeded"}
                    icmp_desc = icmp_types.get(icmp.type, f"Type {icmp.type}")
                    summary = f"ICMP {icmp_desc} {src} → {dst}"

                elif pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    src_port = tcp.sport
                    dst_port = tcp.dport

                    # Identify application protocol by port
                    known_ports = {
                        80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
                        25: "SMTP", 53: "DNS", 110: "POP3", 143: "IMAP",
                        3389: "RDP", 445: "SMB", 139: "NetBIOS",
                        8080: "HTTP-Alt", 8443: "HTTPS-Alt",
                        3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
                        6379: "Redis", 1433: "MSSQL",
                        5900: "VNC", 5222: "XMPP", 23: "Telnet",
                    }
                    protocol = known_ports.get(dst_port, known_ports.get(src_port, "TCP"))

                    flags = tcp.sprintf("%TCP.flags%")
                    summary = f"{protocol} {src}:{src_port} → {dst}:{dst_port} [{flags}]"

                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    src_port = udp.sport
                    dst_port = udp.dport

                    # Enhanced protocol identification by port
                    if dst_port == 5353 or src_port == 5353:
                        protocol = "mDNS"
                        summary = f"mDNS {src}:{src_port} → {dst}:{dst_port}"
                    elif dst_port == 5355 or src_port == 5355:
                        protocol = "LLMNR"
                        llmnr_name = self._extract_llmnr_name(pkt)
                        summary = f"LLMNR {'Query' if dst_port == 5355 else 'Response'}: {llmnr_name}" if llmnr_name else f"LLMNR {src} → {dst}"
                    elif dst_port == 137 or src_port == 137 or dst_port == 138 or src_port == 138:
                        protocol = "NetBIOS"
                        summary = f"NetBIOS {src}:{src_port} → {dst}:{dst_port}"
                    elif dst_port == 1900 or src_port == 1900:
                        protocol = "SSDP"
                        ssdp_info = self._extract_ssdp_info(pkt)
                        summary = f"SSDP {ssdp_info}" if ssdp_info else f"SSDP {src} → {dst}"
                    elif dst_port == 67 or dst_port == 68 or src_port == 67 or src_port == 68:
                        protocol = "DHCP"
                        summary = f"DHCP {src} → {dst}"
                    else:
                        known_udp = {
                            53: "DNS", 123: "NTP", 161: "SNMP", 162: "SNMP-Trap",
                            514: "Syslog", 69: "TFTP", 500: "IKE",
                            4500: "IPSec-NAT", 1194: "OpenVPN",
                        }
                        protocol = known_udp.get(dst_port, known_udp.get(src_port, "UDP"))
                        summary = f"{protocol} {src}:{src_port} → {dst}:{dst_port}"

                else:
                    protocol = f"IP/{ip.proto}"
                    summary = f"{protocol} {src} → {dst}"

            # IPv6
            elif pkt.haslayer(IPv6):
                ipv6 = pkt[IPv6]
                src = ipv6.src
                dst = ipv6.dst

                try:
                    from scapy.all import ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS, ICMPv6ND_RA
                    if pkt.haslayer(ICMPv6ND_NS):
                        protocol = "NDP"
                        summary = f"NDP Neighbor Solicitation {src} → {dst}"
                    elif pkt.haslayer(ICMPv6ND_NA):
                        protocol = "NDP"
                        summary = f"NDP Neighbor Advertisement {src} → {dst}"
                    elif pkt.haslayer(ICMPv6ND_RS):
                        protocol = "NDP"
                        summary = f"NDP Router Solicitation {src}"
                    elif pkt.haslayer(ICMPv6ND_RA):
                        protocol = "NDP"
                        summary = f"NDP Router Advertisement {src}"
                    else:
                        protocol = "IPv6"
                        summary = f"IPv6 {src} → {dst}"
                except ImportError:
                    protocol = "IPv6"
                    summary = f"IPv6 {src} → {dst}"

            # Layer 2 only
            elif pkt.haslayer(Ether):
                eth = pkt[Ether]
                src = eth.src
                dst = eth.dst
                protocol = f"ETH/0x{eth.type:04x}"
                summary = f"Ethernet {src} → {dst} type={protocol}"

            else:
                summary = pkt.summary() if hasattr(pkt, "summary") else "Unknown"

            return PacketInfo(
                timestamp=ts,
                protocol=protocol,
                src=src,
                dst=dst,
                size=size,
                summary=summary,
                src_port=src_port,
                dst_port=dst_port,
                src_mac=src_mac,
                dst_mac=dst_mac,
            )

        except Exception:
            return None

    def _extract_llmnr_name(self, pkt) -> str:
        """Try to extract the queried name from an LLMNR packet."""
        try:
            from scapy.all import DNS
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qd:
                    name = dns.qd.qname
                    if isinstance(name, bytes):
                        return name.decode("utf-8", errors="ignore").rstrip(".")
                    return str(name).rstrip(".")
        except Exception:
            pass
        return ""

    def _extract_ssdp_info(self, pkt) -> str:
        """Try to extract SSDP method or device info from the payload."""
        try:
            raw = bytes(pkt.payload.payload.payload) if pkt.payload and pkt.payload.payload else b""
            if raw:
                first_line = raw.split(b"\r\n")[0].decode("utf-8", errors="ignore")
                if "M-SEARCH" in first_line:
                    return "M-SEARCH (Discovery)"
                elif "NOTIFY" in first_line:
                    for line in raw.split(b"\r\n"):
                        line_str = line.decode("utf-8", errors="ignore")
                        if line_str.upper().startswith("NT:"):
                            return f"NOTIFY {line_str[3:].strip()}"
                        elif line_str.upper().startswith("SERVER:"):
                            return f"NOTIFY ({line_str[7:].strip()})"
                    return "NOTIFY (Alive)"
                elif "HTTP" in first_line:
                    return "Response"
                return first_line[:60]
        except Exception:
            pass
        return ""
