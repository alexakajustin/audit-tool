"""
Passive Network Sniffer — captures and analyzes traffic without injection.

Runs in a background thread. Yields PacketInfo objects for real-time
streaming via WebSocket. Supports BPF filters and PCAP import/export.

Enhanced protocol identification: mDNS, LLMNR, SSDP, NetBIOS, NDP.
Tracks DNS queries, security observations, and network intelligence.
Deep traffic intelligence: DNS reverse mapping, QUIC/HTTP3 SNI,
content categorization, per-device activity timelines.
"""

from __future__ import annotations

import os
import struct
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

        # ── Per-device Deep Activity Profiling ───────────────
        self._device_dns: dict[str, OrderedDict] = {}              # IP -> {domain: count}  (DNS queries per device)
        self._device_sni: dict[str, OrderedDict] = {}              # IP -> {domain: count}  (TLS SNI per device)
        self._device_http_hosts: dict[str, set] = {}               # IP -> set of HTTP Host headers
        self._device_http_urls: dict[str, list] = {}               # IP -> list of full HTTP URLs (GET/POST)
        self._device_user_agents: dict[str, set] = {}              # IP -> set of User-Agent strings
        self._device_hostnames: dict[str, str] = {}                # IP -> hostname (from DHCP/NetBIOS/mDNS)
        self._device_os: dict[str, str] = {}                       # IP -> OS guess (from User-Agent)

        # ── Deep Traffic Intelligence (v2) ────────────────────
        self._dns_reverse: dict[str, str] = {}                     # IP -> domain (from DNS responses)
        self._device_timeline: dict[str, list] = {}                # IP -> [{timestamp, domain, protocol, type}]
        self._device_categories: dict[str, dict] = {}              # IP -> {category: hit_count}
        self._intercepted_ips: set[str] = set()                    # IPs currently being MITM'd

        # ── DoH Providers (connections to these = hidden DNS) ──
        self._doh_providers: set[str] = {
            "cloudflare-dns.com", "dns.google", "doh.opendns.com",
            "dns.quad9.net", "doh.cleanbrowsing.org", "dns.adguard.com",
            "doh.dns.sb", "dns.nextdns.io", "dns.mullvad.net",
        }
        self._doh_provider_ips: set[str] = {
            "1.1.1.1", "1.0.0.1",                                 # Cloudflare
            "8.8.8.8", "8.8.4.4",                                 # Google
            "9.9.9.9", "149.112.112.112",                          # Quad9
            "208.67.222.222", "208.67.220.220",                    # OpenDNS
            "94.140.14.14", "94.140.15.15",                        # AdGuard
        }

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
        self._device_dns = {}
        self._device_sni = {}
        self._device_http_hosts = {}
        self._device_http_urls = {}
        self._device_user_agents = {}
        self._device_hostnames = {}
        self._device_os = {}
        self._dns_reverse = {}
        self._device_timeline = {}
        self._device_categories = {}

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
                # Per-device deep profiles
                "device_profiles": self._build_device_profiles(),
                # Deep Traffic Intelligence v2
                "intercepted_ips": list(self._intercepted_ips),
                "dns_reverse_map_size": len(self._dns_reverse),
                "category_summary": self._build_global_category_summary(),
                "activity_feed": self._build_activity_feed(),
            }

    def get_recent_packets(self, count: int = 50) -> list[dict]:
        """Get the most recent N packets as dicts."""
        with self._lock:
            return [p.to_dict() for p in self._packets[-count:]]

    def set_intercepted_ips(self, ips: set[str]) -> None:
        """Update the set of IPs currently being MITM'd (called from ArpSpoofer)."""
        with self._lock:
            self._intercepted_ips = set(ips)

    def get_device_timeline(self, ip: str, limit: int = 100) -> list[dict]:
        """Get timestamped activity log for a specific device."""
        with self._lock:
            entries = self._device_timeline.get(ip, [])
            return entries[-limit:]

    def get_category_summary(self) -> dict:
        """Get content category breakdown across all profiled devices."""
        with self._lock:
            result = {}
            for ip, cats in self._device_categories.items():
                if ip == self._local_ip:
                    continue
                result[ip] = {
                    "hostname": self._device_hostnames.get(ip, ""),
                    "mac": self._ip_to_mac.get(ip, ""),
                    "categories": dict(cats),
                    "intercepted": ip in self._intercepted_ips,
                }
            return result

    def _build_device_profiles(self) -> list[dict]:
        """Build per-device activity profiles (called inside lock)."""
        profiles = []
        all_ips = set()
        all_ips.update(self._device_dns.keys())
        all_ips.update(self._device_sni.keys())
        all_ips.update(self._device_http_hosts.keys())
        all_ips.update(self._data_volume.keys())

        for ip in sorted(all_ips):
            # Combine DNS + SNI + HTTP into unified browsing list
            sites = OrderedDict()
            # SNI is the richest source (HTTPS domains)
            for domain, count in self._device_sni.get(ip, {}).items():
                sites[domain] = sites.get(domain, 0) + count
            # DNS queries
            for domain, count in self._device_dns.get(ip, {}).items():
                sites[domain] = sites.get(domain, 0) + count
            # HTTP hosts
            for host in self._device_http_hosts.get(ip, set()):
                sites[host] = sites.get(host, 0) + 1

            # Sort by count descending
            sorted_sites = sorted(sites.items(), key=lambda x: x[1], reverse=True)

            profile = {
                "ip": ip,
                "hostname": self._device_hostnames.get(ip, ""),
                "mac": self._ip_to_mac.get(ip, ""),
                "os": self._device_os.get(ip, ""),
                "user_agents": list(self._device_user_agents.get(ip, set()))[:5],
                "data_volume": self._data_volume.get(ip, 0),
                "sites_visited": sorted_sites[:50],
                "http_urls": self._device_http_urls.get(ip, [])[-20:],
                "services": list(self._services_seen.get(ip, set())),
                "connections": list(self._host_connections.get(ip, set()))[:15],
                "dns_count": sum(self._device_dns.get(ip, {}).values()),
                "sni_count": sum(self._device_sni.get(ip, {}).values()),
                # Deep Traffic Intelligence v2
                "intercepted": ip in self._intercepted_ips,
                "categories": dict(self._device_categories.get(ip, {})),
                "flag_adult": self._device_categories.get(ip, {}).get("adult", 0) > 0,
                "timeline": self._device_timeline.get(ip, [])[-50:],
                "domains_resolved": len(self._device_dns.get(ip, {})),
            }
            # Only include devices with some activity
            if profile["sites_visited"] or profile["data_volume"] > 0:
                profiles.append(profile)

        # Sort by data volume descending
        profiles.sort(key=lambda p: p["data_volume"], reverse=True)
        return profiles[:30]

    def _build_global_category_summary(self) -> dict:
        """Aggregate content categories across all devices (called inside lock)."""
        totals: dict[str, int] = {}
        for ip, cats in self._device_categories.items():
            if ip == self._local_ip:
                continue
            for cat, count in cats.items():
                totals[cat] = totals.get(cat, 0) + count
        return totals

    def _build_activity_feed(self) -> list[dict]:
        """Build a real-time cross-device activity feed (called inside lock)."""
        all_entries = []
        for ip, timeline in self._device_timeline.items():
            if ip == self._local_ip:
                continue
            for entry in timeline[-30:]:  # Last 30 per device
                all_entries.append({
                    **entry,
                    "ip": ip,
                    "hostname": self._device_hostnames.get(ip, ""),
                    "intercepted": ip in self._intercepted_ips,
                })
        # Sort by timestamp descending, return last 100
        all_entries.sort(key=lambda e: e.get("timestamp", 0), reverse=True)
        return all_entries[:100]

    def _add_timeline_entry(self, ip: str, domain: str, protocol: str, entry_type: str) -> None:
        """Add a timestamped activity entry for a device (called inside lock)."""
        if not ip or ip == self._local_ip:
            return
        if ip not in self._device_timeline:
            self._device_timeline[ip] = []
        entry = {
            "timestamp": time.time(),
            "domain": domain,
            "protocol": protocol,
            "type": entry_type,
            "category": self._categorize_domain(domain),
        }
        self._device_timeline[ip].append(entry)
        # Cap at 200 entries per device
        if len(self._device_timeline[ip]) > 200:
            self._device_timeline[ip] = self._device_timeline[ip][-200:]

    def _track_category(self, ip: str, domain: str) -> None:
        """Track content category for a domain visit (called inside lock)."""
        if not ip or not domain or ip == self._local_ip:
            return
        cat = self._categorize_domain(domain)
        if cat:
            if ip not in self._device_categories:
                self._device_categories[ip] = {}
            self._device_categories[ip][cat] = self._device_categories[ip].get(cat, 0) + 1

    def _categorize_domain(self, domain: str) -> str:
        """Classify a domain into a content category using pattern matching."""
        if not domain:
            return ""
        d = domain.lower()

        # Adult / NSFW
        adult_patterns = [
            "pornhub", "xvideos", "xhamster", "redtube", "youporn", "xnxx",
            "brazzers", "bangbros", "realitykings", "naughtyamerica",
            "chaturbate", "stripchat", "livejasmin", "cam4", "bongacams",
            "onlyfans", "fansly", "manyvids", "clips4sale",
            "spankbang", "eporner", "tube8", "xtube", "beeg",
            "porn", "xxx", "hentai", "rule34", "nhentai", "hanime",
            "sexe", "adult", "nsfw", "erotic",
        ]
        if any(p in d for p in adult_patterns):
            return "adult"

        # Social Media
        social_patterns = [
            "facebook.com", "fbcdn.net", "instagram.com", "cdninstagram",
            "twitter.com", "x.com", "twimg.com",
            "tiktok.com", "tiktokcdn.com", "musical.ly",
            "reddit.com", "redd.it", "redditstatic.com",
            "snapchat.com", "sc-cdn.net",
            "linkedin.com", "licdn.com",
            "pinterest.com", "pinimg.com",
            "tumblr.com", "discord.com", "discordapp.com",
            "telegram.org", "t.me", "whatsapp.com", "whatsapp.net",
            "mastodon", "threads.net",
        ]
        if any(p in d for p in social_patterns):
            return "social_media"

        # Streaming / Entertainment
        streaming_patterns = [
            "youtube.com", "googlevideo.com", "ytimg.com", "yt3.ggpht",
            "netflix.com", "nflxvideo.net", "nflxso.net", "nflxext.com",
            "disneyplus.com", "disney-plus.net", "bamgrid.com",
            "hbomax.com", "max.com", "hbogo.com",
            "primevideo.com", "amazonvideo.com", "aiv-cdn.net",
            "hulu.com", "hulustream.com",
            "twitch.tv", "jtvnw.net", "twitchcdn.net",
            "spotify.com", "scdn.co", "spotifycdn.com",
            "soundcloud.com", "deezer.com", "tidal.com",
            "crunchyroll.com", "funimation.com", "vrv.co",
            "roku.com", "peacocktv.com", "paramountplus.com",
            "apple.com/tv", "applemusic",
        ]
        if any(p in d for p in streaming_patterns):
            return "streaming"

        # Gaming
        gaming_patterns = [
            "steampowered.com", "steamcommunity.com", "steamstatic.com",
            "epicgames.com", "unrealengine.com",
            "ea.com", "origin.com", "ea-api.com",
            "riotgames.com", "leagueoflegends.com",
            "blizzard.com", "battle.net", "blz-contentstack.com",
            "xbox.com", "xboxlive.com",
            "playstation.com", "playstation.net", "sonyentertainmentnetwork.com",
            "ubisoft.com", "ubi.com",
            "roblox.com", "rbxcdn.com",
            "minecraft.net", "mojang.com",
            "twitch.tv", "curseforge.com",
        ]
        if any(p in d for p in gaming_patterns):
            return "gaming"

        # News
        news_patterns = [
            "cnn.com", "bbc.com", "bbc.co.uk", "reuters.com", "apnews.com",
            "foxnews.com", "msnbc.com", "nbcnews.com", "abcnews.go.com",
            "nytimes.com", "washingtonpost.com", "theguardian.com",
            "wsj.com", "bloomberg.com", "cnbc.com", "aljazeera.com",
            "digi24.ro", "mediafax.ro", "hotnews.ro", "stiripesurse.ro",
            "news.google", "news.yahoo",
        ]
        if any(p in d for p in news_patterns):
            return "news"

        # Finance / Banking
        finance_patterns = [
            "paypal.com", "stripe.com", "wise.com", "revolut.com",
            "bank", "banking", "chase.com", "wellsfargo.com",
            "americanexpress.com", "capitalone.com",
            "coinbase.com", "binance.com", "kraken.com", "crypto.com",
            "robinhood.com", "etrade.com", "schwab.com",
            "bcr.ro", "brd.ro", "ingbank.ro", "raiffeisen.ro",
        ]
        if any(p in d for p in finance_patterns):
            return "finance"

        # Shopping
        shopping_patterns = [
            "amazon.com", "amazon.co", "amazon.", "amzn.to",
            "ebay.com", "aliexpress.com", "alibaba.com",
            "walmart.com", "target.com", "bestbuy.com",
            "shopify.com", "etsy.com",
            "emag.ro", "olx.ro", "altex.ro", "pcgarage.ro",
        ]
        if any(p in d for p in shopping_patterns):
            return "shopping"

        # VPN / Proxy (evasion)
        vpn_patterns = [
            "nordvpn.com", "expressvpn.com", "surfshark.com",
            "protonvpn.com", "cyberghostvpn.com", "privateinternetaccess.com",
            "torproject.org", "tor2web",
            "mullvad.net", "windscribe.com", "tunnelbear.com",
            "openvpn", "wireguard",
        ]
        if any(p in d for p in vpn_patterns):
            return "vpn_proxy"

        # Productivity
        productivity_patterns = [
            "office.com", "office365.com", "microsoft.com", "live.com",
            "google.com", "googleapis.com", "gstatic.com",
            "zoom.us", "zoomgov.com",
            "slack.com", "slack-edge.com",
            "notion.so", "trello.com", "asana.com", "monday.com",
            "atlassian.com", "jira.", "confluence.",
            "github.com", "gitlab.com", "bitbucket.org",
            "stackoverflow.com", "stackexchange.com",
        ]
        if any(p in d for p in productivity_patterns):
            return "productivity"

        # Email
        email_patterns = [
            "gmail.com", "mail.google", "outlook.com", "outlook.live",
            "yahoo.com/mail", "mail.yahoo", "protonmail.com", "proton.me",
            "zoho.com/mail", "icloud.com/mail", "fastmail.com",
        ]
        if any(p in d for p in email_patterns):
            return "email"

        # Cloud Storage
        cloud_patterns = [
            "dropbox.com", "drive.google", "onedrive.live",
            "icloud.com", "box.com", "mega.nz", "mega.io",
            "wetransfer.com", "mediafire.com", "4shared.com",
        ]
        if any(p in d for p in cloud_patterns):
            return "cloud_storage"

        return ""

    def _extract_quic_sni(self, payload: bytes) -> str:
        """
        Extract SNI from a QUIC Initial packet (HTTP/3).

        QUIC Initial packets contain a TLS ClientHello in the crypto frames.
        The SNI extension is in the same format as regular TLS.
        """
        try:
            if len(payload) < 20:
                return ""

            # QUIC long header: first byte has form bit (1) + fixed bit (1) + type (2)
            first_byte = payload[0]

            # Check if long header (bit 7 set)
            if not (first_byte & 0x80):
                return ""

            # Check if Initial packet (type bits 4-5 = 0b00)
            packet_type = (first_byte & 0x30) >> 4
            if packet_type != 0x00:
                return ""

            # Skip: Version (4 bytes) at offset 1
            offset = 5

            if offset >= len(payload):
                return ""

            # DCID Length + DCID
            dcid_len = payload[offset]
            offset += 1 + dcid_len

            if offset >= len(payload):
                return ""

            # SCID Length + SCID
            scid_len = payload[offset]
            offset += 1 + scid_len

            if offset >= len(payload):
                return ""

            # Token Length (variable-length integer)
            token_len_first = payload[offset]
            token_len_type = (token_len_first & 0xC0) >> 6
            if token_len_type == 0:
                token_len = token_len_first & 0x3F
                offset += 1
            elif token_len_type == 1:
                if offset + 2 > len(payload):
                    return ""
                token_len = ((token_len_first & 0x3F) << 8) | payload[offset + 1]
                offset += 2
            else:
                return ""  # Token too large for Initial

            offset += token_len

            if offset + 2 > len(payload):
                return ""

            # Packet Length (variable-length integer) — skip
            pkt_len_first = payload[offset]
            pkt_len_type = (pkt_len_first & 0xC0) >> 6
            if pkt_len_type == 0:
                offset += 1
            elif pkt_len_type == 1:
                offset += 2
            elif pkt_len_type == 2:
                offset += 4
            else:
                offset += 8

            # The rest is encrypted for real QUIC, but some implementations
            # and the initial crypto handshake may have the ClientHello visible.
            # Search for TLS ClientHello pattern in remaining bytes
            remaining = payload[offset:]
            return self._find_sni_in_bytes(remaining)

        except Exception:
            pass
        return ""

    def _find_sni_in_bytes(self, data: bytes) -> str:
        """Search for a TLS SNI extension pattern anywhere in raw bytes."""
        try:
            # Look for the server_name extension type (0x00 0x00) followed by
            # reasonable-looking SNI data. This is a heuristic scan.
            i = 0
            while i < len(data) - 10:
                # Look for extension type 0x0000 (server_name)
                if data[i] == 0x00 and data[i + 1] == 0x00:
                    ext_len = (data[i + 2] << 8) | data[i + 3]
                    if 4 < ext_len < 256 and i + 4 + ext_len <= len(data):
                        # SNI list: list_len(2), name_type(1), name_len(2), name
                        name_offset = i + 4
                        if name_offset + 5 <= len(data):
                            name_type = data[name_offset + 2]
                            name_len = (data[name_offset + 3] << 8) | data[name_offset + 4]
                            if name_type == 0x00 and 3 < name_len < 253:
                                if name_offset + 5 + name_len <= len(data):
                                    name = data[name_offset + 5: name_offset + 5 + name_len]
                                    try:
                                        sni = name.decode("ascii", errors="ignore").strip()
                                        # Validate it looks like a domain
                                        if sni and "." in sni and len(sni) > 3 and " " not in sni:
                                            return sni
                                    except Exception:
                                        pass
                i += 1
        except Exception:
            pass
        return ""

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

            # Track DNS queries (what sites are being browsed) — GLOBAL + PER-DEVICE
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qr == 0 and dns.qd:  # Query
                    qname = dns.qd.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="ignore")
                    qname = str(qname).rstrip(".")
                    if qname and len(qname) > 3 and "." in qname:
                        self._dns_queries[qname] = self._dns_queries.get(qname, 0) + 1
                        # Per-device DNS tracking
                        querier = info.src
                        if querier:
                            if querier not in self._device_dns:
                                self._device_dns[querier] = OrderedDict()
                            self._device_dns[querier][qname] = self._device_dns[querier].get(qname, 0) + 1
                            # Timeline + Category tracking
                            self._add_timeline_entry(querier, qname, "DNS", "dns_query")
                            self._track_category(querier, qname)

                # ── DNS Response Parsing (IP→Domain reverse map) ─────
                elif dns.qr == 1 and dns.ancount and dns.ancount > 0:
                    # Extract the queried name
                    query_name = ""
                    if dns.qd:
                        qn = dns.qd.qname
                        if isinstance(qn, bytes):
                            qn = qn.decode("utf-8", errors="ignore")
                        query_name = str(qn).rstrip(".")

                    if query_name and "." in query_name:
                        # Parse answer records to map resolved IPs back to the domain
                        try:
                            for i in range(min(dns.ancount, 20)):
                                rr = dns.an[i] if hasattr(dns.an, '__getitem__') else dns.an
                                if hasattr(rr, 'rdata'):
                                    rdata = str(rr.rdata)
                                    # Check if rdata is an IP address
                                    try:
                                        import ipaddress
                                        ipaddress.ip_address(rdata)
                                        # Valid IP → map it back to the domain
                                        if len(self._dns_reverse) < 50000:  # Safety cap
                                            self._dns_reverse[rdata] = query_name
                                    except (ValueError, TypeError):
                                        pass  # CNAME or other non-IP record
                        except Exception:
                            pass

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

            # ── TLS SNI Extraction (HTTPS domain visibility) ─────
            # Even on HTTPS, the TLS ClientHello sends the server name in cleartext!
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                tcp = pkt[TCP]
                if tcp.dport in (443, 8443, 993, 995, 465, 636, 989, 990, 5061):
                    try:
                        payload = bytes(pkt[Raw].load)
                        sni = self._extract_tls_sni(payload)
                        if sni:
                            # Per-device SNI tracking
                            client_ip = info.src
                            if client_ip:
                                if client_ip not in self._device_sni:
                                    self._device_sni[client_ip] = OrderedDict()
                                self._device_sni[client_ip][sni] = self._device_sni[client_ip].get(sni, 0) + 1
                                # Timeline + Category tracking
                                self._add_timeline_entry(client_ip, sni, "TLS", "tls_connect")
                                self._track_category(client_ip, sni)

                                # ── DoH Detection ────────────────────────
                                if sni in self._doh_providers:
                                    alert_key = f"doh:{client_ip}:{sni}"
                                    if alert_key not in self._alerts_triggered:
                                        self._alerts_triggered.add(alert_key)
                                        if len(self._security_alerts) < 200:
                                            self._security_alerts.append({
                                                "type": "dns_bypass_doh",
                                                "severity": "warning",
                                                "message": f"DNS-over-HTTPS detected via {sni} — DNS queries are hidden from monitoring",
                                                "src": client_ip,
                                                "dst": info.dst,
                                                "timestamp": info.timestamp,
                                            })
                    except Exception:
                        pass

            # ── QUIC / HTTP/3 SNI Extraction ───────────────────
            # Modern browsers use QUIC (UDP:443) which bypasses TLS SNI capture
            if pkt.haslayer(UDP) and pkt.haslayer(Raw):
                udp = pkt[UDP]
                if udp.dport == 443 or udp.sport == 443:
                    try:
                        payload = bytes(pkt[Raw].load)
                        quic_sni = self._extract_quic_sni(payload)
                        if quic_sni:
                            client_ip = info.src
                            if client_ip:
                                if client_ip not in self._device_sni:
                                    self._device_sni[client_ip] = OrderedDict()
                                self._device_sni[client_ip][quic_sni] = self._device_sni[client_ip].get(quic_sni, 0) + 1
                                self._add_timeline_entry(client_ip, quic_sni, "QUIC", "quic_connect")
                                self._track_category(client_ip, quic_sni)

                                # DoH over QUIC detection
                                if quic_sni in self._doh_providers:
                                    alert_key = f"doh_quic:{client_ip}:{quic_sni}"
                                    if alert_key not in self._alerts_triggered:
                                        self._alerts_triggered.add(alert_key)
                                        if len(self._security_alerts) < 200:
                                            self._security_alerts.append({
                                                "type": "dns_bypass_doh",
                                                "severity": "warning",
                                                "message": f"DNS-over-HTTPS (QUIC) detected via {quic_sni} — DNS queries are hidden",
                                                "src": client_ip,
                                                "dst": info.dst,
                                                "timestamp": info.timestamp,
                                            })
                    except Exception:
                        pass

            # ── DoH Detection by IP (port 443 to known DoH provider IPs) ──
            if info.dst_port == 443 and info.dst in self._doh_provider_ips:
                alert_key = f"doh_ip:{info.src}:{info.dst}"
                if alert_key not in self._alerts_triggered:
                    self._alerts_triggered.add(alert_key)
                    if len(self._security_alerts) < 200:
                        # Try to get domain from DNS reverse map
                        provider = self._dns_reverse.get(info.dst, info.dst)
                        self._security_alerts.append({
                            "type": "dns_bypass_doh",
                            "severity": "warning",
                            "message": f"Possible DNS-over-HTTPS connection to {provider} ({info.dst})",
                            "src": info.src,
                            "dst": info.dst,
                            "timestamp": info.timestamp,
                        })

            # ── Security alerts ──────────────────────────────
            # Cleartext HTTP traffic — deep extraction (Host, URL, User-Agent)
            if info.protocol == "HTTP" and pkt.haslayer(Raw):
                raw = bytes(pkt[Raw].load)
                try:
                    text = raw.decode("utf-8", errors="ignore")
                    lines = text.split("\r\n")
                    request_line = lines[0] if lines else ""
                    host_header = ""
                    user_agent = ""

                    for line in lines[1:]:
                        upper = line.upper()
                        if upper.startswith("HOST:"):
                            host_header = line[5:].strip()
                        elif upper.startswith("USER-AGENT:"):
                            user_agent = line[11:].strip()

                    if host_header:
                        self._http_hosts.add(host_header)
                        # Per-device HTTP tracking
                        if info.src:
                            if info.src not in self._device_http_hosts:
                                self._device_http_hosts[info.src] = set()
                            self._device_http_hosts[info.src].add(host_header)
                            # Timeline + Category tracking
                            self._add_timeline_entry(info.src, host_header, "HTTP", "http_request")
                            self._track_category(info.src, host_header)

                            # Capture full URL (GET /path HTTP/1.1)
                            if request_line and (request_line.startswith("GET ") or request_line.startswith("POST ")):
                                method_path = request_line.split(" ")[0:2]
                                if len(method_path) == 2:
                                    full_url = f"{method_path[0]} http://{host_header}{method_path[1]}"
                                    if info.src not in self._device_http_urls:
                                        self._device_http_urls[info.src] = []
                                    if len(self._device_http_urls[info.src]) < 100:
                                        self._device_http_urls[info.src].append(full_url)

                        if user_agent and info.src:
                            if info.src not in self._device_user_agents:
                                self._device_user_agents[info.src] = set()
                            if len(self._device_user_agents[info.src]) < 10:
                                self._device_user_agents[info.src].add(user_agent[:200])
                            # Guess OS from User-Agent
                            if info.src not in self._device_os or not self._device_os[info.src]:
                                self._device_os[info.src] = self._guess_os(user_agent)

                        if host_header and len(self._security_alerts) < 200:
                            self._security_alerts.append({
                                "type": "cleartext_http",
                                "severity": "warning",
                                "message": f"Cleartext HTTP to {host_header}",
                                "src": info.src,
                                "dst": info.dst,
                                "timestamp": info.timestamp,
                            })
                except Exception:
                    pass

            # ── DHCP Hostname Extraction ─────────────────────
            if info.protocol == "DHCP" and pkt.haslayer("DHCP"):
                try:
                    dhcp_opts = pkt["DHCP"].options
                    for opt in dhcp_opts:
                        if isinstance(opt, tuple):
                            if opt[0] == "hostname":
                                hostname = opt[1].decode("utf-8", errors="ignore") if isinstance(opt[1], bytes) else str(opt[1])
                                if hostname and info.src and info.src != "0.0.0.0":
                                    self._device_hostnames[info.src] = hostname
                except Exception:
                    pass

            # ── NetBIOS Name Extraction ──────────────────────
            if pkt.haslayer(UDP) and pkt[UDP].sport == 137 and pkt.haslayer(Raw):
                try:
                    raw_data = bytes(pkt[Raw].load)
                    if len(raw_data) > 56:
                        # NetBIOS name is at offset 57, 15 bytes, space-padded
                        name_bytes = raw_data[57:72]
                        name = name_bytes.decode("ascii", errors="ignore").strip()
                        if name and info.src and len(name) > 1:
                            self._device_hostnames[info.src] = name
                except Exception:
                    pass

            # ── mDNS Hostname Extraction ─────────────────────
            if info.protocol == "mDNS" and pkt.haslayer(DNS):
                try:
                    dns_layer = pkt[DNS]
                    if dns_layer.ancount and dns_layer.ancount > 0:
                        for i in range(min(dns_layer.ancount, 5)):
                            rr = dns_layer.an[i] if hasattr(dns_layer.an, '__getitem__') else dns_layer.an
                            if hasattr(rr, 'rrname'):
                                rrname = rr.rrname
                                if isinstance(rrname, bytes):
                                    rrname = rrname.decode("utf-8", errors="ignore")
                                rrname = str(rrname).rstrip(".")
                                if rrname.endswith(".local") and info.src:
                                    hostname = rrname.replace(".local", "")
                                    if hostname:
                                        self._device_hostnames[info.src] = hostname
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

    def _extract_tls_sni(self, payload: bytes) -> str:
        """
        Extract Server Name Indication (SNI) from a TLS ClientHello.

        Even HTTPS traffic leaks the destination domain in the TLS handshake.
        This parses the raw ClientHello bytes to find the server_name extension.
        """
        try:
            if len(payload) < 11:
                return ""

            # TLS record: ContentType(1) Version(2) Length(2) HandshakeType(1) ...
            content_type = payload[0]
            if content_type != 0x16:  # Not a Handshake record
                return ""

            handshake_type = payload[5]
            if handshake_type != 0x01:  # Not ClientHello
                return ""

            # ClientHello structure:
            # HandshakeType(1) Length(3) Version(2) Random(32) SessionIDLen(1) SessionID(var)
            # CipherSuitesLen(2) CipherSuites(var) CompressionLen(1) Compression(var)
            # ExtensionsLen(2) Extensions(var)

            offset = 5 + 1 + 3 + 2 + 32  # Skip to SessionID length (offset 43)

            if offset >= len(payload):
                return ""

            # Skip Session ID
            session_id_len = payload[offset]
            offset += 1 + session_id_len

            if offset + 2 > len(payload):
                return ""

            # Skip Cipher Suites
            cipher_suites_len = (payload[offset] << 8) | payload[offset + 1]
            offset += 2 + cipher_suites_len

            if offset + 1 > len(payload):
                return ""

            # Skip Compression Methods
            compression_len = payload[offset]
            offset += 1 + compression_len

            if offset + 2 > len(payload):
                return ""

            # Extensions
            extensions_len = (payload[offset] << 8) | payload[offset + 1]
            offset += 2
            extensions_end = offset + extensions_len

            while offset + 4 <= min(extensions_end, len(payload)):
                ext_type = (payload[offset] << 8) | payload[offset + 1]
                ext_len = (payload[offset + 2] << 8) | payload[offset + 3]
                offset += 4

                if ext_type == 0x0000:  # server_name extension
                    if offset + 5 <= len(payload):
                        # SNI list length(2), name type(1), name length(2), name(var)
                        name_type = payload[offset + 2]
                        name_len = (payload[offset + 3] << 8) | payload[offset + 4]

                        if name_type == 0x00 and offset + 5 + name_len <= len(payload):
                            server_name = payload[offset + 5: offset + 5 + name_len]
                            sni = server_name.decode("ascii", errors="ignore").strip()
                            if sni and "." in sni and len(sni) > 3:
                                return sni
                    return ""

                offset += ext_len

        except Exception:
            pass
        return ""

    def _guess_os(self, user_agent: str) -> str:
        """Guess the operating system from an HTTP User-Agent string."""
        ua = user_agent.lower()
        if "windows nt 10" in ua:
            return "Windows 10/11"
        elif "windows nt 6.3" in ua:
            return "Windows 8.1"
        elif "windows nt 6.1" in ua:
            return "Windows 7"
        elif "windows" in ua:
            return "Windows"
        elif "macintosh" in ua or "mac os x" in ua:
            return "macOS"
        elif "iphone" in ua:
            return "iOS (iPhone)"
        elif "ipad" in ua:
            return "iOS (iPad)"
        elif "android" in ua:
            return "Android"
        elif "linux" in ua:
            return "Linux"
        elif "chromeos" in ua or "cros" in ua:
            return "ChromeOS"
        return ""

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
