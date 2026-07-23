import time
import os
from typing import Optional
from fpdf import FPDF

class MetricsManager:
    """
    Manages background network security metrics gathering.
    Tracks packet counts, hosts, and alerts during a user-defined window,
    then compiles them into an elegant, minimalist PDF grading report.
    """

    def __init__(self):
        self.is_gathering = False
        self.start_time: float = 0.0
        self.stop_time: float = 0.0
        
        # Start snapshots
        self.start_packet_count = 0
        self.start_hosts = set()
        self.start_alerts = []

        # Results
        self.duration = 0.0
        self.packets_gathered = 0
        self.unique_hosts_seen = []
        self.new_alerts = []
        
        # Saved report path
        self.pdf_report_path = ""

    def start(self, sniffer_service) -> bool:
        """Starts gathering metrics, activating the sniffer if it is not already running."""
        if self.is_gathering:
            return False

        # Ensure the sniffer and passive discovery are running
        try:
            from network.interfaces import get_best_interface
            import api
            best = get_best_interface()
            iface = best.name if best else ""

            if not sniffer_service.is_running:
                sniffer_service.start(interface=iface)
            
            if hasattr(api, 'passive_discovery') and api.passive_discovery and not api.passive_discovery.is_running:
                # Add a callback to upsert to inventory when devices are found
                def on_found(dev):
                    if hasattr(api, 'inventory') and api.inventory:
                        api.inventory.upsert_device(dev)
                api.passive_discovery.start(interface=iface, on_device_found=on_found)
                
        except Exception as e:
            print(f"[MetricsManager] Warning: failed to auto-start services ({e})")

        # Capture start snapshot for packets
        stats = sniffer_service.get_stats()
        self.start_packet_count = stats.get("total_packets", 0)
        
        self.is_gathering = True
        self.start_time = time.time()
        self.stop_time = 0.0
        self.pdf_report_path = ""
        
        print("[MetricsManager] Metrics gathering STARTED.")
        return True

    def stop(self, sniffer_service, export_dir: str) -> dict:
        """Stops gathering and computes the security posture score and grade."""
        if not self.is_gathering:
            return {"error": "Metrics gathering was not running"}

        self.stop_time = time.time()
        self.duration = self.stop_time - self.start_time
        self.is_gathering = False

        # Capture end snapshot
        stats = sniffer_service.get_stats()
        self.raw_stats = stats
        end_packet_count = stats.get("total_packets", 0)
        end_hosts = set(stats.get("unique_hosts", []))
        
        # To be comprehensive, we use ALL security alerts and ALL hosts seen, not just deltas.
        self.new_alerts = list(stats.get("security_alerts", []))
        self.unique_hosts_seen = list(end_hosts)

        # Calculate delta packets captured during this session
        self.packets_gathered = max(0, end_packet_count - self.start_packet_count)

        # Capture VLAN intelligence snapshot
        self.vlan_intel = {"switches": [], "vlans": [], "subnets": [], "routes": []}
        try:
            import api
            if hasattr(api, 'vlan_discovery') and api.vlan_discovery:
                intel = api.vlan_discovery.get_full_intelligence()
                self.vlan_intel = {
                    "switches": intel.get("switches", []),
                    "vlans": intel.get("vlans", []),
                    "subnets": intel.get("subnets", []),
                    "routes": intel.get("routes", []),
                    "protocol_counts": intel.get("status", {}).get("protocol_counts", {}),
                }
        except Exception as e:
            print(f"[MetricsManager] Warning: failed to capture VLAN intelligence ({e})")

        # Capture Inventory Snapshot
        self.inventory_stats = {}
        self.devices_list = []
        try:
            import api
            if hasattr(api, 'inventory') and api.inventory:
                self.inventory_stats = api.inventory.get_stats()
                self.devices_list = api.inventory.get_all(sort_by="last_seen", sort_order="desc")
        except Exception as e:
            print(f"[MetricsManager] Warning: failed to capture inventory ({e})")

        # Capture MITM Snapshot
        self.mitm_status = {}
        try:
            import api
            if hasattr(api, 'arp_spoofer') and api.arp_spoofer:
                self.mitm_status = api.arp_spoofer.get_status()
        except Exception as e:
            print(f"[MetricsManager] Warning: failed to capture MITM status ({e})")

        # Build PDF file path
        os.makedirs(export_dir, exist_ok=True)
        filename = f"security_report_{int(time.time())}.pdf"
        self.pdf_report_path = os.path.join(export_dir, filename)

        # Generate report
        self._generate_pdf_report()

        print("[MetricsManager] Metrics gathering STOPPED.")
        return self.get_status()

    def get_status(self) -> dict:
        """Returns the current status and metrics of the gathering session."""
        current_duration = 0.0
        live_packets = self.packets_gathered
        live_hosts_count = len(self.unique_hosts_seen)
        live_alerts_count = len(self.new_alerts)

        if self.is_gathering:
            current_duration = time.time() - self.start_time
            # Grab live stats dynamically
            try:
                import api
                if api.sniffer and api.sniffer.is_running:
                    stats = api.sniffer.get_stats()
                    live_packets = max(0, stats.get("total_packets", 0) - self.start_packet_count)
                    live_hosts_count = len(stats.get("unique_hosts", []))
                    live_alerts_count = len(stats.get("security_alerts", []))
            except Exception:
                pass
        else:
            current_duration = self.duration

        return {
            "is_gathering": self.is_gathering,
            "duration": current_duration,
            "packets_gathered": live_packets,
            "unique_hosts_count": live_hosts_count,
            "alerts_triggered_count": live_alerts_count,
            "pdf_available": bool(self.pdf_report_path and os.path.exists(self.pdf_report_path)),
            "pdf_filename": os.path.basename(self.pdf_report_path) if self.pdf_report_path else ""
        }

    def _format_bytes(self, num: float) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if num < 1024.0:
                return f"{num:.1f} {unit}"
            num /= 1024.0
        return f"{num:.1f} TB"

    def _generate_pdf_report(self):
        """Generates the elegant, minimalist PDF security report using fpdf2."""
        pdf = FPDF(orientation="P", unit="mm", format="A4")
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        
        # Color definitions
        c_dark_navy = (21, 27, 43)
        c_text_dark = (40, 50, 70)
        c_muted = (100, 110, 130)
        
        # ── Title / Header ──
        pdf.set_font("helvetica", "B", 24)
        pdf.set_text_color(*c_dark_navy)
        pdf.cell(0, 12, "NETAUDIT TELEMETRY REPORT", ln=True, align="L")
        
        pdf.set_font("helvetica", "", 10)
        pdf.set_text_color(*c_muted)
        current_date = time.strftime("%Y-%m-%d %H:%M:%S")
        pdf.cell(0, 5, f"Automated Security & Network Health Audit  |  Generated: {current_date}", ln=True, align="L")
        
        # Thin divider line
        pdf.set_draw_color(220, 225, 235)
        pdf.set_line_width(0.4)
        pdf.line(10, 30, 200, 30)
        pdf.ln(10)
        
        # Move Y down a bit instead of drawing the scorecard box
        pdf.set_xy(10, 35)

        raw_stats = getattr(self, "raw_stats", {})
        pps = raw_stats.get("packets_per_second", 0)

        # ── Network Telemetry Summary ──
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(*c_dark_navy)
        pdf.cell(0, 8, "Network Telemetry Summary", ln=True)
        pdf.ln(2)
        
        # Minimalist metadata table
        pdf.set_font("helvetica", "B", 9)
        pdf.set_fill_color(240, 243, 248)
        pdf.set_text_color(*c_dark_navy)
        pdf.cell(45, 7, " Metric", border="B", fill=True)
        pdf.cell(50, 7, " Value", border="B", fill=True)
        pdf.cell(45, 7, " Metric", border="B", fill=True)
        pdf.cell(50, 7, " Value", border="B", fill=True, ln=True)
        
        pdf.set_font("helvetica", "", 9)
        pdf.set_text_color(*c_text_dark)
        
        # Row 1
        pdf.cell(45, 7, " Duration", border="B")
        pdf.cell(50, 7, f" {self.duration:.1f} seconds", border="B")
        pdf.cell(45, 7, " Packets Analyzed", border="B")
        pdf.cell(50, 7, f" {self.packets_gathered} packets", border="B", ln=True)
        
        # Row 2
        pdf.cell(45, 7, " Unique Hosts Communicating", border="B")
        pdf.cell(50, 7, f" {len(self.unique_hosts_seen)} hosts", border="B")
        pdf.cell(45, 7, " Avg Traffic Rate", border="B")
        pdf.cell(50, 7, f" {pps:.2f} Packets/Sec", border="B", ln=True)

        # Row 3
        pdf.cell(45, 7, " Sniffer Active Interface", border="B")
        pdf.cell(50, 7, f" {raw_stats.get('local_ip', 'Dynamic')}", border="B")
        pdf.cell(45, 7, " Security Alerts Triggered", border="B")
        pdf.cell(50, 7, f" {len(self.new_alerts)} alerts", border="B", ln=True)
        pdf.ln(8)

        # ── Asset & Inventory Overview ──
        inv_stats = getattr(self, "inventory_stats", {})
        devices_list = getattr(self, "devices_list", [])
        if inv_stats and devices_list:
            pdf.set_font("helvetica", "B", 12)
            pdf.set_text_color(*c_dark_navy)
            pdf.cell(0, 8, "Asset & Device Inventory Overview", ln=True)
            pdf.ln(2)
            
            with pdf.table(borders_layout="HORIZONTAL_LINES", text_align="LEFT", col_widths=(65, 125)) as summary_table:
                pdf.set_font("helvetica", "B", 9)
                row = summary_table.row()
                row.cell("Metric")
                row.cell("Value")
                
                pdf.set_font("helvetica", "", 9)
                
                total_devs = inv_stats.get("total_devices", 0)
                online_devs = inv_stats.get("online_devices", 0)
                offline_devs = inv_stats.get("offline_devices", 0)
                total_ports = inv_stats.get("total_open_ports", 0)
                
                row = summary_table.row()
                row.cell("Total Devices Discovered")
                row.cell(f"{total_devs} (Online: {online_devs} / Offline: {offline_devs})")
                
                row = summary_table.row()
                row.cell("Total Open Ports Detected")
                row.cell(f"{total_ports}")
                
                os_dist = inv_stats.get("os_distribution", {})
                if os_dist:
                    os_str = ", ".join(f"{k} ({v})" for k, v in list(os_dist.items())[:5])
                    row = summary_table.row()
                    row.cell("Top Operating Systems")
                    row.cell(os_str)
                    
                vendor_dist = inv_stats.get("vendor_distribution", {})
                if vendor_dist:
                    v_str = ", ".join(f"{k} ({v})" for k, v in list(vendor_dist.items())[:5])
                    row = summary_table.row()
                    row.cell("Top Hardware Vendors")
                    row.cell(v_str)
            pdf.ln(8)

            # ── Detailed Device List ──
            pdf.set_font("helvetica", "B", 12)
            pdf.set_text_color(*c_dark_navy)
            pdf.cell(0, 8, "Discovered Network Devices (Top 30 Recently Active)", ln=True)
            pdf.ln(2)
            
            with pdf.table(borders_layout="HORIZONTAL_LINES", text_align="LEFT", col_widths=(25, 35, 35, 45, 40)) as table:
                pdf.set_font("helvetica", "B", 8)
                row = table.row()
                row.cell("IP Address")
                row.cell("MAC Address")
                row.cell("Hostname")
                row.cell("Vendor / OS")
                row.cell("Open Ports")
                
                pdf.set_font("helvetica", "", 8)
                for d in devices_list[:30]:
                    row = table.row()
                    row.cell(d.ip or "-")
                    row.cell(d.mac)
                    row.cell(str(d.hostname)[:20] or "-")
                    
                    vos = []
                    if d.vendor: vos.append(d.vendor[:15])
                    if d.os: vos.append(d.os[:15])
                    row.cell(" / ".join(vos) or "-")
                    
                    if d.ports:
                        p_str = ", ".join(str(p.port) for p in d.ports[:8])
                        if len(d.ports) > 8: p_str += "..."
                        row.cell(p_str)
                    else:
                        row.cell("-")
            pdf.ln(8)

        # ── Protocol Distribution ──
        protocols = raw_stats.get("protocols", {})
        if protocols:
            pdf.set_font("helvetica", "B", 12)
            pdf.set_text_color(*c_dark_navy)
            pdf.cell(0, 8, "Protocol Distribution Summary", ln=True)
            pdf.ln(2)
            
            with pdf.table(borders_layout="HORIZONTAL_LINES", text_align="LEFT") as table:
                pdf.set_font("helvetica", "B", 9)
                row = table.row()
                row.cell("Protocol Layer")
                row.cell("Packet Count")
                row.cell("Traffic Share")
                
                pdf.set_font("helvetica", "", 9)
                total_pkts = sum(protocols.values()) or 1
                for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:10]:
                    share = (count / total_pkts) * 100
                    row = table.row()
                    row.cell(str(proto))
                    row.cell(f"{count:,}")
                    row.cell(f"{share:.1f}%")
            pdf.ln(8)

        # ── Top Network Talkers ──
        top_talkers = raw_stats.get("top_talkers", [])
        if top_talkers:
            pdf.set_font("helvetica", "B", 12)
            pdf.set_text_color(*c_dark_navy)
            pdf.cell(0, 8, "Top Bandwidth Consumers (Hosts)", ln=True)
            pdf.ln(2)
            
            with pdf.table(borders_layout="HORIZONTAL_LINES", text_align="LEFT") as table:
                pdf.set_font("helvetica", "B", 9)
                row = table.row()
                row.cell("Host IP Address")
                row.cell("Data Transferred")
                
                pdf.set_font("helvetica", "", 9)
                for ip, bytes_val in top_talkers[:10]:
                    row = table.row()
                    row.cell(str(ip))
                    row.cell(self._format_bytes(bytes_val))
            pdf.ln(8)

        # ── Top DNS Queries ──
        dns_queries = [d for d in raw_stats.get("dns_queries", []) if not str(d[0]).endswith(".arpa")]
        if dns_queries:
            pdf.set_font("helvetica", "B", 12)
            pdf.set_text_color(*c_dark_navy)
            pdf.cell(0, 8, "Top DNS Resolution Queries", ln=True)
            pdf.ln(2)
            
            with pdf.table(borders_layout="HORIZONTAL_LINES", text_align="LEFT") as table:
                pdf.set_font("helvetica", "B", 9)
                row = table.row()
                row.cell("Target Domain Name")
                row.cell("Request Count")
                
                pdf.set_font("helvetica", "", 9)
                for domain, count in dns_queries[:10]:
                    row = table.row()
                    row.cell(str(domain))
                    row.cell(f"{count} queries")
            pdf.ln(8)

        # ── Most Visited Websites ──
        http_hosts = raw_stats.get("http_hosts", [])
        if http_hosts:
            pdf.set_font("helvetica", "B", 12)
            pdf.set_text_color(*c_dark_navy)
            pdf.cell(0, 8, "Most Visited Websites / Hostnames (HTTP)", ln=True)
            pdf.ln(2)
            
            with pdf.table(borders_layout="HORIZONTAL_LINES", text_align="LEFT") as table:
                pdf.set_font("helvetica", "B", 9)
                row = table.row()
                row.cell("Website / Hostname")
                
                pdf.set_font("helvetica", "", 9)
                for host in http_hosts[:15]:
                    row = table.row()
                    row.cell(str(host))
            pdf.ln(8)

        # ── Discovered Services ──
        services = raw_stats.get("services", {})
        if services:
            # Filter services map for entries that actually have protocols
            svc_items = [item for item in services.items() if item[1]]
            if svc_items:
                pdf.set_font("helvetica", "B", 12)
                pdf.set_text_color(*c_dark_navy)
                pdf.cell(0, 8, "Detected Network Services", ln=True)
                pdf.ln(2)
                
                with pdf.table(borders_layout="HORIZONTAL_LINES", text_align="LEFT") as table:
                    pdf.set_font("helvetica", "B", 9)
                    row = table.row()
                    row.cell("Host IP Address")
                    row.cell("Detected Services / Broadcast Ports")
                    
                    pdf.set_font("helvetica", "", 9)
                    for ip, svcs in sorted(svc_items, key=lambda x: len(x[1]), reverse=True)[:10]:
                        row = table.row()
                        row.cell(str(ip))
                        row.cell(", ".join(str(s) for s in svcs))
                pdf.ln(8)

        # ── VLAN & Network Infrastructure Intelligence ──
        vlan_intel = getattr(self, "vlan_intel", {})
        switches = vlan_intel.get("switches", [])
        vlans = vlan_intel.get("vlans", [])
        subnets = vlan_intel.get("subnets", [])
        routes = vlan_intel.get("routes", [])
        vlan_proto_counts = vlan_intel.get("protocol_counts", {})

        has_vlan_data = switches or vlans or subnets or routes

        if has_vlan_data:
            # Section header
            pdf.set_font("helvetica", "B", 14)
            pdf.set_text_color(*c_dark_navy)
            pdf.cell(0, 10, "Network Infrastructure Intelligence (VLAN / Routing)", ln=True)
            pdf.set_font("helvetica", "I", 8.5)
            pdf.set_text_color(*c_muted)
            proto_summary = ", ".join(f"{k}: {v}" for k, v in sorted(vlan_proto_counts.items(), key=lambda x: x[1], reverse=True)) if vlan_proto_counts else "None"
            pdf.cell(0, 5, f"Infrastructure protocol packets captured: {proto_summary}", ln=True)
            pdf.ln(4)

        # Discovered Switches (CDP / LLDP)
        if switches:
            pdf.set_font("helvetica", "B", 12)
            pdf.set_text_color(*c_dark_navy)
            pdf.cell(0, 8, "Discovered Switches & Routers (CDP / LLDP)", ln=True)
            pdf.ln(2)

            with pdf.table(borders_layout="HORIZONTAL_LINES", text_align="LEFT") as table:
                pdf.set_font("helvetica", "B", 9)
                row = table.row()
                row.cell("Device Name")
                row.cell("Mgmt IP")
                row.cell("Platform")
                row.cell("Your Port")
                row.cell("Native VLAN")
                row.cell("Protocol")

                pdf.set_font("helvetica", "", 9)
                pdf.set_text_color(*c_text_dark)
                for sw in switches[:15]:
                    row = table.row()
                    row.cell(str(sw.get("device_id", ""))[:30])
                    row.cell(str(sw.get("management_ip", "")))
                    row.cell(str(sw.get("platform", ""))[:35])
                    row.cell(str(sw.get("local_port", ""))[:25])
                    nv = sw.get("native_vlan")
                    row.cell(str(nv) if nv is not None else "-")
                    row.cell(str(sw.get("source_protocol", "")).upper())
            pdf.ln(8)

        # Discovered VLANs
        if vlans:
            pdf.set_font("helvetica", "B", 12)
            pdf.set_text_color(*c_dark_navy)
            pdf.cell(0, 8, f"Discovered VLANs ({len(vlans)} total)", ln=True)
            pdf.ln(2)

            with pdf.table(borders_layout="HORIZONTAL_LINES", text_align="LEFT") as table:
                pdf.set_font("helvetica", "B", 9)
                row = table.row()
                row.cell("VLAN ID")
                row.cell("Name")
                row.cell("Subnet")
                row.cell("Source")
                row.cell("Switch")
                row.cell("Native")

                pdf.set_font("helvetica", "", 9)
                pdf.set_text_color(*c_text_dark)
                for v in vlans[:25]:
                    row = table.row()
                    row.cell(str(v.get("vlan_id", "")))
                    row.cell(str(v.get("name", ""))[:25])
                    row.cell(str(v.get("subnet", "")) or "-")
                    row.cell(str(v.get("source_protocol", "")).upper())
                    row.cell(str(v.get("source_switch", ""))[:20] or "-")
                    row.cell("Yes" if v.get("is_native") else "")
            pdf.ln(8)

        # Discovered Subnets
        if subnets:
            pdf.set_font("helvetica", "B", 12)
            pdf.set_text_color(*c_dark_navy)
            pdf.cell(0, 8, f"Discovered Subnets ({len(subnets)} total)", ln=True)
            pdf.ln(2)

            with pdf.table(borders_layout="HORIZONTAL_LINES", text_align="LEFT") as table:
                pdf.set_font("helvetica", "B", 9)
                row = table.row()
                row.cell("Subnet CIDR")
                row.cell("Gateway")
                row.cell("VLAN")
                row.cell("Hosts Seen")
                row.cell("Source")
                row.cell("Router")

                pdf.set_font("helvetica", "", 9)
                pdf.set_text_color(*c_text_dark)
                for s in subnets[:25]:
                    row = table.row()
                    row.cell(str(s.get("cidr", "")))
                    row.cell(str(s.get("gateway", "")) or "-")
                    vid = s.get("vlan_id")
                    row.cell(str(vid) if vid is not None else "-")
                    dc = s.get("device_count", 0)
                    row.cell(str(dc) if dc else "-")
                    row.cell(str(s.get("source_protocol", "")).upper()[:20])
                    row.cell(str(s.get("source_router", ""))[:20] or "-")
            pdf.ln(8)

        # Routing Table
        if routes:
            pdf.set_font("helvetica", "B", 12)
            pdf.set_text_color(*c_dark_navy)
            pdf.cell(0, 8, f"Learned Routes ({len(routes)} entries)", ln=True)
            pdf.ln(2)

            with pdf.table(borders_layout="HORIZONTAL_LINES", text_align="LEFT") as table:
                pdf.set_font("helvetica", "B", 9)
                row = table.row()
                row.cell("Destination")
                row.cell("Next Hop")
                row.cell("Metric")
                row.cell("Protocol")
                row.cell("Router")
                row.cell("Area / AS")

                pdf.set_font("helvetica", "", 9)
                pdf.set_text_color(*c_text_dark)
                for r in routes[:30]:
                    row = table.row()
                    row.cell(str(r.get("destination", "")))
                    row.cell(str(r.get("next_hop", "")) or "-")
                    row.cell(str(r.get("metric", 0)))
                    row.cell(str(r.get("protocol", "")).upper())
                    row.cell(str(r.get("advertising_router", ""))[:20] or "-")
                    area_as = r.get("area", "") or (str(r.get("as_number", "")) if r.get("as_number") else "")
                    row.cell(str(area_as) or "-")
            pdf.ln(8)

        # ── Active Interception (MITM) Summary ──
        mitm_status = getattr(self, "mitm_status", {})
        if mitm_status and mitm_status.get("packets_sent", 0) > 0:
            pdf.set_font("helvetica", "B", 12)
            pdf.set_text_color(*c_dark_navy)
            pdf.cell(0, 8, "Active Network Interception (MITM Spoofing) Summary", ln=True)
            pdf.set_font("helvetica", "I", 8.5)
            pdf.set_text_color(*c_muted)
            pdf.cell(0, 5, "NOTE: The tool actively intercepted traffic via ARP spoofing to enhance traffic analysis.", ln=True)
            pdf.ln(4)
            
            pdf.set_font("helvetica", "B", 9)
            pdf.set_fill_color(240, 243, 248)
            pdf.set_text_color(*c_dark_navy)
            pdf.cell(45, 7, " Intercepted Targets", border="B", fill=True)
            pdf.cell(50, 7, " Spoofed Packets Sent", border="B", fill=True)
            pdf.cell(45, 7, " Spoofing Duration", border="B", fill=True)
            pdf.cell(50, 7, " Gateway Targeted", border="B", fill=True, ln=True)
            
            pdf.set_font("helvetica", "", 9)
            pdf.set_text_color(*c_text_dark)
            targets = mitm_status.get("targets", [])
            pdf.cell(45, 7, f" {len(targets)} Hosts", border="B")
            pdf.cell(50, 7, f" {mitm_status.get('packets_sent')} pkts", border="B")
            pdf.cell(45, 7, f" {mitm_status.get('duration', 0):.1f} sec", border="B")
            pdf.cell(50, 7, f" {mitm_status.get('gateway_ip')}", border="B", ln=True)
            pdf.ln(8)

        # ── Detailed Security Findings ──
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(*c_dark_navy)
        pdf.cell(0, 8, "Security Findings & Anomalies", ln=True)
        pdf.ln(2)
        
        if not self.new_alerts:
            pdf.set_font("helvetica", "I", 10)
            pdf.set_text_color(*c_muted)
            pdf.cell(0, 10, "No new security anomalies or threats were detected during this gathering session.", ln=True)
            pdf.ln(5)
        else:
            # Table layout using FPDF2 table Context Manager for native wrapping
            pdf.set_text_color(*c_dark_navy)
            with pdf.table(borders_layout="HORIZONTAL_LINES", text_align="LEFT") as table:
                pdf.set_font("helvetica", "B", 9)
                row = table.row()
                row.cell("Severity")
                row.cell("Source")
                row.cell("Alert Type")
                row.cell("Finding Description")
                
                pdf.set_font("helvetica", "", 9)
                pdf.set_text_color(*c_text_dark)
                for a in self.new_alerts:
                    severity = a.get("severity", "info").upper()
                    src = a.get("src", "Unknown")
                    alert_type = a.get("type", "General")
                    msg = a.get("message", "")
                    
                    row = table.row()
                    row.cell(severity)
                    row.cell(src)
                    row.cell(alert_type)
                    row.cell(msg)
            pdf.ln(8)

        # ── Recommendations ──
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(*c_dark_navy)
        pdf.cell(0, 8, "Mitigation & Recommendations", ln=True)
        pdf.ln(2)
        
        recommendations = []
        alert_types = {a.get("type") for a in self.new_alerts}
        
        if "arp_spoofing" in alert_types:
            recommendations.append("Enforce Dynamic ARP Inspection (DAI) on switch ports to prevent ARP poisoning/spoofing.")
        if "rogue_dhcp" in alert_types:
            recommendations.append("Configure DHCP Snooping on managed network switches to block unauthorized DHCP offers.")
        if "cleartext_credentials" in alert_types:
            recommendations.append("Enforce encrypted protocol alternatives (SFTP, SSH, IMAPS, POP3S) and disable legacy services.")
        if "weak_tls" in alert_types:
            recommendations.append("Update server configurations to disable SSL 3.0, TLS 1.0, and TLS 1.1; enforce TLS 1.2 or TLS 1.3.")
        if "port_scan" in alert_types:
            recommendations.append("Investigate the source of the TCP port scans for potentially compromised devices or mapping activity.")
        if "dns_bypass" in alert_types:
            recommendations.append("Block outbound port 53 traffic from local workstations except to authorized corporate DNS resolvers.")
        if "cleartext_http" in alert_types:
            recommendations.append("Transition unencrypted web administration pages and internal services to HTTP over TLS (HTTPS).")

        # VLAN-related recommendations
        vlan_intel = getattr(self, "vlan_intel", {})
        if vlan_intel.get("switches"):
            # Check for CDP being enabled (information leak)
            cdp_switches = [s for s in vlan_intel["switches"] if s.get("source_protocol") == "cdp"]
            if cdp_switches:
                recommendations.append("CDP is broadcasting sensitive infrastructure details (switch models, IOS versions, VLANs). Disable CDP on access ports or restrict to trusted interfaces using 'no cdp enable'.")
            lldp_switches = [s for s in vlan_intel["switches"] if s.get("source_protocol") == "lldp"]
            if lldp_switches:
                recommendations.append("LLDP is revealing switch topology and management addresses. Consider limiting LLDP on user-facing ports with 'no lldp transmit'.")
        if vlan_intel.get("vlans"):
            native_vlans = [v for v in vlan_intel["vlans"] if v.get("is_native") and v.get("vlan_id") == 1]
            if native_vlans:
                recommendations.append("Native VLAN is set to the default VLAN 1. Change the native VLAN to an unused VLAN ID to mitigate VLAN hopping attacks.")
        if vlan_intel.get("routes"):
            recommendations.append("Routing protocol advertisements (OSPF/EIGRP/RIP) are visible on access ports. Enable routing protocol authentication and restrict advertisements to designated interfaces.")

        # Inventory-related recommendations
        inv_stats = getattr(self, "inventory_stats", {})
        if inv_stats:
            if inv_stats.get("total_open_ports", 0) > 10:
                recommendations.append("High number of open ports detected across the network. Review exposed services and apply strict firewall rules to minimize attack surface.")
            
            os_dist = inv_stats.get("os_distribution", {})
            if os_dist:
                for os_name in os_dist.keys():
                    if "Windows 7" in os_name or "XP" in os_name or "Server 2008" in os_name or "Server 2003" in os_name:
                        recommendations.append(f"Legacy OS detected ({os_name}). Legacy operating systems are highly vulnerable and must be isolated or decommissioned immediately.")
                        break
            
        if not recommendations:
            recommendations.append("Maintain continuous passive monitoring to identify unauthorized assets or communication drifts.")
            recommendations.append("Regularly run active vulnerability scans to verify patch levels and system configurations.")
            
        pdf.set_font("helvetica", "", 9.5)
        pdf.set_text_color(*c_text_dark)
        for rec in recommendations:
            pdf.cell(6, 6, ">>", ln=False, align="C")
            pdf.multi_cell(0, 6, rec)
            pdf.ln(1)

        # Save output file
        pdf.output(self.pdf_report_path)
