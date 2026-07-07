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
        dns_queries = raw_stats.get("dns_queries", [])
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
