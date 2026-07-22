"""
MITM / ARP Spoofing API routes — scan network, start/stop interception.
"""

from flask import Blueprint, jsonify, request
import api

mitm_bp = Blueprint("mitm", __name__)


@mitm_bp.route("/api/mitm/status", methods=["GET"])
def mitm_status():
    """Get current MITM status, targets, and stats."""
    if not api.arp_spoofer:
        return jsonify({"error": "ARP Spoofer not available"}), 503
    return jsonify(api.arp_spoofer.get_status())


@mitm_bp.route("/api/mitm/scan", methods=["POST"])
def mitm_scan():
    """
    ARP scan the local subnet to discover all live devices.
    Body JSON (optional):
        interface: str — network interface to scan from
    """
    if not api.arp_spoofer:
        return jsonify({"error": "ARP Spoofer not available"}), 503

    data = request.get_json(force=True, silent=True) or {}
    interface = data.get("interface", "")

    hosts = api.arp_spoofer.scan_network(interface=interface)
    return jsonify({
        "hosts": hosts,
        "count": len(hosts),
        "gateway_ip": api.arp_spoofer._gateway_ip,
        "gateway_mac": api.arp_spoofer._gateway_mac,
        "local_ip": api.arp_spoofer._local_ip,
    })


@mitm_bp.route("/api/mitm/start", methods=["POST"])
def mitm_start():
    """
    Start ARP spoofing against specified targets.
    Body JSON:
        targets: list[str] — IP addresses to intercept
        gateway_ip: str (optional) — override auto-detected gateway
    """
    if not api.arp_spoofer:
        return jsonify({"error": "ARP Spoofer not available"}), 503

    data = request.get_json(force=True, silent=True) or {}
    targets = data.get("targets", [])
    gateway_ip = data.get("gateway_ip", "")

    if not targets:
        return jsonify({"error": "No targets specified"}), 400

    result = api.arp_spoofer.start(target_ips=targets, gateway_ip=gateway_ip)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)


@mitm_bp.route("/api/mitm/stop", methods=["POST"])
def mitm_stop():
    """Stop ARP spoofing and restore the network."""
    if not api.arp_spoofer:
        return jsonify({"error": "ARP Spoofer not available"}), 503

    result = api.arp_spoofer.stop()
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)


@mitm_bp.route("/api/mitm/start-all", methods=["POST"])
def mitm_start_all():
    """
    One-click intercept ALL devices on the subnet.
    Scans, selects all non-gateway hosts, starts spoofing + sniffer.
    Body JSON (optional):
        interface: str — network interface
    """
    if not api.arp_spoofer:
        return jsonify({"error": "ARP Spoofer not available"}), 503

    data = request.get_json(force=True, silent=True) or {}
    interface = data.get("interface", "")

    result = api.arp_spoofer.start_all(interface=interface)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)


@mitm_bp.route("/api/mitm/activity", methods=["GET"])
def mitm_activity():
    """
    Get per-IP traffic activity summary.
    Returns ALL IPs generating traffic, ranked by data volume,
    with intercepted IPs flagged. Includes hostname, top domains,
    and packet counts.
    """
    if not api.arp_spoofer:
        return jsonify({"error": "ARP Spoofer not available"}), 503

    # Get MITM status for intercepted IPs
    status = api.arp_spoofer.get_status()
    intercepted_ips = set(t["ip"] for t in status.get("targets", []))

    # Get all traffic data from sniffer
    traffic_entries = []
    if api.sniffer:
        stats = api.sniffer.get_stats()
        device_profiles = stats.get("device_profiles", [])
        top_talkers = stats.get("top_talkers", [])
        local_ip = stats.get("local_ip", "")

        # Build a lookup from device profiles for rich data
        profile_map = {}
        for profile in device_profiles:
            profile_map[profile.get("ip", "")] = profile

        # Use top_talkers as the ranked source (already sorted by volume)
        seen_ips = set()
        for ip, bytes_val in top_talkers:
            if ip == local_ip:
                continue
            seen_ips.add(ip)
            prof = profile_map.get(ip, {})

            # Get sites visited, filtering out reverse DNS (.arpa) noise
            all_sites = _filter_arpa(prof.get("sites_visited", []))
            top_sites = [{"domain": s[0], "hits": s[1]} for s in all_sites[:3]]
            all_sites_list = [{"domain": s[0], "hits": s[1]} for s in all_sites[:30]]

            traffic_entries.append({
                "ip": ip,
                "hostname": prof.get("hostname", ""),
                "mac": prof.get("mac", ""),
                "data_volume": bytes_val,
                "data_volume_formatted": _format_bytes(bytes_val),
                "dns_count": prof.get("dns_count", 0),
                "sni_count": prof.get("sni_count", 0),
                "top_sites": top_sites,
                "all_sites": all_sites_list,
                "os": prof.get("os", ""),
                "intercepted": ip in intercepted_ips,
                "services": prof.get("services", []),
            })

        # Also include any profiled devices not in top_talkers
        for prof in device_profiles:
            ip = prof.get("ip", "")
            if ip in seen_ips or ip == local_ip:
                continue
            seen_ips.add(ip)
            vol = prof.get("data_volume", 0)
            all_sites = _filter_arpa(prof.get("sites_visited", []))
            top_sites = [{"domain": s[0], "hits": s[1]} for s in all_sites[:3]]
            all_sites_list = [{"domain": s[0], "hits": s[1]} for s in all_sites[:30]]

            traffic_entries.append({
                "ip": ip,
                "hostname": prof.get("hostname", ""),
                "mac": prof.get("mac", ""),
                "data_volume": vol,
                "data_volume_formatted": _format_bytes(vol),
                "dns_count": prof.get("dns_count", 0),
                "sni_count": prof.get("sni_count", 0),
                "top_sites": top_sites,
                "all_sites": all_sites_list,
                "os": prof.get("os", ""),
                "intercepted": ip in intercepted_ips,
                "services": prof.get("services", []),
            })

    # Sort by data volume descending, add rank numbers
    traffic_entries.sort(key=lambda e: e["data_volume"], reverse=True)
    for i, entry in enumerate(traffic_entries):
        entry["rank"] = i + 1

    return jsonify({
        "targets": list(intercepted_ips),
        "target_count": len(intercepted_ips),
        "entries": traffic_entries,
        "total_ips": len(traffic_entries),
        "is_running": status.get("is_running", False),
        "packets_sent": status.get("packets_sent", 0),
    })


def _format_bytes(num: float) -> str:
    """Format byte count into human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} TB"


def _filter_arpa(sites: list) -> list:
    """Filter out reverse DNS entries (in-addr.arpa, ip6.arpa) from site lists."""
    return [s for s in sites if not s[0].endswith('.arpa')]

