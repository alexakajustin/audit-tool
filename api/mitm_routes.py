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
    Get per-target browsing activity summary.
    Returns device profiles for only MITM-intercepted IPs.
    """
    if not api.arp_spoofer:
        return jsonify({"error": "ARP Spoofer not available"}), 503

    status = api.arp_spoofer.get_status()
    target_ips = [t["ip"] for t in status.get("targets", [])]

    if not target_ips:
        return jsonify({"targets": [], "profiles": []})

    # Get device profiles from sniffer for intercepted IPs only
    profiles = []
    if api.sniffer:
        stats = api.sniffer.get_stats()
        for profile in stats.get("device_profiles", []):
            if profile.get("ip") in target_ips:
                profiles.append(profile)

    return jsonify({
        "targets": target_ips,
        "target_count": len(target_ips),
        "profiles": profiles,
        "is_running": status.get("is_running", False),
        "packets_sent": status.get("packets_sent", 0),
    })
