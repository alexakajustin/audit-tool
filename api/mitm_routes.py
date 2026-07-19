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
