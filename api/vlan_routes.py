"""
api/vlan_routes.py — Flask routes for VLAN & Subnet Intelligence.
"""

from flask import Blueprint, jsonify
import api

vlan_bp = Blueprint("vlans", __name__)


@vlan_bp.route("/api/vlans/status", methods=["GET"])
def vlan_status():
    """Get VLAN discovery engine status and all discovered intelligence."""
    if not api.vlan_discovery:
        return jsonify({"error": "VLAN discovery service not initialized"}), 500
    return jsonify(api.vlan_discovery.get_full_intelligence())


@vlan_bp.route("/api/vlans/start", methods=["POST"])
def start_vlan_discovery():
    """Start the VLAN discovery sniffer."""
    if not api.vlan_discovery:
        return jsonify({"error": "VLAN discovery service not initialized"}), 500

    if api.vlan_discovery.is_running:
        return jsonify({"error": "VLAN discovery is already running"}), 409

    # Auto-detect best interface
    try:
        from network.interfaces import get_best_interface
        best = get_best_interface()
        iface = best.name if best else ""
    except Exception:
        iface = ""

    api.vlan_discovery.start(interface=iface)
    return jsonify({"status": "started", "interface": iface})


@vlan_bp.route("/api/vlans/stop", methods=["POST"])
def stop_vlan_discovery():
    """Stop the VLAN discovery sniffer."""
    if not api.vlan_discovery:
        return jsonify({"error": "VLAN discovery service not initialized"}), 500

    if not api.vlan_discovery.is_running:
        return jsonify({"error": "VLAN discovery is not running"}), 400

    result = api.vlan_discovery.stop()
    return jsonify(result)


@vlan_bp.route("/api/vlans/vlans", methods=["GET"])
def list_vlans():
    """List all discovered VLANs."""
    if not api.vlan_discovery:
        return jsonify({"error": "VLAN discovery service not initialized"}), 500
    return jsonify({"vlans": api.vlan_discovery.get_vlans()})


@vlan_bp.route("/api/vlans/subnets", methods=["GET"])
def list_subnets():
    """List all inferred subnets."""
    if not api.vlan_discovery:
        return jsonify({"error": "VLAN discovery service not initialized"}), 500
    return jsonify({"subnets": api.vlan_discovery.get_subnets()})


@vlan_bp.route("/api/vlans/switches", methods=["GET"])
def list_switches():
    """List all discovered switches (CDP/LLDP)."""
    if not api.vlan_discovery:
        return jsonify({"error": "VLAN discovery service not initialized"}), 500
    return jsonify({"switches": api.vlan_discovery.get_switches()})


@vlan_bp.route("/api/vlans/routes", methods=["GET"])
def list_routes():
    """List all learned routes."""
    if not api.vlan_discovery:
        return jsonify({"error": "VLAN discovery service not initialized"}), 500
    return jsonify({"routes": api.vlan_discovery.get_routes()})
