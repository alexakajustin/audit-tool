"""
api/vlan_routes.py — Flask routes for VLAN & Subnet Intelligence.
"""

from flask import Blueprint, jsonify, request
import api

vlan_bp = Blueprint("vlans", __name__)


@vlan_bp.route("/api/vlans/status", methods=["GET"])
def vlan_status():
    """Get VLAN discovery engine status and all discovered intelligence."""
    if not api.vlan_discovery:
        return jsonify({"error": "VLAN discovery service not initialized"}), 500
    
    # Auto-seed if empty
    intelligence = api.vlan_discovery.get_full_intelligence()
    if not intelligence.get("subnets"):
        api.vlan_discovery._seed_local_network_intelligence()
        intelligence = api.vlan_discovery.get_full_intelligence()
        
    return jsonify(intelligence)


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


@vlan_bp.route("/api/vlans/findings", methods=["GET"])
def list_findings():
    """List all security audit findings from active probes."""
    if not api.vlan_discovery:
        return jsonify({"error": "VLAN discovery service not initialized"}), 500
    return jsonify({"findings": api.vlan_discovery.get_security_findings()})


@vlan_bp.route("/api/vlans/probe", methods=["POST"])
def trigger_probe():
    """Manually trigger active probe cycle (SNMP, gateway sweep, etc.)."""
    if not api.vlan_discovery:
        return jsonify({"error": "VLAN discovery service not initialized"}), 500
    result = api.vlan_discovery.run_manual_probe()
    return jsonify(result)


@vlan_bp.route("/api/vlans/hosts", methods=["GET"])
def list_cross_vlan_hosts():
    """List all live hosts discovered on remote VLANs via sweep."""
    if not api.vlan_discovery:
        return jsonify({"error": "VLAN discovery service not initialized"}), 500
    return jsonify({"hosts": api.vlan_discovery.get_cross_vlan_hosts()})


@vlan_bp.route("/api/vlans/sweep", methods=["POST"])
def sweep_subnet():
    """Sweep a specific subnet for live hosts."""
    if not api.vlan_discovery:
        return jsonify({"error": "VLAN discovery service not initialized"}), 500
    data = request.get_json(silent=True) or {}
    cidr = data.get("cidr", "")
    if not cidr:
        return jsonify({"error": "Missing 'cidr' parameter"}), 400

    import threading
    result_holder = {"result": None}

    def _do_sweep():
        result_holder["result"] = api.vlan_discovery.sweep_subnet(cidr)

    t = threading.Thread(target=_do_sweep, daemon=True)
    t.start()
    return jsonify({"status": "sweep_started", "subnet": cidr})
