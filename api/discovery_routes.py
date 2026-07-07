"""
Discovery API routes — scan management and interface listing.
Thin adapter: validate input → call core → format output.
"""

from flask import Blueprint, jsonify, request

import api
from core.models import ScanTarget
from network.interfaces import get_interfaces, get_best_interface

discovery_bp = Blueprint("discovery", __name__)


@discovery_bp.route("/api/interfaces", methods=["GET"])
def list_interfaces():
    """List available network interfaces."""
    interfaces = get_interfaces()
    best = get_best_interface()
    return jsonify({
        "interfaces": [i.to_dict() for i in interfaces],
        "recommended": best.to_dict() if best else None,
    })


@discovery_bp.route("/api/scanners", methods=["GET"])
def list_scanners():
    """List all registered scanners with capabilities."""
    return jsonify({"scanners": api.registry.list_info()})


@discovery_bp.route("/api/discovery/scan", methods=["POST"])
def start_scan():
    """
    Start a network discovery scan.

    Body JSON:
        subnet: str (required) — e.g. "192.168.1.0/24"
        interface: str (optional) — network interface name
        scanners: list[str] (optional) — scanner names to use
        options: dict (optional) — scanner-specific options
    """
    data = request.get_json(force=True, silent=True) or {}

    subnet = data.get("subnet", "")
    scanners = data.get("scanners", [])
    
    # WiFi scanner does not require a subnet target
    is_wifi_only = len(scanners) == 1 and scanners[0] == "wifi_scanner"
    
    if not subnet and not is_wifi_only:
        return jsonify({"error": "subnet is required"}), 400

    target = ScanTarget(
        subnet=subnet,
        interface=data.get("interface", ""),
        scanner_names=data.get("scanners", []),
        options=data.get("options", {}),
    )

    # Callback: save discovered devices to inventory in real-time
    def on_device_found(device):
        api.inventory.upsert_device(device)
        # Emit via SocketIO if available
        try:
            from flask_socketio import emit
            emit(
                "device_found",
                device.to_dict(),
                namespace="/ws/discovery",
                broadcast=True,
            )
        except Exception:
            pass

    def on_complete(result):
        try:
            from flask_socketio import emit
            emit(
                "scan_complete",
                result.to_dict(),
                namespace="/ws/discovery",
                broadcast=True,
            )
        except Exception:
            pass

    started = api.orchestrator.start_scan(
        target=target,
        on_device_found=on_device_found,
        on_complete=on_complete,
    )

    if not started:
        return jsonify({"error": "A scan is already running"}), 409

    return jsonify({"status": "started", "target": target.to_dict()})


@discovery_bp.route("/api/discovery/status", methods=["GET"])
def scan_status():
    """Get the current scan status."""
    return jsonify(api.orchestrator.get_status())


@discovery_bp.route("/api/discovery/stop", methods=["POST"])
def stop_scan():
    """Cancel the current scan."""
    api.orchestrator.stop_scan()
    return jsonify({"status": "stopped"})
