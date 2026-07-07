"""
Passive Discovery API routes — start/stop/status for the background
broadcast traffic discovery engine.
"""

from flask import Blueprint, jsonify, request

import api
from network.interfaces import get_interfaces, get_best_interface

passive_discovery_bp = Blueprint("passive_discovery", __name__)


@passive_discovery_bp.route("/api/passive-discovery/status", methods=["GET"])
def passive_discovery_status():
    """Get current passive discovery status."""
    return jsonify(api.passive_discovery.get_status())


@passive_discovery_bp.route("/api/passive-discovery/start", methods=["POST"])
def start_passive_discovery():
    """
    Start passive discovery.

    Body JSON:
        interface: str (optional) — network interface
    """
    if api.passive_discovery.is_running:
        return jsonify({"error": "Passive discovery is already running"}), 409

    data = request.get_json(force=True, silent=True) or {}
    interface = data.get("interface", "")

    def on_device_found(device):
        """Save to inventory and emit via WebSocket."""
        api.inventory.upsert_device(device)
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

    api.passive_discovery.start(
        interface=interface,
        on_device_found=on_device_found,
    )

    return jsonify({"status": "started", "interface": interface})


@passive_discovery_bp.route("/api/passive-discovery/stop", methods=["POST"])
def stop_passive_discovery():
    """Stop passive discovery."""
    if not api.passive_discovery.is_running:
        return jsonify({"error": "Passive discovery is not running"}), 400

    result = api.passive_discovery.stop()
    return jsonify(result)
