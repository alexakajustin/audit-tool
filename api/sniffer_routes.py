"""
Sniffer API routes — start/stop capture, stats, PCAP import/export.
"""

import os
import time

from flask import Blueprint, jsonify, request
from werkzeug.utils import secure_filename

import api
from config import Config

sniffer_bp = Blueprint("sniffer", __name__)


@sniffer_bp.route("/api/sniffer/start", methods=["POST"])
def start_sniffer():
    """
    Start the passive sniffer.

    Body JSON:
        interface: str (optional) — network interface
        filter: str (optional) — BPF filter expression
    """
    if api.sniffer.is_running:
        return jsonify({"error": "Sniffer is already running"}), 409

    data = request.get_json(force=True, silent=True) or {}
    interface = data.get("interface", "")
    bpf_filter = data.get("filter", "").strip()

    # Exclude traffic to/from the Flask server to prevent infinite feedback loops
    port = Config.PORT
    exclude_rule = f"not port {port}"
    if bpf_filter:
        bpf_filter = f"({bpf_filter}) and {exclude_rule}"
    else:
        bpf_filter = exclude_rule

    def on_packet(pkt_info):
        """Emit packet via SocketIO for real-time streaming."""
        try:
            from flask_socketio import emit
            emit(
                "packet",
                pkt_info.to_dict(),
                namespace="/ws/sniffer",
                broadcast=True,
            )
        except Exception:
            pass

    api.sniffer.start(
        interface=interface,
        bpf_filter=bpf_filter,
        on_packet=on_packet,
    )

    return jsonify({"status": "started", "interface": interface, "filter": bpf_filter})


@sniffer_bp.route("/api/sniffer/stop", methods=["POST"])
def stop_sniffer():
    """Stop the passive sniffer and return capture summary."""
    if not api.sniffer.is_running:
        return jsonify({"error": "Sniffer is not running"}), 400

    result = api.sniffer.stop()
    return jsonify(result.to_dict())


@sniffer_bp.route("/api/sniffer/stats", methods=["GET"])
def sniffer_stats():
    """Get current sniffer statistics."""
    return jsonify(api.sniffer.get_stats())


@sniffer_bp.route("/api/sniffer/packets", methods=["GET"])
def get_packets():
    """Get recent captured packets."""
    count = request.args.get("count", 50, type=int)
    packets = api.sniffer.get_recent_packets(count=min(count, 500))
    return jsonify({"packets": packets, "count": len(packets)})


@sniffer_bp.route("/api/sniffer/export", methods=["GET"])
def export_pcap():
    """Export captured packets as PCAP file."""
    Config.ensure_dirs()
    filename = f"capture_{int(time.time())}.pcap"
    filepath = os.path.join(Config.PCAP_DIR, filename)

    try:
        api.sniffer.export_pcap(filepath)
        return jsonify({"status": "exported", "path": filepath, "filename": filename})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@sniffer_bp.route("/api/sniffer/import", methods=["POST"])
def import_pcap():
    """Import and analyze a PCAP file."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No filename"}), 400

    Config.ensure_dirs()
    filename = secure_filename(file.filename)
    filepath = os.path.join(Config.PCAP_DIR, filename)
    file.save(filepath)

    try:
        result = api.sniffer.import_pcap(filepath)
        return jsonify(result.to_dict())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@sniffer_bp.route("/api/sniffer/timeline/<ip>", methods=["GET"])
def get_device_timeline(ip):
    """Get timestamped activity log for a specific device."""
    limit = request.args.get("limit", 100, type=int)
    timeline = api.sniffer.get_device_timeline(ip=ip, limit=min(limit, 500))
    return jsonify({"ip": ip, "timeline": timeline, "count": len(timeline)})


@sniffer_bp.route("/api/sniffer/categories", methods=["GET"])
def get_categories():
    """Get content category breakdown across all profiled devices."""
    categories = api.sniffer.get_category_summary()
    return jsonify(categories)
