"""
api/metrics_routes.py — Flask routes for background metrics gathering and report downloading.
"""

import os
from flask import Blueprint, jsonify, send_file
import api
from config import Config

metrics_bp = Blueprint("metrics", __name__)

@metrics_bp.route("/api/metrics/start", methods=["POST"])
def start_metrics():
    """Start background metrics gathering."""
    if not api.sniffer:
        return jsonify({"error": "Sniffer service not initialized"}), 500
    
    if api.metrics_manager.is_gathering:
        return jsonify({"error": "Metrics gathering is already running"}), 409

    success = api.metrics_manager.start(api.sniffer)
    if success:
        return jsonify({"status": "started", "message": "Metrics gathering started"})
    else:
        return jsonify({"error": "Failed to start metrics gathering"}), 400

@metrics_bp.route("/api/metrics/stop", methods=["POST"])
def stop_metrics():
    """Stop metrics gathering and generate PDF report."""
    if not api.sniffer:
        return jsonify({"error": "Sniffer service not initialized"}), 500

    if not api.metrics_manager.is_gathering:
        return jsonify({"error": "Metrics gathering is not active"}), 400

    result = api.metrics_manager.stop(api.sniffer, Config.EXPORT_DIR)
    return jsonify(result)

@metrics_bp.route("/api/metrics/status", methods=["GET"])
def get_metrics_status():
    """Get the current state of metrics gathering."""
    return jsonify(api.metrics_manager.get_status())

@metrics_bp.route("/api/metrics/download", methods=["GET"])
def download_metrics_report():
    """Download the generated PDF report."""
    status = api.metrics_manager.get_status()
    if not status["pdf_available"]:
        return jsonify({"error": "No PDF report available. Gather and stop metrics first."}), 404

    pdf_path = api.metrics_manager.pdf_report_path
    if not os.path.exists(pdf_path):
        return jsonify({"error": "PDF report file not found on disk"}), 404

    filename = status["pdf_filename"]
    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf"
    )
