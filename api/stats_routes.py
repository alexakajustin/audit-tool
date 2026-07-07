"""
Stats API routes — dashboard aggregate statistics.
"""

from flask import Blueprint, jsonify

import api

stats_bp = Blueprint("stats", __name__)


@stats_bp.route("/api/stats", methods=["GET"])
def dashboard_stats():
    """Get aggregate dashboard statistics."""
    inv_stats = api.inventory.get_stats()
    sniffer_stats = api.sniffer.get_stats()
    pd_stats = api.passive_discovery.get_status()

    return jsonify({
        "inventory": inv_stats,
        "sniffer": sniffer_stats,
        "passive_discovery": pd_stats,
        "scan": api.orchestrator.get_status(),
        "scanners": api.registry.list_info(),
    })
