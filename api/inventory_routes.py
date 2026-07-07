"""
Inventory API routes — device CRUD and export.
"""

from flask import Blueprint, Response, jsonify, request

import api

inventory_bp = Blueprint("inventory", __name__)


@inventory_bp.route("/api/inventory", methods=["GET"])
def list_devices():
    """
    List all inventoried devices.

    Query params:
        search: str — filter by IP, MAC, vendor, hostname, OS
        status: str — filter by status (online/offline/unknown)
        sort_by: str — field to sort by (default: last_seen)
        sort_order: str — asc or desc (default: desc)
    """
    devices = api.inventory.get_all(
        search=request.args.get("search", ""),
        status=request.args.get("status", ""),
        sort_by=request.args.get("sort_by", "last_seen"),
        sort_order=request.args.get("sort_order", "desc"),
    )
    return jsonify({
        "devices": [d.to_dict() for d in devices],
        "total": len(devices),
    })


@inventory_bp.route("/api/inventory/<device_id>", methods=["GET"])
def get_device(device_id):
    """Get a single device by ID."""
    device = api.inventory.get_by_id(device_id)
    if not device:
        return jsonify({"error": "Device not found"}), 404
    return jsonify(device.to_dict())


@inventory_bp.route("/api/inventory/<device_id>", methods=["DELETE"])
def delete_device(device_id):
    """Remove a device from inventory."""
    deleted = api.inventory.delete(device_id)
    if not deleted:
        return jsonify({"error": "Device not found"}), 404
    return jsonify({"status": "deleted", "id": device_id})


@inventory_bp.route("/api/inventory/clear", methods=["POST"])
def clear_inventory():
    """Delete all devices from inventory."""
    count = api.inventory.clear_all()
    return jsonify({"status": "cleared", "count": count})


@inventory_bp.route("/api/inventory/export/<fmt>", methods=["GET"])
def export_inventory(fmt):
    """
    Export inventory in the specified format.
    Supported: csv, json
    """
    if fmt == "csv":
        data = api.inventory.export_csv()
        return Response(
            data,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=inventory.csv"},
        )
    elif fmt == "json":
        data = api.inventory.export_json()
        return Response(
            data,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=inventory.json"},
        )
    else:
        return jsonify({"error": f"Unsupported format: {fmt}"}), 400
