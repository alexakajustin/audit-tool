"""
Inventory Manager — persists and manages discovered devices in SQLite.

Single Responsibility: CRUD + merge for the device inventory.
YAGNI: raw sqlite3, no ORM. Simple queries, simple schema.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
import time
from typing import Optional

from core.models import Device, DeviceStatus, PortInfo


class InventoryManager:
    """
    Manages the device inventory in SQLite.
    Smart merge: re-discovered devices update existing records.
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._ensure_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _ensure_db(self) -> None:
        """Create the schema if it doesn't exist."""
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)

        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY,
                    mac TEXT UNIQUE NOT NULL,
                    ip TEXT DEFAULT '',
                    vendor TEXT DEFAULT '',
                    hostname TEXT DEFAULT '',
                    os TEXT DEFAULT '',
                    ports TEXT DEFAULT '[]',
                    status TEXT DEFAULT 'unknown',
                    discovery_methods TEXT DEFAULT '[]',
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    response_time_ms REAL,
                    notes TEXT DEFAULT ''
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip)
            """)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def upsert_device(self, device: Device) -> Device:
        """
        Insert or update a device. If MAC exists, merge fields.
        Returns the final device state.
        """
        existing = self.get_by_mac(device.mac)
        if existing:
            existing.merge(device)
            self._update(existing)
            return existing
        else:
            self._insert(device)
            return device

    def upsert_many(self, devices: list[Device]) -> int:
        """Upsert multiple devices. Returns count of upserted devices."""
        for device in devices:
            self.upsert_device(device)
        return len(devices)

    def get_all(
        self,
        search: str = "",
        status: str = "",
        sort_by: str = "last_seen",
        sort_order: str = "desc",
    ) -> list[Device]:
        """
        Get all devices with optional filtering and sorting.
        """
        query = "SELECT * FROM devices WHERE 1=1"
        params: list = []

        if search:
            query += (
                " AND (ip LIKE ? OR mac LIKE ? OR vendor LIKE ? "
                "OR hostname LIKE ? OR os LIKE ?)"
            )
            like = f"%{search}%"
            params.extend([like, like, like, like, like])

        if status:
            query += " AND status = ?"
            params.append(status)

        # Sanitize sort
        allowed_sorts = {"ip", "mac", "vendor", "hostname", "os", "status",
                         "first_seen", "last_seen", "response_time_ms"}
        if sort_by not in allowed_sorts:
            sort_by = "last_seen"
        order = "DESC" if sort_order.lower() == "desc" else "ASC"
        query += f" ORDER BY {sort_by} {order}"

        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_device(row) for row in rows]

    def get_by_id(self, device_id: str) -> Optional[Device]:
        """Get a device by its ID."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE id = ?", (device_id,)
            ).fetchone()
            return self._row_to_device(row) if row else None

    def get_by_mac(self, mac: str) -> Optional[Device]:
        """Get a device by its MAC address."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE mac = ?", (mac.upper(),)
            ).fetchone()
            return self._row_to_device(row) if row else None

    def delete(self, device_id: str) -> bool:
        """Delete a device by ID."""
        with self._get_conn() as conn:
            cursor = conn.execute(
                "DELETE FROM devices WHERE id = ?", (device_id,)
            )
            return cursor.rowcount > 0

    def clear_all(self) -> int:
        """Delete all devices. Returns count deleted."""
        with self._get_conn() as conn:
            cursor = conn.execute("DELETE FROM devices")
            return cursor.rowcount

    def get_count(self) -> int:
        """Get total device count."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT COUNT(*) FROM devices").fetchone()
            return row[0] if row else 0

    def get_stats(self) -> dict:
        """Get aggregate statistics for the dashboard."""
        with self._get_conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            online = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE status = 'online'"
            ).fetchone()[0]

            # Vendor distribution
            vendor_rows = conn.execute(
                "SELECT vendor, COUNT(*) as cnt FROM devices "
                "WHERE vendor != '' GROUP BY vendor ORDER BY cnt DESC LIMIT 10"
            ).fetchall()
            vendors = {row["vendor"]: row["cnt"] for row in vendor_rows}

            # OS distribution
            os_rows = conn.execute(
                "SELECT os, COUNT(*) as cnt FROM devices "
                "WHERE os != '' GROUP BY os ORDER BY cnt DESC LIMIT 10"
            ).fetchall()
            os_dist = {row["os"]: row["cnt"] for row in os_rows}

            # Count devices with open ports
            all_devices = self.get_all()
            total_ports = sum(len(d.ports) for d in all_devices)

            return {
                "total_devices": total,
                "online_devices": online,
                "offline_devices": total - online,
                "total_open_ports": total_ports,
                "vendor_distribution": vendors,
                "os_distribution": os_dist,
            }

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_csv(self) -> str:
        """Export inventory as CSV string."""
        devices = self.get_all()
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            "ID", "MAC", "IP", "Vendor", "Hostname", "OS",
            "Open Ports", "Status", "Discovery Methods",
            "First Seen", "Last Seen", "Response Time (ms)", "Notes",
        ])

        for d in devices:
            ports_str = "; ".join(
                f"{p.port}/{p.protocol} ({p.service})" for p in d.ports
            )
            writer.writerow([
                d.id, d.mac, d.ip, d.vendor, d.hostname, d.os,
                ports_str, d.status.value, ", ".join(d.discovery_methods),
                d.first_seen, d.last_seen, d.response_time_ms, d.notes,
            ])

        return output.getvalue()

    def export_json(self) -> str:
        """Export inventory as JSON string."""
        devices = self.get_all()
        return json.dumps([d.to_dict() for d in devices], indent=2)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _insert(self, device: Device) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO devices
                   (id, mac, ip, vendor, hostname, os, ports, status,
                    discovery_methods, first_seen, last_seen,
                    response_time_ms, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    device.id, device.mac.upper(), device.ip, device.vendor,
                    device.hostname, device.os,
                    json.dumps([p.to_dict() for p in device.ports]),
                    device.status.value,
                    json.dumps(device.discovery_methods),
                    device.first_seen, device.last_seen,
                    device.response_time_ms, device.notes,
                ),
            )

    def _update(self, device: Device) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """UPDATE devices SET
                   ip=?, vendor=?, hostname=?, os=?, ports=?, status=?,
                   discovery_methods=?, first_seen=?, last_seen=?,
                   response_time_ms=?, notes=?
                   WHERE id=?""",
                (
                    device.ip, device.vendor, device.hostname, device.os,
                    json.dumps([p.to_dict() for p in device.ports]),
                    device.status.value,
                    json.dumps(device.discovery_methods),
                    device.first_seen, device.last_seen,
                    device.response_time_ms, device.notes,
                    device.id,
                ),
            )

    def _row_to_device(self, row: sqlite3.Row) -> Device:
        """Convert a database row back to a Device object."""
        ports_raw = json.loads(row["ports"]) if row["ports"] else []
        ports = [PortInfo(**p) for p in ports_raw]

        methods = json.loads(row["discovery_methods"]) if row["discovery_methods"] else []

        return Device(
            id=row["id"],
            mac=row["mac"],
            ip=row["ip"],
            vendor=row["vendor"],
            hostname=row["hostname"],
            os=row["os"],
            ports=ports,
            status=DeviceStatus(row["status"]) if row["status"] else DeviceStatus.UNKNOWN,
            discovery_methods=methods,
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            response_time_ms=row["response_time_ms"],
            notes=row["notes"],
        )
