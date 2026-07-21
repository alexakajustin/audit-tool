"""
NetAudit — Advanced Cybersecurity Audit & Network Discovery Tool

Entry point: wires together all components and starts the Flask server.
"""

import os
import sys

from flask import Flask, render_template
from flask_socketio import SocketIO

from config import Config
from core.registry import ScannerRegistry
from core.orchestrator import ScanOrchestrator
from core.inventory import InventoryManager
from core.metrics_manager import MetricsManager
from sniffers.passive_sniffer import PassiveSniffer
from sniffers.passive_discovery import PassiveDiscovery
from sniffers.vlan_discovery import VLANDiscovery
from sniffers.arp_spoofer import ArpSpoofer
from network.interfaces import get_best_interface
import api


def create_app() -> tuple[Flask, SocketIO]:
    """Application factory — creates and configures the Flask app."""

    # Ensure data directories exist
    Config.ensure_dirs()

    # Clear previous session data (database, pcaps, exports)
    if os.path.exists(Config.DB_PATH):
        try:
            os.remove(Config.DB_PATH)
        except Exception:
            pass

    for folder in [Config.PCAP_DIR, Config.EXPORT_DIR]:
        if os.path.exists(folder):
            for filename in os.listdir(folder):
                file_path = os.path.join(folder, filename)
                try:
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                except Exception:
                    pass

    # Handle PyInstaller _MEIPASS for bundled templates and static files
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # Running as a bundled executable
        base_dir = sys._MEIPASS
        template_dir = os.path.join(base_dir, "templates")
        static_dir = os.path.join(base_dir, "static")
    else:
        # Running from source
        base_dir = os.path.dirname(os.path.abspath(__file__))
        template_dir = os.path.join(base_dir, "templates")
        static_dir = os.path.join(base_dir, "static")

    # Create Flask app
    app = Flask(
        __name__,
        static_folder=static_dir,
        template_folder=template_dir,
    )
    app.config["SECRET_KEY"] = Config.SECRET_KEY

    # Initialize SocketIO
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

    # ── Wire up core services ────────────────────────────────
    # 1. Scanner Registry — auto-discovers scanner plugins
    registry = ScannerRegistry()
    registry.discover("scanners")

    # 2. Scan Orchestrator — coordinates multi-scanner runs
    orchestrator = ScanOrchestrator(registry)

    # 3. Inventory Manager — SQLite persistence
    inventory = InventoryManager(Config.DB_PATH)

    # 4. Passive Sniffer
    sniffer = PassiveSniffer()

    # 5. Passive Discovery Engine — mines broadcast traffic
    passive_discovery = PassiveDiscovery()

    # 6. Metrics Manager — delta background intelligence
    metrics_manager = MetricsManager()

    # 7. VLAN Discovery Engine — infrastructure protocol intelligence
    vlan_discovery = VLANDiscovery()

    # 8. ARP Spoofer / MITM Engine — active traffic interception
    arp_spoofer = ArpSpoofer()
    arp_spoofer.set_sniffer(sniffer)  # Link MITM to sniffer for auto-start & tagging

    # Inject services into the API layer
    api.init_services(registry, orchestrator, inventory, sniffer, passive_discovery, metrics_manager, vlan_discovery, arp_spoofer)

    # ── Register API blueprints ──────────────────────────────
    from api.discovery_routes import discovery_bp
    from api.inventory_routes import inventory_bp
    from api.sniffer_routes import sniffer_bp
    from api.stats_routes import stats_bp
    from api.passive_discovery_routes import passive_discovery_bp
    from api.metrics_routes import metrics_bp
    from api.vlan_routes import vlan_bp
    from api.mitm_routes import mitm_bp
    from api.topology_routes import topology_bp

    app.register_blueprint(discovery_bp)
    app.register_blueprint(inventory_bp)
    app.register_blueprint(sniffer_bp)
    app.register_blueprint(metrics_bp)
    app.register_blueprint(passive_discovery_bp)
    app.register_blueprint(vlan_bp)
    app.register_blueprint(stats_bp)
    app.register_blueprint(mitm_bp)
    app.register_blueprint(topology_bp)

    # ── Root route — serves the SPA ──────────────────────────
    @app.route("/")
    def index():
        return render_template("index.html")

    # ── SocketIO event handlers ──────────────────────────────
    @socketio.on("connect", namespace="/ws/discovery")
    def on_discovery_connect():
        pass

    @socketio.on("connect", namespace="/ws/sniffer")
    def on_sniffer_connect():
        pass

    # ── Auto-start passive discovery ─────────────────────────
    def _auto_start_passive_discovery():
        """Start passive discovery automatically on the best interface."""
        try:
            best = get_best_interface()
            iface = best.name if best else ""

            def on_device_found(device):
                inventory.upsert_device(device)
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

            passive_discovery.start(
                interface=iface,
                on_device_found=on_device_found,
            )
            print(f"  Passive Discovery: AUTO-STARTED on '{iface}'")
        except Exception as e:
            print(f"  Passive Discovery: Failed to auto-start ({e})")

    _auto_start_passive_discovery()

    # ── Auto-start VLAN discovery ─────────────────────────────
    def _auto_start_vlan_discovery():
        """Start VLAN discovery automatically on the best interface."""
        try:
            best = get_best_interface()
            iface = best.name if best else ""
            vlan_discovery.start(interface=iface)
            print(f"  VLAN Discovery:    AUTO-STARTED on '{iface}'")
        except Exception as e:
            print(f"  VLAN Discovery:    Failed to auto-start ({e})")

    _auto_start_vlan_discovery()

    # ── Log startup info ─────────────────────────────────────
    scanner_count = len(registry.get_all())
    available_count = len(registry.get_available())

    print(f"\n{'='*60}")
    print(f"  NetAudit — Cybersecurity Discovery Tool")
    print(f"{'='*60}")
    print(f"  Scanners registered: {scanner_count} ({available_count} available)")
    for s in registry.get_all():
        status = "[+]" if s.is_available() else "[-]"
        admin = " [ADMIN]" if s.get_capabilities().requires_admin else ""
        print(f"    {status} {s.display_name}{admin}")
    print(f"  Passive Discovery: {'RUNNING' if passive_discovery.is_running else 'STOPPED'}")
    print(f"  VLAN Discovery:    {'RUNNING' if vlan_discovery.is_running else 'STOPPED'}")
    print(f"  ARP Spoofer/MITM:  READY")
    print(f"  Database: {Config.DB_PATH}")
    print(f"  Server:   http://{Config.HOST}:{Config.PORT}")
    print(f"{'='*60}\n")

    return app, socketio


# ── Main ──────────────────────────────────────────────────────
if __name__ == "__main__":
    app, socketio = create_app()
    socketio.run(
        app,
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
        allow_unsafe_werkzeug=True,
    )
