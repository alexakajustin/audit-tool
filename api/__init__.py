"""
API package — thin Flask adapter layer.
Registers all blueprints and provides access to shared services.
"""

from __future__ import annotations

from core.inventory import InventoryManager
from core.orchestrator import ScanOrchestrator
from core.registry import ScannerRegistry
from sniffers.passive_sniffer import PassiveSniffer
from sniffers.passive_discovery import PassiveDiscovery


# Shared service instances — initialized in app.py, used by routes
registry: ScannerRegistry = None  # type: ignore
orchestrator: ScanOrchestrator = None  # type: ignore
inventory: InventoryManager = None  # type: ignore
sniffer: PassiveSniffer = None  # type: ignore
passive_discovery: PassiveDiscovery = None  # type: ignore


def init_services(
    reg: ScannerRegistry,
    orch: ScanOrchestrator,
    inv: InventoryManager,
    sniff: PassiveSniffer,
    pd: PassiveDiscovery,
) -> None:
    """Initialize shared services — called once from app.py."""
    global registry, orchestrator, inventory, sniffer, passive_discovery
    registry = reg
    orchestrator = orch
    inventory = inv
    sniffer = sniff
    passive_discovery = pd
