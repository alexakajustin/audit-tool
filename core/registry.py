"""
Scanner Registry — auto-discovers and manages scanner plugins.

Open/Closed: new scanner = new file in scanners/, zero changes here.
Dependency Inversion: the rest of the system asks the registry for
scanners by capability, never imports concrete classes directly.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Optional

from core.base import BaseScanner


class ScannerRegistry:
    """
    Discovers and manages scanner plugins.

    Scans the 'scanners' package for classes that extend BaseScanner,
    instantiates them, and provides lookup by name or capability.
    """

    def __init__(self):
        self._scanners: dict[str, BaseScanner] = {}

    def discover(self, package_name: str = "scanners") -> None:
        """
        Auto-discover all BaseScanner subclasses in the given package.
        Call once at startup.
        """
        try:
            package = importlib.import_module(package_name)
        except ImportError:
            return

        # Handle PyInstaller environment pathing for module loading
        import sys
        import os
        
        # When bundled with PyInstaller, __path__ might not work as expected
        # with pkgutil, but we told PyInstaller to include the scanners folder
        path = package.__path__
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            scanner_dir = os.path.join(sys._MEIPASS, "scanners")
            if os.path.exists(scanner_dir):
                path = [scanner_dir]

        for importer, module_name, is_pkg in pkgutil.iter_modules(path):
            try:
                module = importlib.import_module(f"{package_name}.{module_name}")

                for attr_name, attr in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(attr, BaseScanner)
                        and attr is not BaseScanner
                        and not inspect.isabstract(attr)
                    ):
                        instance = attr()
                        self._scanners[instance.name] = instance

            except Exception:
                # Skip broken scanner modules — don't crash the app
                continue

    def register(self, scanner: BaseScanner) -> None:
        """Manually register a scanner instance."""
        self._scanners[scanner.name] = scanner

    def get(self, name: str) -> Optional[BaseScanner]:
        """Get a scanner by name."""
        return self._scanners.get(name)

    def get_all(self) -> list[BaseScanner]:
        """Get all registered scanners."""
        return list(self._scanners.values())

    def get_available(self) -> list[BaseScanner]:
        """Get only scanners whose prerequisites are met."""
        return [s for s in self._scanners.values() if s.is_available()]

    def get_by_capability(self, **kwargs) -> list[BaseScanner]:
        """
        Find scanners matching capability criteria.

        Example: registry.get_by_capability(can_detect_ports=True)
        """
        results = []
        for scanner in self._scanners.values():
            caps = scanner.get_capabilities()
            match = all(
                getattr(caps, key, None) == value
                for key, value in kwargs.items()
            )
            if match:
                results.append(scanner)
        return results

    def list_info(self) -> list[dict]:
        """Get summary info for all scanners — used by the API."""
        info = []
        for scanner in self._scanners.values():
            info.append({
                "name": scanner.name,
                "display_name": scanner.display_name,
                "description": scanner.description,
                "capabilities": scanner.get_capabilities().to_dict(),
                "available": scanner.is_available(),
            })
        return info
