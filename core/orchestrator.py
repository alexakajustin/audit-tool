"""
Scan Orchestrator — coordinates running multiple scanners and merging results.

Dependency Inversion: depends on BaseScanner (abstraction), not on
concrete scanner classes. Doesn't know about Flask or WebSockets —
communicates progress via callbacks.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from core.base import BaseScanner
from core.models import Device, ScanResult, ScanState, ScanTarget
from core.registry import ScannerRegistry


class ScanOrchestrator:
    """
    Coordinates multi-scanner runs against a target.
    Merges results from different scanners by MAC address.
    """

    def __init__(self, registry: ScannerRegistry):
        self._registry = registry
        self._current_scan: Optional[_ScanJob] = None
        self._lock = threading.Lock()

    @property
    def is_scanning(self) -> bool:
        with self._lock:
            return self._current_scan is not None and self._current_scan.is_running

    def get_status(self) -> dict:
        """Get the current scan status."""
        with self._lock:
            if not self._current_scan:
                return {"state": "idle", "results": None}
            return self._current_scan.to_dict()

    def start_scan(
        self,
        target: ScanTarget,
        on_device_found: Optional[Callable[[Device], None]] = None,
        on_complete: Optional[Callable[[ScanResult], None]] = None,
    ) -> bool:
        """
        Start a scan in a background thread.

        Args:
            target: What and how to scan.
            on_device_found: Called each time a new device is discovered.
            on_complete: Called when all scanners have finished.

        Returns:
            True if scan started, False if one is already running.
        """
        if self.is_scanning:
            return False

        # Resolve which scanners to use
        if target.scanner_names:
            scanners = [
                self._registry.get(name)
                for name in target.scanner_names
                if self._registry.get(name)
            ]
        else:
            # Default: use all available scanners
            scanners = self._registry.get_available()

        if not scanners:
            return False

        with self._lock:
            self._current_scan = _ScanJob(
                target=target,
                scanners=scanners,
                on_device_found=on_device_found,
                on_complete=on_complete,
            )
            self._current_scan.start()

        return True

    def stop_scan(self) -> None:
        """Cancel the current scan."""
        with self._lock:
            if self._current_scan:
                self._current_scan.cancel()


class _ScanJob:
    """
    Internal: a single scan execution.
    Runs each scanner sequentially, merges results by MAC.
    """

    def __init__(
        self,
        target: ScanTarget,
        scanners: list[BaseScanner],
        on_device_found: Optional[Callable[[Device], None]] = None,
        on_complete: Optional[Callable[[ScanResult], None]] = None,
    ):
        self.target = target
        self.scanners = scanners
        self.on_device_found = on_device_found
        self.on_complete = on_complete

        self.is_running = False
        self.is_cancelled = False
        self.merged_result = ScanResult(scanner_name="orchestrator")
        self.scanner_results: list[ScanResult] = []
        self._thread: Optional[threading.Thread] = None

        # Merged devices by MAC
        self._devices_by_mac: dict[str, Device] = {}
        self._seen_macs: set[str] = set()

    def start(self) -> None:
        self.is_running = True
        self.merged_result.state = ScanState.RUNNING
        self.merged_result.start_time = time.time()

        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def cancel(self) -> None:
        self.is_cancelled = True
        self.is_running = False
        self.merged_result.state = ScanState.CANCELLED

    def to_dict(self) -> dict:
        return {
            "state": self.merged_result.state.value,
            "target": self.target.to_dict(),
            "scanners_total": len(self.scanners),
            "scanners_completed": len(self.scanner_results),
            "current_scanner": (
                self.scanners[len(self.scanner_results)].display_name
                if len(self.scanner_results) < len(self.scanners)
                else None
            ),
            "devices_found": len(self._devices_by_mac),
            "results": self.merged_result.to_dict(),
        }

    def _run(self) -> None:
        """Execute each scanner sequentially and merge results."""
        try:
            for scanner in self.scanners:
                if self.is_cancelled:
                    break

                result = scanner.scan(
                    target=self.target,
                    on_device_found=self._on_single_device,
                )
                self.scanner_results.append(result)

                if result.errors:
                    self.merged_result.errors.extend(result.errors)

            # Final merge
            self.merged_result.devices = list(self._devices_by_mac.values())
            self.merged_result.end_time = time.time()
            self.merged_result.state = (
                ScanState.CANCELLED if self.is_cancelled else ScanState.COMPLETE
            )

        except Exception as e:
            self.merged_result.errors.append(f"Orchestrator error: {e}")
            self.merged_result.state = ScanState.FAILED

        finally:
            self.is_running = False
            if self.on_complete:
                try:
                    self.on_complete(self.merged_result)
                except Exception:
                    pass

    def _on_single_device(self, device: Device) -> None:
        """Handle a newly discovered device — merge or add."""
        mac = device.mac

        if mac in self._devices_by_mac:
            # Merge into existing
            self._devices_by_mac[mac].merge(device)
        else:
            # New device
            self._devices_by_mac[mac] = device

        # Notify callback only for genuinely new devices
        if mac not in self._seen_macs:
            self._seen_macs.add(mac)
            if self.on_device_found:
                try:
                    self.on_device_found(device)
                except Exception:
                    pass
