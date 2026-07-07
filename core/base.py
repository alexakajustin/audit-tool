"""
Abstract base classes for scanners and sniffers.
This is the contract — every plugin implements these interfaces.
The rest of the system depends ONLY on these abstractions.
"""

from abc import ABC, abstractmethod
from typing import Callable, Generator, Optional

from core.models import (
    CaptureResult,
    Device,
    PacketInfo,
    ScanCapabilities,
    ScanResult,
    ScanTarget,
)


class BaseScanner(ABC):
    """
    Abstract scanner interface.

    Single Responsibility: one scanner, one discovery method.
    Open/Closed: new scanners extend this, existing code doesn't change.
    Liskov: any subclass is a valid drop-in replacement.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique scanner identifier (e.g. 'arp_sweep', 'nmap_discovery')."""
        ...

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable scanner name for the UI."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Short description of what this scanner does."""
        ...

    @abstractmethod
    def get_capabilities(self) -> ScanCapabilities:
        """Declare what this scanner can detect."""
        ...

    @abstractmethod
    def scan(
        self,
        target: ScanTarget,
        on_device_found: Optional[Callable[[Device], None]] = None,
    ) -> ScanResult:
        """
        Execute the scan against the given target.

        Args:
            target: What to scan (subnet, interface, options).
            on_device_found: Optional callback invoked each time a device
                             is discovered — enables real-time progress.

        Returns:
            ScanResult containing all discovered devices.
        """
        ...

    def is_available(self) -> bool:
        """
        Check if this scanner's prerequisites are met.
        Override to check for nmap binary, admin rights, etc.
        Default: always available.
        """
        return True


class BaseSniffer(ABC):
    """
    Abstract sniffer interface.

    Interface Segregation: sniffers don't need scan methods,
    scanners don't need sniffer methods.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique sniffer identifier."""
        ...

    @property
    @abstractmethod
    def is_running(self) -> bool:
        """Whether the sniffer is currently capturing."""
        ...

    @abstractmethod
    def start(
        self,
        interface: str,
        bpf_filter: str = "",
        on_packet: Optional[Callable[[PacketInfo], None]] = None,
    ) -> None:
        """
        Start capturing packets.

        Args:
            interface: Network interface to capture on.
            bpf_filter: Berkeley Packet Filter expression (e.g. "arp", "port 80").
            on_packet: Optional callback for each captured packet.
        """
        ...

    @abstractmethod
    def stop(self) -> CaptureResult:
        """Stop capturing and return the capture summary."""
        ...

    @abstractmethod
    def get_stats(self) -> dict:
        """Get current capture statistics without stopping."""
        ...

    @abstractmethod
    def export_pcap(self, filepath: str) -> str:
        """Export captured packets to a PCAP file. Returns the file path."""
        ...

    @abstractmethod
    def import_pcap(self, filepath: str) -> CaptureResult:
        """Import and analyze a PCAP file. Returns analysis results."""
        ...
