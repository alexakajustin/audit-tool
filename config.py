"""
Application configuration.
KISS: one file, all settings, environment-aware.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")


class Config:
    """Application configuration with sensible defaults."""

    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "audit-tool-dev-key-change-in-prod")
    DEBUG = os.environ.get("FLASK_DEBUG", "true").lower() == "true"
    HOST = os.environ.get("HOST", "127.0.0.1")
    PORT = int(os.environ.get("PORT", 5000))

    # Database
    DB_PATH = os.path.join(DATA_DIR, "inventory.db")

    # Scanner defaults
    NMAP_TOP_PORTS = int(os.environ.get("NMAP_TOP_PORTS", 100))
    ARP_TIMEOUT = int(os.environ.get("ARP_TIMEOUT", 3))
    SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", 300))

    # Sniffer
    SNIFFER_MAX_PACKETS = int(os.environ.get("SNIFFER_MAX_PACKETS", 10000))
    SNIFFER_BUFFER_SIZE = int(os.environ.get("SNIFFER_BUFFER_SIZE", 500))

    # Paths
    PCAP_DIR = os.path.join(DATA_DIR, "pcaps")
    EXPORT_DIR = os.path.join(DATA_DIR, "exports")

    @classmethod
    def ensure_dirs(cls):
        """Create required directories if they don't exist."""
        for directory in [DATA_DIR, cls.PCAP_DIR, cls.EXPORT_DIR]:
            os.makedirs(directory, exist_ok=True)
