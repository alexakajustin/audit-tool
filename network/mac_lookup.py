"""
MAC address to vendor name resolution.
Uses mac-vendor-lookup for offline OUI database lookups.
KISS: simple dict cache, no external services.
"""

from __future__ import annotations

from typing import Optional

# Lazy-loaded to avoid import cost if never used
_lookup_instance = None


def _get_lookup():
    """Lazy-initialize the MAC lookup instance."""
    global _lookup_instance
    if _lookup_instance is None:
        try:
            from mac_vendor_lookup import MacLookup
            _lookup_instance = MacLookup()
            # Pre-load the OUI database
            try:
                _lookup_instance.update_vendors()
            except Exception:
                pass  # Use bundled database if update fails
        except ImportError:
            _lookup_instance = None
    return _lookup_instance


# Simple dict cache — YAGNI: no TTL, no eviction, no Redis
_cache: dict[str, str] = {}


def lookup_vendor(mac: str) -> str:
    """
    Resolve a MAC address to a vendor name.

    Args:
        mac: MAC address in any common format
             (aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF, etc.)

    Returns:
        Vendor name string, or "" if unknown.
    """
    if not mac:
        return ""

    # Normalize MAC
    normalized = mac.upper().replace("-", ":").replace(".", ":")
    # Use first 3 octets as cache key (OUI)
    oui = ":".join(normalized.split(":")[:3])

    if oui in _cache:
        return _cache[oui]

    vendor = _resolve(normalized)
    _cache[oui] = vendor
    return vendor


def _resolve(mac: str) -> str:
    """Attempt to resolve MAC via the lookup library."""
    lookup = _get_lookup()
    if lookup is None:
        return ""

    try:
        return lookup.lookup(mac)
    except Exception:
        return ""


def bulk_lookup(macs: list[str]) -> dict[str, str]:
    """
    Resolve multiple MAC addresses at once.
    Returns: {mac: vendor} mapping.
    """
    return {mac: lookup_vendor(mac) for mac in macs}
