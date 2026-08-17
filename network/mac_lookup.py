"""
MAC address to vendor name resolution.
Uses a robust synchronous approach to avoid asyncio event loop conflicts
in multi-threaded Flask environments.
"""

from __future__ import annotations

import os
import urllib.request
from typing import Optional

# Simple dict cache — YAGNI: no TTL, no eviction, no Redis
_cache: dict[str, str] = {}

# In-memory database of OUI -> Vendor
_vendors_db: dict[str, str] = {}
_db_loaded = False


def _load_vendors_db():
    global _db_loaded
    if _db_loaded:
        return
        
    # Standard cache path used by mac-vendor-lookup
    cache_path = os.path.expanduser("~/.cache/mac-vendors.txt")
    
    # Try to download if it doesn't exist
    if not os.path.exists(cache_path):
        try:
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            url = "https://standards-oui.ieee.org/oui/oui.txt"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8', errors='ignore')
                with open(cache_path, 'w', encoding='utf-8') as f:
                    for line in content.splitlines():
                        if "(hex)" in line:
                            parts = line.split("(hex)")
                            mac = parts[0].strip().replace("-", "")
                            vendor = parts[1].strip()
                            f.write(f"{mac}:{vendor}\n")
        except Exception:
            pass

    # Load from cache file
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.strip().split(":", 1)
                    if len(parts) == 2:
                        _vendors_db[parts[0]] = parts[1]
        except Exception:
            pass
            
    _db_loaded = True


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
    oui_parts = normalized.split(":")[:3]
    if len(oui_parts) < 3:
        return ""
        
    oui = ":".join(oui_parts)

    if oui in _cache:
        return _cache[oui]

    vendor = _resolve(normalized)
    _cache[oui] = vendor
    return vendor


def _resolve(mac: str) -> str:
    """Attempt to resolve MAC synchronously using the local OUI database."""
    if not _db_loaded:
        _load_vendors_db()
        
    prefix = mac.replace(":", "").replace("-", "").replace(".", "")[:6].upper()
    return _vendors_db.get(prefix, "")


def bulk_lookup(macs: list[str]) -> dict[str, str]:
    """
    Resolve multiple MAC addresses at once.
    Returns: {mac: vendor} mapping.
    """
    return {mac: lookup_vendor(mac) for mac in macs}
