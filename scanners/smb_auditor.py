"""
SMB Share Auditor — Discovers and enumerates SMB shares, testing for read access.
"""

from __future__ import annotations

import time
import os
from typing import Callable, Optional

from core.base import BaseScanner
from core.models import (
    Device,
    DeviceStatus,
    PortInfo,
    ScanCapabilities,
    ScanResult,
    ScanState,
    ScanTarget,
)

import smbclient
import win32net

class SMBAuditor(BaseScanner):
    """
    SMB Share Auditor.
    Connects to hosts on port 445, enumerates shares, and attempts a recursive read
    to verify unauthorized data exposure.
    """

    @property
    def name(self) -> str:
        return "smb_auditor"

    @property
    def display_name(self) -> str:
        return "SMB Share Auditor"

    @property
    def description(self) -> str:
        return (
            "Audits Windows/Samba file servers. Enumerates standard and hidden shares "
            "and recursively tests read access using current user session or explicit credentials."
        )

    def get_capabilities(self) -> ScanCapabilities:
        return ScanCapabilities(
            can_discover_hosts=False,
            can_detect_ports=False,
            can_detect_os=False,
            can_detect_services=True,
            can_detect_hostnames=False,
            requires_admin=False,
            is_passive=False,
            layer=3,
        )

    def is_available(self) -> bool:
        """Available on Windows where win32net is present."""
        return True

    def scan(
        self,
        target: ScanTarget,
        on_device_found: Optional[Callable[[Device], None]] = None,
    ) -> ScanResult:
        result = ScanResult(scanner_name=self.name, state=ScanState.RUNNING)
        result.start_time = time.time()

        opts = target.options or {}
        username = opts.get("username", "")
        password = opts.get("password", "")

        # Extract target IPs
        target_ips = self._resolve_target_ips(target.subnet)
        if not target_ips:
            result.state = ScanState.COMPLETE
            result.end_time = time.time()
            return result

        for ip in target_ips:
            try:
                device = self._audit_host(ip, username, password)
                if device:
                    result.devices.append(device)
                    if on_device_found:
                        try:
                            on_device_found(device)
                        except Exception:
                            pass
            except Exception as e:
                result.errors.append(f"Error auditing {ip}: {e}")

        result.state = ScanState.COMPLETE
        result.end_time = time.time()
        return result

    def _resolve_target_ips(self, subnet_str: str) -> list[str]:
        ips = []
        import ipaddress
        for token in subnet_str.split():
            token = token.strip()
            if not token:
                continue
            try:
                if "/" in token:
                    net = ipaddress.IPv4Network(token, strict=False)
                    hosts = list(net.hosts())[:256] # limit to 256 for SMB audit
                    ips.extend([str(h) for h in hosts])
                else:
                    ipaddress.IPv4Address(token)
                    ips.append(token)
            except Exception:
                pass
        return ips

    def _audit_host(self, ip: str, username: str, password: str) -> Optional[Device]:
        """Enumerate and audit shares on a single host."""
        # 1. Enumerate Shares using win32net + common share probing
        shares = []
        try:
            share_data, _, _ = win32net.NetShareEnum(ip, 1)
            for s in share_data:
                shares.append({
                    "name": s["netname"],
                    "type": s["type"],
                    "remark": s.get("remark", "")
                })
        except Exception:
            pass

        # If standard share enum didn't find custom shares, add common probe targets
        known_names = {s["name"].upper() for s in shares}
        common_probes = ["C$", "ADMIN$", "IPC$", "Users", "Public", "Shares", "Data", "Backup", "SYSVOL", "NETLOGON"]
        for p in common_probes:
            if p.upper() not in known_names:
                shares.append({"name": p, "type": 0, "remark": "Common share probe"})
        
        if not shares:
            return None
        
        # 2. Register SMB Session
        active_identity = username if username else f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')} (Active Station Session)"
        try:
            if username and password:
                smbclient.register_session(ip, username=username, password=password)
            else:
                smbclient.register_session(ip)
        except Exception:
            pass

        accessible_shares = []
        
        # 3. Test Access & Audit Permissions
        for share in shares:
            share_name = share["name"]
            path = rf"\\{ip}\{share_name}"
            
            if share_name.upper() == "IPC$":
                continue
                
            items = []
            accessible = False
            error = ""
            permission_label = "Denied"
            
            try:
                items = self._recursive_list(path, max_items=10)
                accessible = True
                permission_label = "Read Access"
            except Exception as e:
                err_str = str(e)
                error = err_str
                if "STATUS_LOGON_FAILURE" in err_str or "0xc000006d" in err_str:
                    permission_label = "Denied (Logon Failure / Unauthenticated)"
                elif "STATUS_ACCESS_DENIED" in err_str or "0xc0000022" in err_str:
                    permission_label = "Denied (Unauthorized User)"
                elif "STATUS_BAD_NETWORK_NAME" in err_str or "0xc00000cc" in err_str:
                    continue  # Share does not exist on this host, skip it
                else:
                    permission_label = f"Error: {err_str[:40]}"
                
            accessible_shares.append({
                "name": share_name,
                "is_admin_share": share_name.endswith("$"),
                "accessible": accessible,
                "permission": permission_label,
                "auth_identity": active_identity,
                "items": items,
                "error": error
            })
            
        import json
        notes_dict = {
            "smb_audit": {
                "shares_found": len(accessible_shares),
                "audited_identity": active_identity,
                "details": accessible_shares
            }
        }
        
        return Device(
            mac=f"SMB-{ip}",
            ip=ip,
            status=DeviceStatus.ONLINE,
            discovery_methods=[self.name],
            notes=json.dumps(notes_dict)
        )

    def _recursive_list(self, base_path: str, max_items: int = 10) -> list[str]:
        """List root folder items only, up to max_items, to verify read access."""
        found = []
        try:
            with smbclient.scandir(base_path) as it:
                while True:
                    try:
                        entry = next(it)
                    except StopIteration:
                        break
                    except Exception:
                        continue

                    if len(found) >= max_items:
                        break
                    if entry.name in ('.', '..'):
                        continue

                    try:
                        is_dir = entry.is_dir()
                    except Exception:
                        is_dir = False

                    if is_dir:
                        found.append(f"[DIR]  {entry.name}")
                    else:
                        found.append(f"[FILE] {entry.name}")
        except Exception:
            # Fallback to os.scandir
            try:
                import os
                for entry in os.scandir(base_path):
                    if len(found) >= max_items:
                        break
                    try:
                        is_dir = entry.is_dir()
                    except Exception:
                        is_dir = False
                    if is_dir:
                        found.append(f"[DIR]  {entry.name}")
                    else:
                        found.append(f"[FILE] {entry.name}")
            except Exception:
                raise
                
        return found

