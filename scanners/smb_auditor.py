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

    def _is_smb_port_open(self, ip: str, timeout: float = 2.5) -> bool:
        """Fast TCP probe to verify if port 445 is actively listening."""
        import socket
        try:
            with socket.create_connection((ip, 445), timeout=timeout):
                return True
        except (socket.timeout, socket.error, OSError):
            return False

    def scan(
        self,
        target: ScanTarget,
        on_device_found: Optional[Callable[[Device], None]] = None,
    ) -> ScanResult:
        import concurrent.futures

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

        # Step 1: Fast parallel port 445 pre-check (skips non-SMB / offline hosts in <0.5s)
        active_smb_ips = []
        if len(target_ips) == 1:
            active_smb_ips = target_ips
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
                future_to_ip = {executor.submit(self._is_smb_port_open, ip): ip for ip in target_ips}
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            active_smb_ips.append(ip)
                    except Exception:
                        pass

        if not active_smb_ips:
            result.state = ScanState.COMPLETE
            result.end_time = time.time()
            return result

        # Step 2: Concurrent host auditing on active SMB servers
        def audit_worker(ip_addr: str) -> Optional[Device]:
            try:
                return self._audit_host(ip_addr, username, password)
            except Exception as e:
                result.errors.append(f"Error auditing {ip_addr}: {e}")
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_ip = {executor.submit(audit_worker, ip): ip for ip in active_smb_ips}
            done, not_done = concurrent.futures.wait(future_to_ip.keys(), timeout=30.0)
            
            for future in done:
                try:
                    dev = future.result()
                    if dev:
                        result.devices.append(dev)
                        if on_device_found:
                            try:
                                on_device_found(dev)
                            except Exception:
                                pass
                except Exception as e:
                    result.errors.append(f"Worker error: {e}")

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
        # 1. Enumerate Shares using win32net
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
            # If win32net NetShareEnum fails (e.g. remote access denied), probe standard administrative shares
            shares = [
                {"name": "C$", "type": 0, "remark": "Default Drive Share"},
                {"name": "ADMIN$", "type": 0, "remark": "Remote Admin Share"},
                {"name": "IPC$", "type": 3, "remark": "Remote IPC"},
            ]
        
        if not shares:
            return None
        
        # 2. Register SMB Session if credentials provided or cached via DPAPI unlock
        from core.dpapi_vault import get_unlocked_cache
        unlocked_cache = get_unlocked_cache()
        cached_match = unlocked_cache.get(ip)
        if not cached_match:
            for k, v in unlocked_cache.items():
                if ip in k:
                    cached_match = v
                    break

        target_user = username or (cached_match.get("username") if cached_match else "")
        target_pass = password or (cached_match.get("password") if cached_match else "")

        if target_user and "\\" not in target_user and "@" not in target_user:
            target_user = f"{ip}\\{target_user}"

        active_identity = target_user if target_user else f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')} (Active Station Session)"
        try:
            if target_user and target_pass:
                smbclient.register_session(ip, username=target_user, password=target_pass)
            elif target_user:
                smbclient.register_session(ip, username=target_user)
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
                # Filter out non-existent shares
                if "STATUS_BAD_NETWORK_NAME" in err_str or "0xc00000cc" in err_str or "WinError 67" in err_str or "network name cannot be found" in err_str:
                    continue
                elif "STATUS_LOGON_FAILURE" in err_str or "0xc000006d" in err_str or "WinError 1326" in err_str:
                    permission_label = "Denied (Logon Failure / Unauthenticated)"
                elif "STATUS_ACCESS_DENIED" in err_str or "0xc0000022" in err_str or "WinError 5" in err_str:
                    permission_label = "Denied (Unauthorized User)"
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
        
        # Method 1: Try native OS first (automatically uses active session / cached credentials)
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
            return found
        except Exception as os_err:
            # Native OS failed (e.g. Access Denied or WinError 67 for hidden shares without auth).
            # We will now fallback to smbclient.
            pass

        # Method 2: smbclient fallback
        try:
            with smbclient.scandir(base_path) as it:
                for entry in it:
                    try:
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
                        continue
        except Exception:
            raise
                
        return found



