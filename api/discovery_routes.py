"""
Discovery API routes — scan management and interface listing.
Thin adapter: validate input → call core → format output.
"""

from flask import Blueprint, jsonify, request

import api
from core.models import ScanTarget
from network.interfaces import get_interfaces, get_best_interface

discovery_bp = Blueprint("discovery", __name__)


@discovery_bp.route("/api/interfaces", methods=["GET"])
def list_interfaces():
    """List available network interfaces."""
    interfaces = get_interfaces()
    best = get_best_interface()
    return jsonify({
        "interfaces": [i.to_dict() for i in interfaces],
        "recommended": best.to_dict() if best else None,
    })


@discovery_bp.route("/api/scanners", methods=["GET"])
def list_scanners():
    """List all registered scanners with capabilities."""
    return jsonify({"scanners": api.registry.list_info()})


@discovery_bp.route("/api/discovery/scan", methods=["POST"])
def start_scan():
    """
    Start a network discovery scan.

    Body JSON:
        subnet: str (required) — e.g. "192.168.1.0/24"
        interface: str (optional) — network interface name
        scanners: list[str] (optional) — scanner names to use
        options: dict (optional) — scanner-specific options
    """
    data = request.get_json(force=True, silent=True) or {}

    subnet = data.get("subnet", "")
    scanners = data.get("scanners", [])
    
    # WiFi scanner does not require a subnet target
    is_wifi_only = len(scanners) == 1 and scanners[0] == "wifi_scanner"
    
    if not subnet and not is_wifi_only:
        # Auto-resolve subnets from interfaces and VLAN discovery
        subnets_set = set()
        
        # Local interfaces
        interfaces = get_interfaces()
        for i in interfaces:
            if i.subnet:
                subnets_set.add(i.subnet)
                
        # VLAN / Traceroute discovery subnets
        if hasattr(api, 'vlan_discovery') and api.vlan_discovery:
            for s in api.vlan_discovery.get_subnets():
                subnets_set.add(s["cidr"])
                
        if not subnets_set:
            return jsonify({"error": "Could not auto-determine any subnets. Please check network connectivity."}), 400
            
        subnet = " ".join(list(subnets_set))

    target = ScanTarget(
        subnet=subnet,
        interface=data.get("interface", ""),
        scanner_names=data.get("scanners", []),
        options=data.get("options", {}),
    )

    # Callback: save discovered devices to inventory in real-time
    def on_device_found(device):
        api.inventory.upsert_device(device)
        # Emit via SocketIO if available
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

    def on_complete(result):
        if result and result.devices:
            try:
                api.inventory.upsert_many(result.devices)
            except Exception:
                pass
        try:
            from flask_socketio import emit
            emit(
                "scan_complete",
                result.to_dict(),
                namespace="/ws/discovery",
                broadcast=True,
            )
        except Exception:
            pass

    started = api.orchestrator.start_scan(
        target=target,
        on_device_found=on_device_found,
        on_complete=on_complete,
    )

    if not started:
        return jsonify({"error": "A scan is already running"}), 409

    return jsonify({"status": "started", "target": target.to_dict()})


@discovery_bp.route("/api/discovery/scan_ports", methods=["POST"])
def scan_device_ports():
    """
    On-demand TCP port scan for a specific IP or all devices in inventory.
    """
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip", "").strip()
    profile = data.get("profile", "fast")

    from scanners.port_scanner import PortScanner
    scanner = PortScanner()

    target_ips = []
    if ip:
        target_ips = [ip]
    else:
        devices = api.inventory.get_all()
        target_ips = [d.ip for d in devices if d.ip and not d.ip.startswith("127.")]

    if not target_ips:
        return jsonify({"error": "No target IPs found to scan"}), 400

    target = ScanTarget(
        subnet=" ".join(target_ips),
        options={"scan_type": profile},
    )

    result = scanner.scan(target)
    for dev in result.devices:
        api.inventory.upsert_device(dev)

    return jsonify({
        "status": "complete",
        "scanned_count": len(target_ips),
        "devices_with_open_ports": len(result.devices),
        "devices": [d.to_dict() for d in result.devices],
    })


@discovery_bp.route("/api/discovery/status", methods=["GET"])
def scan_status():
    """Get the current scan status."""
    return jsonify(api.orchestrator.get_status())


@discovery_bp.route("/api/discovery/stop", methods=["POST"])
def stop_scan():
    """Cancel the current scan."""
    api.orchestrator.stop_scan()
    return jsonify({"status": "stopped"})


@discovery_bp.route("/api/discovery/scan_smb", methods=["POST"])
def scan_smb():
    """
    On-demand SMB audit scan for a specific IP or all devices with port 445.
    """
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip", "").strip()
    username = data.get("username", "")
    password = data.get("password", "")

    from scanners.smb_auditor import SMBAuditor
    scanner = SMBAuditor()

    target_ips = []
    if ip:
        target_ips = [ip]
    else:
        # 1. Collect from Inventory (hosts with port 445 or online)
        devices = api.inventory.get_all()
        for d in devices:
            if d.ip and not d.ip.startswith("127."):
                has_smb = any(p.port == 445 and p.state == "open" for p in d.ports)
                if has_smb or d.status.value == "online":
                    target_ips.append(d.ip)
        
        # 2. Collect from Windows Credential Manager targets
        try:
            import win32cred
            import re
            creds = win32cred.CredEnumerate(None, 0) or []
            for c in creds:
                t = c.get("TargetName", "")
                m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', t)
                if m:
                    target_ips.append(m.group(0))
        except Exception:
            pass

        # 3. Add local host IP if present
        try:
            import socket
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            if local_ip and not local_ip.startswith("127."):
                target_ips.append(local_ip)
        except Exception:
            pass

        # De-duplicate while preserving order
        seen = set()
        deduped = []
        for tip in target_ips:
            if tip not in seen:
                seen.add(tip)
                deduped.append(tip)
        target_ips = deduped

        # If still empty, default to local machine
        if not target_ips:
            target_ips = ["127.0.0.1"]

    target = ScanTarget(
        subnet=" ".join(target_ips),
        options={"username": username, "password": password},
    )

    result = scanner.scan(target)
    
    devices_updated = []
    for dev in result.devices:
        api.inventory.upsert_device(dev)
        devices_updated.append(dev.to_dict())

    return jsonify({
        "status": "complete",
        "scanned_count": len(target_ips),
        "devices_with_shares": len(result.devices),
        "devices": devices_updated,
    })


@discovery_bp.route("/api/discovery/smb_listdir", methods=["POST"])
def smb_listdir():
    """
    On-demand SMB directory listing for the interactive File Explorer.
    Includes smart credential matching from Windows Credential Manager and
    robust handling for locked/system files.
    """
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip", "").strip()
    share = data.get("share", "").strip()
    path = data.get("path", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not ip or not share:
        return jsonify({"error": "IP and Share are required"}), 400

    # Smart credential resolution: if no username provided, check Windows Credential Manager
    if not username:
        try:
            import win32cred
            creds = win32cred.CredEnumerate(None, 0) or []
            for c in creds:
                t = c.get("TargetName", "")
                if ip in t and c.get("UserName"):
                    username = c.get("UserName")
                    break
        except Exception:
            pass

    import smbclient
    try:
        if username and password:
            smbclient.register_session(ip, username=username, password=password)
        elif username:
            smbclient.register_session(ip, username=username)
        else:
            smbclient.register_session(ip)
    except Exception as e:
        # If smbclient registration fails, we will still attempt native OS UNC fallback
        pass

    # Construct the UNC path
    unc_path = rf"\\{ip}\{share}"
    if path:
        path_clean = path.replace("/", "\\").strip("\\")
        unc_path = rf"{unc_path}\{path_clean}"

    items = []
    scan_error = None

    # If NO explicit password given, try native Windows OS first (uses active station session / OS cached tokens)
    if not password:
        try:
            import os
            for entry in os.scandir(unc_path):
                try:
                    is_dir = entry.is_dir()
                except Exception:
                    is_dir = False

                size = 0
                if not is_dir:
                    try:
                        size = entry.stat().st_size
                    except Exception:
                        size = 0

                items.append({
                    "name": entry.name,
                    "is_dir": is_dir,
                    "size": size,
                })
            scan_error = None
        except Exception as os_err:
            scan_error = os_err

    # If items found via native OS, return immediately
    if items and not scan_error:
        items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
        return jsonify({"status": "success", "items": items, "path": unc_path, "resolved_user": username})

    # Method 2: smbclient (with explicit credentials or SSPI)
    try:
        with smbclient.scandir(unc_path) as it:
            for entry in it:
                try:
                    if entry.name in ('.', '..'):
                        continue

                    try:
                        is_dir = entry.is_dir()
                    except Exception:
                        is_dir = False

                    size = 0
                    if not is_dir:
                        try:
                            size = entry.stat().st_size
                        except Exception:
                            size = 0

                    items.append({
                        "name": entry.name,
                        "is_dir": is_dir,
                        "size": size,
                    })
                except Exception:
                    continue
        scan_error = None
    except Exception as e:
        scan_error = e

    if scan_error and not items:
        err_msg = str(scan_error)
        if "WinError 67" in err_msg or "0xc00000cc" in err_msg or "network name cannot be found" in err_msg or "STATUS_BAD_NETWORK_NAME" in err_msg:
            return jsonify({"error": f"Share '{share}' does not exist on {ip}."}), 404
        return jsonify({"error": f"Failed to list directory: {err_msg}"}), 500

    # Sort items: directories first, then alphabetical
    items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    return jsonify({"status": "success", "items": items, "path": unc_path, "resolved_user": username})




@discovery_bp.route("/api/discovery/smb_session_info", methods=["GET"])
def smb_session_info():
    """
    Discover active workstation identity and Windows Credential Manager targets
    without requiring administrator privileges (standard workstation emulation).
    """
    import os
    import platform
    import re

    info = {
        "username": os.environ.get("USERNAME", ""),
        "domain": os.environ.get("USERDOMAIN", ""),
        "logon_server": os.environ.get("LOGONSERVER", ""),
        "dns_domain": os.environ.get("USERDNSDOMAIN", ""),
        "computer_name": os.environ.get("COMPUTERNAME", platform.node()),
        "full_account": f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}",
        "groups": [],
        "is_admin": False,
        "vault_targets": []
    }

    # Query Token Groups (unprivileged standard user token query)
    try:
        import win32api
        import win32security
        tok = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
        groups = win32security.GetTokenInformation(tok, win32security.TokenGroups)
        group_names = []
        for g_sid, _ in groups:
            try:
                g_acc, g_dom, _ = win32security.LookupAccountSid(None, g_sid)
                if g_acc and g_acc != "None":
                    name = f"{g_dom}\\{g_acc}" if g_dom else g_acc
                    group_names.append(name)
            except Exception:
                pass
        info["groups"] = group_names
        info["is_admin"] = any("Administrator" in g for g in group_names)
    except Exception as e:
        info["groups_error"] = str(e)

    # Query Windows Credential Manager for saved targets (unprivileged)
    try:
        import win32cred
        creds = win32cred.CredEnumerate(None, 0) or []
        vault_items = []
        for c in creds:
            target = c.get("TargetName", "")
            user = c.get("UserName", "")
            ctype = c.get("Type", 1)
            password = ""

            try:
                detail = win32cred.CredRead(target, ctype, 0)
                blob = detail.get("CredentialBlob")
                if blob:
                    try:
                        s = blob.decode('utf-8')
                        if s and all(32 <= ord(ch) < 127 for ch in s):
                            password = s
                        else:
                            s16 = blob.decode('utf-16-le', errors='ignore').rstrip('\x00')
                            if s16 and any(32 <= ord(ch) < 127 for ch in s16):
                                password = s16
                    except Exception:
                        pass
            except Exception:
                pass
            
            # Extract IP if present in target
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', target)
            ip = ip_match.group(0) if ip_match else ""
            
            type_label = "Domain Password" if ctype == 2 else "Generic"
            if user or ip:
                vault_items.append({
                    "target": target,
                    "ip": ip,
                    "username": user,
                    "password": password,
                    "has_password": bool(password),
                    "type": type_label,
                })
        info["vault_targets"] = vault_items
    except Exception as e:
        info["vault_error"] = str(e)

    return jsonify(info)

