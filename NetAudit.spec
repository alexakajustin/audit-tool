# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=[],
    datas=[('templates', 'templates'), ('static', 'static'), ('scanners', 'scanners')],
    hiddenimports=['scanners.arp_cache_scanner', 'scanners.arp_scanner', 'scanners.dhcp_scanner', 'scanners.nmap_scanner', 'scanners.wifi_scanner', 'scapy.all', 'scapy.route', 'scapy.layers.inet', 'scapy.layers.inet6', 'scapy.layers.l2', 'scapy.layers.dhcp', 'scapy.layers.dns', 'scapy.contrib.cdp', 'scapy.layers.cdp', 'scapy.contrib.lldp', 'scapy.layers.lldp', 'scapy.contrib.ospf', 'scapy.layers.ospf', 'scapy.contrib.eigrp', 'scapy.layers.eigrp', 'engineio.async_drivers.threading', 'flask_socketio'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='NetAudit',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='NetAudit',
)
