"""
PyInstaller build script for NetAudit.

This script runs PyInstaller with the correct arguments to bundle the application,
templates, static files, and dynamic scanner modules into a single executable.
"""

import os
import subprocess
import sys
import shutil

def build():
    # Ensure we are in the project root
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)

    print("Cleaning previous builds...")
    if os.path.exists("build"):
        shutil.rmtree("build")
        
    exe_dir = os.path.join("dist", "NetAudit")
    if os.path.exists(exe_dir):
        shutil.rmtree(exe_dir)
        
    if os.path.exists("NetAudit.spec"):
        os.remove("NetAudit.spec")

    print("\nRunning PyInstaller...")
    
    # We need to explicitly include the scanners folder because it's loaded dynamically
    # via pkgutil/importlib in registry.py, which PyInstaller can't always detect.
    
    # Also include the web assets
    
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "NetAudit",
        "--onedir",
        "--clean",
        "--add-data", f"templates{os.pathsep}templates",
        "--add-data", f"static{os.pathsep}static",
        "--add-data", f"scanners{os.pathsep}scanners",
        
        # Explicitly import things that might be hidden imports
        "--hidden-import", "scanners.arp_cache_scanner",
        "--hidden-import", "scanners.arp_scanner",
        "--hidden-import", "scanners.dhcp_scanner",
        "--hidden-import", "scanners.nmap_scanner",
        "--hidden-import", "scanners.wifi_scanner",
        
        # Scapy dynamic imports that often get missed
        "--hidden-import", "scapy.all",
        "--hidden-import", "scapy.route",
        "--hidden-import", "scapy.layers.inet",
        "--hidden-import", "scapy.layers.inet6",
        "--hidden-import", "scapy.layers.l2",
        "--hidden-import", "scapy.layers.dhcp",
        "--hidden-import", "scapy.layers.dns",
        
        # Flask/SocketIO dynamic imports
        "--hidden-import", "engineio.async_drivers.threading",
        "--hidden-import", "flask_socketio",
        
        "app.py"
    ]
    
    # Use subprocess.run to show output in real-time
    result = subprocess.run(cmd)
    
    if result.returncode == 0:
        print("\nBuild successful!")
        print("Executable folder is located in the 'dist' directory: dist/NetAudit/NetAudit.exe")
    else:
        print("\nBuild failed!")
        sys.exit(1)

if __name__ == "__main__":
    build()
