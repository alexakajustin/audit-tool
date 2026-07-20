"""
Topology API routes — constructs a graph of the network infrastructure.
"""

from flask import Blueprint, jsonify
import ipaddress

import api

topology_bp = Blueprint("topology", __name__)


@topology_bp.route("/api/topology", methods=["GET"])
def get_topology():
    """
    Generate nodes and edges for the frontend Vis-Network graph.
    Combines inventory endpoints, subnets, routers, and switches.
    """
    nodes = []
    edges = []
    
    # Track what we've added to avoid duplicates
    node_ids = set()

    def add_node(_id, label, group, title=""):
        if _id not in node_ids:
            nodes.append({"id": _id, "label": label, "group": group, "title": title})
            node_ids.add(_id)

    def add_edge(_from, _to, label="", dashed=False):
        edge = {"from": _from, "to": _to}
        if label:
            edge["label"] = label
        if dashed:
            edge["dashes"] = True
        edges.append(edge)

    # 1. Add the central "Internet" node
    add_node("internet", "Internet", "internet", "The World Wide Web")

    # 2. Add Subnets and Routers from VLAN Intelligence
    subnets = []
    if hasattr(api, 'vlan_discovery') and api.vlan_discovery:
        subnets = api.vlan_discovery.get_subnets()
        
    for s in subnets:
        cidr = s.get("cidr")
        gateway = s.get("gateway")
        
        # Add Subnet Cloud
        add_node(cidr, cidr, "subnet", f"Subnet: {cidr}")
        
        # Add Gateway/Router
        if gateway:
            add_node(gateway, gateway, "router", f"Gateway Router: {gateway}")
            # Connect Gateway to Subnet
            add_edge(gateway, cidr)
            
            # If this is a local private gateway, connect it to the Internet as a default route visual
            # (In reality it might go through another router, but for shock value we map it upstream)
            add_edge("internet", gateway, dashed=True)

    # 3. Add Switches from VLAN Intelligence
    switches = []
    if hasattr(api, 'vlan_discovery') and api.vlan_discovery:
        switches = api.vlan_discovery.get_switches()
        
    for sw in switches:
        dev_id = sw.get("device_id")
        ip = sw.get("management_ip")
        name = dev_id.split(".")[0] if dev_id else "Switch"
        
        add_node(dev_id, name, "switch", f"Switch: {name}\nIP: {ip}\nPlatform: {sw.get('platform')}")
        
        # Try to connect switch to its subnet
        if ip:
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                connected = False
                for s in subnets:
                    net = ipaddress.IPv4Network(s.get("cidr"), strict=False)
                    if ip_obj in net:
                        add_edge(s.get("cidr"), dev_id)
                        connected = True
                        break
                # If no subnet matched, connect to a generic LAN node
                if not connected:
                    add_node("lan", "Local LAN", "subnet")
                    add_edge("lan", dev_id)
            except Exception:
                pass

    # 4. Add Endpoints (PCs, Cameras, etc) from Inventory
    devices = []
    if hasattr(api, 'inventory') and api.inventory:
        devices = api.inventory.get_all()
        
    for dev in devices:
        mac = dev.mac
        ip = dev.ip
        hostname = dev.hostname or ip or mac
        
        # Skip if this IP is already a router (traceroute hop or gateway)
        if ip in node_ids:
            # We already added this as a router node, don't duplicate as endpoint
            continue
            
        label = hostname
        if len(label) > 15:
            label = label[:12] + "..."
            
        group = "endpoint"
        # Heuristics for icons
        vendor = (dev.vendor or "").lower()
        if "apple" in vendor or "samsung" in vendor:
            group = "mobile"
        elif "hikvision" in vendor or "dahua" in vendor:
            group = "camera"
            
        title = f"IP: {ip}\nMAC: {mac}\nVendor: {dev.vendor}"
        add_node(mac, label, group, title)
        
        # Connect endpoint to its Subnet
        if ip:
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                connected = False
                for s in subnets:
                    net = ipaddress.IPv4Network(s.get("cidr"), strict=False)
                    if ip_obj in net:
                        add_edge(s.get("cidr"), mac)
                        connected = True
                        break
                
                if not connected:
                    add_node("lan", "Local LAN", "subnet")
                    add_edge("lan", mac)
            except Exception:
                pass

    # If absolutely nothing was added (empty scan), add placeholders
    if len(nodes) == 1:
        add_node("local", "Local Network", "subnet")
        add_edge("internet", "local", dashed=True)

    return jsonify({"nodes": nodes, "edges": edges})
