"""
Topology API routes — constructs a graph of the network infrastructure.
Dynamically maps multi-hop routing chains (e.g. PC -> .88.1 -> .99.1 -> 10.x -> Internet)
using exact traceroute hop levels for a true hierarchical network layout.
"""

from flask import Blueprint, jsonify
import ipaddress
import socket

import api
from network.interfaces import get_interfaces

topology_bp = Blueprint("topology", __name__)


@topology_bp.route("/api/topology", methods=["GET"])
def get_topology():
    """
    Generate nodes and edges for the frontend Vis-Network graph.
    Builds a strict hierarchical layout following traceroute hop paths.
    """
    nodes = []
    edges = []
    node_ids = set()

    # Identify local machine's IPs and MACs
    my_ips = set()
    my_macs = set()
    try:
        for iface in get_interfaces():
            if iface.ip:
                my_ips.add(iface.ip)
            if iface.mac:
                my_macs.add(iface.mac.upper())
    except Exception:
        pass

    def add_node(_id, label, group, title="", level=None):
        if _id not in node_ids:
            node = {"id": _id, "label": label, "group": group, "title": title}
            if level is not None:
                node["level"] = level
            nodes.append(node)
            node_ids.add(_id)

    def add_edge(_from, _to, label="", dashed=False):
        edge = {"from": _from, "to": _to}
        if label:
            edge["label"] = label
        if dashed:
            edge["dashes"] = True
        edges.append(edge)

    # ── Level 0: Internet Root ─────────────────────────────────
    add_node("internet", "☁ Internet", "internet", "The Public Internet", level=0)

    # Fetch discovery subnets and traceroute hops
    subnets = []
    traceroute_hops = []
    if hasattr(api, 'vlan_discovery') and api.vlan_discovery:
        subnets = api.vlan_discovery.get_subnets()
        if hasattr(api.vlan_discovery, 'get_traceroute_hops'):
            traceroute_hops = api.vlan_discovery.get_traceroute_hops()

    routers_added = set()
    hop_level_map = {}     # router_ip -> level
    subnet_level_map = {}  # cidr -> level
    num_hops = len(traceroute_hops)

    # ── Level 1..N: Sequential Router Hop Chain ────────────────
    # traceroute_hops: [Hop 1 (closest/local), Hop 2, Hop 3, ..., Hop N (closest to internet)]
    if traceroute_hops:
        for idx, hop_ip in enumerate(traceroute_hops):
            # Index 0 is local router (lowest in tree), Index N-1 is highest router (closest to Internet)
            dist_from_internet = num_hops - idx
            router_lvl = dist_from_internet * 2

            hop_level_map[hop_ip] = router_lvl
            add_node(hop_ip, hop_ip, "router", f"Gateway Router (Hop {idx+1}): {hop_ip}", level=router_lvl)
            routers_added.add(hop_ip)

            if idx == num_hops - 1:
                # Highest hop connects to Internet
                add_edge("internet", hop_ip, dashed=True)
            else:
                # Connect upstream router -> downstream router
                next_upstream_hop = traceroute_hops[idx + 1]
                add_edge(next_upstream_hop, hop_ip)

    # ── Add any standalone routers not in traceroute chain ─────
    for s in subnets:
        gateway = s.get("gateway")
        if gateway and gateway not in routers_added:
            standalone_lvl = (num_hops + 1) * 2 if num_hops else 2
            add_node(gateway, gateway, "router", f"Gateway Router: {gateway}", level=standalone_lvl)
            add_edge("internet", gateway, dashed=True)
            routers_added.add(gateway)
            hop_level_map[gateway] = standalone_lvl

    # ── Subnets ────────────────────────────────────────────────
    max_router_lvl = max(hop_level_map.values()) if hop_level_map else 2
    for s in subnets:
        cidr = s.get("cidr")
        gateway = s.get("gateway")

        if gateway and gateway in hop_level_map:
            sub_lvl = hop_level_map[gateway] + 1
        else:
            sub_lvl = max_router_lvl + 1

        subnet_level_map[cidr] = sub_lvl
        add_node(cidr, cidr, "subnet", f"Subnet: {cidr}", level=sub_lvl)

        if gateway and gateway in node_ids:
            add_edge(gateway, cidr)
        else:
            add_edge("internet", cidr, dashed=True)

    # ── MY PC Node ─────────────────────────────────────────────
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "This PC"

    my_label = f"⬤ {hostname}"
    my_ip_label = ", ".join(sorted(my_ips)) if my_ips else ""

    # Place MY PC below its primary local subnet level
    max_subnet_lvl = max(subnet_level_map.values()) if subnet_level_map else 3
    my_pc_level = max_subnet_lvl + 1

    # Find local subnet level for MY PC
    for iface in get_interfaces():
        if iface.subnet and iface.subnet in subnet_level_map:
            my_pc_level = subnet_level_map[iface.subnet] + 1
            break

    add_node("my_pc", my_label, "my_pc",
             f"THIS MACHINE\nHostname: {hostname}\nIPs: {my_ip_label}",
             level=my_pc_level)

    # Connect MY PC to its local subnet(s)
    my_pc_connected = False
    for iface in get_interfaces():
        if iface.subnet and iface.subnet in node_ids:
            add_edge(iface.subnet, "my_pc")
            my_pc_connected = True

    if not my_pc_connected and traceroute_hops:
        # Connect to first hop (local router)
        add_edge(traceroute_hops[0], "my_pc")
        my_pc_connected = True

    if not my_pc_connected:
        if subnets:
            add_edge(subnets[0].get("cidr"), "my_pc")
        else:
            add_edge("internet", "my_pc", dashed=True)

    # ── Switches ───────────────────────────────────────────────
    switches = []
    if hasattr(api, 'vlan_discovery') and api.vlan_discovery:
        switches = api.vlan_discovery.get_switches()

    for sw in switches:
        dev_id = sw.get("device_id")
        ip = sw.get("management_ip")
        name = dev_id.split(".")[0] if dev_id else "Switch"
        sw_lvl = max_subnet_lvl

        add_node(dev_id, name, "switch",
                 f"Switch: {name}\nIP: {ip}\nPlatform: {sw.get('platform')}",
                 level=sw_lvl)

        if ip:
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                for s in subnets:
                    net = ipaddress.IPv4Network(s.get("cidr"), strict=False)
                    if ip_obj in net:
                        add_edge(s.get("cidr"), dev_id)
                        break
            except Exception:
                pass

    # ── Endpoints ──────────────────────────────────────────────
    devices = []
    if hasattr(api, 'inventory') and api.inventory:
        devices = api.inventory.get_all()

    for dev in devices:
        mac = dev.mac
        ip = dev.ip
        hostname_dev = dev.hostname or ip or mac

        # Skip if MY PC or already added as a router
        if ip in my_ips or mac.upper() in my_macs or ip in node_ids:
            continue

        label = hostname_dev
        if len(label) > 15:
            label = label[:12] + "..."

        group = "endpoint"
        vendor = (dev.vendor or "").lower()
        if "apple" in vendor or "samsung" in vendor:
            group = "mobile"
        elif "hikvision" in vendor or "dahua" in vendor:
            group = "camera"

        # Determine level based on subnet
        endpoint_lvl = my_pc_level
        connected = False

        if ip:
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                for s in subnets:
                    net_cidr = s.get("cidr")
                    net = ipaddress.IPv4Network(net_cidr, strict=False)
                    if ip_obj in net:
                        if net_cidr in subnet_level_map:
                            endpoint_lvl = subnet_level_map[net_cidr] + 1
                        add_edge(net_cidr, mac)
                        connected = True
                        break
            except Exception:
                pass

        if not connected:
            add_node("unknown_net", "Unknown Net", "subnet", level=max_subnet_lvl)
            add_edge("unknown_net", mac)
            endpoint_lvl = max_subnet_lvl + 1

        title = f"IP: {ip}\nMAC: {mac}\nVendor: {dev.vendor}"
        add_node(mac, label, group, title, level=endpoint_lvl)

    # Placeholder fallback
    if len(nodes) <= 2:
        add_node("local", "Local Network", "subnet", level=2)
        add_edge("internet", "local", dashed=True)
        add_edge("local", "my_pc")

    return jsonify({"nodes": nodes, "edges": edges})
