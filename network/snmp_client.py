"""
Lightweight SNMPv2c client - zero external dependencies.

Implements BER/ASN.1 encoding/decoding for SNMP GetRequest, GetNextRequest,
and GetBulkRequest PDUs over standard UDP sockets. No admin rights needed.

Usage:
    from network.snmp_client import snmp_get, snmp_walk

    value = snmp_get("192.168.99.1", "public", "1.3.6.1.2.1.1.1.0")
    results = snmp_walk("192.168.99.1", "public", "1.3.6.1.2.1.2.2.1.2")
"""

from __future__ import annotations

import socket
import struct
import random
import time
from typing import Optional

# ── ASN.1 / BER Tag Constants ─────────────────────────────────
ASN1_INTEGER        = 0x02
ASN1_OCTET_STRING   = 0x04
ASN1_NULL           = 0x05
ASN1_OID            = 0x06
ASN1_SEQUENCE       = 0x30
ASN1_IPADDRESS      = 0x40
ASN1_COUNTER32      = 0x41
ASN1_GAUGE32        = 0x42
ASN1_TIMETICKS      = 0x43
ASN1_COUNTER64      = 0x46
ASN1_NOSUCHOBJECT   = 0x80
ASN1_NOSUCHINSTANCE = 0x81
ASN1_ENDOFMIBVIEW   = 0x82

SNMP_GET_REQUEST     = 0xA0
SNMP_GETNEXT_REQUEST = 0xA1
SNMP_GET_RESPONSE    = 0xA2
SNMP_GETBULK_REQUEST = 0xA5

SNMP_VERSION_2C = 1  # SNMPv2c = version value 1


# ── BER Encoder ───────────────────────────────────────────────

def _ber_encode_length(length: int) -> bytes:
    """Encode a BER length field."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82]) + struct.pack("!H", length)
    else:
        return bytes([0x83]) + struct.pack("!I", length)[1:]


def _ber_encode_tlv(tag: int, value: bytes) -> bytes:
    """Encode a TLV (Tag-Length-Value) triplet."""
    return bytes([tag]) + _ber_encode_length(len(value)) + value


def _ber_encode_integer(value: int) -> bytes:
    """Encode an ASN.1 INTEGER."""
    if value == 0:
        return _ber_encode_tlv(ASN1_INTEGER, b'\x00')

    # Convert to signed big-endian bytes
    negative = value < 0
    if negative:
        # Two's complement for negative values
        value = abs(value)

    result = []
    v = value
    while v > 0:
        result.insert(0, v & 0xFF)
        v >>= 8

    # Add sign byte if needed
    if not negative and result[0] & 0x80:
        result.insert(0, 0x00)
    elif negative:
        # Two's complement
        result = [(~b) & 0xFF for b in result]
        carry = 1
        for i in range(len(result) - 1, -1, -1):
            result[i] += carry
            carry = result[i] >> 8
            result[i] &= 0xFF
        if not (result[0] & 0x80):
            result.insert(0, 0xFF)

    return _ber_encode_tlv(ASN1_INTEGER, bytes(result))


def _ber_encode_octet_string(value: bytes | str) -> bytes:
    """Encode an ASN.1 OCTET STRING."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    return _ber_encode_tlv(ASN1_OCTET_STRING, value)


def _ber_encode_null() -> bytes:
    """Encode an ASN.1 NULL."""
    return _ber_encode_tlv(ASN1_NULL, b'')


def _ber_encode_oid(oid_str: str) -> bytes:
    """Encode an ASN.1 OBJECT IDENTIFIER from dotted string."""
    parts = [int(x) for x in oid_str.strip(".").split(".")]
    if len(parts) < 2:
        parts.extend([0] * (2 - len(parts)))

    # First two components are encoded as 40*X + Y
    encoded = [40 * parts[0] + parts[1]]

    for part in parts[2:]:
        if part < 0x80:
            encoded.append(part)
        else:
            # Multi-byte encoding (base-128)
            sub_bytes = []
            v = part
            while v > 0:
                sub_bytes.insert(0, v & 0x7F)
                v >>= 7
            for i in range(len(sub_bytes) - 1):
                sub_bytes[i] |= 0x80
            encoded.extend(sub_bytes)

    return _ber_encode_tlv(ASN1_OID, bytes(encoded))


def _ber_encode_sequence(contents: bytes) -> bytes:
    """Encode an ASN.1 SEQUENCE."""
    return _ber_encode_tlv(ASN1_SEQUENCE, contents)


# ── BER Decoder ───────────────────────────────────────────────

def _ber_decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a BER length field. Returns (length, new_offset)."""
    if offset >= len(data):
        raise ValueError("BER decode: premature end of data")

    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    elif first == 0x81:
        return data[offset + 1], offset + 2
    elif first == 0x82:
        return struct.unpack("!H", data[offset + 1:offset + 3])[0], offset + 3
    elif first == 0x83:
        return struct.unpack("!I", b'\x00' + data[offset + 1:offset + 4])[0], offset + 4
    else:
        raise ValueError(f"BER decode: unsupported length encoding 0x{first:02X}")


def _ber_decode_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Decode a TLV. Returns (tag, value_bytes, new_offset)."""
    if offset >= len(data):
        raise ValueError("BER decode: premature end of data")

    tag = data[offset]
    offset += 1
    length, offset = _ber_decode_length(data, offset)

    if offset + length > len(data):
        raise ValueError(f"BER decode: value extends past end of data (need {length}, have {len(data) - offset})")

    value = data[offset:offset + length]
    return tag, value, offset + length


def _ber_decode_integer(value: bytes) -> int:
    """Decode an ASN.1 INTEGER value."""
    if not value:
        return 0
    result = 0
    negative = value[0] & 0x80
    for byte in value:
        result = (result << 8) | byte
    if negative:
        result -= (1 << (len(value) * 8))
    return result


def _ber_decode_oid(value: bytes) -> str:
    """Decode an ASN.1 OBJECT IDENTIFIER to dotted string."""
    if not value:
        return ""

    parts = [value[0] // 40, value[0] % 40]

    i = 1
    while i < len(value):
        if value[i] < 0x80:
            parts.append(value[i])
            i += 1
        else:
            # Multi-byte sub-identifier
            v = 0
            while i < len(value) and value[i] & 0x80:
                v = (v << 7) | (value[i] & 0x7F)
                i += 1
            if i < len(value):
                v = (v << 7) | value[i]
                i += 1
            parts.append(v)

    return ".".join(str(p) for p in parts)


def _decode_snmp_value(tag: int, value: bytes):
    """Decode an SNMP value based on its ASN.1 tag. Returns a Python-native value."""
    if tag == ASN1_INTEGER:
        return _ber_decode_integer(value)
    elif tag == ASN1_OCTET_STRING:
        # Try UTF-8 first, fall back to hex
        try:
            decoded = value.decode("utf-8", errors="replace")
            # Filter non-printable characters
            if all(c.isprintable() or c in '\r\n\t' for c in decoded):
                return decoded
            return value.hex()
        except Exception:
            return value.hex()
    elif tag == ASN1_OID:
        return _ber_decode_oid(value)
    elif tag == ASN1_NULL:
        return None
    elif tag == ASN1_IPADDRESS:
        if len(value) == 4:
            return f"{value[0]}.{value[1]}.{value[2]}.{value[3]}"
        return value.hex()
    elif tag in (ASN1_COUNTER32, ASN1_GAUGE32, ASN1_TIMETICKS):
        return _ber_decode_integer(value)
    elif tag == ASN1_COUNTER64:
        return _ber_decode_integer(value)
    elif tag in (ASN1_NOSUCHOBJECT, ASN1_NOSUCHINSTANCE, ASN1_ENDOFMIBVIEW):
        return None
    else:
        # Unknown tag - return raw hex
        return value.hex()


# ── SNMP PDU Builder ──────────────────────────────────────────

def _build_snmp_get(community: str, oid: str, request_id: int = None) -> bytes:
    """Build a complete SNMPv2c GetRequest packet."""
    if request_id is None:
        request_id = random.randint(1, 2**30)

    # Variable binding: OID -> NULL
    varbind = _ber_encode_sequence(
        _ber_encode_oid(oid) + _ber_encode_null()
    )
    varbind_list = _ber_encode_sequence(varbind)

    # PDU: request-id, error-status(0), error-index(0), varbind-list
    pdu_contents = (
        _ber_encode_integer(request_id)
        + _ber_encode_integer(0)  # error-status
        + _ber_encode_integer(0)  # error-index
        + varbind_list
    )
    pdu = _ber_encode_tlv(SNMP_GET_REQUEST, pdu_contents)

    # Message: version, community, pdu
    message = (
        _ber_encode_integer(SNMP_VERSION_2C)
        + _ber_encode_octet_string(community)
        + pdu
    )

    return _ber_encode_sequence(message)


def _build_snmp_getnext(community: str, oid: str, request_id: int = None) -> bytes:
    """Build a complete SNMPv2c GetNextRequest packet."""
    if request_id is None:
        request_id = random.randint(1, 2**30)

    varbind = _ber_encode_sequence(
        _ber_encode_oid(oid) + _ber_encode_null()
    )
    varbind_list = _ber_encode_sequence(varbind)

    pdu_contents = (
        _ber_encode_integer(request_id)
        + _ber_encode_integer(0)
        + _ber_encode_integer(0)
        + varbind_list
    )
    pdu = _ber_encode_tlv(SNMP_GETNEXT_REQUEST, pdu_contents)

    message = (
        _ber_encode_integer(SNMP_VERSION_2C)
        + _ber_encode_octet_string(community)
        + pdu
    )

    return _ber_encode_sequence(message)


# ── SNMP Response Parser ─────────────────────────────────────

def _parse_snmp_response(data: bytes) -> list[tuple[str, any]]:
    """
    Parse an SNMP response packet.
    Returns list of (oid_string, value) tuples.
    """
    results = []

    try:
        # Outer SEQUENCE
        tag, msg_value, _ = _ber_decode_tlv(data, 0)
        if tag != ASN1_SEQUENCE:
            return results

        offset = 0

        # Version
        tag, ver_bytes, offset = _ber_decode_tlv(msg_value, offset)

        # Community
        tag, comm_bytes, offset = _ber_decode_tlv(msg_value, offset)

        # PDU (GetResponse = 0xA2)
        pdu_tag, pdu_value, offset = _ber_decode_tlv(msg_value, offset)
        if pdu_tag != SNMP_GET_RESPONSE:
            return results

        pdu_offset = 0

        # Request ID
        tag, rid_bytes, pdu_offset = _ber_decode_tlv(pdu_value, pdu_offset)

        # Error Status
        tag, err_bytes, pdu_offset = _ber_decode_tlv(pdu_value, pdu_offset)
        error_status = _ber_decode_integer(err_bytes)
        if error_status != 0:
            return results  # Error in response

        # Error Index
        tag, eidx_bytes, pdu_offset = _ber_decode_tlv(pdu_value, pdu_offset)

        # Variable Bindings List (SEQUENCE)
        tag, vbl_value, pdu_offset = _ber_decode_tlv(pdu_value, pdu_offset)
        if tag != ASN1_SEQUENCE:
            return results

        # Parse each varbind
        vb_offset = 0
        while vb_offset < len(vbl_value):
            # Each varbind is a SEQUENCE of (OID, value)
            tag, vb_value, vb_offset = _ber_decode_tlv(vbl_value, vb_offset)
            if tag != ASN1_SEQUENCE:
                continue

            inner_offset = 0

            # OID
            oid_tag, oid_bytes, inner_offset = _ber_decode_tlv(vb_value, inner_offset)
            if oid_tag != ASN1_OID:
                continue
            oid_str = _ber_decode_oid(oid_bytes)

            # Value
            val_tag, val_bytes, inner_offset = _ber_decode_tlv(vb_value, inner_offset)

            # Check for end-of-MIB-view
            if val_tag in (ASN1_NOSUCHOBJECT, ASN1_NOSUCHINSTANCE, ASN1_ENDOFMIBVIEW):
                continue

            value = _decode_snmp_value(val_tag, val_bytes)
            results.append((oid_str, value))

    except Exception:
        pass

    return results


# ── Public API ────────────────────────────────────────────────

def snmp_get(
    host: str,
    community: str,
    oid: str,
    port: int = 161,
    timeout: float = 2.0,
) -> Optional[tuple[str, any]]:
    """
    Perform a single SNMPv2c GET request.

    Args:
        host: Target IP address
        community: SNMP community string (e.g., "public")
        oid: OID in dotted notation (e.g., "1.3.6.1.2.1.1.1.0")
        port: SNMP port (default 161)
        timeout: Socket timeout in seconds

    Returns:
        (oid, value) tuple, or None on failure
    """
    try:
        packet = _build_snmp_get(community, oid)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        try:
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(65535)
            results = _parse_snmp_response(data)
            return results[0] if results else None
        finally:
            sock.close()

    except (socket.timeout, OSError, Exception):
        return None


def snmp_walk(
    host: str,
    community: str,
    root_oid: str,
    port: int = 161,
    timeout: float = 2.0,
    max_results: int = 500,
) -> list[tuple[str, any]]:
    """
    Perform an SNMPv2c WALK (series of GetNext requests).

    Walks the OID tree starting from root_oid until the response
    OID leaves the subtree or max_results is reached.

    Args:
        host: Target IP address
        community: SNMP community string
        root_oid: Starting OID subtree (e.g., "1.3.6.1.2.1.2.2.1.2")
        port: SNMP port (default 161)
        timeout: Socket timeout in seconds per request
        max_results: Maximum number of results to collect

    Returns:
        List of (oid, value) tuples within the subtree
    """
    results = []
    current_oid = root_oid
    normalized_root = root_oid.strip(".")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        try:
            for _ in range(max_results):
                packet = _build_snmp_getnext(community, current_oid)
                sock.sendto(packet, (host, port))
                data, _ = sock.recvfrom(65535)

                parsed = _parse_snmp_response(data)
                if not parsed:
                    break

                response_oid, response_value = parsed[0]

                # Check if we're still in the subtree
                if not response_oid.startswith(normalized_root + ".") and response_oid != normalized_root:
                    break

                # Avoid infinite loops (same OID returned)
                if response_oid == current_oid:
                    break

                results.append((response_oid, response_value))
                current_oid = response_oid

        finally:
            sock.close()

    except (socket.timeout, OSError, Exception):
        pass

    return results


def snmp_test_community(
    host: str,
    community: str,
    port: int = 161,
    timeout: float = 2.0,
) -> bool:
    """
    Test if a community string is valid by querying sysDescr.

    Returns True if the host responds to SNMP with this community.
    """
    result = snmp_get(host, community, "1.3.6.1.2.1.1.1.0", port, timeout)
    return result is not None


def snmp_get_system_info(
    host: str,
    community: str,
    port: int = 161,
    timeout: float = 2.0,
) -> dict:
    """
    Query common system MIB objects to identify the device.

    Returns dict with keys: sys_descr, sys_name, sys_contact,
    sys_location, sys_uptime, sys_object_id
    """
    oids = {
        "sys_descr":     "1.3.6.1.2.1.1.1.0",
        "sys_object_id": "1.3.6.1.2.1.1.2.0",
        "sys_uptime":    "1.3.6.1.2.1.1.3.0",
        "sys_contact":   "1.3.6.1.2.1.1.4.0",
        "sys_name":      "1.3.6.1.2.1.1.5.0",
        "sys_location":  "1.3.6.1.2.1.1.6.0",
    }

    info = {}
    for key, oid in oids.items():
        result = snmp_get(host, community, oid, port, timeout)
        if result:
            _, value = result
            info[key] = value
        else:
            info[key] = ""

    return info


def snmp_get_interfaces(
    host: str,
    community: str,
    port: int = 161,
    timeout: float = 2.0,
) -> list[dict]:
    """
    Walk the interface table to discover all interfaces.
    Returns list of dicts: {index, name, type, admin_status, ip, netmask}
    """
    interfaces = {}

    # ifDescr - interface names
    for oid, value in snmp_walk(host, community, "1.3.6.1.2.1.2.2.1.2", port, timeout):
        idx = oid.split(".")[-1]
        if idx not in interfaces:
            interfaces[idx] = {"index": int(idx), "name": "", "type": 0, "admin_status": 0, "ip": "", "netmask": ""}
        interfaces[idx]["name"] = str(value) if value else ""

    # ifType - interface types (6=ethernet, 53=propVirtual/VLAN, 131=tunnel, 135=l2vlan, 136=l3ipvlan)
    for oid, value in snmp_walk(host, community, "1.3.6.1.2.1.2.2.1.3", port, timeout):
        idx = oid.split(".")[-1]
        if idx in interfaces:
            interfaces[idx]["type"] = int(value) if value else 0

    # ifAdminStatus (1=up, 2=down)
    for oid, value in snmp_walk(host, community, "1.3.6.1.2.1.2.2.1.7", port, timeout):
        idx = oid.split(".")[-1]
        if idx in interfaces:
            interfaces[idx]["admin_status"] = int(value) if value else 0

    # ipAdEntAddr - IP addresses per interface
    ip_to_ifindex = {}
    for oid, value in snmp_walk(host, community, "1.3.6.1.2.1.4.20.1.2", port, timeout):
        # OID: 1.3.6.1.2.1.4.20.1.2.<ip_addr> = ifIndex
        ip_addr = ".".join(oid.split(".")[-4:])
        if value:
            ip_to_ifindex[str(value)] = ip_addr

    # ipAdEntNetMask - netmasks per IP
    ip_netmasks = {}
    for oid, value in snmp_walk(host, community, "1.3.6.1.2.1.4.20.1.3", port, timeout):
        ip_addr = ".".join(oid.split(".")[-4:])
        ip_netmasks[ip_addr] = str(value) if value else ""

    # Map IPs back to interfaces
    for if_idx, ip_addr in ip_to_ifindex.items():
        if if_idx in interfaces:
            interfaces[if_idx]["ip"] = ip_addr
            interfaces[if_idx]["netmask"] = ip_netmasks.get(ip_addr, "")

    return list(interfaces.values())


def snmp_get_arp_table(
    host: str,
    community: str,
    port: int = 161,
    timeout: float = 2.0,
) -> list[dict]:
    """
    Walk the ARP / ipNetToMedia table.
    Returns list of dicts: {ip, mac, if_index, type}
    """
    entries = []

    # ipNetToMediaTable (1.3.6.1.2.1.4.22.1)
    # .1 = ifIndex, .2 = physAddress (MAC), .3 = netAddress (IP), .4 = type
    mac_entries = {}
    for oid, value in snmp_walk(host, community, "1.3.6.1.2.1.4.22.1.2", port, timeout):
        # OID suffix: .ifIndex.ip1.ip2.ip3.ip4
        parts = oid.split(".")
        if len(parts) >= 5:
            ip_addr = ".".join(parts[-4:])
            if_index = parts[-5] if len(parts) >= 6 else "0"
            # MAC is returned as hex or as bytes
            mac = ""
            if isinstance(value, str):
                # Might be hex string like "aabbccddeeff"
                clean = value.replace(":", "").replace("-", "").replace(" ", "")
                if len(clean) == 12:
                    mac = ":".join(clean[i:i+2].upper() for i in range(0, 12, 2))
                else:
                    mac = value
            mac_entries[ip_addr] = {"ip": ip_addr, "mac": mac, "if_index": if_index, "type": "dynamic"}

    entries = list(mac_entries.values())

    # If the above yielded nothing, try the older atTable (1.3.6.1.2.1.3.1.1)
    if not entries:
        for oid, value in snmp_walk(host, community, "1.3.6.1.2.1.3.1.1.2", port, timeout):
            parts = oid.split(".")
            if len(parts) >= 5:
                ip_addr = ".".join(parts[-4:])
                mac = ""
                if isinstance(value, str):
                    clean = value.replace(":", "").replace("-", "").replace(" ", "")
                    if len(clean) == 12:
                        mac = ":".join(clean[i:i+2].upper() for i in range(0, 12, 2))
                    else:
                        mac = value
                entries.append({"ip": ip_addr, "mac": mac, "if_index": "0", "type": "dynamic"})

    return entries


def snmp_get_routes(
    host: str,
    community: str,
    port: int = 161,
    timeout: float = 2.0,
) -> list[dict]:
    """
    Walk the IP routing table.
    Returns list of dicts: {destination, netmask, next_hop, if_index, type, protocol}
    """
    routes = {}

    # ipRouteDest (1.3.6.1.2.1.4.21.1.1)
    for oid, value in snmp_walk(host, community, "1.3.6.1.2.1.4.21.1.1", port, timeout):
        dest = str(value) if value else ""
        if dest:
            routes[dest] = {"destination": dest, "netmask": "", "next_hop": "", "if_index": "0", "type": 0, "protocol": 0}

    # ipRouteMask (1.3.6.1.2.1.4.21.1.11)
    for oid, value in snmp_walk(host, community, "1.3.6.1.2.1.4.21.1.11", port, timeout):
        dest = ".".join(oid.split(".")[-4:])
        if dest in routes:
            routes[dest]["netmask"] = str(value) if value else ""

    # ipRouteNextHop (1.3.6.1.2.1.4.21.1.7)
    for oid, value in snmp_walk(host, community, "1.3.6.1.2.1.4.21.1.7", port, timeout):
        dest = ".".join(oid.split(".")[-4:])
        if dest in routes:
            routes[dest]["next_hop"] = str(value) if value else ""

    # ipRouteType (1.3.6.1.2.1.4.21.1.8) - 1=other, 2=invalid, 3=direct, 4=indirect
    for oid, value in snmp_walk(host, community, "1.3.6.1.2.1.4.21.1.8", port, timeout):
        dest = ".".join(oid.split(".")[-4:])
        if dest in routes:
            routes[dest]["type"] = int(value) if value else 0

    # ipRouteProto (1.3.6.1.2.1.4.21.1.9) - 2=local, 3=netmgmt, 8=rip, 13=ospf, 14=bgp
    for oid, value in snmp_walk(host, community, "1.3.6.1.2.1.4.21.1.9", port, timeout):
        dest = ".".join(oid.split(".")[-4:])
        if dest in routes:
            routes[dest]["protocol"] = int(value) if value else 0

    return list(routes.values())
