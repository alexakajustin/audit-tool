"""
Windows DPAPI Vault Decryptor module for NetAudit.

Decodes DPAPI-encrypted credential files from %LOCALAPPDATA%\\Microsoft\\Credentials\\
using the machine/user login password.
"""

import os
import re
import struct
import win32api
import win32security

from impacket.dpapi import (
    MasterKeyFile,
    MasterKey,
    CredentialFile,
    DPAPI_BLOB,
    CREDENTIAL_BLOB,
    deriveKeysFromUser,
)

# In-memory cache for decrypted vault credentials
_UNLOCKED_VAULT_CACHE = {}


def get_current_user_sid() -> str:
    """Get the SID string for the current process token."""
    try:
        tok = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
        sid, _ = win32security.GetTokenInformation(tok, win32security.TokenUser)
        return win32security.ConvertSidToStringSid(sid)
    except Exception:
        return ""


def get_unlocked_cache():
    """Return current decrypted cache."""
    return _UNLOCKED_VAULT_CACHE


def unlock_vault_with_password(password: str, sid: str = None) -> dict:
    """
    Derive keys from user's login password, decrypt master keys,
    and decrypt all stored Windows credential files.
    """
    global _UNLOCKED_VAULT_CACHE

    if not sid:
        sid = get_current_user_sid()
    if not sid:
        return {"success": False, "error": "Unable to retrieve current user SID"}

    try:
        keys = deriveKeysFromUser(sid, password)
    except Exception as e:
        return {"success": False, "error": f"Key derivation failed: {e}"}

    protect_dir = os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Protect', sid)
    if not os.path.isdir(protect_dir):
        return {"success": False, "error": f"Protect directory not found: {protect_dir}"}

    decrypted_master_keys = {}

    # Step 1: Decrypt DPAPI master keys
    try:
        for mk_fname in os.listdir(protect_dir):
            mk_fpath = os.path.join(protect_dir, mk_fname)
            if not os.path.isfile(mk_fpath) or mk_fname.lower() == 'preferred':
                continue

            try:
                with open(mk_fpath, 'rb') as f:
                    mk_data = f.read()

                mkf = MasterKeyFile(mk_data)
                header_size = 128
                master_key_raw = mk_data[header_size:header_size + mkf['MasterKeyLen']]
                mk = MasterKey(master_key_raw)

                for key in keys:
                    decrypted_key = mk.decrypt(key)
                    if decrypted_key:
                        decrypted_master_keys[mk_fname.lower()] = decrypted_key
                        break
            except Exception:
                continue
    except Exception as e:
        return {"success": False, "error": f"Master key scanning failed: {e}"}

    if not decrypted_master_keys:
        return {
            "success": False,
            "error": "Password incorrect or could not decrypt DPAPI master keys.",
            "master_keys_decrypted": 0
        }

    # Step 2: Decrypt Windows credential files
    cred_dir = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Credentials')
    decrypted_credentials = []

    if os.path.isdir(cred_dir):
        for fname in os.listdir(cred_dir):
            fpath = os.path.join(cred_dir, fname)
            if not os.path.isfile(fpath):
                continue

            try:
                with open(fpath, 'rb') as f:
                    cdata = f.read()

                cf = CredentialFile(cdata)
                blob = DPAPI_BLOB(cf['Data'])

                guid_raw = blob['GuidMasterKey']
                p = struct.unpack_from('<IHH', guid_raw, 0)
                guid_str = f"{p[0]:08x}-{p[1]:04x}-{p[2]:04x}-{guid_raw[8:10].hex()}-{guid_raw[10:16].hex()}".lower()

                if guid_str in decrypted_master_keys:
                    mk = decrypted_master_keys[guid_str]
                    decrypted_data = blob.decrypt(mk)

                    if decrypted_data:
                        cred = CREDENTIAL_BLOB(decrypted_data)
                        target = cred['Target'].decode('utf-16le', errors='ignore').rstrip('\x00')
                        username = cred['Username'].decode('utf-16le', errors='ignore').rstrip('\x00')
                        desc = cred['Description'].decode('utf-16le', errors='ignore').rstrip('\x00')

                        pwd_raw = cred['Unknown3']
                        password_val = ""
                        if pwd_raw:
                            try:
                                password_val = pwd_raw.decode('utf-16le', errors='ignore').rstrip('\x00')
                            except Exception:
                                password_val = pwd_raw.hex()

                        # Extract IP if present in target
                        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', target)
                        ip = ip_match.group(0) if ip_match else ""

                        item = {
                            "target": target,
                            "ip": ip,
                            "username": username,
                            "password": password_val,
                            "has_password": bool(password_val),
                            "description": desc,
                            "type": "Domain Password" if cred['Type'] == 2 else "Generic",
                            "file": fname
                        }
                        decrypted_credentials.append(item)
            except Exception:
                continue

    # Update global in-memory cache
    for item in decrypted_credentials:
        if item.get("target"):
            _UNLOCKED_VAULT_CACHE[item["target"]] = item
        if item.get("ip"):
            _UNLOCKED_VAULT_CACHE[item["ip"]] = item

    return {
        "success": True,
        "master_keys_decrypted": len(decrypted_master_keys),
        "credentials_decrypted": len(decrypted_credentials),
        "credentials": decrypted_credentials
    }
