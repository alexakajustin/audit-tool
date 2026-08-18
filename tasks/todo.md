# Implementation Tasks: DPAPI Vault Decryptor & Credential Manager

- [x] Create `core/dpapi_vault.py` (DPAPI key derivation from user password & credential file decryptor) <!-- id: 1 -->
- [x] Implement `/api/discovery/unlock-vault` endpoint in `api/discovery_routes.py` <!-- id: 2 -->
- [x] Auto-merge decrypted credentials into `/api/discovery/smb_session_info` <!-- id: 3 -->
- [x] Auto-resolve matching decrypted credentials in `smb_listdir` and `scanners/smb_auditor.py` <!-- id: 4 -->
- [x] Add "This machine password" unlock input & button to SMB tab (`static/js/components/smb.js`) <!-- id: 5 -->
- [x] Add `API.unlockVault(password)` to API client (`static/js/utils/api.js`) <!-- id: 6 -->
- [x] Verify module imports and endpoints <!-- id: 7 -->
