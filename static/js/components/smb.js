/**
 * SMB Audit & Credential Explorer Component
 * Features:
 * - Station Identity & Credential Vault Discovery (Automatic unprivileged session emulation)
 * - Smart Credential Auto-Matching per Target IP
 * - Robust Directory Explorer (Locked/system file resilience)
 * - Permission auditing per share
 */
const SMBPage = {
    _pollInterval: null,
    _devices: [],
    _sessionInfo: null,
    
    // Explorer State
    _ip: '',
    _share: '',
    _path: '', // empty means root of share
    _user: '',
    _pass: '',

    title: 'SMB Share & Credential Audit',
    subtitle: 'Station session emulation, credential discovery, and permission audit',

    async render(container) {
        container.innerHTML = `
            <div class="fade-in" style="display:flex; flex-direction:column; height:calc(100vh - 120px); gap:14px;">
                
                <!-- Station Session & Credential Discovery Banner -->
                <div class="card" id="smb-session-card" style="padding:12px 18px; margin-bottom:0; background:linear-gradient(135deg, rgba(16, 26, 45, 0.95), rgba(24, 38, 64, 0.95)); border:1px solid rgba(0, 240, 255, 0.2);">
                    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
                        <div style="display:flex; align-items:center; gap:12px;">
                            <div style="width:36px; height:36px; border-radius:8px; background:rgba(0, 240, 255, 0.12); display:flex; align-items:center; justify-content:center; color:var(--cyan);">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                            </div>
                            <div>
                                <div style="display:flex; align-items:center; gap:8px;">
                                    <span style="font-size:0.75rem; text-transform:uppercase; letter-spacing:1px; color:var(--text-muted);">Active Workstation Session:</span>
                                    <strong id="station-account" style="color:var(--cyan); font-family:'JetBrains Mono', monospace;">Detecting...</strong>
                                    <span class="badge" style="background:rgba(0, 255, 136, 0.15); color:var(--green); font-size:0.7rem; border:1px solid rgba(0, 255, 136, 0.3);">SSPI / Non-Admin Emulation</span>
                                </div>
                                <div id="station-groups-preview" style="font-size:0.75rem; color:var(--text-muted); margin-top:2px;">
                                    Reading session security context...
                                </div>
                            </div>
                        </div>

                        <!-- Discovered Credentials in Vault -->
                        <div id="station-vault-section" style="display:flex; align-items:center; gap:6px; flex-wrap:wrap;">
                            <!-- Discovered target pills will be injected here -->
                        </div>
                    </div>
                </div>

                <!-- Top Control & Audit Bar -->
                <div class="card" style="padding:10px 18px; display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
                    <div style="display:flex; gap:10px; align-items:center; flex:1;">
                        <input type="text" id="smb-ip-input" class="form-control form-control-sm" placeholder="Target IP (leave empty for all)" style="max-width:190px;">
                        <div style="position:relative; flex:1; max-width:260px;">
                            <input type="text" id="smb-user" class="form-control form-control-sm" placeholder="Username (SSPI session if empty)" oninput="delete this.dataset.autoMatched">
                            <span id="smb-user-badge" style="position:absolute; right:8px; top:50%; transform:translateY(-50%); font-size:0.65rem; color:var(--cyan); pointer-events:none; display:none;">Auto</span>
                        </div>
                        <input type="password" id="smb-pass" class="form-control form-control-sm" placeholder="Password (optional)" style="max-width:160px;">
                    </div>
                    
                    <button id="btn-scan-smb" class="btn btn-primary btn-sm" onclick="SMBPage.scanSMB()" style="background:var(--purple); color:white; border:none; display:flex; align-items:center; gap:6px;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
                        Discover & Audit Shares
                    </button>
                </div>

                <!-- Explorer Split View -->
                <div style="display:flex; flex:1; gap:14px; min-height:0;">
                    
                    <!-- Left Sidebar: Discovered Servers & Permissions -->
                    <div class="card" style="width: 320px; display:flex; flex-direction:column; overflow-y:auto; padding:0;">
                        <div class="card-header" style="position:sticky; top:0; background:var(--bg-dark); z-index:1; border-bottom:1px solid var(--border-color); padding:10px 16px; display:flex; justify-content:space-between; align-items:center;">
                            <span class="card-title" style="font-size:0.85rem;">SMB Servers & Shares</span>
                            <span id="smb-tree-count" style="font-size:0.75rem; color:var(--text-muted);">0 found</span>
                        </div>
                        <div id="smb-tree" style="padding:6px 0;">
                            <div class="empty-state" style="padding:24px 16px; text-align:center;">
                                <div class="spinner spinner-sm"></div>
                            </div>
                        </div>
                    </div>

                    <!-- Right Main Area: File Explorer & Audit Details -->
                    <div class="card" style="flex:1; display:flex; flex-direction:column; padding:0; overflow:hidden;">
                        
                        <!-- Address Bar / Breadcrumbs -->
                        <div style="background: rgba(0,0,0,0.25); border-bottom: 1px solid var(--border-color); padding: 8px 16px; display:flex; align-items:center; gap:8px;">
                            <button class="btn btn-sm" onclick="SMBPage.navigateUp()" style="padding:4px 8px; background:transparent; border:none; color:var(--text-muted);" title="Up one folder">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 19V5M5 12l7-7 7 7"/></svg>
                            </button>
                            <div id="smb-breadcrumbs" style="flex:1; font-family:'JetBrains Mono', monospace; font-size:0.85rem; color:var(--cyan); display:flex; align-items:center; overflow-x:auto; white-space:nowrap; gap:4px;">
                                <span style="color:var(--text-muted)">Select a share to audit and browse</span>
                            </div>
                            <button class="btn btn-sm" onclick="SMBPage.refreshCurrent()" style="padding:4px 8px; background:transparent; border:none; color:var(--text-muted);" title="Refresh">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
                            </button>
                        </div>

                        <!-- Content Pane -->
                        <div id="smb-explorer-content" style="flex:1; overflow-y:auto; padding:16px; background: var(--bg-darker);">
                            <div class="empty-state" style="height:100%; display:flex; flex-direction:column; justify-content:center; align-items:center;">
                                <svg viewBox="0 0 24 24" fill="none" stroke="var(--border-color)" stroke-width="1" width="48" height="48" style="margin-bottom:12px;">
                                    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
                                </svg>
                                <p style="color:var(--text-muted); font-size:0.9rem;">Select a share from the left to browse files or test access</p>
                            </div>
                        </div>
                        
                        <!-- Status Bar -->
                        <div id="smb-status-bar" style="border-top: 1px solid var(--border-color); padding: 5px 16px; font-size: 0.75rem; color: var(--text-muted); display:flex; justify-content:space-between; align-items:center;">
                            <span id="smb-item-count">Ready</span>
                            <span id="smb-auth-indicator" style="font-family:'JetBrains Mono', monospace;">Auth: Active Station Session</span>
                        </div>
                    </div>

                </div>
            </div>
        `;

        await this._loadSessionInfo();
        await this._loadNetworkTree();
    },

    destroy() {
        if (this._pollInterval) {
            clearInterval(this._pollInterval);
            this._pollInterval = null;
        }
    },

    _updateCreds() {
        this._user = document.getElementById('smb-user')?.value || '';
        this._pass = document.getElementById('smb-pass')?.value || '';
        const authInd = document.getElementById('smb-auth-indicator');
        const badge = document.getElementById('smb-user-badge');
        const userInput = document.getElementById('smb-user');

        if (badge) {
            badge.style.display = (userInput && userInput.dataset.autoMatched === 'true') ? 'inline-block' : 'none';
        }

        if (authInd) {
            authInd.textContent = this._user 
                ? `Auth: ${this._user} ${userInput?.dataset.autoMatched === 'true' ? '(Vault Auto-Matched)' : ''}` 
                : `Auth: Active Session (${this._sessionInfo?.full_account || 'SSPI'})`;
        }
    },

    async _loadSessionInfo() {
        try {
            const data = await API.getSMBSessionInfo();
            this._sessionInfo = data;

            // Update session identity banner
            const accountEl = document.getElementById('station-account');
            const groupsEl = document.getElementById('station-groups-preview');
            const vaultEl = document.getElementById('station-vault-section');

            if (accountEl) accountEl.textContent = data.full_account || `${data.domain}\\${data.username}`;
            if (groupsEl && data.groups) {
                const grpSample = data.groups.slice(0, 3).join(', ');
                groupsEl.textContent = `Groups (${data.groups.length}): ${grpSample}${data.groups.length > 3 ? '...' : ''}`;
            }

            // Render discovered vault targets
            if (vaultEl && data.vault_targets && data.vault_targets.length > 0) {
                let vHtml = '<span style="font-size:0.75rem; color:var(--text-muted); margin-right:4px;">Discovered Vault Accounts:</span>';
                data.vault_targets.slice(0, 6).forEach(v => {
                    const label = v.ip ? `${v.ip} (${v.username || 'Saved'})` : (v.username || v.target);
                    vHtml += `
                        <button class="btn btn-sm" onclick="SMBPage.useVaultTarget('${v.ip}', '${v.username}')"
                                style="font-size:0.7rem; padding:2px 8px; background:rgba(0, 240, 255, 0.08); border:1px solid rgba(0, 240, 255, 0.25); color:var(--cyan); border-radius:12px; cursor:pointer;"
                                title="Click to use target: ${v.target}">
                            🔑 ${label}
                        </button>
                    `;
                });
                vaultEl.innerHTML = vHtml;
            }
        } catch (e) {
            console.error('Failed to load session info:', e);
        }
    },

    useVaultTarget(ip, username) {
        if (ip) {
            const ipInput = document.getElementById('smb-ip-input');
            if (ipInput) ipInput.value = ip;
            this._ip = ip;
        }
        if (username) {
            const userInput = document.getElementById('smb-user');
            if (userInput) {
                userInput.value = username;
                userInput.dataset.autoMatched = 'true';
            }
            this._user = username;
        }
        this._updateCreds();
        App.toast(`Selected target: ${ip || username}`, 'info');
        if (ip) {
            this._loadDirectoryForHost(ip);
        }
    },

    async scanSMB() {
        const btn = document.getElementById('btn-scan-smb');
        const ip = document.getElementById('smb-ip-input')?.value || '';
        this._updateCreds();

        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Auditing...';
        }
        App.toast(ip ? `Auditing SMB shares on ${ip}...` : 'Auditing SMB servers on network with station session...', 'info');

        try {
            const data = await API.scanSMB({ ip, username: this._user, password: this._pass });
            App.toast(`SMB Audit complete! Discovered ${data.devices_with_shares} server(s)`, 'success');
            await this._loadNetworkTree();
        } catch (e) {
            App.toast('Failed: ' + e.message, 'error');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg> Discover & Audit Shares';
            }
        }
    },

    async _loadNetworkTree() {
        try {
            const data = await API.getInventory({ sort_by: 'ip', sort_order: 'asc' });
            
            // Extract devices that have SMB notes
            this._devices = data.devices.filter(d => {
                if (!d.notes) return false;
                try {
                    const n = JSON.parse(d.notes);
                    return !!n.smb_audit;
                } catch(e) {
                    return false;
                }
            });

            this._renderNetworkTree();
        } catch (e) {
            document.getElementById('smb-tree').innerHTML = '<div style="padding:16px;color:var(--red);">Failed to load server tree.</div>';
        }
    },

    _renderNetworkTree() {
        const treeEl = document.getElementById('smb-tree');
        const countEl = document.getElementById('smb-tree-count');
        
        if (countEl) countEl.textContent = `${this._devices.length} server${this._devices.length !== 1 ? 's' : ''}`;

        if (this._devices.length === 0) {
            treeEl.innerHTML = `
                <div class="empty-state" style="padding:24px 16px; text-align:center;">
                    <p style="font-size:0.8rem; color:var(--text-muted);">No SMB servers audited yet.<br>Click "Discover & Audit Shares" above.</p>
                </div>
            `;
            return;
        }

        let html = '<div class="smb-tree-list" style="display:flex; flex-direction:column; gap:4px;">';
        
        this._devices.forEach(d => {
            try {
                const n = JSON.parse(d.notes);
                const shares = n.smb_audit.details || [];
                const label = d.hostname ? `${d.hostname} (${d.ip})` : d.ip;
                
                // Server Node
                html += `
                    <div class="smb-tree-node" style="border-bottom:1px solid rgba(255,255,255,0.04); padding-bottom:4px;">
                        <div class="smb-tree-item" style="padding:6px 14px; display:flex; align-items:center; gap:8px; font-weight:600; font-size:0.82rem; color:var(--text-color);">
                            <svg viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" stroke-width="2" width="15" height="15"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                            ${label}
                        </div>
                        <div class="smb-tree-children" style="display:flex; flex-direction:column;">
                `;

                // Share Nodes
                shares.forEach(share => {
                    const isSelected = (this._ip === d.ip && this._share === share.name);
                    const bg = isSelected ? 'rgba(0, 240, 255, 0.12)' : 'transparent';
                    const isAcc = share.accessible;
                    const badgeColor = isAcc ? 'var(--green)' : 'var(--text-muted)';
                    const badgeBg = isAcc ? 'rgba(0, 255, 136, 0.15)' : 'rgba(255, 255, 255, 0.05)';
                    const badgeText = isAcc ? 'READ' : (share.is_admin_share ? 'DENIED (ADMIN$)' : 'DENIED');
                    
                    html += `
                        <div class="smb-tree-item share-item" 
                             onclick="SMBPage.openShare('${d.ip}', '${share.name.replace(/\\/g, '\\\\')}')"
                             style="padding:5px 14px 5px 32px; display:flex; align-items:center; justify-content:space-between; cursor:pointer; background:${bg}; border-radius:4px; margin:1px 6px;">
                            <div style="display:flex; align-items:center; gap:8px; overflow:hidden;">
                                <svg viewBox="0 0 24 24" fill="${isAcc ? 'rgba(0, 255, 136, 0.2)' : 'none'}" stroke="${isAcc ? 'var(--green)' : 'var(--text-muted)'}" stroke-width="1.7" width="14" height="14">
                                    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
                                </svg>
                                <span style="font-size:0.8rem; font-family:'JetBrains Mono', monospace; color:${isAcc ? 'var(--text-color)' : 'var(--text-muted)'}">${share.name}</span>
                            </div>
                            <span class="badge" style="font-size:0.6rem; padding:1px 5px; background:${badgeBg}; color:${badgeColor};">${badgeText}</span>
                        </div>
                    `;
                });

                html += `</div></div>`;
            } catch(e) {}
        });

        html += '</div>';
        treeEl.innerHTML = html;
    },

    _loadDirectoryForHost(ip) {
        const d = this._devices.find(dev => dev.ip === ip);
        if (d) {
            try {
                const n = JSON.parse(d.notes);
                const firstShare = n.smb_audit?.details?.[0]?.name;
                if (firstShare) {
                    this.openShare(ip, firstShare);
                }
            } catch(e) {}
        }
    },

    openShare(ip, share) {
        this._ip = ip;
        this._share = share;
        this._path = '';
        
        // Smart auto-matching: if username field is empty or was auto-matched, check discovered vault targets
        const ipInput = document.getElementById('smb-ip-input');
        if (ipInput) ipInput.value = ip;
        
        const matchingVault = this._sessionInfo?.vault_targets?.find(v => v.ip === ip || (v.target && v.target.includes(ip)));
        const userInput = document.getElementById('smb-user');
        
        if (matchingVault && matchingVault.username) {
            if (userInput && (!userInput.value || userInput.dataset.autoMatched === 'true')) {
                userInput.value = matchingVault.username;
                userInput.dataset.autoMatched = 'true';
                this._user = matchingVault.username;
            }
        } else {
            if (userInput && userInput.dataset.autoMatched === 'true') {
                userInput.value = '';
                delete userInput.dataset.autoMatched;
                this._user = '';
            }
        }

        this._updateCreds();
        this._renderNetworkTree(); // Update highlight
        this.loadDirectory();
    },

    openFolder(folderName) {
        if (this._path) {
            this._path += '\\' + folderName;
        } else {
            this._path = folderName;
        }
        this.loadDirectory();
    },

    navigateUp() {
        if (!this._path) return;
        const parts = this._path.split('\\');
        parts.pop();
        this._path = parts.join('\\');
        this.loadDirectory();
    },
    
    navigateToCrumb(index) {
        if (index === -1) {
            this._path = '';
        } else {
            const parts = this._path.split('\\');
            this._path = parts.slice(0, index + 1).join('\\');
        }
        this.loadDirectory();
    },

    refreshCurrent() {
        if (this._ip && this._share) {
            this.loadDirectory();
        }
    },

    async loadDirectory() {
        this._updateCreds();
        const contentEl = document.getElementById('smb-explorer-content');
        const countEl = document.getElementById('smb-item-count');
        const crumbEl = document.getElementById('smb-breadcrumbs');

        // Render Breadcrumbs cleanly (\\ip\share\path)
        this._renderBreadcrumbs(crumbEl);

        contentEl.innerHTML = `
            <div style="height:100%; display:flex; justify-content:center; align-items:center;">
                <div class="spinner"></div>
            </div>
        `;
        countEl.textContent = 'Querying share...';

        try {
            const data = await API.listSMBDirectory({
                ip: this._ip,
                share: this._share,
                path: this._path,
                username: this._user,
                password: this._pass
            });

            this._renderDirectoryItems(contentEl, data.items);
            countEl.textContent = `${data.items.length} item${data.items.length !== 1 ? 's' : ''}`;
            
        } catch (e) {
            const activeAcc = this._user || this._sessionInfo?.full_account || 'Active Station Session';
            
            // Check if there is a discovered vault target for this IP
            const matchingVault = this._sessionInfo?.vault_targets?.find(v => v.ip === this._ip || v.target.includes(this._ip));
            const vaultHint = matchingVault 
                ? `<div style="margin-top:12px; padding:10px; background:rgba(0, 240, 255, 0.08); border-radius:6px; border:1px solid rgba(0, 240, 255, 0.2);">
                    <div style="font-size:0.8rem; color:var(--cyan); margin-bottom:6px;">💡 Discovered Credential in Station Vault: <strong>${matchingVault.username || matchingVault.target}</strong></div>
                    <button class="btn btn-sm btn-primary" onclick="SMBPage.useVaultTarget('${matchingVault.ip || this._ip}', '${matchingVault.username}')" style="font-size:0.75rem; padding:3px 10px;">
                        Authenticate as ${matchingVault.username}
                    </button>
                   </div>`
                : '';

            contentEl.innerHTML = `
                <div class="empty-state" style="height:100%; display:flex; flex-direction:column; justify-content:center; align-items:center; max-width:550px; margin:0 auto;">
                    <div style="width:48px; height:48px; border-radius:50%; background:rgba(255, 71, 87, 0.12); display:flex; align-items:center; justify-content:center; color:var(--red); margin-bottom:12px;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="24" height="24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    </div>
                    <h4 style="color:var(--red); margin-bottom:6px;">Security Audit: Access Denied</h4>
                    <p style="font-size:0.85rem; color:var(--text-muted); text-align:center; line-height:1.5;">
                        Station identity <strong style="color:var(--text-color);">${activeAcc}</strong> does not have permission to read <span class="mono" style="color:var(--cyan);">\\\\${this._ip}\\${this._share}</span>.
                    </p>
                    <div style="margin-top:8px; padding:8px 12px; background:rgba(0,0,0,0.3); border-radius:4px; font-family:'JetBrains Mono', monospace; font-size:0.75rem; color:var(--text-muted); text-align:left; width:100%;">
                        ${e.message}
                    </div>
                    ${vaultHint}
                </div>
            `;
            countEl.textContent = 'Access Denied';
        }
    },

    _renderBreadcrumbs(container) {
        let html = `
            <span style="cursor:pointer;" onclick="SMBPage.navigateToCrumb(-1)">
                \\\\${this._ip}\\${this._share}
            </span>
        `;

        if (this._path) {
            const parts = this._path.split('\\');
            parts.forEach((p, i) => {
                html += `
                    <span style="color:var(--text-muted)">\\</span>
                    <span style="cursor:pointer;" onclick="SMBPage.navigateToCrumb(${i})">${p}</span>
                `;
            });
        }
        
        container.innerHTML = html;
    },

    _renderDirectoryItems(container, items) {
        if (items.length === 0) {
            container.innerHTML = `
                <div class="empty-state" style="height:100%; display:flex; flex-direction:column; justify-content:center; align-items:center;">
                    <p style="color:var(--text-muted); font-size:0.85rem;">This folder is empty or contains no readable files.</p>
                </div>
            `;
            return;
        }

        let html = '<div style="display:grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap:10px; align-content:start;">';
        
        items.forEach(item => {
            const icon = item.is_dir 
                ? '<svg viewBox="0 0 24 24" fill="rgba(0, 240, 255, 0.15)" stroke="var(--cyan)" stroke-width="1.5" width="30" height="30"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>'
                : '<svg viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5" width="30" height="30"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>';
            
            const onclick = item.is_dir ? `onclick="SMBPage.openFolder('${item.name.replace(/'/g, "\\'")}')"` : '';
            const cursor = item.is_dir ? 'cursor:pointer;' : 'cursor:default;';
            const sizeStr = item.is_dir ? 'Folder' : this._formatBytes(item.size);

            html += `
                <div class="smb-file-item" ${onclick} style="display:flex; align-items:center; gap:10px; padding:8px 10px; border-radius:6px; background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.05); ${cursor} transition:all 0.15s ease;">
                    ${icon}
                    <div style="display:flex; flex-direction:column; overflow:hidden;">
                        <span style="font-size:0.82rem; font-weight:500; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${item.name}">${item.name}</span>
                        <span style="font-size:0.68rem; color:var(--text-muted);">${sizeStr}</span>
                    </div>
                </div>
            `;
        });

        html += '</div>';

        if (!document.getElementById('smb-styles')) {
            const style = document.createElement('style');
            style.id = 'smb-styles';
            style.innerHTML = `
                .smb-tree-item:hover { background: rgba(255,255,255,0.06) !important; }
                .smb-file-item:hover { background: rgba(0, 240, 255, 0.08) !important; border-color: rgba(0, 240, 255, 0.25) !important; }
            `;
            document.head.appendChild(style);
        }

        container.innerHTML = html;
    },

    _formatBytes(bytes, decimals = 1) {
        if (!+bytes) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
    }
};
