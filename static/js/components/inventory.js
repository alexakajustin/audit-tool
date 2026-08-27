/**
 * Inventory Component - device inventory with search, sort, filter, and export.
 */
const InventoryPage = {
    _currentSort: { by: 'last_seen', order: 'desc' },
    _searchDebounce: null,
    _pollInterval: null,
    _interfaces: [],
    _scanners: [],
    _selectedScanners: new Set(),

    title: 'Discovery & Inventory',
    subtitle: 'Scan, discover, and manage network devices',

    async render(container) {
        container.innerHTML = `
            <div class="fade-in">
                <!-- Passive Discovery Banner -->
                <div class="card passive-discovery-card" style="margin-bottom:20px">
                    <div class="card-header">
                        <span class="card-title" style="display:flex;align-items:center;gap:8px">
                            <span class="pd-live-dot" id="disc-pd-dot"></span>
                            Passive Discovery (Background)
                        </span>
                        <div style="display:flex;gap:8px;align-items:center">
                            <span id="disc-pd-count" style="color:var(--cyan);font-size:0.85rem;font-weight:600">0 devices</span>
                            <button id="btn-disc-pd-toggle" class="btn btn-sm btn-success" onclick="InventoryPage.togglePassiveDiscovery()">Start</button>
                        </div>
                    </div>
                    <p style="color:var(--text-muted);font-size:0.82rem;margin-top:8px;line-height:1.5">
                        Listens to broadcast traffic (ARP, DHCP, mDNS, LLMNR, NetBIOS, SSDP) to discover
                        devices on the network <strong>without sending any packets</strong>. Runs automatically in the background.
                    </p>
                    <div id="disc-pd-protos" style="display:flex;gap:6px;flex-wrap:wrap;margin-top:10px"></div>
                </div>

                <!-- Active Scan Configuration -->
                <div class="card" style="margin-bottom:20px">
                    <div class="card-header" style="cursor:pointer" onclick="document.getElementById('active-scan-body').classList.toggle('hidden')">
                        <span class="card-title">Active Scan Configuration</span>
                        <span style="font-size:0.8rem;color:var(--text-muted)">(Click to expand/collapse)</span>
                    </div>

                    <div id="active-scan-body" class="hidden">
                        <div class="scan-config" style="margin-top:15px">
                            <div class="form-group">
                                <label class="form-label">Network Interface</label>
                                <select id="disc-interface" class="form-control">
                                    <option value="">Loading interfaces...</option>
                                </select>
                            </div>

                            <div class="form-group scan-config-full">
                                <label class="form-label">Scanners</label>
                                <div id="disc-scanners" class="scanner-chips">
                                    <span style="color:var(--text-muted)">Loading...</span>
                                </div>
                            </div>

                            <div class="form-group">
                                <label class="form-label">Scan Type (Nmap)</label>
                                <select id="disc-scan-type" class="form-control" onchange="InventoryPage.updatePortsInput()">
                                    <option value="discovery">Host Discovery (fast)</option>
                                    <option value="ports">Port Scan (top 100)</option>
                                    <option value="full">Full Scan (ports + services)</option>
                                </select>
                            </div>

                            <div class="form-group">
                                <label class="form-label">Custom Ports (TCP)</label>
                                <input type="text" id="disc-custom-ports" class="form-control" />
                                <div style="font-size:0.7rem;color:var(--text-muted);margin-top:4px">Editable. Shows the default ports for the selected profile.</div>
                            </div>

                            <div class="form-group" style="display:flex;flex-direction:column;gap:10px;justify-content:flex-end">
                                <label class="checkbox-group">
                                    <input type="checkbox" id="disc-skip-ping" />
                                    <span class="form-label" style="margin:0;text-transform:none;letter-spacing:0">Skip ping (for stealth hosts)</span>
                                </label>
                                <label class="checkbox-group">
                                    <input type="checkbox" id="disc-os-detect" />
                                    <span class="form-label" style="margin:0;text-transform:none;letter-spacing:0">OS detection (requires admin)</span>
                                </label>
                            </div>
                        </div>

                        <div style="display:flex;gap:10px;margin-top:15px">
                            <button id="btn-start-scan" class="btn btn-primary" onclick="InventoryPage.startScan()">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                                Start Scan
                            </button>
                            <button id="btn-scan-ports" class="btn btn-secondary" onclick="InventoryPage.scanAllPorts()" title="Rapidly scan ports on all discovered hosts">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                                Scan Open Ports
                            </button>
                            <button id="btn-stop-scan" class="btn btn-danger" onclick="InventoryPage.stopScan()" style="display:none">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="6" width="12" height="12"/></svg>
                                Stop Scan
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Scan Status -->
                <div id="scan-status-bar" class="scan-status-bar" style="display:none;margin-bottom:20px">
                    <span class="scan-status-label">Status</span>
                    <span class="scan-status-value" id="scan-state">Idle</span>
                    <div class="progress-bar">
                        <div class="progress-fill" id="scan-progress" style="width:0%"></div>
                    </div>
                    <span class="scan-status-label">Devices</span>
                    <span class="scan-status-value" id="scan-device-count">0</span>
                </div>

                <!-- Toolbar -->
                <div style="display:flex;gap:10px;margin-bottom:16px;align-items:center;flex-wrap:wrap">
                    <input type="text" id="inv-search" class="form-control"
                           placeholder="Search by IP, MAC, vendor, hostname, OS..."
                           style="max-width:400px" oninput="InventoryPage._onSearch()" />

                    <select id="inv-status-filter" class="form-control" style="max-width:160px"
                            onchange="InventoryPage._reload()">
                        <option value="">All Statuses</option>
                        <option value="online">Online</option>
                        <option value="offline">Offline</option>
                        <option value="unknown">Unknown</option>
                    </select>

                    <div style="flex:1"></div>

                    <button class="btn btn-sm" onclick="InventoryPage.exportCSV()">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                            <polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                        </svg>
                        Export CSV
                    </button>
                    <button class="btn btn-sm" onclick="InventoryPage.exportJSON()">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                            <polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                        </svg>
                        Export JSON
                    </button>
                    <button class="btn btn-danger btn-sm" onclick="InventoryPage.clearAll()">
                        Clear All
                    </button>
                </div>

                <!-- Device Count -->
                <div style="margin-bottom:12px;color:var(--text-muted);font-size:0.8rem">
                    <span id="inv-count">0 devices</span>
                </div>

                <!-- Table -->
                <div id="inventory-table-wrap">
                    <div class="loading-overlay"><div class="spinner"></div></div>
                </div>
            </div>
        `;

        await this._loadInterfaces();
        await this._loadScanners();
        await this._checkExistingScan();
        this._startPDPolling();
        await this._reload();
        this.updatePortsInput();
    },

    destroy() {
        if (this._searchDebounce) clearTimeout(this._searchDebounce);
        if (this._pollInterval) {
            clearInterval(this._pollInterval);
            this._pollInterval = null;
        }
    },

    _onSearch() {
        if (this._searchDebounce) clearTimeout(this._searchDebounce);
        this._searchDebounce = setTimeout(() => this._reload(), 300);
    },

    async _reload() {
        const search = document.getElementById('inv-search')?.value || '';
        const status = document.getElementById('inv-status-filter')?.value || '';

        try {
            const data = await API.getInventory({
                search,
                status,
                sort_by: this._currentSort.by,
                sort_order: this._currentSort.order,
            });

            document.getElementById('inv-count').textContent =
                `${data.total} device${data.total !== 1 ? 's' : ''}`;

            this._renderTable(data.devices);
        } catch (e) {
            App.toast('Failed to load inventory: ' + e.message, 'error');
        }
    },

    _renderTable(devices) {
        const container = document.getElementById('inventory-table-wrap');

        if (devices.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                        <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                    </svg>
                    <p>No devices in inventory. Run a discovery scan first.</p>
                </div>
            `;
            return;
        }

        const sortArrow = (field) => {
            if (this._currentSort.by !== field) return '';
            return `<span class="sort-arrow">${this._currentSort.order === 'asc' ? '▲' : '▼'}</span>`;
        };

        const sorted = (field) => this._currentSort.by === field ? 'sorted' : '';

        container.innerHTML = `
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th class="${sorted('status')}" onclick="InventoryPage._sort('status')">Status${sortArrow('status')}</th>
                            <th class="${sorted('ip')}" onclick="InventoryPage._sort('ip')">IP Address${sortArrow('ip')}</th>
                            <th class="${sorted('mac')}" onclick="InventoryPage._sort('mac')">MAC Address${sortArrow('mac')}</th>
                            <th class="${sorted('vendor')}" onclick="InventoryPage._sort('vendor')">Vendor${sortArrow('vendor')}</th>
                            <th class="${sorted('hostname')}" onclick="InventoryPage._sort('hostname')">Hostname${sortArrow('hostname')}</th>
                            <th class="${sorted('os')}" onclick="InventoryPage._sort('os')">OS${sortArrow('os')}</th>
                            <th>Ports</th>
                            <th class="${sorted('last_seen')}" onclick="InventoryPage._sort('last_seen')">Last Seen${sortArrow('last_seen')}</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${devices.map(d => `
                            <tr>
                                <td><span class="badge badge-${d.status}">${d.status}</span></td>
                                <td class="mono" style="color:var(--cyan)">${d.ip || '-'}</td>
                                <td class="mono">${d.mac}</td>
                                <td>${d.vendor || '-'}</td>
                                <td>${d.hostname || '-'}</td>
                                <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis" title="${d.os || ''}">${d.os || '-'}</td>
                                <td>
                                    ${d.ports.length > 0
                ? d.ports.slice(0, 5).map(p =>
                    `<span class="badge badge-scanner" style="margin:1px">${p.port}</span>`
                ).join('') + (d.ports.length > 5 ? `<span style="color:var(--text-muted)">+${d.ports.length - 5}</span>` : '')
                : '-'}
                                    ${(() => {
                try {
                    const n = JSON.parse(d.notes);
                    if (n.smb_audit) {
                        const accessible = n.smb_audit.details.filter(x => x.accessible).length;
                        return `<div style="margin-top:4px;font-size:0.75rem;color:var(--purple)"><b>SMB:</b> ${n.smb_audit.shares_found} shares (${accessible} readable)</div>`;
                    }
                } catch (e) { }
                return '';
            })()}
                                </td>
                                <td style="color:var(--text-muted);font-size:0.78rem">${this._formatTime(d.last_seen)}</td>
                                <td>
                                    <button class="btn btn-sm btn-danger" onclick="InventoryPage.deleteDevice('${d.id}')" title="Remove">
                                        ✕
                                    </button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    },

    _sort(field) {
        if (this._currentSort.by === field) {
            this._currentSort.order = this._currentSort.order === 'asc' ? 'desc' : 'asc';
        } else {
            this._currentSort.by = field;
            this._currentSort.order = 'asc';
        }
        this._reload();
    },

    async deleteDevice(id) {
        try {
            await API.deleteDevice(id);
            App.toast('Device removed', 'info');
            this._reload();
        } catch (e) {
            App.toast('Failed to delete: ' + e.message, 'error');
        }
    },

    async clearAll() {
        if (!confirm('Remove all devices from inventory?')) return;
        try {
            await API.clearInventory();
            App.toast('Inventory cleared', 'info');
            this._reload();
        } catch (e) {
            App.toast('Failed to clear: ' + e.message, 'error');
        }
    },

    exportCSV() {
        window.open('/api/inventory/export/csv', '_blank');
    },

    exportJSON() {
        window.open('/api/inventory/export/json', '_blank');
    },

    _formatTime(ts) {
        if (!ts) return '-';
        const d = new Date(ts * 1000);
        return d.toLocaleString();
    },

    // ── Discovery Logic Ported Over ──

    async togglePassiveDiscovery() {
        try {
            const status = await API.getPassiveDiscoveryStatus();
            if (status.is_running) {
                await API.stopPassiveDiscovery();
                App.toast('Passive Discovery stopped', 'info');
            } else {
                await API.startPassiveDiscovery();
                App.toast('Passive Discovery started', 'success');
            }
            await this._updatePDStatus();
        } catch (e) {
            App.toast('Failed: ' + e.message, 'error');
        }
    },

    _startPDPolling() {
        if (!this._pollInterval) {
            this._pollInterval = setInterval(() => this._updatePDStatus(), 3000);
        }
        this._updatePDStatus();
    },

    async _updatePDStatus() {
        try {
            const pd = await API.getPassiveDiscoveryStatus();
            const dot = document.getElementById('disc-pd-dot');
            const countEl = document.getElementById('disc-pd-count');
            const btn = document.getElementById('btn-disc-pd-toggle');
            const protosEl = document.getElementById('disc-pd-protos');

            if (dot) {
                dot.style.background = pd.is_running ? 'var(--green)' : 'var(--text-muted)';
                dot.style.boxShadow = pd.is_running ? '0 0 8px var(--green)' : 'none';
            }
            if (countEl) countEl.textContent = `${pd.devices_found || 0} devices`;
            if (btn) {
                btn.textContent = pd.is_running ? 'Stop' : 'Start';
                btn.className = pd.is_running ? 'btn btn-sm btn-danger' : 'btn btn-sm btn-success';
            }

            if (protosEl && pd.protocol_hits) {
                const entries = Object.entries(pd.protocol_hits).sort((a, b) => b[1] - a[1]);
                const colorMap = {
                    ARP: '#00f0ff', DHCP: '#00ff88', mDNS: '#a55eea',
                    LLMNR: '#00b8c5', NetBIOS: '#ffd32a', SSDP: '#ff9f43', DNS: '#a55eea',
                };
                protosEl.innerHTML = entries.map(([proto, count]) =>
                    `<span class="badge badge-protocol" style="background:${colorMap[proto] || 'rgba(255,255,255,0.06)'};color:${colorMap[proto] ? '#0a0e1a' : 'var(--text-muted)'};font-weight:600">${proto}: ${count}</span>`
                ).join('');
            }

            if (pd.devices_found > 0) {
                await this._reload();
            }
        } catch (e) { /* ignore */ }
    },

    async _loadInterfaces() {
        try {
            const data = await API.getInterfaces();
            const select = document.getElementById('disc-interface');
            if (select) {
                select.innerHTML = data.interfaces.map(iface => {
                    const ipText = iface.ip ? `${iface.ip} (${iface.subnet})` : 'Unconnected (e.g. Wi-Fi AP Scan)';
                    return `<option value="${iface.name}" ${data.recommended && iface.name === data.recommended.name ? 'selected' : ''}>
                        ${iface.name} - ${ipText}
                    </option>`;
                }).join('');
            }
            this._interfaces = data.interfaces;
        } catch (e) {
            App.toast('Failed to load interfaces: ' + e.message, 'error');
        }
    },

    async _loadScanners() {
        try {
            const data = await API.getScanners();
            this._scanners = data.scanners;

            this._selectedScanners.clear();
            data.scanners.forEach(s => {
                if (s.available && s.name !== 'arp_cache') {
                    this._selectedScanners.add(s.name);
                }
            });

            const container = document.getElementById('disc-scanners');
            if (container) {
                container.innerHTML = data.scanners.map(s => {
                    const isSelected = this._selectedScanners.has(s.name);
                    const classStr = s.available
                        ? (isSelected ? 'scanner-chip selected' : 'scanner-chip')
                        : 'scanner-chip unavailable';
                    return `
                        <div class="${classStr}"
                             data-scanner="${s.name}"
                             onclick="InventoryPage.toggleScanner('${s.name}', ${s.available})">
                            <span class="chip-dot"></span>
                            ${s.display_name}
                            ${s.capabilities.requires_admin ? '<span style="font-size:0.65rem;opacity:0.5">ADMIN</span>' : ''}
                        </div>
                    `;
                }).join('');
            }
        } catch (e) {
            App.toast('Failed to load scanners: ' + e.message, 'error');
        }
    },

    toggleScanner(name, available) {
        if (!available) return;
        if (this._selectedScanners.has(name)) {
            this._selectedScanners.delete(name);
        } else {
            this._selectedScanners.add(name);
        }
        const chip = document.querySelector(`[data-scanner="${name}"]`);
        if (chip) chip.classList.toggle('selected');
    },

    updatePortsInput() {
        const typeSelect = document.getElementById('disc-scan-type');
        const portsInput = document.getElementById('disc-custom-ports');
        if (!typeSelect || !portsInput) return;

        const val = typeSelect.value;
        const top25 = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5000,5432,5900,6379,8000,8080,8443,8888";
        const top100 = "21,22,23,25,53,80,110,135,139,143,443,445,554,993,995,1433,1521,1723,1883,1900,2049,3000,3306,3389,5000,5357,5432,5900,6379,7547,8000,8008,8080,8081,8443,8888,9000,9090,9100,27017";
        const full = "1-65535 (or specify full list)";

        if (val === 'discovery') {
            portsInput.value = top25;
        } else if (val === 'ports') {
            portsInput.value = top100;
        } else if (val === 'full') {
            portsInput.value = top100; // Same base, but implies more aggressive Nmap profiling
        }
    },

    async startScan() {
        if (this._selectedScanners.size === 0) {
            App.toast('Please select at least one scanner', 'warning');
            return;
        }
        
        const portsInput = document.getElementById('disc-custom-ports');
        const customPorts = portsInput ? portsInput.value.trim() : "";

        const config = {
            subnet: "", 
            interface: document.getElementById('disc-interface').value,
            scanners: [...this._selectedScanners],
            options: {
                scan_type: document.getElementById('disc-scan-type').value,
                skip_ping: document.getElementById('disc-skip-ping').checked,
                os_detection: document.getElementById('disc-os-detect').checked,
                custom_ports: customPorts || undefined,
            },
        };

        try {
            await API.startScan(config);
            App.toast('Scan started', 'success');
            this._showScanRunning(true);
            this._startPolling();
        } catch (e) {
            App.toast('Failed to start scan: ' + e.message, 'error');
        }
    },

    async stopScan() {
        try {
            await API.stopScan();
            App.toast('Scan stopped', 'info');
            this._showScanRunning(false);
            this._stopPolling();
            await this._reload();
        } catch (e) {
            App.toast('Failed to stop scan: ' + e.message, 'error');
        }
    },

    async scanAllPorts() {
        const btn = document.getElementById('btn-scan-ports');
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Scanning...';
        }
        App.toast('Probing open ports on all discovered devices...', 'info');

        const portsInput = document.getElementById('disc-custom-ports');
        const customPorts = portsInput ? portsInput.value.trim() : "";

        try {
            const data = await API.scanPorts({ profile: 'fast', ports: customPorts });
            App.toast(`Port scan complete! Discovered services on ${data.devices_with_open_ports} device(s)`, 'success');
            await this._reload();
        } catch (e) {
            App.toast('Failed to scan ports: ' + e.message, 'error');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg> Scan Open Ports';
            }
        }
    },

    async _checkExistingScan() {
        try {
            const status = await API.getScanStatus();
            if (status.state === 'running') {
                this._showScanRunning(true);
                this._startPolling();
            }
        } catch (e) { /* ignore */ }
    },

    _showScanRunning(running) {
        const startBtn = document.getElementById('btn-start-scan');
        const stopBtn = document.getElementById('btn-stop-scan');
        const statusBar = document.getElementById('scan-status-bar');

        if (startBtn) startBtn.style.display = running ? 'none' : 'inline-flex';
        if (stopBtn) stopBtn.style.display = running ? 'inline-flex' : 'none';
        if (statusBar) statusBar.style.display = running ? 'flex' : 'none';
    },

    _startPolling() {
        this._stopPolling();
        this._pollInterval = setInterval(() => this._pollStatus(), 2000);
    },

    _stopPolling() {
        if (this._pollInterval) {
            clearInterval(this._pollInterval);
            this._pollInterval = null;
        }
    },

    async _pollStatus() {
        try {
            const status = await API.getScanStatus();
            const stateEl = document.getElementById('scan-state');
            const countEl = document.getElementById('scan-device-count');
            const progressEl = document.getElementById('scan-progress');

            if (stateEl) stateEl.textContent = status.state;
            if (countEl) countEl.textContent = status.devices_found || 0;

            if (status.scanners_total && progressEl) {
                const pct = (status.scanners_completed / status.scanners_total) * 100;
                progressEl.style.width = pct + '%';
            }

            await this._reload();

            if (status.state !== 'running') {
                this._showScanRunning(false);
                this._stopPolling();
                if (progressEl) progressEl.style.width = '100%';
                App.toast('Scan complete', 'success');
                this._startPDPolling();
            }
        } catch (e) { /* retry */ }
    }
};
