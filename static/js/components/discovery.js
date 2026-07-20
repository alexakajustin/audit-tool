/**
 * Discovery Component — configure and launch network scans.
 * Includes passive discovery status and active scan configuration.
 */
const DiscoveryPage = {
    _pollInterval: null,
    _interfaces: [],
    _scanners: [],
    _selectedScanners: new Set(),

    title: 'Discovery',
    subtitle: 'Scan and discover network devices',

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
                            <button id="btn-disc-pd-toggle" class="btn btn-sm btn-success" onclick="DiscoveryPage.togglePassiveDiscovery()">Start</button>
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
                    <div class="card-header">
                        <span class="card-title">Active Scan Configuration</span>
                    </div>

                    <div class="scan-config">
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
                            <select id="disc-scan-type" class="form-control">
                                <option value="discovery">Host Discovery (fast)</option>
                                <option value="ports">Port Scan (top 100)</option>
                                <option value="full">Full Scan (ports + services)</option>
                            </select>
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

                    <div style="display:flex;gap:10px;margin-top:8px">
                        <button id="btn-start-scan" class="btn btn-primary" onclick="DiscoveryPage.startScan()">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                            Start Scan
                        </button>
                        <button id="btn-stop-scan" class="btn btn-danger" onclick="DiscoveryPage.stopScan()" style="display:none">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="6" width="12" height="12"/></svg>
                            Stop Scan
                        </button>
                    </div>
                </div>

                <!-- Scan Status -->
                <div id="scan-status-bar" class="scan-status-bar" style="display:none">
                    <span class="scan-status-label">Status</span>
                    <span class="scan-status-value" id="scan-state">Idle</span>
                    <div class="progress-bar">
                        <div class="progress-fill" id="scan-progress" style="width:0%"></div>
                    </div>
                    <span class="scan-status-label">Devices</span>
                    <span class="scan-status-value" id="scan-device-count">0</span>
                </div>

                <!-- Results Table -->
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Discovered Devices</span>
                        <span id="disc-result-count" style="color:var(--text-muted);font-size:0.8rem"></span>
                    </div>
                    <div id="discovery-results">
                        <div class="empty-state">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                                <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
                            </svg>
                            <p>No devices discovered yet. Passive discovery is running in the background — devices will appear automatically. You can also run an active scan above.</p>
                        </div>
                    </div>
                </div>
            </div>
        `;

        await this._loadInterfaces();
        await this._loadScanners();
        await this._checkExistingScan();
        this._startPDPolling();
    },

    destroy() {
        if (this._pollInterval) {
            clearInterval(this._pollInterval);
            this._pollInterval = null;
        }
    },

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
        // Poll passive discovery status every 3s (reuse main poll interval)
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

            // Also refresh the results table if passive discovery is finding devices
            if (pd.devices_found > 0) {
                await this._loadResults();
            }
        } catch (e) { /* ignore */ }
    },

    async _loadInterfaces() {
        try {
            const data = await API.getInterfaces();
            const select = document.getElementById('disc-interface');

            select.innerHTML = data.interfaces.map(iface => {
                const ipText = iface.ip ? `${iface.ip} (${iface.subnet})` : 'Unconnected (e.g. Wi-Fi AP Scan)';
                return `<option value="${iface.name}" ${data.recommended && iface.name === data.recommended.name ? 'selected' : ''}>
                    ${iface.name} — ${ipText}
                </option>`;
            }).join('');

            this._interfaces = data.interfaces;
        } catch (e) {
            App.toast('Failed to load interfaces: ' + e.message, 'error');
        }
    },

    async _loadScanners() {
        try {
            const data = await API.getScanners();
            this._scanners = data.scanners;

            // Pre-select available scanners (except ARP Cache scanner by default)
            this._selectedScanners.clear();
            data.scanners.forEach(s => {
                if (s.available && s.name !== 'arp_cache') {
                    this._selectedScanners.add(s.name);
                }
            });

            const container = document.getElementById('disc-scanners');
            container.innerHTML = data.scanners.map(s => {
                const isSelected = this._selectedScanners.has(s.name);
                const classStr = s.available 
                    ? (isSelected ? 'scanner-chip selected' : 'scanner-chip') 
                    : 'scanner-chip unavailable';
                return `
                    <div class="${classStr}"
                         data-scanner="${s.name}"
                         onclick="DiscoveryPage.toggleScanner('${s.name}', ${s.available})">
                        <span class="chip-dot"></span>
                        ${s.display_name}
                        ${s.capabilities.requires_admin ? '<span style="font-size:0.65rem;opacity:0.5">ADMIN</span>' : ''}
                    </div>
                `;
            }).join('');
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

        // Update UI
        const chip = document.querySelector(`[data-scanner="${name}"]`);
        if (chip) chip.classList.toggle('selected');

        // No subnet logic needed
    },

    async startScan() {
        if (this._selectedScanners.size === 0) {
            App.toast('Please select at least one scanner', 'warning');
            return;
        }

        const config = {
            subnet: "", // Let the backend auto-determine the target subnets!
            interface: document.getElementById('disc-interface').value,
            scanners: [...this._selectedScanners],
            options: {
                scan_type: document.getElementById('disc-scan-type').value,
                skip_ping: document.getElementById('disc-skip-ping').checked,
                os_detection: document.getElementById('disc-os-detect').checked,
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
            await this._loadResults();
        } catch (e) {
            App.toast('Failed to stop scan: ' + e.message, 'error');
        }
    },

    async _checkExistingScan() {
        try {
            const status = await API.getScanStatus();
            if (status.state === 'running') {
                this._showScanRunning(true);
                this._startPolling();
            } else if (status.results && status.results.devices && status.results.devices.length > 0) {
                this._renderResults(status.results.devices);
            } else {
                // Load from inventory
                await this._loadResults();
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

            // Simulate progress
            if (status.scanners_total && progressEl) {
                const pct = (status.scanners_completed / status.scanners_total) * 100;
                progressEl.style.width = pct + '%';
            }

            // Load results as they come in
            await this._loadResults();

            if (status.state !== 'running') {
                this._showScanRunning(false);
                this._stopPolling();
                if (progressEl) progressEl.style.width = '100%';
                App.toast('Scan complete', 'success');
                this._startPDPolling();
            }
        } catch (e) { /* retry */ }
    },

    async _loadResults() {
        try {
            const data = await API.getInventory({ sort_by: 'last_seen', sort_order: 'desc' });
            if (data.devices.length > 0) {
                this._renderResults(data.devices);
            }
        } catch (e) { /* ignore */ }
    },

    _renderResults(devices) {
        const container = document.getElementById('discovery-results');
        const countEl = document.getElementById('disc-result-count');

        if (countEl) countEl.textContent = `${devices.length} device${devices.length !== 1 ? 's' : ''}`;

        container.innerHTML = `
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>IP Address</th>
                            <th>MAC Address</th>
                            <th>Vendor</th>
                            <th>Hostname</th>
                            <th>OS</th>
                            <th>Ports</th>
                            <th>Method</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${devices.map(d => `
                            <tr>
                                <td><span class="badge badge-${d.status}">${d.status}</span></td>
                                <td class="mono" style="color:var(--cyan)">${d.ip || '—'}</td>
                                <td class="mono">${d.mac}</td>
                                <td>${d.vendor || '—'}</td>
                                <td>${d.hostname || '—'}</td>
                                <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis">${d.os || '—'}</td>
                                <td>${d.ports.length > 0 ? d.ports.map(p =>
                                    `<span class="badge badge-scanner" style="margin:1px">${p.port}/${p.protocol}</span>`
                                ).join('') : '—'}</td>
                                <td>${d.discovery_methods.map(m =>
                                    `<span class="badge badge-scanner" style="margin:1px;font-size:0.65rem">${m}</span>`
                                ).join('')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    },
};
