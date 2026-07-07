/**
 * Dashboard Component — network overview with live statistics.
 */
const DashboardPage = {
    _refreshInterval: null,

    title: 'Dashboard',
    subtitle: 'Network overview and statistics',

    async render(container) {
        container.innerHTML = `
            <div class="fade-in">
                <!-- Stats Cards -->
                <div class="stats-grid" id="dashboard-stats">
                    ${this._renderStatCard('Total Devices', '—', 'cyan', 'devices')}
                    ${this._renderStatCard('Online', '—', 'green', 'online')}
                    ${this._renderStatCard('Open Ports', '—', 'orange', 'ports')}
                    ${this._renderStatCard('Sniffer', '—', 'red', 'sniffer')}
                </div>

                <!-- Passive Discovery Status -->
                <div class="card passive-discovery-card" style="margin-bottom:16px">
                    <div class="card-header">
                        <span class="card-title" style="display:flex;align-items:center;gap:8px">
                            <span class="pd-live-dot" id="pd-dot"></span>
                            Passive Discovery
                        </span>
                        <div style="display:flex;gap:8px;align-items:center">
                            <span id="pd-status-text" style="color:var(--text-muted);font-size:0.8rem">Checking...</span>
                            <button id="btn-pd-toggle" class="btn btn-sm btn-success" onclick="DashboardPage.togglePassiveDiscovery()">
                                Start
                            </button>
                        </div>
                    </div>
                    <div id="pd-stats" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(140px, 1fr));gap:12px;margin-top:8px">
                        <div class="pd-stat">
                            <div class="pd-stat-value" id="pd-devices" style="color:var(--cyan)">0</div>
                            <div class="pd-stat-label">Devices Found</div>
                        </div>
                        <div class="pd-stat">
                            <div class="pd-stat-value" id="pd-packets" style="color:var(--green)">0</div>
                            <div class="pd-stat-label">Broadcast Pkts</div>
                        </div>
                        <div class="pd-stat">
                            <div class="pd-stat-value" id="pd-duration" style="color:var(--purple)">0s</div>
                            <div class="pd-stat-label">Listening</div>
                        </div>
                    </div>
                    <div id="pd-protocols" style="display:flex;gap:6px;flex-wrap:wrap;margin-top:12px"></div>
                </div>

                <div class="grid-2">
                    <!-- Vendor Distribution -->
                    <div class="card">
                        <div class="card-header">
                            <span class="card-title">Vendor Distribution</span>
                        </div>
                        <div id="vendor-chart" class="proto-bars">
                            <div class="empty-state" style="padding:20px">
                                <p>No data yet. Run a discovery scan.</p>
                            </div>
                        </div>
                    </div>

                    <!-- Recent Discoveries -->
                    <div class="card">
                        <div class="card-header">
                            <span class="card-title">Recent Discoveries</span>
                        </div>
                        <div id="recent-devices">
                            <div class="empty-state" style="padding:20px">
                                <p>No devices discovered yet.</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Scanner Status -->
                <div class="card" style="margin-top:16px">
                    <div class="card-header">
                        <span class="card-title">Available Scanners</span>
                    </div>
                    <div id="scanners-list" class="scanner-chips"></div>
                </div>
            </div>
        `;

        await this._loadData();
        this._refreshInterval = setInterval(() => this._loadData(), 5000);
    },

    destroy() {
        if (this._refreshInterval) {
            clearInterval(this._refreshInterval);
            this._refreshInterval = null;
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
            await this._loadData();
        } catch (e) {
            App.toast('Failed: ' + e.message, 'error');
        }
    },

    async _loadData() {
        try {
            const stats = await API.getStats();
            this._updateStats(stats);
            this._updateVendorChart(stats.inventory.vendor_distribution);
            this._updateScanners(stats.scanners);
            this._updateRecentDevices();

            // Update passive discovery status
            try {
                const pd = await API.getPassiveDiscoveryStatus();
                this._updatePassiveDiscovery(pd);
            } catch (e) { /* ignore */ }
        } catch (e) {
            // Silently retry on next interval
        }
    },

    _updatePassiveDiscovery(pd) {
        const dot = document.getElementById('pd-dot');
        const statusText = document.getElementById('pd-status-text');
        const btn = document.getElementById('btn-pd-toggle');
        const devicesEl = document.getElementById('pd-devices');
        const packetsEl = document.getElementById('pd-packets');
        const durationEl = document.getElementById('pd-duration');
        const protosEl = document.getElementById('pd-protocols');

        if (dot) {
            dot.style.background = pd.is_running ? 'var(--green)' : 'var(--text-muted)';
            dot.style.boxShadow = pd.is_running ? '0 0 8px var(--green)' : 'none';
        }
        if (statusText) statusText.textContent = pd.is_running ? 'LISTENING' : 'STOPPED';
        if (btn) {
            btn.textContent = pd.is_running ? 'Stop' : 'Start';
            btn.className = pd.is_running ? 'btn btn-sm btn-danger' : 'btn btn-sm btn-success';
        }
        if (devicesEl) devicesEl.textContent = pd.devices_found || 0;
        if (packetsEl) packetsEl.textContent = pd.broadcast_packets || 0;
        if (durationEl) durationEl.textContent = this._formatDuration(pd.duration || 0);

        if (protosEl && pd.protocol_hits) {
            const entries = Object.entries(pd.protocol_hits).sort((a, b) => b[1] - a[1]);
            if (entries.length > 0) {
                const colorMap = {
                    ARP: '#00f0ff', DHCP: '#00ff88', mDNS: '#a55eea',
                    LLMNR: '#00b8c5', NetBIOS: '#ffd32a', SSDP: '#ff9f43',
                    DNS: '#a55eea',
                };
                protosEl.innerHTML = entries.map(([proto, count]) =>
                    `<span class="badge badge-protocol" style="background:${colorMap[proto] || 'rgba(255,255,255,0.06)'};color:${colorMap[proto] ? '#0a0e1a' : 'var(--text-muted)'};font-weight:600">
                        ${proto}: ${count}
                    </span>`
                ).join('');
            }
        }
    },

    _updateStats(stats) {
        const inv = stats.inventory;
        const sniff = stats.sniffer;

        this._setStatValue('devices', inv.total_devices);
        this._setStatValue('online', inv.online_devices);
        this._setStatValue('ports', inv.total_open_ports);
        this._setStatValue('sniffer', sniff.is_running ? 'LIVE' : 'OFF');

        // Update sniffer indicator
        const dot = document.getElementById('sniffer-live-dot');
        if (dot) dot.style.display = sniff.is_running ? 'block' : 'none';
    },

    _setStatValue(id, value) {
        const el = document.querySelector(`[data-stat="${id}"] .stat-value`);
        if (el) el.textContent = value;
    },

    _updateVendorChart(vendors) {
        const container = document.getElementById('vendor-chart');
        if (!container || !vendors) return;

        const entries = Object.entries(vendors);
        if (entries.length === 0) return;

        const maxCount = Math.max(...entries.map(e => e[1]));
        const colors = ['#00f0ff', '#00ff88', '#a55eea', '#ff9f43', '#ff3b5c', '#ffd32a', '#00b8c5', '#ff6b81'];

        container.innerHTML = entries.map(([vendor, count], i) => `
            <div class="proto-bar-row">
                <span class="proto-bar-label">${this._truncate(vendor, 14)}</span>
                <div class="proto-bar-track">
                    <div class="proto-bar-fill" style="width:${(count/maxCount)*100}%;background:${colors[i % colors.length]}"></div>
                </div>
                <span class="proto-bar-count">${count}</span>
            </div>
        `).join('');
    },

    async _updateRecentDevices() {
        const container = document.getElementById('recent-devices');
        if (!container) return;

        try {
            const data = await API.getInventory({ sort_by: 'last_seen', sort_order: 'desc' });
            const devices = data.devices.slice(0, 6);

            if (devices.length === 0) return;

            container.innerHTML = `
                <div style="display:flex;flex-direction:column;gap:8px">
                    ${devices.map(d => `
                        <div style="display:flex;align-items:center;gap:12px;padding:8px 12px;border-radius:var(--radius-sm);background:var(--bg-deep)">
                            <span class="badge badge-${d.status}">${d.status}</span>
                            <span class="mono" style="color:var(--cyan);min-width:110px">${d.ip || '—'}</span>
                            <span class="mono" style="min-width:130px;color:var(--text-muted)">${d.mac}</span>
                            <span style="flex:1;color:var(--text-secondary)">${d.vendor || 'Unknown'}</span>
                            <span style="color:var(--text-muted);font-size:0.75rem">${d.discovery_methods.map(m =>
                                `<span class="badge badge-scanner" style="margin:1px;font-size:0.6rem">${m}</span>`
                            ).join('')}</span>
                            <span style="color:var(--text-muted);font-size:0.75rem">${this._timeAgo(d.last_seen)}</span>
                        </div>
                    `).join('')}
                </div>
            `;
        } catch (e) { /* ignore */ }
    },

    _updateScanners(scanners) {
        const container = document.getElementById('scanners-list');
        if (!container || !scanners) return;

        container.innerHTML = scanners.map(s => `
            <div class="scanner-chip ${s.available ? '' : 'unavailable'}">
                <span class="chip-dot" style="background:${s.available ? 'var(--green)' : 'var(--text-muted)'}"></span>
                ${s.display_name}
                ${s.capabilities.requires_admin ? '<span style="font-size:0.65rem;opacity:0.5">ADMIN</span>' : ''}
            </div>
        `).join('');
    },

    _renderStatCard(label, value, color, id) {
        const icons = {
            devices: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',
            online: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
            ports: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="5" y="2" width="14" height="20" rx="2"/><path d="M12 18h.01"/></svg>',
            sniffer: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>',
        };

        return `
            <div class="stat-card" data-stat="${id}" style="--accent-color:var(--${color})">
                <div class="stat-icon ${color}">${icons[id] || ''}</div>
                <div class="stat-info">
                    <div class="stat-value">${value}</div>
                    <div class="stat-label">${label}</div>
                </div>
            </div>
        `;
    },

    _truncate(str, max) {
        return str.length > max ? str.substring(0, max) + '…' : str;
    },

    _timeAgo(timestamp) {
        const seconds = Math.floor(Date.now() / 1000 - timestamp);
        if (seconds < 60) return 'just now';
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
        return `${Math.floor(seconds / 86400)}d ago`;
    },

    _formatDuration(seconds) {
        if (seconds < 60) return `${Math.round(seconds)}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
        return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
    },
};
