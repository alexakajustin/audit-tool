/**
 * VLAN Intelligence Component — discovers VLANs, subnets, switches,
 * and routing topology from infrastructure protocol broadcasts.
 */
const VLANsPage = {
    _refreshInterval: null,

    title: 'VLAN Intelligence',
    subtitle: 'Cross-network infrastructure discovery via CDP, LLDP, and routing protocols',

    async render(container) {
        container.innerHTML = `
            <div class="fade-in">
                <!-- Control Bar -->
                <div class="card vlan-control-card" style="margin-bottom:16px">
                    <div class="card-header">
                        <span class="card-title" style="display:flex;align-items:center;gap:8px">
                            <span class="pd-live-dot" id="vlan-dot" style="background:var(--text-muted)"></span>
                            VLAN Discovery Engine
                        </span>
                        <div style="display:flex;gap:12px;align-items:center">
                            <span id="vlan-status-text" style="color:var(--text-muted);font-size:0.8rem">Checking...</span>
                            <button id="btn-vlan-toggle" class="btn btn-sm btn-success" onclick="VLANsPage.toggleDiscovery()">
                                Start
                            </button>
                        </div>
                    </div>
                    <div id="vlan-live-stats" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(120px, 1fr));gap:12px;margin-top:8px">
                        <div class="pd-stat">
                            <div class="pd-stat-value" id="vlan-stat-packets" style="color:var(--cyan)">0</div>
                            <div class="pd-stat-label">Infra Packets</div>
                        </div>
                        <div class="pd-stat">
                            <div class="pd-stat-value" id="vlan-stat-switches" style="color:var(--orange)">0</div>
                            <div class="pd-stat-label">Switches</div>
                        </div>
                        <div class="pd-stat">
                            <div class="pd-stat-value" id="vlan-stat-vlans" style="color:var(--green)">0</div>
                            <div class="pd-stat-label">VLANs</div>
                        </div>
                        <div class="pd-stat">
                            <div class="pd-stat-value" id="vlan-stat-subnets" style="color:var(--purple)">0</div>
                            <div class="pd-stat-label">Subnets</div>
                        </div>
                        <div class="pd-stat">
                            <div class="pd-stat-value" id="vlan-stat-routes" style="color:var(--red)">0</div>
                            <div class="pd-stat-label">Routes</div>
                        </div>
                        <div class="pd-stat">
                            <div class="pd-stat-value" id="vlan-stat-duration" style="color:var(--text-muted)">0s</div>
                            <div class="pd-stat-label">Listening</div>
                        </div>
                    </div>
                    <!-- Protocol Activity Badges -->
                    <div id="vlan-proto-badges" style="display:flex;gap:6px;flex-wrap:wrap;margin-top:12px"></div>
                </div>

                <!-- Discovered Switches (CDP / LLDP) -->
                <div class="card" style="margin-bottom:16px">
                    <div class="card-header">
                        <span class="card-title">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width:18px;height:18px;vertical-align:middle;margin-right:6px">
                                <rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/>
                                <circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/>
                                <path d="M10 6h6M10 18h6"/>
                            </svg>
                            Discovered Switches & Routers
                        </span>
                        <span id="switch-count-badge" class="vlan-badge vlan-badge-muted">0 devices</span>
                    </div>
                    <div id="switches-container">
                        <div class="empty-state" style="padding:24px">
                            <p>Listening for CDP / LLDP broadcasts from managed switches...</p>
                            <p style="font-size:0.78rem;color:var(--text-muted);margin-top:4px">
                                Managed switches send CDP/LLDP every 30-60 seconds. Wait for the first broadcast.
                            </p>
                        </div>
                    </div>
                </div>

                <div class="grid-2">
                    <!-- VLAN Map -->
                    <div class="card">
                        <div class="card-header">
                            <span class="card-title">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width:18px;height:18px;vertical-align:middle;margin-right:6px">
                                    <path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/>
                                </svg>
                                Discovered VLANs
                            </span>
                            <span id="vlan-count-badge" class="vlan-badge vlan-badge-green">0</span>
                        </div>
                        <div id="vlans-table-container">
                            <div class="empty-state" style="padding:20px">
                                <p>No VLANs discovered yet.</p>
                            </div>
                        </div>
                    </div>

                    <!-- Subnet Intelligence -->
                    <div class="card">
                        <div class="card-header">
                            <span class="card-title">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width:18px;height:18px;vertical-align:middle;margin-right:6px">
                                    <circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/>
                                </svg>
                                Subnet Intelligence
                            </span>
                            <span id="subnet-count-badge" class="vlan-badge vlan-badge-purple">0</span>
                        </div>
                        <div id="subnets-table-container">
                            <div class="empty-state" style="padding:20px">
                                <p>No subnets inferred yet.</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Routing Table -->
                <div class="card" style="margin-top:16px">
                    <div class="card-header">
                        <span class="card-title">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width:18px;height:18px;vertical-align:middle;margin-right:6px">
                                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                            </svg>
                            Routing Table (OSPF / EIGRP / RIP)
                        </span>
                        <span id="route-count-badge" class="vlan-badge vlan-badge-red">0</span>
                    </div>
                    <div id="routes-table-container">
                        <div class="empty-state" style="padding:20px">
                            <p>No routes learned yet. Waiting for OSPF, EIGRP, or RIP broadcasts...</p>
                        </div>
                    </div>
                </div>
            </div>
        `;

        this._refresh();
        this._refreshInterval = setInterval(() => this._refresh(), 3000);
    },

    destroy() {
        if (this._refreshInterval) {
            clearInterval(this._refreshInterval);
            this._refreshInterval = null;
        }
    },

    async toggleDiscovery() {
        const btn = document.getElementById('btn-vlan-toggle');
        if (!btn) return;
        btn.disabled = true;

        try {
            const statusResp = await API.get('/api/vlans/status');
            const isRunning = statusResp?.status?.is_running;

            if (isRunning) {
                await API.post('/api/vlans/stop');
                App.toast('VLAN Discovery stopped', 'info');
            } else {
                await API.post('/api/vlans/start');
                App.toast('VLAN Discovery started — listening for CDP, LLDP, OSPF, EIGRP...', 'success');
            }
        } catch (e) {
            App.toast('Failed to toggle VLAN discovery', 'error');
        }

        btn.disabled = false;
        setTimeout(() => this._refresh(), 500);
    },

    async _refresh() {
        try {
            const data = await API.get('/api/vlans/status');
            if (!data) return;

            const status = data.status || {};
            const vlans = data.vlans || [];
            const subnets = data.subnets || [];
            const switches = data.switches || [];
            const routes = data.routes || [];

            // ── Control bar updates ──
            const dot = document.getElementById('vlan-dot');
            const statusText = document.getElementById('vlan-status-text');
            const btn = document.getElementById('btn-vlan-toggle');

            if (dot) {
                dot.style.background = status.is_running ? 'var(--green)' : 'var(--text-muted)';
                if (status.is_running) {
                    dot.classList.add('pd-live-dot-active');
                } else {
                    dot.classList.remove('pd-live-dot-active');
                }
            }
            if (statusText) {
                statusText.textContent = status.is_running
                    ? `ACTIVE — ${status.total_packets || 0} packets captured`
                    : 'STOPPED';
            }
            if (btn) {
                btn.textContent = status.is_running ? 'Stop' : 'Start';
                btn.className = status.is_running
                    ? 'btn btn-sm btn-danger'
                    : 'btn btn-sm btn-success';
            }

            // ── Live stats ──
            this._updateStat('vlan-stat-packets', status.total_packets || 0);
            this._updateStat('vlan-stat-switches', switches.length);
            this._updateStat('vlan-stat-vlans', vlans.length);
            this._updateStat('vlan-stat-subnets', subnets.length);
            this._updateStat('vlan-stat-routes', routes.length);

            const duration = status.duration || 0;
            const dEl = document.getElementById('vlan-stat-duration');
            if (dEl) {
                if (duration < 60) dEl.textContent = `${Math.floor(duration)}s`;
                else if (duration < 3600) dEl.textContent = `${Math.floor(duration / 60)}m ${Math.floor(duration % 60)}s`;
                else dEl.textContent = `${Math.floor(duration / 3600)}h ${Math.floor((duration % 3600) / 60)}m`;
            }

            // ── Protocol badges ──
            const badgeContainer = document.getElementById('vlan-proto-badges');
            if (badgeContainer) {
                const counts = status.protocol_counts || {};
                const protoColors = {
                    'CDP': 'var(--cyan)',
                    'LLDP': 'var(--green)',
                    '802.1Q': 'var(--orange)',
                    'OSPF': 'var(--purple)',
                    'EIGRP': 'var(--red)',
                    'RIP': '#e8a838',
                    'STP': 'var(--text-muted)',
                    'HSRP': '#38e8c6',
                    'VRRP': '#c678dd',
                };
                badgeContainer.innerHTML = Object.entries(counts)
                    .sort((a, b) => b[1] - a[1])
                    .map(([proto, count]) => {
                        const color = protoColors[proto] || 'var(--text-muted)';
                        return `<span class="protocol-tag" style="border-color:${color};color:${color}">${proto}: ${count}</span>`;
                    }).join('');
            }

            // ── Badge counts ──
            this._setBadge('switch-count-badge', `${switches.length} device${switches.length !== 1 ? 's' : ''}`);
            this._setBadge('vlan-count-badge', vlans.length);
            this._setBadge('subnet-count-badge', subnets.length);
            this._setBadge('route-count-badge', routes.length);

            // ── Render sections ──
            this._renderSwitches(switches);
            this._renderVLANs(vlans);
            this._renderSubnets(subnets);
            this._renderRoutes(routes);

        } catch (e) {
            // silently fail on refresh
        }
    },

    _updateStat(id, value) {
        const el = document.getElementById(id);
        if (el) el.textContent = typeof value === 'number' ? value.toLocaleString() : value;
    },

    _setBadge(id, text) {
        const el = document.getElementById(id);
        if (el) el.textContent = text;
    },

    _renderSwitches(switches) {
        const container = document.getElementById('switches-container');
        if (!container) return;

        if (!switches.length) {
            container.innerHTML = `
                <div class="empty-state" style="padding:24px">
                    <p>Listening for CDP / LLDP broadcasts from managed switches...</p>
                    <p style="font-size:0.78rem;color:var(--text-muted);margin-top:4px">
                        Managed switches send CDP/LLDP every 30-60 seconds. Wait for the first broadcast.
                    </p>
                </div>`;
            return;
        }

        container.innerHTML = `<div class="switch-cards-grid">${switches.map(sw => this._renderSwitchCard(sw)).join('')}</div>`;
    },

    _renderSwitchCard(sw) {
        const isCDP = sw.source_protocol === 'cdp';
        const protoBadge = isCDP
            ? '<span class="vlan-badge vlan-badge-cyan">CDP</span>'
            : sw.source_protocol === 'lldp'
                ? '<span class="vlan-badge vlan-badge-green">LLDP</span>'
                : `<span class="vlan-badge vlan-badge-muted">${sw.source_protocol.toUpperCase()}</span>`;

        const capabilities = (sw.capabilities || [])
            .map(c => `<span class="protocol-tag" style="border-color:var(--cyan);color:var(--cyan);font-size:0.7rem">${c}</span>`)
            .join('');

        const vlanBadges = (sw.vlans_advertised || [])
            .map(v => `<span class="vlan-id-badge">VLAN ${v}</span>`)
            .join(' ');

        const age = sw.last_seen ? this._formatAge(sw.last_seen) : '';

        return `
            <div class="switch-card">
                <div class="switch-card-header">
                    <div class="switch-card-name">
                        <svg viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" stroke-width="1.5" style="width:20px;height:20px;flex-shrink:0">
                            <rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/>
                            <circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/>
                            <path d="M10 6h6M10 18h6"/>
                        </svg>
                        <span>${this._escHtml(sw.device_id)}</span>
                    </div>
                    ${protoBadge}
                </div>
                <div class="switch-card-body">
                    ${sw.management_ip ? `<div class="switch-detail"><span class="switch-label">Mgmt IP</span><span class="switch-value">${this._escHtml(sw.management_ip)}</span></div>` : ''}
                    ${sw.platform ? `<div class="switch-detail"><span class="switch-label">Platform</span><span class="switch-value">${this._escHtml(sw.platform.substring(0, 60))}</span></div>` : ''}
                    ${sw.local_port ? `<div class="switch-detail"><span class="switch-label">Your Port</span><span class="switch-value">${this._escHtml(sw.local_port)}</span></div>` : ''}
                    ${sw.native_vlan != null ? `<div class="switch-detail"><span class="switch-label">Native VLAN</span><span class="switch-value">${sw.native_vlan}</span></div>` : ''}
                    ${sw.source_mac ? `<div class="switch-detail"><span class="switch-label">MAC</span><span class="switch-value" style="font-family:var(--font-mono);font-size:0.75rem">${this._escHtml(sw.source_mac)}</span></div>` : ''}
                    ${sw.software_version ? `<div class="switch-detail"><span class="switch-label">Software</span><span class="switch-value" style="font-size:0.72rem">${this._escHtml(sw.software_version.substring(0, 80))}</span></div>` : ''}
                    ${capabilities ? `<div class="switch-detail"><span class="switch-label">Capabilities</span><div style="display:flex;gap:4px;flex-wrap:wrap">${capabilities}</div></div>` : ''}
                    ${vlanBadges ? `<div class="switch-detail"><span class="switch-label">VLANs</span><div style="display:flex;gap:4px;flex-wrap:wrap">${vlanBadges}</div></div>` : ''}
                </div>
                ${age ? `<div class="switch-card-footer">Last seen ${age}</div>` : ''}
            </div>
        `;
    },

    _renderVLANs(vlans) {
        const container = document.getElementById('vlans-table-container');
        if (!container) return;

        if (!vlans.length) {
            container.innerHTML = '<div class="empty-state" style="padding:20px"><p>No VLANs discovered yet.</p></div>';
            return;
        }

        const rows = vlans.map(v => `
            <tr>
                <td><span class="vlan-id-badge">${v.vlan_id}</span></td>
                <td>${this._escHtml(v.name || '—')}</td>
                <td style="font-family:var(--font-mono);font-size:0.8rem">${this._escHtml(v.subnet || '—')}</td>
                <td><span class="protocol-tag" style="border-color:var(--cyan);color:var(--cyan);font-size:0.7rem">${v.source_protocol.toUpperCase()}</span></td>
                <td>${this._escHtml(v.source_switch || '—')}</td>
                <td>${v.is_native ? '<span class="vlan-badge vlan-badge-green" style="font-size:0.65rem">NATIVE</span>' : ''}</td>
            </tr>
        `).join('');

        container.innerHTML = `
            <div class="table-wrapper">
                <table class="data-table">
                    <thead><tr>
                        <th>ID</th><th>Name</th><th>Subnet</th><th>Source</th><th>Switch</th><th>Flags</th>
                    </tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;
    },

    _renderSubnets(subnets) {
        const container = document.getElementById('subnets-table-container');
        if (!container) return;

        if (!subnets.length) {
            container.innerHTML = '<div class="empty-state" style="padding:20px"><p>No subnets inferred yet.</p></div>';
            return;
        }

        const rows = subnets.map(s => `
            <tr>
                <td style="font-family:var(--font-mono);font-size:0.8rem;color:var(--cyan)">${this._escHtml(s.cidr)}</td>
                <td>${this._escHtml(s.gateway || '—')}</td>
                <td>${s.vlan_id != null ? `<span class="vlan-id-badge">${s.vlan_id}</span>` : '—'}</td>
                <td>${s.device_count || '—'}</td>
                <td><span class="protocol-tag" style="border-color:var(--purple);color:var(--purple);font-size:0.7rem">${(s.source_protocol || '—').toUpperCase()}</span></td>
                <td>${this._escHtml(s.source_router || '—')}</td>
            </tr>
        `).join('');

        container.innerHTML = `
            <div class="table-wrapper">
                <table class="data-table">
                    <thead><tr>
                        <th>Subnet CIDR</th><th>Gateway</th><th>VLAN</th><th>Hosts</th><th>Source</th><th>Router</th>
                    </tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;
    },

    _renderRoutes(routes) {
        const container = document.getElementById('routes-table-container');
        if (!container) return;

        if (!routes.length) {
            container.innerHTML = '<div class="empty-state" style="padding:20px"><p>No routes learned yet. Waiting for OSPF, EIGRP, or RIP broadcasts...</p></div>';
            return;
        }

        const protoColors = {
            'ospf': 'var(--purple)',
            'eigrp': 'var(--red)',
            'rip_v1': '#e8a838',
            'rip_v2': '#e8a838',
        };

        const rows = routes.map(r => {
            const color = protoColors[r.protocol] || 'var(--text-muted)';
            return `
                <tr>
                    <td style="font-family:var(--font-mono);font-size:0.8rem">${this._escHtml(r.destination)}</td>
                    <td>${this._escHtml(r.next_hop || '—')}</td>
                    <td>${r.metric}</td>
                    <td><span class="protocol-tag" style="border-color:${color};color:${color};font-size:0.7rem">${r.protocol.toUpperCase()}</span></td>
                    <td>${this._escHtml(r.advertising_router || '—')}</td>
                    <td>${r.area || r.as_number || '—'}</td>
                </tr>
            `;
        }).join('');

        container.innerHTML = `
            <div class="table-wrapper">
                <table class="data-table">
                    <thead><tr>
                        <th>Destination</th><th>Next Hop</th><th>Metric</th><th>Protocol</th><th>Router</th><th>Area/AS</th>
                    </tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;
    },

    _formatAge(timestamp) {
        const seconds = Math.floor(Date.now() / 1000 - timestamp);
        if (seconds < 60) return `${seconds}s ago`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
        return `${Math.floor(seconds / 3600)}h ago`;
    },

    _escHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = String(str);
        return div.innerHTML;
    },
};
