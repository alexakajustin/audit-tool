/**
 * Sniffer Component — passive packet capture with live console.
 * Enhanced: Network Intelligence panel, auto-exclude local IP,
 * security alerts, DNS query tracking, top talkers.
 */
const SnifferPage = {
    _pollInterval: null,
    _autoScroll: true,
    _packetCount: 0,
    _visibleProtocols: new Set(),
    _knownProtocols: new Set(),
    _visibleIps: new Set(),
    _knownIps: new Set(),
    _lastPacketId: null,
    _localIp: '',
    _trafficSort: { col: 'data_volume', dir: 'desc' },
    _trafficData: [],
    _expandedIps: new Set(),

    title: 'Sniffer',
    subtitle: 'Passive network traffic capture & intelligence',

    async render(container) {
        container.innerHTML = `
            <div class="fade-in">
                <!-- Controls -->
                <div class="card" style="margin-bottom:16px">
                    <div style="display:flex;gap:16px;align-items:flex-end;flex-wrap:wrap">
                        <div class="form-group" style="margin:0;flex:1;min-width:200px">
                            <label class="form-label">Interface</label>
                            <select id="sniff-interface" class="form-control">
                                <option value="">Default</option>
                            </select>
                        </div>
                        <div class="form-group" style="margin:0;flex:2;min-width:200px">
                            <label class="form-label">BPF Filter</label>
                            <input type="text" id="sniff-filter" class="form-control"
                                   placeholder="e.g. arp, port 80, host 192.168.1.1" />
                        </div>
                        <div style="display:flex;gap:8px">
                            <button id="btn-sniff-start" class="btn btn-primary" onclick="SnifferPage.start()">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                                Start Capture
                            </button>
                            <button id="btn-sniff-stop" class="btn btn-danger" onclick="SnifferPage.stop()" style="display:none">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="6" width="12" height="12"/></svg>
                                Stop
                            </button>
                            <button class="btn btn-sm" onclick="SnifferPage.clearConsole()">Clear</button>
                        </div>
                    </div>
                </div>

                <!-- MITM / ARP Spoof Control Panel -->
                <div class="card" style="margin-bottom:16px;border:1px solid rgba(255,59,92,0.15)">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
                        <span style="font-weight:600;font-size:0.9rem;display:flex;align-items:center;gap:8px">
                            <svg viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2" style="width:18px;height:18px">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                                <path d="M12 8v4M12 16h.01"/>
                            </svg>
                            <span style="color:var(--red)">ACTIVE INTERCEPTION</span>
                            <span id="mitm-status-dot" style="width:8px;height:8px;border-radius:50%;background:var(--text-muted);display:inline-block"></span>
                            <span id="mitm-status-text" style="color:var(--text-muted);font-size:0.72rem;font-weight:400">Inactive</span>
                        </span>
                        <div style="display:flex;gap:6px;align-items:center">
                            <span id="mitm-pkt-count" style="color:var(--text-muted);font-size:0.7rem;font-family:var(--font-mono)"></span>
                            <button class="btn btn-sm" onclick="SnifferPage.mitmScan()" id="btn-mitm-scan" style="font-size:0.72rem;padding:4px 10px">
                                Scan Network
                            </button>
                            <button class="btn btn-sm" onclick="SnifferPage.mitmStartAll()" id="btn-mitm-start-all" style="font-size:0.72rem;padding:4px 10px;background:rgba(255,59,92,0.25);color:var(--red);border-color:rgba(255,59,92,0.4);font-weight:600">
                                ⚡ Intercept ALL Devices
                            </button>
                            <button class="btn btn-sm" onclick="SnifferPage.mitmStart()" id="btn-mitm-start" style="font-size:0.72rem;padding:4px 10px;display:none;background:rgba(255,59,92,0.15);color:var(--red);border-color:rgba(255,59,92,0.3)">
                                Start Interception
                            </button>
                            <button class="btn btn-sm" onclick="SnifferPage.mitmStop()" id="btn-mitm-stop" style="font-size:0.72rem;padding:4px 10px;display:none;background:rgba(255,59,92,0.3);color:#fff;border-color:var(--red)">
                                Stop
                            </button>
                        </div>
                    </div>
                    <div id="mitm-targets" style="display:flex;flex-wrap:wrap;gap:6px;max-height:120px;overflow-y:auto">
                        <span style="color:var(--text-muted);font-size:0.78rem">Click "Scan Network" to discover devices on your subnet for interception.</span>
                    </div>
                </div>

                <!-- LIVE TRAFFIC BY IP TABLE -->
                <div class="card" style="margin-bottom:16px">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
                        <span style="font-weight:600;font-size:0.9rem;display:flex;align-items:center;gap:8px">
                            <svg viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2" style="width:18px;height:18px">
                                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                            </svg>
                            <span style="color:var(--green)">LIVE TRAFFIC BY IP</span>
                            <span id="traffic-ip-count" style="color:var(--text-muted);font-size:0.72rem;font-weight:400"></span>
                        </span>
                    </div>
                    <div id="traffic-table-container" style="max-height:420px;overflow-y:auto">
                        <table style="width:100%;border-collapse:collapse;font-size:0.78rem" id="traffic-table">
                            <thead>
                                <tr style="border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--bg-card);z-index:1">
                                    <th onclick="SnifferPage.sortTrafficBy('rank')" style="text-align:left;padding:6px 8px;color:var(--text-muted);font-weight:600;font-size:0.7rem;text-transform:uppercase;cursor:pointer;user-select:none;white-space:nowrap" id="th-rank"># <span class="sort-arrow"></span></th>
                                    <th onclick="SnifferPage.sortTrafficBy('ip')" style="text-align:left;padding:6px 8px;color:var(--text-muted);font-weight:600;font-size:0.7rem;text-transform:uppercase;cursor:pointer;user-select:none;white-space:nowrap" id="th-ip">IP Address <span class="sort-arrow"></span></th>
                                    <th onclick="SnifferPage.sortTrafficBy('hostname')" style="text-align:left;padding:6px 8px;color:var(--text-muted);font-weight:600;font-size:0.7rem;text-transform:uppercase;cursor:pointer;user-select:none;white-space:nowrap" id="th-hostname">Hostname <span class="sort-arrow"></span></th>
                                    <th onclick="SnifferPage.sortTrafficBy('data_volume')" style="text-align:right;padding:6px 8px;color:var(--text-muted);font-weight:600;font-size:0.7rem;text-transform:uppercase;cursor:pointer;user-select:none;white-space:nowrap" id="th-data_volume">Traffic <span class="sort-arrow"></span></th>
                                    <th style="text-align:left;padding:6px 8px;color:var(--text-muted);font-weight:600;font-size:0.7rem;text-transform:uppercase;white-space:nowrap">Top Sites</th>
                                    <th onclick="SnifferPage.sortTrafficBy('intercepted')" style="text-align:center;padding:6px 8px;color:var(--text-muted);font-weight:600;font-size:0.7rem;text-transform:uppercase;cursor:pointer;user-select:none;white-space:nowrap" id="th-intercepted">Status <span class="sort-arrow"></span></th>
                                </tr>
                            </thead>
                            <tbody id="traffic-table-body">
                                <tr><td colspan="6" style="padding:20px;text-align:center;color:var(--text-muted);font-style:italic">Start the sniffer to see live traffic per IP...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Stats -->
                <div class="sniffer-stats" id="sniff-stats">
                    <div class="sniffer-stat">
                        <div class="stat-value" id="sniff-total" style="color:var(--cyan)">0</div>
                        <div class="stat-label">Packets</div>
                    </div>
                    <div class="sniffer-stat">
                        <div class="stat-value" id="sniff-hosts" style="color:var(--green)">0</div>
                        <div class="stat-label">Hosts Seen</div>
                    </div>
                    <div class="sniffer-stat">
                        <div class="stat-value" id="sniff-pps" style="color:var(--orange)">0</div>
                        <div class="stat-label">Pkts/sec</div>
                    </div>
                    <div class="sniffer-stat">
                        <div class="stat-value" id="sniff-duration" style="color:var(--purple)">0s</div>
                        <div class="stat-label">Duration</div>
                    </div>
                    <div class="sniffer-stat">
                        <div class="stat-value" id="sniff-alerts" style="color:var(--red)">0</div>
                        <div class="stat-label">Security Alerts</div>
                    </div>
                    <div class="sniffer-stat">
                        <div class="stat-value" id="sniff-dns-count" style="color:var(--cyan)">0</div>
                        <div class="stat-label">DNS Queries</div>
                    </div>
                </div>

                <!-- NETWORK INTELLIGENCE PANEL -->
                <div class="intel-grid" style="margin-bottom:16px">
                    <!-- Security Alerts -->
                    <div class="card intel-card intel-card-critical">
                        <div class="card-header">
                            <span class="card-title" style="color:var(--red);display:flex;align-items:center;gap:6px">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                                SECURITY FINDINGS
                            </span>
                            <span id="intel-alert-count" class="badge badge-offline" style="font-size:0.7rem">0</span>
                        </div>
                        <div id="intel-alerts" class="intel-scroll" style="max-height:180px;overflow-y:auto">
                            <div class="intel-empty">Monitoring for cleartext credentials, HTTP, Telnet, SNMP...</div>
                        </div>
                    </div>

                    <!-- DNS Queries (what sites are being browsed) -->
                    <div class="card intel-card">
                        <div class="card-header">
                            <span class="card-title" style="color:var(--cyan);display:flex;align-items:center;gap:6px">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
                                DNS QUERIES — Sites Being Browsed
                            </span>
                        </div>
                        <div id="intel-dns" class="intel-scroll" style="max-height:180px;overflow-y:auto">
                            <div class="intel-empty">Waiting for DNS traffic...</div>
                        </div>
                    </div>

                    <!-- Top Talkers -->
                    <div class="card intel-card">
                        <div class="card-header">
                            <span class="card-title" style="color:var(--green);display:flex;align-items:center;gap:6px">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                                TOP TALKERS — Data Volume
                            </span>
                        </div>
                        <div id="intel-talkers" class="intel-scroll" style="max-height:180px;overflow-y:auto">
                            <div class="intel-empty">Collecting traffic data...</div>
                        </div>
                    </div>

                    <!-- Services Detected -->
                    <div class="card intel-card">
                        <div class="card-header">
                            <span class="card-title" style="color:var(--orange);display:flex;align-items:center;gap:6px">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
                                SERVICES DETECTED ON HOSTS
                            </span>
                        </div>
                        <div id="intel-services" class="intel-scroll" style="max-height:180px;overflow-y:auto">
                            <div class="intel-empty">Detecting services...</div>
                        </div>
                    </div>
                </div>

                <!-- DEVICE ACTIVITY PROFILER (the shock-value feature) -->
                <div class="card" style="margin-bottom:16px">
                    <div class="card-header">
                        <span class="card-title" style="display:flex;align-items:center;gap:8px;color:var(--red)">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:18px;height:18px">
                                <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4-4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/>
                            </svg>
                            DEVICE ACTIVITY PROFILER — Who Is Doing What
                        </span>
                        <span id="profile-count-badge" style="color:var(--text-muted);font-size:0.75rem">0 devices</span>
                    </div>
                    <div id="device-profiles-container" style="max-height:500px;overflow-y:auto">
                        <div class="intel-empty" style="padding:20px">Capturing traffic to build device profiles... Browse sites on other devices to see their activity appear here.</div>
                    </div>
                </div>

                <!-- NETWORK ACTIVITY FEED (real-time cross-device) -->
                <div class="card" style="margin-bottom:16px">
                    <div class="card-header">
                        <span class="card-title" style="display:flex;align-items:center;gap:8px;color:var(--green)">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:18px;height:18px">
                                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                            </svg>
                            LIVE ACTIVITY FEED — All Devices
                            <span id="feed-live-dot" style="width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:pulse-glow 2s ease-in-out infinite;display:none"></span>
                        </span>
                        <span id="feed-count" style="color:var(--text-muted);font-size:0.75rem">0 events</span>
                    </div>
                    <div id="activity-feed-container" style="max-height:300px;overflow-y:auto;font-family:var(--font-mono);font-size:0.75rem">
                        <div class="intel-empty" style="padding:20px">Waiting for network activity...</div>
                    </div>
                </div>

                <!-- Filters -->
                <div class="card" style="margin-bottom:16px">
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
                        <div>
                            <div class="card-header" style="margin-bottom:8px;padding:0">
                                <span class="card-title" style="font-size:0.85rem;color:var(--text-muted)">Protocol Filters</span>
                            </div>
                            <div id="sniff-filters" style="display:flex;gap:12px;flex-wrap:wrap;">
                                <span class="empty-state" style="padding:0;font-size:0.85rem">Start sniffing to discover protocols</span>
                            </div>
                        </div>
                        <div>
                            <div class="card-header" style="margin-bottom:8px;padding:0;display:flex;justify-content:space-between;align-items:center">
                                <span class="card-title" style="font-size:0.85rem;color:var(--text-muted)">IP / Host Filters <span id="sniff-local-ip-label" style="color:var(--orange);font-size:0.7rem"></span></span>
                                <div style="display:flex;gap:8px">
                                    <button class="btn btn-sm" style="padding:2px 6px;font-size:0.7rem;line-height:1" onclick="SnifferPage.selectBtn('ip', true)">All</button>
                                    <button class="btn btn-sm" style="padding:2px 6px;font-size:0.7rem;line-height:1" onclick="SnifferPage.selectBtn('ip', false)">None</button>
                                </div>
                            </div>
                            <div id="sniff-ip-filters" style="max-height:150px;overflow-y:auto;display:flex;flex-direction:column;gap:4px;padding:6px;border:1px solid var(--bg-deepest);border-radius:4px;background:var(--bg-deepest)">
                                <span class="empty-state" style="padding:0;font-size:0.85rem">Start sniffing to discover IPs</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="grid-2">
                    <!-- Packet Console -->
                    <div class="sniffer-console" style="grid-column: span 2">
                        <div class="console-header">
                            <span class="console-title">
                                <span id="sniff-live-indicator" style="display:none;width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:pulse-glow 2s ease-in-out infinite"></span>
                                Packet Capture
                            </span>
                            <span style="color:var(--text-muted);font-size:0.75rem" id="sniff-packet-count">0 packets</span>
                        </div>
                        <div class="console-body" id="sniff-console" style="max-height:600px">
                            <div class="empty-state" style="padding:40px">
                                <p>Start the sniffer to capture packets in real-time.</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Protocol Distribution -->
                <div class="card" style="margin-top:16px">
                    <div class="card-header">
                        <span class="card-title">Protocol Distribution</span>
                    </div>
                    <div id="sniff-proto-chart" class="proto-bars">
                        <div class="empty-state" style="padding:20px"><p>No data yet.</p></div>
                    </div>
                </div>
            </div>
        `;

        // Clear state on page load so filters re-render correctly
        this._knownProtocols.clear();
        this._visibleProtocols.clear();
        this._knownIps.clear();
        this._visibleIps.clear();
        this._lastPacketId = null;
        this._packetCount = 0;

        await this._loadInterfaces();
        await this._checkStatus();
    },

    destroy() {
        this._stopPolling();
    },

    async _loadInterfaces() {
        try {
            const data = await API.getInterfaces();
            const select = document.getElementById('sniff-interface');
            data.interfaces.forEach(iface => {
                const opt = document.createElement('option');
                opt.value = iface.name;
                const ipText = iface.ip ? iface.ip : 'Unconnected';
                opt.textContent = `${iface.name} — ${ipText}`;
                if (data.recommended && iface.name === data.recommended.name) opt.selected = true;
                select.appendChild(opt);
            });
        } catch (e) { /* ignore */ }
    },

    async _checkStatus() {
        try {
            const stats = await API.getSnifferStats();
            if (stats.is_running) {
                this._localIp = stats.local_ip || '';
                this._showRunning(true);
                this._startPolling();
                await this._loadPackets();
            }
            await this._pollMitmStatus();
        } catch (e) { /* ignore */ }
    },

    async start() {
        const iface = document.getElementById('sniff-interface').value;
        const filter = document.getElementById('sniff-filter').value;

        try {
            await API.startSniffer({ interface: iface, filter });
            App.toast('Sniffer started', 'success');
            this._showRunning(true);
            this._startPolling();
        } catch (e) {
            App.toast('Failed to start sniffer: ' + e.message, 'error');
        }
    },

    async stop() {
        try {
            const result = await API.stopSniffer();
            App.toast(`Sniffer stopped — ${result.total_packets} packets captured`, 'info');
            this._showRunning(false);
            this._stopPolling();
        } catch (e) {
            App.toast('Failed to stop sniffer: ' + e.message, 'error');
        }
    },

    // ── MITM / ARP Spoofing Controls ────────────────────

    async mitmScan() {
        const btn = document.getElementById('btn-mitm-scan');
        if (btn) { btn.textContent = 'Scanning...'; btn.disabled = true; }

        try {
            const iface = document.getElementById('sniff-interface').value;
            const resp = await fetch('/api/mitm/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ interface: iface }),
            });
            const data = await resp.json();

            if (data.error) {
                App.toast('Scan failed: ' + data.error, 'error');
                return;
            }

            const container = document.getElementById('mitm-targets');
            if (!container) return;

            if (!data.hosts || data.hosts.length === 0) {
                container.innerHTML = '<span style="color:var(--text-muted);font-size:0.78rem">No devices found. Make sure you have admin privileges and the correct interface selected.</span>';
                return;
            }

            container.innerHTML = data.hosts.map(h => {
                const isGw = h.is_gateway;
                const label = h.hostname ? `${h.ip} (${h.hostname})` : h.ip;
                const color = isGw ? 'var(--orange)' : 'var(--cyan)';
                const tag = isGw ? ' <span style="color:var(--orange);font-size:0.6rem;font-weight:600">GATEWAY</span>' : '';
                return `
                    <label style="display:flex;align-items:center;gap:5px;padding:4px 10px;border-radius:6px;background:var(--bg-deep);border:1px solid var(--border);cursor:pointer;font-size:0.75rem;white-space:nowrap;${isGw ? 'opacity:0.4;pointer-events:none' : ''}">
                        <input type="checkbox" class="mitm-target-chk" value="${h.ip}" data-mac="${h.mac}" ${isGw ? 'disabled' : 'checked'}>
                        <span style="color:${color};font-family:var(--font-mono)">${h.ip}</span>
                        <span style="color:var(--text-muted);font-size:0.65rem">${h.mac}</span>
                        ${h.hostname ? `<span style="color:var(--green);font-size:0.65rem">${h.hostname}</span>` : ''}
                        ${tag}
                    </label>
                `;
            }).join('');

            // Show the start button
            const startBtn = document.getElementById('btn-mitm-start');
            if (startBtn) startBtn.style.display = 'inline-flex';

            App.toast(`Found ${data.hosts.length} devices on subnet`, 'success');

        } catch (e) {
            App.toast('Network scan failed: ' + e.message, 'error');
        } finally {
            if (btn) { btn.textContent = 'Scan Network'; btn.disabled = false; }
        }
    },

    async mitmStart() {
        const checkboxes = document.querySelectorAll('.mitm-target-chk:checked');
        const targets = Array.from(checkboxes).map(c => c.value);

        if (!targets.length) {
            App.toast('Select at least one target device', 'error');
            return;
        }

        try {
            const resp = await fetch('/api/mitm/start', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ targets }),
            });
            const data = await resp.json();

            if (data.error) {
                App.toast('MITM failed: ' + data.error, 'error');
                return;
            }

            App.toast(`Intercepting ${data.target_count} device(s) — traffic will now flow through your PC`, 'success');
            this._showMitmRunning(true);

        } catch (e) {
            App.toast('Failed to start MITM: ' + e.message, 'error');
        }
    },

    async mitmStartAll() {
        const btn = document.getElementById('btn-mitm-start-all');
        if (btn) { btn.textContent = '⚡ Scanning & Intercepting...'; btn.disabled = true; }

        try {
            const iface = document.getElementById('sniff-interface').value;
            const resp = await fetch('/api/mitm/start-all', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ interface: iface }),
            });
            const data = await resp.json();

            if (data.error) {
                App.toast('Intercept ALL failed: ' + data.error, 'error');
                return;
            }

            const total = data.total_hosts_found || data.target_count || '?';
            App.toast(`⚡ Intercepting ALL ${data.target_count} devices (${total} found) — full network visibility active`, 'success');
            this._showMitmRunning(true);

            // Also start capture if not already running
            const stats = await API.getSnifferStats();
            if (stats.is_running) {
                this._showRunning(true);
                this._startPolling();
            }

        } catch (e) {
            App.toast('Failed to intercept all: ' + e.message, 'error');
        } finally {
            if (btn) { btn.textContent = '⚡ Intercept ALL Devices'; btn.disabled = false; }
        }
    },

    async mitmStop() {
        try {
            const resp = await fetch('/api/mitm/stop', { method: 'POST' });
            const data = await resp.json();

            App.toast('Interception stopped — ARP tables restored', 'info');
            this._showMitmRunning(false);

        } catch (e) {
            App.toast('Failed to stop MITM: ' + e.message, 'error');
        }
    },

    _showMitmRunning(running) {
        const dot = document.getElementById('mitm-status-dot');
        const text = document.getElementById('mitm-status-text');
        const startBtn = document.getElementById('btn-mitm-start');
        const stopBtn = document.getElementById('btn-mitm-stop');
        const scanBtn = document.getElementById('btn-mitm-scan');
        const startAllBtn = document.getElementById('btn-mitm-start-all');

        if (dot) dot.style.background = running ? 'var(--red)' : 'var(--text-muted)';
        if (dot && running) dot.style.boxShadow = '0 0 8px var(--red)';
        if (dot && !running) dot.style.boxShadow = 'none';
        if (text) {
            text.textContent = running ? 'ACTIVE — Intercepting' : 'Inactive';
            text.style.color = running ? 'var(--red)' : 'var(--text-muted)';
        }
        if (startBtn) startBtn.style.display = running ? 'none' : 'inline-flex';
        if (stopBtn) stopBtn.style.display = running ? 'inline-flex' : 'none';
        if (scanBtn) scanBtn.disabled = running;
        if (startAllBtn) startAllBtn.style.display = running ? 'none' : 'inline-flex';
    },

    async _pollMitmStatus() {
        try {
            const resp = await fetch('/api/mitm/status');
            const data = await resp.json();
            if (data.is_running) {
                this._showMitmRunning(true);
                const pktEl = document.getElementById('mitm-pkt-count');
                if (pktEl) pktEl.textContent = `${data.packets_sent} ARP pkts sent`;
            }
        } catch (e) { /* ignore */ }
    },

    async _pollTrafficTable() {
        try {
            const resp = await fetch('/api/mitm/activity');
            const data = await resp.json();

            const countEl = document.getElementById('traffic-ip-count');
            const entries = data.entries || [];
            if (countEl) countEl.textContent = `${entries.length} IPs active`;

            this._trafficData = entries;
            this._renderTrafficTable();

        } catch (e) { /* ignore */ }
    },

    sortTrafficBy(col) {
        if (this._trafficSort.col === col) {
            this._trafficSort.dir = this._trafficSort.dir === 'asc' ? 'desc' : 'asc';
        } else {
            this._trafficSort.col = col;
            // Default directions: traffic desc, rest asc
            this._trafficSort.dir = (col === 'data_volume' || col === 'rank') ? 'desc' : 'asc';
        }
        this._renderTrafficTable();
    },

    _renderTrafficTable() {
        const tbody = document.getElementById('traffic-table-body');
        if (!tbody) return;

        let entries = [...this._trafficData];

        if (entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="padding:20px;text-align:center;color:var(--text-muted);font-style:italic">No traffic detected yet...</td></tr>';
            this._updateSortArrows();
            return;
        }

        // Sort
        const { col, dir } = this._trafficSort;
        entries.sort((a, b) => {
            let va = a[col], vb = b[col];
            if (col === 'ip') {
                // Numeric IP sort
                const toNum = ip => ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct), 0);
                va = toNum(va || '0.0.0.0');
                vb = toNum(vb || '0.0.0.0');
            } else if (typeof va === 'string') {
                va = (va || '').toLowerCase();
                vb = (vb || '').toLowerCase();
            } else if (typeof va === 'boolean') {
                va = va ? 1 : 0;
                vb = vb ? 1 : 0;
            }
            if (va < vb) return dir === 'asc' ? -1 : 1;
            if (va > vb) return dir === 'asc' ? 1 : -1;
            return 0;
        });

        // Re-rank after sort
        entries.forEach((e, i) => e._displayRank = i + 1);

        tbody.innerHTML = entries.map(e => {
            const rank = e._displayRank;
            const rankColor = rank <= 3 ? 'var(--orange)' : 'var(--text-muted)';
            const rankWeight = rank <= 3 ? '700' : '400';
            const ipColor = e.intercepted ? 'var(--red)' : 'var(--cyan)';
            const badge = e.intercepted
                ? '<span style="display:inline-block;padding:1px 6px;border-radius:4px;background:rgba(255,59,92,0.2);color:var(--red);font-size:0.6rem;font-weight:600">INTERCEPTED</span>'
                : '<span style="display:inline-block;padding:1px 6px;border-radius:4px;background:rgba(0,209,178,0.1);color:var(--green);font-size:0.6rem;font-weight:500">PASSIVE</span>';

            const sites = (e.top_sites || []).map(s =>
                `<span style="color:var(--text-secondary);font-size:0.7rem" title="${s.hits} hits">${s.domain}</span>`
            ).join('<span style="color:var(--border);margin:0 3px">·</span>');

            const hostname = e.hostname
                ? `<span style="color:var(--green);font-size:0.72rem">${e.hostname}</span>`
                : `<span style="color:var(--text-muted);font-size:0.72rem;font-style:italic">—</span>`;

            const isExpanded = this._expandedIps.has(e.ip);
            const chevron = isExpanded ? '▾' : '▸';
            const allSites = e.all_sites || [];
            const hasSites = allSites.length > 0;

            let expandRow = '';
            if (isExpanded && hasSites) {
                const siteRows = allSites.map((s, i) => `
                    <div style="display:flex;justify-content:space-between;align-items:center;padding:3px 12px;${i > 0 ? 'border-top:1px solid var(--border)' : ''}">
                        <span style="color:var(--text-secondary);font-size:0.72rem;font-family:var(--font-mono)">${s.domain}</span>
                        <span style="color:var(--text-muted);font-size:0.68rem;font-family:var(--font-mono);min-width:45px;text-align:right">${s.hits}×</span>
                    </div>
                `).join('');
                expandRow = `
                    <tr class="traffic-expand-row">
                        <td colspan="6" style="padding:0;background:var(--bg-deep);border-bottom:1px solid var(--border)">
                            <div style="max-height:180px;overflow-y:auto;padding:4px 0;margin-left:30px;border-left:2px solid var(--cyan)">
                                <div style="padding:3px 12px;color:var(--cyan);font-size:0.68rem;font-weight:600;text-transform:uppercase">Sites accessed (${allSites.length})</div>
                                ${siteRows}
                            </div>
                        </td>
                    </tr>
                `;
            }

            return `
                <tr style="border-bottom:${isExpanded ? 'none' : '1px solid var(--border)'};transition:background 0.15s;${hasSites ? 'cursor:pointer' : ''}" 
                    onclick="SnifferPage.toggleTrafficRow('${e.ip}')" 
                    onmouseenter="this.style.background='var(--bg-deep)'" 
                    onmouseleave="this.style.background='transparent'">
                    <td style="padding:6px 8px;font-family:var(--font-mono);color:${rankColor};font-weight:${rankWeight};font-size:0.75rem">${hasSites ? '<span style="color:var(--text-muted);font-size:0.7rem;margin-right:2px">' + chevron + '</span>' : ''}${rank}</td>
                    <td style="padding:6px 8px;font-family:var(--font-mono);color:${ipColor};font-weight:500">${e.ip}</td>
                    <td style="padding:6px 8px">${hostname}</td>
                    <td style="padding:6px 8px;text-align:right;font-family:var(--font-mono);color:var(--text-primary);font-weight:500">${e.data_volume_formatted}</td>
                    <td style="padding:6px 8px">${sites || '<span style="color:var(--text-muted);font-size:0.7rem">—</span>'}</td>
                    <td style="padding:6px 8px;text-align:center">${badge}</td>
                </tr>
                ${expandRow}
            `;
        }).join('');

        this._updateSortArrows();
    },

    toggleTrafficRow(ip) {
        if (this._expandedIps.has(ip)) {
            this._expandedIps.delete(ip);
        } else {
            this._expandedIps.add(ip);
        }
        this._renderTrafficTable();
    },

    _updateSortArrows() {
        const cols = ['rank', 'ip', 'hostname', 'data_volume', 'intercepted'];
        for (const c of cols) {
            const th = document.getElementById('th-' + c);
            if (!th) continue;
            const arrow = th.querySelector('.sort-arrow');
            if (!arrow) continue;
            if (this._trafficSort.col === c) {
                arrow.textContent = this._trafficSort.dir === 'asc' ? ' ▲' : ' ▼';
                arrow.style.color = 'var(--cyan)';
            } else {
                arrow.textContent = '';
            }
        }
    },

    clearConsole() {
        const consoleEl = document.getElementById('sniff-console');
        if (consoleEl) {
            consoleEl.innerHTML = '';
            this._packetCount = 0;
            document.getElementById('sniff-packet-count').textContent = '0 packets';
        }
        this._knownProtocols.clear();
        this._visibleProtocols.clear();
        this._knownIps.clear();
        this._visibleIps.clear();
        this._lastPacketId = null;
        const filters = document.getElementById('sniff-filters');
        if (filters) filters.innerHTML = '<span class="empty-state" style="padding:0;font-size:0.85rem">Start sniffing to discover protocols</span>';
        const ipFilters = document.getElementById('sniff-ip-filters');
        if (ipFilters) ipFilters.innerHTML = '<span class="empty-state" style="padding:0;font-size:0.85rem">Start sniffing to discover IPs</span>';
    },

    selectBtn(type, selectAll) {
        if (type === 'ip') {
            const container = document.getElementById('sniff-ip-filters');
            if (!container) return;
            const checkboxes = container.querySelectorAll('input[type="checkbox"]');
            checkboxes.forEach(chk => {
                chk.checked = selectAll;
                if (selectAll) {
                    this._visibleIps.add(chk.value);
                } else {
                    this._visibleIps.delete(chk.value);
                }
            });
            this._applyAllFilters();
        }
    },

    toggleIp(ip, isVisible) {
        if (isVisible) {
            this._visibleIps.add(ip);
        } else {
            this._visibleIps.delete(ip);
        }
        this._applyAllFilters();
    },

    toggleProto(proto, isVisible) {
        if (isVisible) {
            this._visibleProtocols.add(proto);
        } else {
            this._visibleProtocols.delete(proto);
        }
        this._applyAllFilters();
    },

    _applyAllFilters() {
        const lines = document.querySelectorAll('.console-line');
        lines.forEach(line => {
            const proto = line.dataset.proto;
            const src = line.dataset.src;
            const dst = line.dataset.dst;

            const protoVisible = this._visibleProtocols.has(proto);
            const srcVisible = !src || this._visibleIps.has(src);
            const dstVisible = !dst || this._visibleIps.has(dst);
            const ipVisible = srcVisible && dstVisible;  // Hide if EITHER src or dst is filtered out

            line.style.display = (protoVisible && ipVisible) ? 'flex' : 'none';
        });
    },

    _updateFilters(protocols) {
        const container = document.getElementById('sniff-filters');
        if (!container) return;

        const empty = container.querySelector('.empty-state');
        if (empty && Object.keys(protocols).length > 0) {
            empty.remove();
        }

        for (const proto of Object.keys(protocols)) {
            if (!this._knownProtocols.has(proto)) {
                this._knownProtocols.add(proto);
                this._visibleProtocols.add(proto);
                
                const lbl = document.createElement('label');
                lbl.style.display = 'flex';
                lbl.style.alignItems = 'center';
                lbl.style.gap = '6px';
                lbl.style.cursor = 'pointer';
                lbl.style.fontSize = '0.85rem';
                lbl.innerHTML = `<input type="checkbox" checked value="${proto}" onchange="SnifferPage.toggleProto('${proto}', this.checked)"> <span class="badge badge-protocol ${this._protoClass(proto)}">${proto}</span>`;
                container.appendChild(lbl);
            }
        }
    },

    /**
     * Add an IP to the filter list.
     * AUTO-EXCLUDES the user's own local IP by default (unchecked).
     */
    _updateIpFilters(hosts) {
        const container = document.getElementById('sniff-ip-filters');
        if (!container) return;

        if (!hosts || hosts.length === 0) return;

        const empty = container.querySelector('.empty-state');
        if (empty) {
            empty.remove();
        }

        for (const host of hosts) {
            if (host && !this._knownIps.has(host)) {
                this._knownIps.add(host);

                // Auto-exclude the user's own IP
                const isLocal = (host === this._localIp);
                const isChecked = !isLocal;

                if (isChecked) {
                    this._visibleIps.add(host);
                }
                // If local IP, do NOT add to _visibleIps → filtered out by default
                
                const div = document.createElement('div');
                div.style.display = 'flex';
                div.style.alignItems = 'center';
                div.style.gap = '6px';
                div.style.padding = '2px 0';

                const localTag = isLocal 
                    ? '<span style="color:var(--orange);font-size:0.65rem;font-weight:600;margin-left:4px">(YOU)</span>' 
                    : '';

                div.innerHTML = `
                    <input type="checkbox" ${isChecked ? 'checked' : ''} value="${host}" id="chk-ip-${host.replace(/[^a-zA-Z0-9]/g, '_')}" onchange="SnifferPage.toggleIp('${host}', this.checked)">
                    <label for="chk-ip-${host.replace(/[^a-zA-Z0-9]/g, '_')}" style="cursor:pointer;font-size:0.8rem;font-family:var(--font-mono);color:${isLocal ? 'var(--orange)' : 'var(--text-primary)'};margin:0;user-select:none">${host}${localTag}</label>
                `;

                // Put local IP at the top of the list
                if (isLocal) {
                    container.insertBefore(div, container.firstChild);
                } else {
                    container.appendChild(div);
                }
            }
        }
    },

    _showRunning(running) {
        const startBtn = document.getElementById('btn-sniff-start');
        const stopBtn = document.getElementById('btn-sniff-stop');
        const indicator = document.getElementById('sniff-live-indicator');

        if (startBtn) startBtn.style.display = running ? 'none' : 'inline-flex';
        if (stopBtn) stopBtn.style.display = running ? 'inline-flex' : 'none';
        if (indicator) indicator.style.display = running ? 'inline-block' : 'none';

        const dot = document.getElementById('sniffer-live-dot');
        if (dot) dot.style.display = running ? 'block' : 'none';
    },

    _startPolling() {
        this._stopPolling();
        this._pollInterval = setInterval(() => this._poll(), 2000);
    },

    _stopPolling() {
        if (this._pollInterval) {
            clearInterval(this._pollInterval);
            this._pollInterval = null;
        }
    },

    async _poll() {
        try {
            const stats = await API.getSnifferStats();
            this._updateStats(stats);

            // Save local IP for filtering
            if (stats.local_ip && !this._localIp) {
                this._localIp = stats.local_ip;
                const label = document.getElementById('sniff-local-ip-label');
                if (label) label.textContent = `(Your IP: ${this._localIp} — auto-excluded)`;
            }

            if (!stats.is_running) {
                this._showRunning(false);
                this._stopPolling();
            }

            // Update IP filters
            if (stats.unique_hosts) {
                this._updateIpFilters(stats.unique_hosts);
            }

            // Load new packets
            await this._loadPackets();

            // Update protocol chart and filters
            this._updateProtoChart(stats.protocols);
            this._updateFilters(stats.protocols);

            // Update Network Intelligence panels
            this._updateIntel(stats);

            // Poll MITM status and traffic table
            this._pollMitmStatus();
            this._pollTrafficTable();
        } catch (e) { /* retry */ }
    },

    _updateStats(stats) {
        const el = (id) => document.getElementById(id);
        if (el('sniff-total'))    el('sniff-total').textContent = stats.total_packets;
        if (el('sniff-hosts'))    el('sniff-hosts').textContent = stats.unique_hosts_count;
        if (el('sniff-pps'))      el('sniff-pps').textContent = Math.round(stats.packets_per_second);
        if (el('sniff-duration')) el('sniff-duration').textContent = this._formatDuration(stats.duration);
        if (el('sniff-alerts'))   el('sniff-alerts').textContent = (stats.security_alerts || []).length;
        if (el('sniff-dns-count')) el('sniff-dns-count').textContent = (stats.dns_queries || []).length;
    },

    /**
     * Update the Network Intelligence panels with shock-value data.
     */
    _updateIntel(stats) {
        // ── Security Alerts ──────────────────────────────
        const alertsEl = document.getElementById('intel-alerts');
        const alertCountEl = document.getElementById('intel-alert-count');
        if (alertsEl && stats.security_alerts && stats.security_alerts.length > 0) {
            alertCountEl.textContent = stats.security_alerts.length;
            const severityColors = { critical: 'var(--red)', warning: 'var(--orange)', info: 'var(--cyan)' };
            const severityIcons = { critical: '🔴', warning: '🟠', info: '🔵' };
            alertsEl.innerHTML = stats.security_alerts.slice(-15).reverse().map(a => `
                <div class="intel-row" style="border-left:3px solid ${severityColors[a.severity] || 'var(--text-muted)'}">
                    <span style="font-size:0.8rem">${severityIcons[a.severity] || '⚪'}</span>
                    <div style="flex:1;min-width:0">
                        <div style="color:${severityColors[a.severity]};font-weight:600;font-size:0.78rem">${this._escapeHtml(a.message)}</div>
                        <div style="color:var(--text-muted);font-size:0.7rem">${a.src} → ${a.dst}</div>
                    </div>
                </div>
            `).join('');
        }

        // ── DNS Queries ──────────────────────────────────
        const dnsEl = document.getElementById('intel-dns');
        if (dnsEl && stats.dns_queries && stats.dns_queries.length > 0) {
            const sorted = [...stats.dns_queries]
                .filter(([domain]) => !domain.endsWith('.arpa'))
                .sort((a, b) => b[1] - a[1]);
            if (sorted.length > 0) {
                dnsEl.innerHTML = sorted.slice(0, 25).map(([domain, count]) => `
                    <div class="intel-row intel-row-dns">
                        <span class="intel-dns-domain">${this._escapeHtml(domain)}</span>
                        <span class="intel-dns-count">${count}×</span>
                    </div>
                `).join('');
            }
        }

        // ── Top Talkers ──────────────────────────────────
        const talkersEl = document.getElementById('intel-talkers');
        if (talkersEl && stats.top_talkers && stats.top_talkers.length > 0) {
            const filteredTalkers = stats.top_talkers.filter(([ip]) => ip !== this._localIp);
            if (filteredTalkers.length > 0) {
                const maxVol = filteredTalkers[0][1];
                talkersEl.innerHTML = filteredTalkers.slice(0, 15).map(([ip, bytes]) => {
                    const pct = (bytes / maxVol * 100).toFixed(0);
                    return `
                    <div class="intel-row" style="gap:8px">
                        <span class="mono" style="min-width:120px;color:var(--cyan);font-size:0.78rem">${ip}</span>
                        <div style="flex:1;height:4px;background:var(--bg-deep);border-radius:2px;overflow:hidden">
                            <div style="width:${pct}%;height:100%;background:var(--green);border-radius:2px"></div>
                        </div>
                        <span style="min-width:70px;text-align:right;font-size:0.75rem;color:var(--text-muted);font-family:var(--font-mono)">${this._formatBytes(bytes)}</span>
                    </div>`;
                }).join('');
            }
        }

        // ── Services Detected ────────────────────────────
        const servicesEl = document.getElementById('intel-services');
        if (servicesEl && stats.services) {
            const entries = Object.entries(stats.services).filter(([ip]) => ip !== this._localIp);
            if (entries.length > 0) {
                servicesEl.innerHTML = entries.slice(0, 15).map(([ip, svcs]) => `
                    <div class="intel-row" style="gap:8px">
                        <span class="mono" style="min-width:120px;color:var(--cyan);font-size:0.78rem">${ip}</span>
                        <div style="display:flex;gap:4px;flex-wrap:wrap">
                            ${svcs.map(s => {
                                const danger = ['FTP','Telnet','HTTP','SNMP','TFTP'].includes(s);
                                return `<span class="badge badge-protocol" style="${danger ? 'background:rgba(255,59,92,0.15);color:var(--red)' : ''}">${s}</span>`;
                            }).join('')}
                        </div>
                    </div>
                `).join('');
            }
        }

        // ── Device Activity Profiles ────────────────────
        if (stats.device_profiles) {
            this._renderDeviceProfiles(stats.device_profiles);
        }

        // ── Activity Feed ──────────────────────────────
        if (stats.activity_feed) {
            this._renderActivityFeed(stats.activity_feed);
        }
    },

    /**
     * Render per-device activity profiles — the "shock value" panel.
     */
    _renderDeviceProfiles(profiles) {
        const container = document.getElementById('device-profiles-container');
        const badge = document.getElementById('profile-count-badge');
        if (!container) return;

        // Filter out local IP and devices with no sites
        const filtered = profiles.filter(p => p.ip !== this._localIp && (p.sites_visited.length > 0 || p.http_urls.length > 0));

        if (badge) badge.textContent = `${filtered.length} device${filtered.length !== 1 ? 's' : ''} profiled`;

        if (!filtered.length) {
            container.innerHTML = '<div class="intel-empty" style="padding:20px">Capturing traffic to build device profiles... Browse sites on other devices to see their activity appear here.</div>';
            return;
        }

        container.innerHTML = filtered.map(p => {
            const isLocal = p.ip === this._localIp;
            const hostLabel = p.hostname ? `${p.hostname}` : '';
            const osLabel = p.os ? `<span style="color:var(--purple);font-size:0.7rem;margin-left:6px">${this._escapeHtml(p.os)}</span>` : '';
            const macLabel = p.mac ? `<span style="color:var(--text-muted);font-size:0.68rem;font-family:var(--font-mono);margin-left:6px">${p.mac}</span>` : '';

            // Sites visited — the key shock-value data
            const sitesHtml = p.sites_visited.slice(0, 30).map(([domain, count]) => {
                // Color-code by type
                let color = 'var(--text-secondary)';
                const d = domain.toLowerCase();
                if (d.includes('facebook') || d.includes('instagram') || d.includes('tiktok') || d.includes('twitter') || d.includes('reddit') || d.includes('snapchat'))
                    color = 'var(--cyan)';
                else if (d.includes('google') || d.includes('youtube') || d.includes('bing'))
                    color = 'var(--green)';
                else if (d.includes('bank') || d.includes('paypal') || d.includes('stripe'))
                    color = 'var(--orange)';

                return `<span style="display:inline-flex;align-items:center;gap:3px;padding:2px 8px;border-radius:4px;background:rgba(255,255,255,0.03);border:1px solid var(--border);font-size:0.72rem;color:${color};font-family:var(--font-mono)">${this._escapeHtml(domain)}<span style="color:var(--text-muted);font-size:0.6rem;margin-left:2px">×${count}</span></span>`;
            }).join(' ');

            // HTTP URLs (cleartext — extra shocking)
            const urlsHtml = p.http_urls.length > 0
                ? `<div style="margin-top:6px">
                     <span style="color:var(--red);font-size:0.68rem;font-weight:600">⚠ CLEARTEXT HTTP REQUESTS:</span>
                     <div style="margin-top:3px;display:flex;flex-direction:column;gap:2px;max-height:80px;overflow-y:auto">
                       ${p.http_urls.slice(-10).map(url => `<div style="font-family:var(--font-mono);font-size:0.68rem;color:var(--orange);padding:1px 6px;background:rgba(255,59,92,0.06);border-radius:3px;word-break:break-all">${this._escapeHtml(url)}</div>`).join('')}
                     </div>
                   </div>`
                : '';

            // User Agent
            const uaHtml = p.user_agents && p.user_agents.length > 0
                ? `<div style="margin-top:4px;font-size:0.65rem;color:var(--text-muted)">🌐 ${this._escapeHtml(p.user_agents[0].substring(0, 120))}</div>`
                : '';

            // Categories
            let catHtml = '';
            if (p.categories) {
                const cats = Object.entries(p.categories).sort((a,b) => b[1] - a[1]);
                if (cats.length > 0) {
                    catHtml = `<div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:6px">
                        ${cats.map(([c, count]) => `<span class="badge badge-category" style="background:${this._getCategoryColor(c)}20;color:${this._getCategoryColor(c)};border-color:${this._getCategoryColor(c)}40">${c.toUpperCase()} <span style="opacity:0.6;font-size:0.6rem">×${count}</span></span>`).join('')}
                    </div>`;
                }
            }

            // NSFW Warning
            const adultWarning = p.flag_adult ? `<div style="margin-bottom:6px;padding:4px 8px;background:rgba(255,59,92,0.1);border-left:3px solid var(--red);color:var(--red);font-size:0.7rem;font-weight:600;display:flex;align-items:center;gap:6px"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>ADULT/NSFW CONTENT DETECTED</div>` : '';

            // Timeline
            const timelineHtml = p.timeline && p.timeline.length > 0
                ? `<div style="margin-top:8px">
                     <div style="font-size:0.68rem;color:var(--text-muted);margin-bottom:4px;font-weight:600">RECENT ACTIVITY TIMELINE:</div>
                     <div style="display:flex;flex-direction:column;gap:2px;max-height:100px;overflow-y:auto;background:var(--bg-deep);padding:6px;border-radius:4px">
                       ${[...p.timeline].reverse().slice(0, 15).map(t => {
                           const isAdult = t.category === 'adult';
                           return `<div style="font-family:var(--font-mono);font-size:0.68rem;display:flex;gap:6px;color:${isAdult ? 'var(--red)' : 'var(--text-secondary)'}">
                             <span style="color:var(--text-muted)">[${this._formatTimestamp(t.timestamp)}]</span>
                             <span style="color:${this._getCategoryColor(t.category)};min-width:30px">[${t.protocol}]</span>
                             <span style="${isAdult ? 'font-weight:600' : ''}">${this._escapeHtml(t.domain)}</span>
                           </div>`;
                       }).join('')}
                     </div>
                   </div>`
                : '';

            const interceptedTag = p.intercepted ? `<span class="badge" style="background:rgba(255,59,92,0.15);color:var(--red);border-color:var(--red);font-weight:600;font-size:0.6rem;margin-left:6px">⚡ INTERCEPTED</span>` : '';

            return `
                <div style="padding:12px 16px;border-bottom:1px solid var(--border);${isLocal ? 'opacity:0.3' : ''}">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                        <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
                            <span style="font-weight:600;color:var(--cyan);font-family:var(--font-mono);font-size:0.85rem">${p.ip}</span>
                            ${hostLabel ? `<span style="color:var(--green);font-size:0.75rem;font-weight:500">${this._escapeHtml(hostLabel)}</span>` : ''}
                            ${osLabel}${macLabel}${interceptedTag}
                        </div>
                        <div style="display:flex;gap:12px;align-items:center">
                            <span style="font-size:0.7rem;color:var(--text-muted)" title="DNS resolved domains">🌍 ${p.domains_resolved || 0}</span>
                            <span style="font-size:0.7rem;color:var(--text-muted)">${this._formatBytes(p.data_volume)}</span>
                        </div>
                    </div>
                    ${adultWarning}
                    ${catHtml}
                    ${p.sites_visited.length > 0 ? `<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:4px">${sitesHtml}</div>` : ''}
                    ${urlsHtml}${uaHtml}${svcsHtml}${timelineHtml}
                </div>
            `;
        }).join('');
    },

    _renderActivityFeed(feed) {
        const container = document.getElementById('activity-feed-container');
        const count = document.getElementById('feed-count');
        const dot = document.getElementById('feed-live-dot');
        if (!container) return;

        if (dot) dot.style.display = feed.length > 0 ? 'inline-block' : 'none';
        if (count) count.textContent = `${feed.length} events`;

        if (!feed.length) {
            container.innerHTML = '<div class="intel-empty" style="padding:20px">Waiting for network activity...</div>';
            return;
        }

        container.innerHTML = feed.map(f => {
            const isAdult = f.category === 'adult';
            const catColor = this._getCategoryColor(f.category);
            const host = f.hostname ? `${f.ip} (${f.hostname})` : f.ip;
            const intercepted = f.intercepted ? '⚡ ' : '';
            return `
                <div style="padding:4px 8px;border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center;color:${isAdult ? 'var(--red)' : 'var(--text-primary)'};background:${isAdult ? 'rgba(255,59,92,0.05)' : 'transparent'}">
                    <span style="color:var(--text-muted);font-size:0.68rem;min-width:60px">[${this._formatTimestamp(f.timestamp)}]</span>
                    <span style="color:var(--cyan);min-width:120px">${intercepted}${this._escapeHtml(host)}</span>
                    <span style="color:var(--text-muted)">→</span>
                    <span style="flex:1;${isAdult ? 'font-weight:600' : ''}">${this._escapeHtml(f.domain)}</span>
                    ${f.category ? `<span style="font-size:0.65rem;padding:1px 6px;border-radius:4px;background:${catColor}20;color:${catColor}">${f.category.toUpperCase()}</span>` : ''}
                    <span style="font-size:0.65rem;color:var(--text-muted);min-width:30px;text-align:right">${f.protocol}</span>
                </div>
            `;
        }).join('');
    },

    _getCategoryColor(category) {
        const colors = {
            'adult': 'var(--red)',
            'social_media': 'var(--cyan)',
            'streaming': '#e1b12c',
            'gaming': '#9c88ff',
            'news': 'var(--text-secondary)',
            'finance': 'var(--green)',
            'shopping': '#e84118',
            'vpn_proxy': 'var(--orange)',
            'productivity': '#0097e6',
            'email': '#8c7ae6',
            'cloud_storage': '#00a8ff'
        };
        return colors[category] || 'var(--text-muted)';
    },

    async _loadPackets() {
        try {
            const data = await API.getPackets(200);
            const consoleEl = document.getElementById('sniff-console');
            if (!consoleEl || !data.packets.length) return;

            let sliceIndex = 0;
            if (this._lastPacketId) {
                const lastId = this._lastPacketId;
                const matchIdx = data.packets.findIndex(pkt => `${pkt.timestamp}-${pkt.src}-${pkt.dst}-${pkt.size}` === lastId);
                if (matchIdx !== -1) {
                    sliceIndex = matchIdx + 1;
                }
            }

            const newPackets = data.packets.slice(sliceIndex);
            if (newPackets.length === 0) return;

            const lastPkt = data.packets[data.packets.length - 1];
            this._lastPacketId = `${lastPkt.timestamp}-${lastPkt.src}-${lastPkt.dst}-${lastPkt.size}`;
            this._packetCount = data.count;

            document.getElementById('sniff-packet-count').textContent = `${this._packetCount} packets`;

            const empty = consoleEl.querySelector('.empty-state');
            if (empty) empty.remove();

            // Register new IPs
            const newHosts = [];
            for (const pkt of newPackets) {
                if (pkt.src) newHosts.push(pkt.src);
                if (pkt.dst) newHosts.push(pkt.dst);
            }
            this._updateIpFilters(newHosts);

            for (const pkt of newPackets) {
                const line = document.createElement('div');
                line.className = 'console-line';
                line.dataset.proto = pkt.protocol;
                line.dataset.src = pkt.src || '';
                line.dataset.dst = pkt.dst || '';
                
                const protoVisible = this._visibleProtocols.has(pkt.protocol);
                const srcVisible = !pkt.src || this._visibleIps.has(pkt.src);
                const dstVisible = !pkt.dst || this._visibleIps.has(pkt.dst);
                const ipVisible = srcVisible && dstVisible;
                if (!(protoVisible && ipVisible)) {
                    line.style.display = 'none';
                }

                const macInfo = (pkt.src_mac && pkt.src_mac !== pkt.src) 
                    ? `<span class="console-mac">[${pkt.src_mac}]</span>` 
                    : '';

                line.innerHTML = `
                    <span class="console-time">${this._formatTimestamp(pkt.timestamp)}</span>
                    <span class="console-proto"><span class="badge badge-protocol ${this._protoClass(pkt.protocol)}">${pkt.protocol}</span></span>
                    ${macInfo}
                    <span class="console-summary">${this._escapeHtml(pkt.summary)}</span>
                    <span class="console-size">${pkt.size}B</span>
                `;
                consoleEl.appendChild(line);
            }

            // Keep 500 lines in console (increased from 200)
            const lines = consoleEl.querySelectorAll('.console-line');
            if (lines.length > 500) {
                for (let i = 0; i < lines.length - 500; i++) {
                    lines[i].remove();
                }
            }

            if (this._autoScroll) {
                consoleEl.scrollTop = consoleEl.scrollHeight;
            }
        } catch (e) { /* ignore */ }
    },

    _updateProtoChart(protocols) {
        const container = document.getElementById('sniff-proto-chart');
        if (!container || !protocols) return;

        const entries = Object.entries(protocols).sort((a, b) => b[1] - a[1]);
        if (entries.length === 0) return;

        const maxCount = entries[0][1];
        const colorMap = {
            ARP: '#00f0ff', DNS: '#a55eea', DHCP: '#00ff88',
            HTTP: '#ff9f43', HTTPS: '#00b8c5', TCP: '#ffd32a',
            UDP: '#ff9f43', ICMP: '#ff3b5c', SSH: '#00ff88',
            SMB: '#ffd32a', NetBIOS: '#ff6b81', mDNS: '#a55eea',
            LLMNR: '#00b8c5', SSDP: '#ff9f43', NDP: '#00f0ff',
            NTP: '#8892a8', SNMP: '#ff6b81', RDP: '#ff3b5c',
            IPv6: '#a55eea', FTP: '#ff3b5c', Telnet: '#ff3b5c',
        };

        container.innerHTML = entries.slice(0, 12).map(([proto, count]) => `
            <div class="proto-bar-row">
                <span class="proto-bar-label">${proto}</span>
                <div class="proto-bar-track">
                    <div class="proto-bar-fill" style="width:${(count/maxCount)*100}%;background:${colorMap[proto] || '#5a6378'}"></div>
                </div>
                <span class="proto-bar-count">${count}</span>
            </div>
        `).join('');
    },

    _protoClass(protocol) {
        const p = protocol.toLowerCase().replace(/[^a-z]/g, '');
        const known = ['arp','dns','dhcp','http','https','tcp','udp','icmp','ssh','smb','mdns','llmnr','ssdp','netbios','ndp'];
        return known.includes(p) ? `proto-${p}` : 'proto-other';
    },

    _formatTimestamp(ts) {
        const d = new Date(ts * 1000);
        return d.toLocaleTimeString('en-US', { hour12: false, fractionalSecondDigits: 1 });
    },

    _formatDuration(seconds) {
        if (seconds < 60) return `${Math.round(seconds)}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
        return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
    },

    _formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
    },

    _escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },
};
