/**
 * Inventory Component — device inventory with search, sort, filter, and export.
 */
const InventoryPage = {
    _currentSort: { by: 'last_seen', order: 'desc' },
    _searchDebounce: null,

    title: 'Inventory',
    subtitle: 'All discovered network devices',

    async render(container) {
        container.innerHTML = `
            <div class="fade-in">
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

        await this._reload();
    },

    destroy() {
        if (this._searchDebounce) clearTimeout(this._searchDebounce);
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
                                <td class="mono" style="color:var(--cyan)">${d.ip || '—'}</td>
                                <td class="mono">${d.mac}</td>
                                <td>${d.vendor || '—'}</td>
                                <td>${d.hostname || '—'}</td>
                                <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis" title="${d.os || ''}">${d.os || '—'}</td>
                                <td>
                                    ${d.ports.length > 0
                                        ? d.ports.slice(0, 5).map(p =>
                                            `<span class="badge badge-scanner" style="margin:1px">${p.port}</span>`
                                        ).join('') + (d.ports.length > 5 ? `<span style="color:var(--text-muted)">+${d.ports.length - 5}</span>` : '')
                                        : '—'}
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
        if (!ts) return '—';
        const d = new Date(ts * 1000);
        return d.toLocaleString();
    },
};
