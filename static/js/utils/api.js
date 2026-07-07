/**
 * API Client — thin fetch wrapper for backend communication.
 * KISS: no axios, no abstraction layers. Just fetch + JSON.
 */
const API = {
    /**
     * Make an API request.
     * @param {string} endpoint - API path (e.g. "/api/inventory")
     * @param {object} options - fetch options
     * @returns {Promise<any>} parsed JSON response
     */
    async request(endpoint, options = {}) {
        const defaults = {
            headers: { 'Content-Type': 'application/json' },
        };

        const config = { ...defaults, ...options };

        try {
            const response = await fetch(endpoint, config);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || `HTTP ${response.status}`);
            }

            return data;
        } catch (error) {
            if (error.message === 'Failed to fetch') {
                throw new Error('Cannot connect to server');
            }
            throw error;
        }
    },

    get(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    },

    post(endpoint, body = {}) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(body),
        });
    },

    delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    },

    // ── Discovery ──────────────────────────────────────────
    getInterfaces()     { return this.get('/api/interfaces'); },
    getScanners()       { return this.get('/api/scanners'); },
    startScan(config)   { return this.post('/api/discovery/scan', config); },
    getScanStatus()     { return this.get('/api/discovery/status'); },
    stopScan()          { return this.post('/api/discovery/stop'); },

    // ── Passive Discovery ─────────────────────────────────
    getPassiveDiscoveryStatus() { return this.get('/api/passive-discovery/status'); },
    startPassiveDiscovery(config = {}) { return this.post('/api/passive-discovery/start', config); },
    stopPassiveDiscovery()  { return this.post('/api/passive-discovery/stop'); },

    // ── Inventory ──────────────────────────────────────────
    getInventory(params = {}) {
        const query = new URLSearchParams(params).toString();
        return this.get(`/api/inventory${query ? '?' + query : ''}`);
    },
    getDevice(id)       { return this.get(`/api/inventory/${id}`); },
    deleteDevice(id)    { return this.delete(`/api/inventory/${id}`); },
    clearInventory()    { return this.post('/api/inventory/clear'); },

    // ── Sniffer ────────────────────────────────────────────
    startSniffer(config) { return this.post('/api/sniffer/start', config); },
    stopSniffer()        { return this.post('/api/sniffer/stop'); },
    getSnifferStats()    { return this.get('/api/sniffer/stats'); },
    getPackets(count=50) { return this.get(`/api/sniffer/packets?count=${count}`); },

    // ── Stats ──────────────────────────────────────────────
    getStats()          { return this.get('/api/stats'); },
};
