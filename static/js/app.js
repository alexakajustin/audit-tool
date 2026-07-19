/**
 * App — SPA router, global state, and utilities.
 * KISS: hash-based routing, no framework, no build step.
 */
const App = {
    _currentPage: null,
    _pages: {
        dashboard: DashboardPage,
        discovery: DiscoveryPage,
        inventory: InventoryPage,
        sniffer:   SnifferPage,
        vlans:     VLANsPage,
    },

    /**
     * Initialize the application.
     */
    init() {
        // Connect WebSocket
        WS.connect();

        // Route on hash change
        window.addEventListener('hashchange', () => this._route());

        // Initial route
        this._route();
    },

    /**
     * Hash-based router.
     */
    _route() {
        const hash = window.location.hash.replace('#', '') || 'dashboard';
        const page = this._pages[hash];

        if (!page) {
            window.location.hash = '#dashboard';
            return;
        }

        // Destroy current page
        if (this._currentPage && this._currentPage.destroy) {
            this._currentPage.destroy();
        }

        // Update nav
        document.querySelectorAll('.nav-item').forEach(el => {
            el.classList.toggle('active', el.dataset.page === hash);
        });

        // Update header
        document.getElementById('page-title').textContent = page.title || hash;
        document.getElementById('page-subtitle').textContent = page.subtitle || '';

        // Render page
        const container = document.getElementById('page-content');
        this._currentPage = page;
        page.render(container);
    },

    /**
     * Show a toast notification.
     * @param {string} message
     * @param {'success'|'error'|'info'|'warning'} type
     * @param {number} duration - ms before auto-dismiss
     */
    toast(message, type = 'info', duration = 4000) {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        container.appendChild(toast);

        setTimeout(() => {
            toast.classList.add('toast-out');
            setTimeout(() => toast.remove(), 200);
        }, duration);
    },
};

// Boot
document.addEventListener('DOMContentLoaded', () => App.init());
