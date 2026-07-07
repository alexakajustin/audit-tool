/**
 * WebSocket Client — manages Socket.IO connections for real-time updates.
 */
const WS = {
    _socket: null,
    _listeners: {},

    /**
     * Initialize the Socket.IO connection.
     */
    connect() {
        if (this._socket && this._socket.connected) return;

        try {
            this._socket = io({ transports: ['websocket', 'polling'] });

            this._socket.on('connect', () => {
                console.log('[WS] Connected');
            });

            this._socket.on('disconnect', () => {
                console.log('[WS] Disconnected');
            });

            // Re-register stored listeners
            for (const [event, callbacks] of Object.entries(this._listeners)) {
                for (const cb of callbacks) {
                    this._socket.on(event, cb);
                }
            }
        } catch (e) {
            console.warn('[WS] Socket.IO not available:', e.message);
        }
    },

    /**
     * Subscribe to a WebSocket event.
     * @param {string} event - event name
     * @param {function} callback - handler function
     */
    on(event, callback) {
        if (!this._listeners[event]) {
            this._listeners[event] = [];
        }
        this._listeners[event].push(callback);

        if (this._socket) {
            this._socket.on(event, callback);
        }
    },

    /**
     * Remove a listener.
     */
    off(event, callback) {
        if (this._listeners[event]) {
            this._listeners[event] = this._listeners[event].filter(cb => cb !== callback);
        }
        if (this._socket) {
            this._socket.off(event, callback);
        }
    },

    /**
     * Emit an event to the server.
     */
    emit(event, data) {
        if (this._socket) {
            this._socket.emit(event, data);
        }
    },

    /**
     * Check if connected.
     */
    get connected() {
        return this._socket && this._socket.connected;
    }
};
