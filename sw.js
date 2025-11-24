// Simple Service Worker for DPI Tunnel Testing
const CACHE_NAME = 'dpi-tunnel-test-v1';
const TUNNEL_PATH = '/api/tunnel/';

// Security configuration
const AUTH_TOKENS = [
    'digital_hub_secure_token_2024_ultra_v3',
    'quantum_protection_key_advanced_2024',
    'encrypted_tunnel_access_pro_max_2024'
];

// Simple encryption (for demo purposes)
class SimpleCrypto {
    encrypt(text) {
        return btoa(unescape(encodeURIComponent(text)));
    }

    decrypt(encryptedText) {
        try {
            return decodeURIComponent(escape(atob(encryptedText)));
        } catch (e) {
            throw new Error('Decryption failed');
        }
    }
}

const simpleCrypto = new SimpleCrypto();

// Service Worker lifecycle
self.addEventListener('install', (event) => {
    console.log('🛠️ Service Worker installing...');
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    console.log('🛠️ Service Worker activated');
    event.waitUntil(self.clients.claim());
});

// Handle fetch events
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    
    // Handle tunnel API requests
    if (url.pathname.startsWith(TUNNEL_PATH)) {
        event.respondWith(handleTunnelRequest(event.request));
        return;
    }
    
    // For all other requests, use network-first strategy
    event.respondWith(fetch(event.request));
});

// Handle tunnel requests
async function handleTunnelRequest(request) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
        return new Response(null, {
            status: 200,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, X-Auth-Token, X-Session-ID',
                'Access-Control-Max-Age': '86400'
            }
        });
    }

    try {
        const action = request.url.split('/').pop();
        console.log(`🛠️ Processing tunnel action: ${action}`);

        switch (action) {
            case 'connect':
                return await handleConnect(request);
            case 'proxy':
                return await handleProxy(request);
            case 'health-check':
                return await handleHealthCheck(request);
            case 'status':
                return await handleStatus(request);
            default:
                return createJsonResponse({ error: 'Unknown action: ' + action }, 404);
        }
    } catch (error) {
        console.error('Tunnel request error:', error);
        return createJsonResponse({ error: 'Internal server error: ' + error.message }, 500);
    }
}

// Handle connect request
async function handleConnect(request) {
    if (request.method !== 'POST') {
        return createJsonResponse({ error: 'Method not allowed' }, 405);
    }

    const authToken = request.headers.get('X-Auth-Token');
    console.log(`🛠️ Connect request with auth token: ${authToken ? authToken.substring(0, 10) + '...' : 'none'}`);

    if (!AUTH_TOKENS.includes(authToken)) {
        return createJsonResponse({ error: 'Authentication failed' }, 401);
    }

    // Create session
    const sessionId = generateSessionId();
    const responseData = {
        status: 'connected',
        sessionId: sessionId,
        message: 'Tunnel service ready',
        timestamp: Date.now(),
        version: '1.0',
        capabilities: ['proxy', 'health-check', 'status']
    };

    console.log(`🛠️ New session created: ${sessionId}`);
    return createJsonResponse(responseData);
}

// Handle proxy request
async function handleProxy(request) {
    if (request.method !== 'POST') {
        return createJsonResponse({ error: 'Method not allowed' }, 405);
    }

    try {
        const data = await request.json();
        const { target, method, sessionId, authToken } = data;

        console.log(`🛠️ Proxy request for: ${target}`);

        // Validate session
        if (!AUTH_TOKENS.includes(authToken)) {
            return createJsonResponse({ error: 'Authentication failed' }, 401);
        }

        if (!target) {
            return createJsonResponse({ error: 'No target URL provided' }, 400);
        }

        // Validate target URL
        if (!isValidTarget(target)) {
            return createJsonResponse({ error: 'Invalid target URL' }, 400);
        }

        // Make the proxy request
        const proxyRequest = new Request(target, {
            method: method || 'GET',
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        });

        const response = await fetch(proxyRequest);
        const responseText = await response.text();

        const proxyResponse = {
            status: response.status,
            data: simpleCrypto.encrypt(responseText),
            headers: {
                'content-type': response.headers.get('content-type') || 'text/plain'
            },
            timestamp: Date.now(),
            target: target
        };

        console.log(`🛠️ Proxy successful: ${target} -> ${response.status}`);
        return createJsonResponse(proxyResponse);

    } catch (error) {
        console.error('Proxy error:', error);
        return createJsonResponse({ error: 'Proxy error: ' + error.message }, 500);
    }
}

// Handle health check
async function handleHealthCheck(request) {
    const healthData = {
        status: 'operational',
        service: 'dpi-tunnel',
        timestamp: Date.now(),
        version: '1.0',
        uptime: Math.floor(performance.now() / 1000),
        features: ['encryption', 'authentication', 'proxy']
    };

    return createJsonResponse(healthData);
}

// Handle status request
async function handleStatus(request) {
    const statusData = {
        service: 'DPI Tunnel Service Worker',
        version: '1.0',
        timestamp: Date.now(),
        environment: 'production',
        endpoints: ['/connect', '/proxy', '/health-check', '/status']
    };

    return createJsonResponse(statusData);
}

// Utility functions
function createJsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status: status,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    });
}

function generateSessionId() {
    return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

function isValidTarget(url) {
    try {
        const parsed = new URL(url);
        return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
        return false;
    }
}

// Background sync for updates
self.addEventListener('sync', (event) => {
    if (event.tag === 'background-sync') {
        console.log('🛠️ Background sync triggered');
    }
});

console.log('🛠️ DPI Tunnel Service Worker loaded successfully');
