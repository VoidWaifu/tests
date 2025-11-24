// FINAL Service Worker for DPI Tunnel - Simple and Reliable
const CACHE_NAME = 'dpi-tunnel-final-v1';
const TUNNEL_PATH = '/tests/api/tunnel/';

// Security configuration
const AUTH_TOKENS = [
    'digital_hub_secure_token_2024_ultra_v3',
    'quantum_protection_key_advanced_2024',
    'encrypted_tunnel_access_pro_max_2024'
];

// Service Worker lifecycle - SIMPLE and RELIABLE
self.addEventListener('install', (event) => {
    console.log('🛠️ FINAL Service Worker installing...');
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    console.log('🛠️ FINAL Service Worker activating...');
    event.waitUntil(self.clients.claim());
});

// SIMPLE fetch handling - only handle API requests
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    const pathname = url.pathname;
    
    // ONLY handle tunnel API requests
    if (pathname.startsWith(TUNNEL_PATH)) {
        console.log('🛠️ Intercepting tunnel request:', pathname);
        event.respondWith(handleTunnelRequest(event.request));
        return;
    }
    
    // For all other requests, let them through
    return;
});

// SIMPLE tunnel request handler
async function handleTunnelRequest(request) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
        return new Response(null, {
            status: 200,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, X-Auth-Token',
                'Access-Control-Max-Age': '86400'
            }
        });
    }

    try {
        const action = new URL(request.url).pathname.split('/').pop();
        console.log('🛠️ Processing action:', action);

        switch (action) {
            case 'connect':
                return await handleConnect(request);
            case 'health-check':
                return await handleHealthCheck(request);
            case 'test':
                return await handleTest(request);
            case 'simple-proxy':
                return await handleSimpleProxy(request);
            default:
                return createJsonResponse({ error: 'Unknown action' }, 404);
        }
    } catch (error) {
        console.error('🛠️ Tunnel error:', error);
        return createJsonResponse({ error: 'Server error' }, 500);
    }
}

// SIMPLE connect handler
async function handleConnect(request) {
    // Allow both GET and POST
    let authToken;
    
    if (request.method === 'POST') {
        try {
            const data = await request.json();
            authToken = data.authToken;
        } catch (e) {
            authToken = request.headers.get('X-Auth-Token');
        }
    } else if (request.method === 'GET') {
        const url = new URL(request.url);
        authToken = url.searchParams.get('token');
    } else {
        return createJsonResponse({ error: 'Method not allowed' }, 405);
    }

    console.log('🛠️ Connect attempt with token:', authToken ? 'provided' : 'missing');

    if (!AUTH_TOKENS.includes(authToken)) {
        return createJsonResponse({ error: 'Authentication failed' }, 401);
    }

    const responseData = {
        status: 'connected',
        sessionId: 'final_session_' + Date.now(),
        message: 'FINAL Tunnel Service Ready',
        timestamp: Date.now(),
        version: 'final',
        method: request.method
    };

    return createJsonResponse(responseData);
}

// SIMPLE health check
async function handleHealthCheck(request) {
    const healthData = {
        status: 'operational',
        service: 'dpi-tunnel-final',
        timestamp: Date.now(),
        version: 'final',
        message: 'Service Worker is ACTIVE and responding'
    };

    return createJsonResponse(healthData);
}

// SIMPLE test endpoint
async function handleTest(request) {
    const testData = {
        message: 'FINAL test endpoint working!',
        timestamp: Date.now(),
        success: true,
        simple: true
    };

    return createJsonResponse(testData);
}

// SIMPLE proxy handler
async function handleSimpleProxy(request) {
    if (request.method !== 'GET') {
        return createJsonResponse({ error: 'Only GET supported' }, 405);
    }

    try {
        const url = new URL(request.url);
        const target = url.searchParams.get('url');
        
        if (!target) {
            return createJsonResponse({ error: 'No URL provided' }, 400);
        }

        console.log('🛠️ Proxying to:', target);
        
        const response = await fetch(target, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        });
        
        const text = await response.text();
        
        const proxyResponse = {
            status: response.status,
            data: btoa(unescape(encodeURIComponent(text))), // Simple base64
            target: target,
            timestamp: Date.now(),
            encoded: true
        };

        return createJsonResponse(proxyResponse);

    } catch (error) {
        return createJsonResponse({ error: 'Proxy failed: ' + error.message }, 500);
    }
}

// SIMPLE JSON response
function createJsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data, null, 2), {
        status: status,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'X-Service-Worker': 'final'
        }
    });
}

console.log('🛠️ FINAL Service Worker loaded successfully!');
