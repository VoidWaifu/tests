// Enhanced Service Worker for DPI Tunnel - /tests/ directory
const CACHE_NAME = 'dpi-tunnel-tests-v2';
const TUNNEL_PATH = '/tests/api/tunnel/';

// Security configuration
const AUTH_TOKENS = [
    'digital_hub_secure_token_2024_ultra_v3',
    'quantum_protection_key_advanced_2024',
    'encrypted_tunnel_access_pro_max_2024'
];

// Enhanced encryption
class EnhancedCrypto {
    encrypt(text) {
        // Simple XOR encryption for demo
        let result = '';
        const key = 'dpi_tunnel_key_2024';
        for (let i = 0; i < text.length; i++) {
            result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
        }
        return btoa(result);
    }

    decrypt(encryptedText) {
        try {
            const text = atob(encryptedText);
            let result = '';
            const key = 'dpi_tunnel_key_2024';
            for (let i = 0; i < text.length; i++) {
                result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
            }
            return result;
        } catch (e) {
            throw new Error('Decryption failed');
        }
    }
}

const crypto = new EnhancedCrypto();

// Service Worker lifecycle - FORCE activation
self.addEventListener('install', (event) => {
    console.log('🛠️ DPI Tunnel Service Worker installing...');
    self.skipWaiting(); // Force activation
});

self.addEventListener('activate', (event) => {
    console.log('🛠️ DPI Tunnel Service Worker activating...');
    event.waitUntil(
        Promise.all([
            self.clients.claim(), // Take control immediately
            caches.keys().then(cacheNames => {
                return Promise.all(
                    cacheNames.map(cacheName => {
                        if (cacheName !== CACHE_NAME) {
                            console.log('🛠️ Deleting old cache:', cacheName);
                            return caches.delete(cacheName);
                        }
                    })
                );
            })
        ])
    );
});

// Enhanced fetch handling - intercept ALL requests
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    const pathname = url.pathname;
    
    // Log all requests for debugging
    console.log('🛠️ Intercepting request:', pathname, event.request.method);
    
    // Handle tunnel API requests
    if (pathname.startsWith(TUNNEL_PATH)) {
        console.log('🛠️ Processing tunnel request:', pathname);
        event.respondWith(handleTunnelRequest(event.request));
        return;
    }
    
    // Handle direct API requests (without /tests/ prefix in some cases)
    if (pathname.includes('/api/tunnel/')) {
        console.log('🛠️ Processing direct API request:', pathname);
        event.respondWith(handleTunnelRequest(event.request));
        return;
    }
    
    // For HTML pages, use cache-first strategy
    if (pathname.endsWith('.html') || pathname === '/tests/' || pathname === '/tests') {
        event.respondWith(handleHtmlRequest(event.request));
        return;
    }
    
    // For all other requests, use network-first strategy
    event.respondWith(fetch(event.request));
});

// Handle HTML requests with caching
async function handleHtmlRequest(request) {
    try {
        // Try network first
        const networkResponse = await fetch(request);
        if (networkResponse.status === 200) {
            const cache = await caches.open(CACHE_NAME);
            cache.put(request, networkResponse.clone());
        }
        return networkResponse;
    } catch (error) {
        // Fallback to cache
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }
        return new Response('Page not available', { status: 503 });
    }
}

// Enhanced tunnel request handler
async function handleTunnelRequest(request) {
    console.log('🛠️ Handling tunnel request:', request.url, request.method);
    
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
        console.log('🛠️ Handling CORS preflight');
        return new Response(null, {
            status: 200,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD',
                'Access-Control-Allow-Headers': 'Content-Type, X-Auth-Token, X-Session-ID, Authorization, *',
                'Access-Control-Max-Age': '86400',
                'Access-Control-Allow-Credentials': 'true'
            }
        });
    }

    try {
        const url = new URL(request.url);
        let action = url.pathname.split('/').pop();
        
        // Handle different path formats
        if (url.pathname.includes('/api/tunnel/')) {
            const parts = url.pathname.split('/');
            action = parts[parts.length - 1];
        }
        
        console.log(`🛠️ Processing tunnel action: ${action}`, {
            method: request.method,
            headers: Object.fromEntries(request.headers.entries())
        });

        switch (action) {
            case 'connect':
                return await handleConnect(request);
            case 'proxy':
                return await handleProxy(request);
            case 'health-check':
            case 'health':
                return await handleHealthCheck(request);
            case 'status':
                return await handleStatus(request);
            case 'test':
                return await handleTest(request);
            default:
                console.log('🛠️ Unknown action, trying fallback');
                // Try to handle as connect if it's a POST request
                if (request.method === 'POST') {
                    return await handleConnect(request);
                }
                return createJsonResponse({ error: 'Unknown action: ' + action }, 404);
        }
    } catch (error) {
        console.error('🛠️ Tunnel request error:', error);
        return createJsonResponse({ error: 'Internal server error: ' + error.message }, 500);
    }
}

// Enhanced connect handler
async function handleConnect(request) {
    console.log('🛠️ Handling connect request');
    
    // Allow both POST and GET for connect
    if (request.method !== 'POST' && request.method !== 'GET') {
        return createJsonResponse({ error: 'Method not allowed' }, 405);
    }

    let authToken;
    
    if (request.method === 'POST') {
        try {
            const data = await request.json();
            authToken = data.authToken || request.headers.get('X-Auth-Token');
        } catch (e) {
            authToken = request.headers.get('X-Auth-Token');
        }
    } else {
        authToken = request.headers.get('X-Auth-Token');
    }

    console.log(`🛠️ Connect request with auth token: ${authToken ? authToken.substring(0, 10) + '...' : 'none'}`);

    if (!AUTH_TOKENS.includes(authToken)) {
        return createJsonResponse({ error: 'Authentication failed' }, 401);
    }

    // Create session
    const sessionId = generateSessionId();
    const responseData = {
        status: 'connected',
        sessionId: sessionId,
        message: 'Tunnel service ready - Enhanced Service Worker',
        timestamp: Date.now(),
        version: '2.0',
        capabilities: ['proxy', 'health-check', 'status', 'test'],
        basePath: '/tests/',
        method: request.method,
        swActive: true
    };

    console.log(`🛠️ New session created: ${sessionId}`);
    return createJsonResponse(responseData);
}

// Enhanced proxy handler
async function handleProxy(request) {
    console.log('🛠️ Handling proxy request');
    
    if (request.method !== 'POST') {
        return createJsonResponse({ error: 'Method not allowed' }, 405);
    }

    try {
        let data;
        let target, method, sessionId, authToken;
        
        try {
            data = await request.json();
            target = data.target;
            method = data.method;
            sessionId = data.sessionId;
            authToken = data.authToken || request.headers.get('X-Auth-Token');
        } catch (e) {
            return createJsonResponse({ error: 'Invalid JSON in request body' }, 400);
        }

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
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
            }
        });

        const response = await fetch(proxyRequest);
        const responseText = await response.text();

        const proxyResponse = {
            status: response.status,
            data: crypto.encrypt(responseText),
            headers: {
                'content-type': response.headers.get('content-type') || 'text/plain',
                'x-original-status': response.status.toString()
            },
            timestamp: Date.now(),
            target: target,
            encrypted: true,
            swVersion: '2.0'
        };

        console.log(`🛠️ Proxy successful: ${target} -> ${response.status}`);
        return createJsonResponse(proxyResponse);

    } catch (error) {
        console.error('🛠️ Proxy error:', error);
        return createJsonResponse({ error: 'Proxy error: ' + error.message }, 500);
    }
}

// Enhanced health check
async function handleHealthCheck(request) {
    console.log('🛠️ Handling health check');
    
    const healthData = {
        status: 'operational',
        service: 'dpi-tunnel-enhanced',
        timestamp: Date.now(),
        version: '2.0',
        uptime: Math.floor(performance.now() / 1000),
        features: ['encryption', 'authentication', 'proxy', 'cors'],
        directory: '/tests/',
        endpoints: [
            '/tests/api/tunnel/connect',
            '/tests/api/tunnel/proxy', 
            '/tests/api/tunnel/health-check',
            '/tests/api/tunnel/status',
            '/tests/api/tunnel/test'
        ],
        swActive: true,
        corsEnabled: true
    };

    return createJsonResponse(healthData);
}

// Enhanced status
async function handleStatus(request) {
    const statusData = {
        service: 'DPI Tunnel Enhanced Service Worker',
        version: '2.0',
        timestamp: Date.now(),
        environment: 'production',
        baseUrl: 'https://voidwaifu.github.io/tests/',
        endpoints: ['connect', 'proxy', 'health-check', 'status', 'test'],
        swActive: true
    };

    return createJsonResponse(statusData);
}

// Enhanced test endpoint
async function handleTest(request) {
    const testData = {
        message: 'Enhanced test endpoint working!',
        service: 'DPI Tunnel Enhanced',
        directory: '/tests/',
        timestamp: Date.now(),
        randomId: Math.random().toString(36).substr(2, 9),
        swVersion: '2.0',
        corsTest: 'success'
    };

    return createJsonResponse(testData);
}

// Utility functions
function createJsonResponse(data, status = 200) {
    console.log(`🛠️ Creating JSON response: ${status}`, data);
    return new Response(JSON.stringify(data), {
        status: status,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD',
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Expose-Headers': '*',
            'X-Service-Worker': 'active',
            'X-DPI-Tunnel': 'enabled'
        }
    });
}

function generateSessionId() {
    return 'enhanced_session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
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

// Message handling for client communication
self.addEventListener('message', (event) => {
    console.log('🛠️ Received message from client:', event.data);
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
});

console.log('🛠️ Enhanced DPI Tunnel Service Worker loaded successfully - /tests/ directory');
