// Ultimate Service Worker for DPI Tunnel - /tests/ directory
const CACHE_NAME = 'dpi-tunnel-ultimate-v3';
const TUNNEL_PATH = '/tests/api/tunnel/';

// Security configuration
const AUTH_TOKENS = [
    'digital_hub_secure_token_2024_ultra_v3',
    'quantum_protection_key_advanced_2024',
    'encrypted_tunnel_access_pro_max_2024'
];

// Enhanced encryption
class UltimateCrypto {
    encrypt(text) {
        let result = '';
        const key = 'dpi_tunnel_ultimate_key_2024';
        for (let i = 0; i < text.length; i++) {
            result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
        }
        return btoa(result);
    }

    decrypt(encryptedText) {
        try {
            const text = atob(encryptedText);
            let result = '';
            const key = 'dpi_tunnel_ultimate_key_2024';
            for (let i = 0; i < text.length; i++) {
                result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
            }
            return result;
        } catch (e) {
            throw new Error('Decryption failed');
        }
    }
}

const crypto = new UltimateCrypto();

// Service Worker lifecycle - ULTIMATE activation
self.addEventListener('install', (event) => {
    console.log('🚀 Ultimate Service Worker installing...');
    event.waitUntil(self.skipWaiting()); // Force immediate activation
});

self.addEventListener('activate', (event) => {
    console.log('🚀 Ultimate Service Worker activating...');
    event.waitUntil(
        Promise.all([
            self.clients.claim(), // Control all clients immediately
            caches.keys().then(cacheNames => {
                return Promise.all(
                    cacheNames.map(cacheName => {
                        if (cacheName !== CACHE_NAME) {
                            console.log('🗑️ Deleting old cache:', cacheName);
                            return caches.delete(cacheName);
                        }
                    })
                );
            })
        ]).then(() => {
            console.log('✅ Ultimate Service Worker fully activated!');
            // Send message to all clients
            self.clients.matchAll().then(clients => {
                clients.forEach(client => {
                    client.postMessage({
                        type: 'SW_ACTIVATED',
                        version: '3.0'
                    });
                });
            });
        })
    );
});

// ULTIMATE fetch handling - intercept EVERYTHING
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    const pathname = url.pathname;
    
    // Log all requests for debugging
    console.log('🌐 Intercepting request:', pathname, event.request.method);
    
    // Handle ALL tunnel API requests
    if (pathname.startsWith(TUNNEL_PATH) || pathname.includes('/api/tunnel/')) {
        console.log('🚀 Processing tunnel request:', pathname);
        event.respondWith(handleTunnelRequest(event.request));
        return;
    }
    
    // Handle HTML pages with .html extension in API paths (our workaround)
    if (pathname.includes('/api/tunnel/') && pathname.endsWith('.html')) {
        console.log('🔄 Handling HTML workaround for:', pathname);
        event.respondWith(handleHtmlWorkaround(event.request));
        return;
    }
    
    // For regular HTML pages, use cache-first strategy
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

// Handle HTML workaround files
async function handleHtmlWorkaround(request) {
    const url = new URL(request.url);
    const action = url.pathname.split('/').pop().replace('.html', '');
    
    console.log('🔄 Processing HTML workaround for action:', action);
    
    // Return a simple HTML page that will trigger the real API call
    const htmlContent = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>DPI Tunnel - ${action}</title>
            <script>
                // Auto-execute the API call
                const action = '${action}';
                const token = new URLSearchParams(window.location.search).get('token');
                
                fetch('/tests/api/tunnel/' + action, {
                    method: 'POST',
                    headers: token ? {'X-Auth-Token': token} : {}
                })
                .then(response => response.json())
                .then(data => {
                    document.body.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                })
                .catch(error => {
                    document.body.innerHTML = 'Error: ' + error;
                });
            </script>
        </head>
        <body>
            Loading ${action} endpoint via Service Worker...
        </body>
        </html>
    `;
    
    return new Response(htmlContent, {
        status: 200,
        headers: {
            'Content-Type': 'text/html',
            'X-Service-Worker': 'active'
        }
    });
}

// ULTIMATE tunnel request handler
async function handleTunnelRequest(request) {
    console.log('🚀 Handling tunnel request:', request.url, request.method);
    
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
        console.log('🔄 Handling CORS preflight');
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
        
        console.log(`🚀 Processing tunnel action: ${action}`, {
            method: request.method,
            url: request.url,
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
                console.log('🔄 Unknown action, trying fallback to connect');
                return await handleConnect(request);
        }
    } catch (error) {
        console.error('❌ Tunnel request error:', error);
        return createJsonResponse({ error: 'Internal server error: ' + error.message }, 500);
    }
}

// ULTIMATE connect handler
async function handleConnect(request) {
    console.log('🚀 Handling connect request');
    
    // Allow all methods for maximum compatibility
    let authToken;
    
    if (request.method === 'POST') {
        try {
            const data = await request.json();
            authToken = data.authToken || request.headers.get('X-Auth-Token');
        } catch (e) {
            authToken = request.headers.get('X-Auth-Token');
        }
    } else {
        authToken = request.headers.get('X-Auth-Token') || 
                   new URL(request.url).searchParams.get('token');
    }

    console.log(`🔐 Connect request with auth token: ${authToken ? authToken.substring(0, 10) + '...' : 'none'}`);

    if (!AUTH_TOKENS.includes(authToken)) {
        return createJsonResponse({ error: 'Authentication failed' }, 401);
    }

    // Create session
    const sessionId = generateSessionId();
    const responseData = {
        status: 'connected',
        sessionId: sessionId,
        message: 'Ultimate Tunnel Service Ready',
        timestamp: Date.now(),
        version: '3.0',
        capabilities: ['proxy', 'health-check', 'status', 'test'],
        basePath: '/tests/',
        method: request.method,
        swActive: true,
        ultimate: true
    };

    console.log(`✅ New session created: ${sessionId}`);
    return createJsonResponse(responseData);
}

// ULTIMATE proxy handler
async function handleProxy(request) {
    console.log('🚀 Handling proxy request');
    
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

        console.log(`🌐 Proxy request for: ${target}`);

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
            swVersion: '3.0',
            ultimate: true
        };

        console.log(`✅ Proxy successful: ${target} -> ${response.status}`);
        return createJsonResponse(proxyResponse);

    } catch (error) {
        console.error('❌ Proxy error:', error);
        return createJsonResponse({ error: 'Proxy error: ' + error.message }, 500);
    }
}

// ULTIMATE health check
async function handleHealthCheck(request) {
    console.log('❤️ Handling health check');
    
    const healthData = {
        status: 'operational',
        service: 'dpi-tunnel-ultimate',
        timestamp: Date.now(),
        version: '3.0',
        uptime: Math.floor(performance.now() / 1000),
        features: ['encryption', 'authentication', 'proxy', 'cors', 'ultimate'],
        directory: '/tests/',
        endpoints: [
            '/tests/api/tunnel/connect',
            '/tests/api/tunnel/proxy', 
            '/tests/api/tunnel/health-check',
            '/tests/api/tunnel/status',
            '/tests/api/tunnel/test'
        ],
        swActive: true,
        corsEnabled: true,
        ultimate: true
    };

    return createJsonResponse(healthData);
}

// ULTIMATE status
async function handleStatus(request) {
    const statusData = {
        service: 'DPI Tunnel Ultimate Service Worker',
        version: '3.0',
        timestamp: Date.now(),
        environment: 'production',
        baseUrl: 'https://voidwaifu.github.io/tests/',
        endpoints: ['connect', 'proxy', 'health-check', 'status', 'test'],
        swActive: true,
        ultimate: true
    };

    return createJsonResponse(statusData);
}

// ULTIMATE test endpoint
async function handleTest(request) {
    const testData = {
        message: 'Ultimate test endpoint working!',
        service: 'DPI Tunnel Ultimate',
        directory: '/tests/',
        timestamp: Date.now(),
        randomId: Math.random().toString(36).substr(2, 9),
        swVersion: '3.0',
        corsTest: 'success',
        ultimate: true
    };

    return createJsonResponse(testData);
}

// Utility functions
function createJsonResponse(data, status = 200) {
    console.log(`📦 Creating JSON response: ${status}`, data);
    return new Response(JSON.stringify(data), {
        status: status,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD',
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Expose-Headers': '*',
            'X-Service-Worker': 'active',
            'X-DPI-Tunnel': 'ultimate',
            'X-Ultimate-Version': '3.0'
        }
    });
}

function generateSessionId() {
    return 'ultimate_session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

function isValidTarget(url) {
    try {
        const parsed = new URL(url);
        return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
        return false;
    }
}

// Enhanced message handling
self.addEventListener('message', (event) => {
    console.log('📨 Received message from client:', event.data);
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
    
    // Respond to ping messages
    if (event.data && event.data.type === 'PING') {
        event.ports[0].postMessage({
            type: 'PONG',
            version: '3.0',
            ultimate: true
        });
    }
});

console.log('🚀 Ultimate DPI Tunnel Service Worker loaded successfully!');
