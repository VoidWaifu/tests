// ULTIMATE Service Worker - Guaranteed to Work
const CACHE_NAME = 'dpi-tunnel-ultimate-final';
const TUNNEL_PATH = '/tests/api/tunnel/';

// Security
const AUTH_TOKENS = [
    'digital_hub_secure_token_2024_ultra_v3',
    'quantum_protection_key_advanced_2024',
    'encrypted_tunnel_access_pro_max_2024'
];

// ULTIMATE Activation
self.addEventListener('install', (event) => {
    console.log('🚀 ULTIMATE Service Worker INSTALLING...');
    event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
    console.log('🚀 ULTIMATE Service Worker ACTIVATING...');
    event.waitUntil(
        Promise.all([
            self.clients.claim(),
            // Cache critical files
            caches.open(CACHE_NAME).then(cache => {
                return cache.addAll([
                    '/tests/',
                    '/tests/activate.html'
                ]);
            })
        ]).then(() => {
            console.log('✅ ULTIMATE Service Worker READY!');
            // Notify all clients
            self.clients.matchAll().then(clients => {
                clients.forEach(client => {
                    client.postMessage({
                        type: 'SW_ULTIMATE_ACTIVE',
                        version: 'ultimate'
                    });
                });
            });
        })
    );
});

// INTERCEPT EVERYTHING
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    const pathname = url.pathname;
    
    console.log('🌐 Intercepting:', pathname);
    
    // Handle ALL tunnel requests
    if (pathname.includes('/api/tunnel/')) {
        console.log('🚀 INTERCEPTING API REQUEST:', pathname);
        event.respondWith(handleUltimateRequest(event.request));
        return;
    }
    
    // Let all other requests through
});

// ULTIMATE Request Handler
async function handleUltimateRequest(request) {
    console.log('🚀 Processing:', request.url, request.method);
    
    // CORS headers for ALL responses
    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': '*'
    };
    
    // Handle preflight
    if (request.method === 'OPTIONS') {
        return new Response(null, { status: 200, headers: corsHeaders });
    }
    
    const url = new URL(request.url);
    const action = url.pathname.split('/').pop().replace('.json', '');
    
    console.log('🎯 Action:', action, 'Method:', request.method);
    
    try {
        let response;
        
        switch (action) {
            case 'health-check':
                response = await handleHealthCheck(request, corsHeaders);
                break;
            case 'test':
                response = await handleTest(request, corsHeaders);
                break;
            case 'connect':
                response = await handleConnect(request, corsHeaders);
                break;
            case 'simple-proxy':
                response = await handleSimpleProxy(request, corsHeaders);
                break;
            default:
                response = createJsonResponse({
                    error: 'Unknown endpoint',
                    available: ['health-check', 'test', 'connect', 'simple-proxy'],
                    method: request.method,
                    url: request.url
                }, 404, corsHeaders);
        }
        
        console.log('✅ Response ready for:', action);
        return response;
        
    } catch (error) {
        console.error('❌ Handler error:', error);
        return createJsonResponse({
            error: 'Handler failed',
            message: error.message
        }, 500, corsHeaders);
    }
}

// Health Check - DYNAMIC
async function handleHealthCheck(request, corsHeaders) {
    const data = {
        status: 'operational',
        service: 'dpi-tunnel-ultimate',
        timestamp: Date.now(),
        version: 'ultimate',
        message: 'DYNAMIC RESPONSE - Service Worker is ACTIVE!',
        method: request.method,
        dynamic: true,
        sw: 'ACTIVE'
    };
    
    return createJsonResponse(data, 200, corsHeaders);
}

// Test Endpoint - DYNAMIC  
async function handleTest(request, corsHeaders) {
    const data = {
        message: 'DYNAMIC test endpoint - Service Worker WORKING!',
        timestamp: Date.now(),
        success: true,
        dynamic: true,
        random: Math.random().toString(36).substring(7),
        method: request.method
    };
    
    return createJsonResponse(data, 200, corsHeaders);
}

// Connect Endpoint - WITH AUTH
async function handleConnect(request, corsHeaders) {
    let authToken;
    
    if (request.method === 'GET') {
        authToken = new URL(request.url).searchParams.get('token');
    } else if (request.method === 'POST') {
        try {
            const body = await request.json();
            authToken = body.authToken;
        } catch (e) {
            authToken = request.headers.get('X-Auth-Token');
        }
    }
    
    console.log('🔐 Auth token:', authToken ? 'provided' : 'missing');
    
    const isValid = AUTH_TOKENS.includes(authToken);
    
    const data = {
        status: isValid ? 'connected' : 'auth_failed',
        sessionId: isValid ? 'ultimate_session_' + Date.now() : null,
        message: isValid ? 'Authentication SUCCESSFUL!' : 'Authentication FAILED',
        timestamp: Date.now(),
        method: request.method,
        tokenProvided: !!authToken,
        tokenValid: isValid,
        dynamic: true
    };
    
    return createJsonResponse(data, isValid ? 200 : 401, corsHeaders);
}

// Simple Proxy
async function handleSimpleProxy(request, corsHeaders) {
    if (request.method !== 'GET') {
        return createJsonResponse({ error: 'Only GET supported' }, 405, corsHeaders);
    }
    
    const target = new URL(request.url).searchParams.get('url');
    
    if (!target) {
        return createJsonResponse({ error: 'No URL parameter' }, 400, corsHeaders);
    }
    
    try {
        console.log('🌐 Proxying to:', target);
        
        const proxyResponse = await fetch(target, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        });
        
        const text = await proxyResponse.text();
        
        const data = {
            status: 'proxy_success',
            target: target,
            originalStatus: proxyResponse.status,
            data: btoa(unescape(encodeURIComponent(text))),
            timestamp: Date.now(),
            encoded: true,
            dynamic: true
        };
        
        return createJsonResponse(data, 200, corsHeaders);
        
    } catch (error) {
        return createJsonResponse({
            error: 'Proxy failed',
            message: error.message,
            target: target
        }, 500, corsHeaders);
    }
}

// Response helper
function createJsonResponse(data, status = 200, corsHeaders = {}) {
    const headers = {
        'Content-Type': 'application/json',
        'X-Service-Worker': 'ultimate',
        'X-Dynamic': 'true',
        ...corsHeaders
    };
    
    console.log('📦 Sending JSON response:', status, data);
    
    return new Response(JSON.stringify(data, null, 2), {
        status: status,
        headers: headers
    });
}

console.log('🚀 ULTIMATE Service Worker LOADED!');
