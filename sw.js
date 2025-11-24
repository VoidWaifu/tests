const CACHE_NAME = 'tech-blog-cache-v3';
const TUNNEL_PATH = '/api/tunnel/';
const API_BASE = '/api/';

// Enhanced security configuration
const SECURITY_CONFIG = {
    AUTH_TOKENS: [
        'blog_secure_token_2024_advanced_v2',
        'tech_insights_protection_key',
        'encrypted_tunnel_access_2024'
    ],
    ENCRYPTION_KEYS: [
        'primary_encryption_key_32bytes_long_secure!',
        'backup_encryption_key_32bytes_alternate!!'
    ],
    SESSION_TIMEOUT: 30 * 60 * 1000, // 30 minutes
    MAX_REQUEST_SIZE: 10 * 1024 * 1024, // 10MB
    RATE_LIMIT: {
        windowMs: 1 * 60 * 1000, // 1 minute
        maxRequests: 100
    }
};

// Advanced encryption using Web Crypto API
class AdvancedCrypto {
    constructor() {
        this.algorithm = { name: 'AES-GCM', length: 256 };
        this.keyUsages = ['encrypt', 'decrypt'];
    }

    async importKey(keyMaterial) {
        const encoder = new TextEncoder();
        const keyData = encoder.encode(keyMaterial);
        
        // Derive key using PBKDF2
        const baseKey = await crypto.subtle.importKey(
            'raw',
            keyData,
            'PBKDF2',
            false,
            ['deriveKey']
        );

        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: encoder.encode('static_site_salt_2024'),
                iterations: 100000,
                hash: 'SHA-256'
            },
            baseKey,
            this.algorithm,
            false,
            this.keyUsages
        );
    }

    async encrypt(data, key) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoder = new TextEncoder();
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            encoder.encode(data)
        );

        // Combine IV and encrypted data
        const result = new Uint8Array(iv.length + encrypted.byteLength);
        result.set(iv);
        result.set(new Uint8Array(encrypted), iv.length);

        return btoa(String.fromCharCode(...result));
    }

    async decrypt(encryptedData, key) {
        try {
            const data = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
            const iv = data.slice(0, 12);
            const encrypted = data.slice(12);

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                key,
                encrypted
            );

            return new TextDecoder().decode(decrypted);
        } catch (error) {
            throw new Error('Decryption failed: ' + error.message);
        }
    }

    async hashData(data) {
        const encoder = new TextEncoder();
        const hash = await crypto.subtle.digest('SHA-256', encoder.encode(data));
        return btoa(String.fromCharCode(...new Uint8Array(hash)));
    }
}

// Session management
class SessionManager {
    constructor() {
        this.sessions = new Map();
        this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
    }

    createSession(authToken) {
        const sessionId = this.generateSessionId();
        const session = {
            id: sessionId,
            authToken,
            created: Date.now(),
            lastActivity: Date.now(),
            requestCount: 0
        };
        
        this.sessions.set(sessionId, session);
        return sessionId;
    }

    validateSession(sessionId, authToken) {
        const session = this.sessions.get(sessionId);
        if (!session) return false;
        
        if (session.authToken !== authToken) return false;
        if (Date.now() - session.lastActivity > SECURITY_CONFIG.SESSION_TIMEOUT) {
            this.sessions.delete(sessionId);
            return false;
        }
        
        session.lastActivity = Date.now();
        session.requestCount++;
        
        return true;
    }

    generateSessionId() {
        return crypto.randomUUID();
    }

    cleanup() {
        const now = Date.now();
        for (const [sessionId, session] of this.sessions) {
            if (now - session.lastActivity > SECURITY_CONFIG.SESSION_TIMEOUT) {
                this.sessions.delete(sessionId);
            }
        }
    }
}

const advancedCrypto = new AdvancedCrypto();
const sessionManager = new SessionManager();
let cryptoKeys = new Map();

// Initialize crypto keys
async function initializeCrypto() {
    for (const keyMaterial of SECURITY_CONFIG.ENCRYPTION_KEYS) {
        const key = await advancedCrypto.importKey(keyMaterial);
        cryptoKeys.set(keyMaterial, key);
    }
}

// Rate limiting
class RateLimiter {
    constructor() {
        this.requests = new Map();
    }

    checkLimit(identifier) {
        const now = Date.now();
        const windowStart = now - SECURITY_CONFIG.RATE_LIMIT.windowMs;
        
        if (!this.requests.has(identifier)) {
            this.requests.set(identifier, []);
        }
        
        const userRequests = this.requests.get(identifier);
        
        // Remove old requests
        while (userRequests.length > 0 && userRequests[0] < windowStart) {
            userRequests.shift();
        }
        
        // Check if under limit
        if (userRequests.length >= SECURITY_CONFIG.RATE_LIMIT.maxRequests) {
            return false;
        }
        
        userRequests.push(now);
        return true;
    }
}

const rateLimiter = new RateLimiter();

self.addEventListener('install', event => {
    self.skipWaiting();
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => cache.addAll([
                '/',
                '/index.html',
                '/styles.css',
                '/app.js'
            ]))
            .then(() => initializeCrypto())
    );
});

self.addEventListener('activate', event => {
    event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);
    
    if (url.pathname.startsWith(TUNNEL_PATH)) {
        event.respondWith(handleTunnelRequest(event.request));
        return;
    }
    
    if (url.pathname.startsWith(API_BASE)) {
        event.respondWith(handleAPIRequest(event.request));
        return;
    }
    
    // Cache-first with network fallback for static content
    event.respondWith(
        caches.match(event.request)
            .then(response => {
                if (response) {
                    return response;
                }
                
                return fetch(event.request).then(response => {
                    if (response.status === 200 && response.type === 'basic') {
                        const responseToCache = response.clone();
                        caches.open(CACHE_NAME)
                            .then(cache => cache.put(event.request, responseToCache));
                    }
                    return response;
                });
            })
    );
});

async function handleTunnelRequest(request) {
    // Rate limiting
    const clientId = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (!rateLimiter.checkLimit(clientId)) {
        return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
            status: 429,
            headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
        return new Response(null, {
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, X-Auth-Token, X-Session-ID, X-Encryption-Key-ID',
                'Access-Control-Max-Age': '86400'
            }
        });
    }

    try {
        const action = request.url.split('/').pop();
        
        switch (action) {
            case 'connect':
                return await handleSecureConnect(request);
            case 'proxy':
                return await handleSecureProxy(request);
            case 'tcp':
                return await handleTCPTunnel(request);
            case 'udp':
                return await handleUDPTunnel(request);
            case 'websocket':
                return await handleWebSocketProxy(request);
            case 'stream':
                return await handleStreaming(request);
            case 'status':
                return await handleStatus(request);
            default:
                return new Response(JSON.stringify({ error: 'Unknown action' }), { 
                    status: 404,
                    headers: { 
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    }
                });
        }
    } catch (error) {
        console.error('Tunnel error:', error);
        return new Response(JSON.stringify({ error: 'Internal server error' }), {
            status: 500,
            headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}

async function handleSecureConnect(request) {
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }

    const authToken = request.headers.get('X-Auth-Token');
    if (!SECURITY_CONFIG.AUTH_TOKENS.includes(authToken)) {
        return new Response(JSON.stringify({ error: 'Authentication failed' }), {
            status: 401,
            headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }

    const sessionId = sessionManager.createSession(authToken);
    
    return new Response(JSON.stringify({ 
        status: 'connected',
        sessionId,
        timestamp: Date.now(),
        version: '3.0',
        capabilities: ['tcp', 'udp', 'websocket', 'streaming'],
        encryption: 'AES-256-GCM'
    }), {
        headers: { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    });
}

async function handleSecureProxy(request) {
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }

    const authToken = request.headers.get('X-Auth-Token');
    const sessionId = request.headers.get('X-Session-ID');
    const keyId = request.headers.get('X-Encryption-Key-ID') || SECURITY_CONFIG.ENCRYPTION_KEYS[0];

    if (!sessionManager.validateSession(sessionId, authToken)) {
        return new Response(JSON.stringify({ error: 'Invalid session' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }

    const cryptoKey = cryptoKeys.get(keyId);
    if (!cryptoKey) {
        return new Response(JSON.stringify({ error: 'Invalid encryption key' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }

    try {
        const data = await request.json();
        const encryptedTarget = data.target;
        const encryptedData = data.data;
        
        // Decrypt target URL
        const targetUrl = await advancedCrypto.decrypt(encryptedTarget, cryptoKey);
        
        // Validate target URL
        if (!isValidTarget(targetUrl)) {
            return new Response(JSON.stringify({ error: 'Invalid target URL' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
            });
        }

        // Prepare proxy request
        const proxyRequest = new Request(targetUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/octet-stream',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
                'Accept-Encoding': 'gzip, deflate, br'
            },
            body: Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0))
        });

        const response = await fetch(proxyRequest);
        const arrayBuffer = await response.arrayBuffer();
        const base64Data = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
        
        return new Response(JSON.stringify({
            status: response.status,
            data: base64Data,
            headers: Object.fromEntries(response.headers.entries()),
            timestamp: Date.now()
        }), {
            headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: 'Proxy error: ' + error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }
}

async function handleTCPTunnel(request) {
    // Enhanced TCP tunneling for real-time communication
    return await handleSecureTunnel(request, 'tcp');
}

async function handleUDPTunnel(request) {
    // UDP tunneling for DNS and real-time audio/video
    return await handleSecureTunnel(request, 'udp');
}

async function handleWebSocketProxy(request) {
    // WebSocket proxy for real-time bidirectional communication
    if (request.headers.get('Upgrade') === 'websocket') {
        // This would require actual WebSocket support
        return new Response(JSON.stringify({ error: 'WebSocket not supported in this environment' }), {
            status: 501,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }
    
    return await handleSecureTunnel(request, 'websocket');
}

async function handleStreaming(request) {
    // Streaming support for video/audio content
    const authToken = request.headers.get('X-Auth-Token');
    const sessionId = request.headers.get('X-Session-ID');
    
    if (!sessionManager.validateSession(sessionId, authToken)) {
        return new Response(JSON.stringify({ error: 'Invalid session' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }

    try {
        const data = await request.json();
        const targetUrl = await advancedCrypto.decrypt(data.target, cryptoKeys.get(SECURITY_CONFIG.ENCRYPTION_KEYS[0]));
        
        // For streaming, we return a redirect to the actual resource
        // This allows the client to establish a direct streaming connection
        return new Response(JSON.stringify({
            redirect: targetUrl,
            expires: Date.now() + 30000 // 30 seconds
        }), {
            headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: 'Streaming error: ' + error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }
}

async function handleSecureTunnel(request, protocol) {
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed' }), {
            status: 405,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }

    const authToken = request.headers.get('X-Auth-Token');
    const sessionId = request.headers.get('X-Session-ID');
    
    if (!sessionManager.validateSession(sessionId, authToken)) {
        return new Response(JSON.stringify({ error: 'Invalid session' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }

    try {
        const data = await request.json();
        const targetHost = await advancedCrypto.decrypt(data.host, cryptoKeys.get(SECURITY_CONFIG.ENCRYPTION_KEYS[0]));
        const targetPort = parseInt(await advancedCrypto.decrypt(data.port, cryptoKeys.get(SECURITY_CONFIG.ENCRYPTION_KEYS[0])));
        const encryptedPayload = data.data;
        
        // Simulate protocol-specific handling
        // In a real implementation, this would use appropriate protocols
        const response = await fetch(`http://${targetHost}:${targetPort}`, {
            method: 'POST',
            body: Uint8Array.from(atob(encryptedPayload), c => c.charCodeAt(0)),
            headers: {
                'X-Protocol': protocol,
                'X-Session-ID': sessionId
            }
        });
        
        const arrayBuffer = await response.arrayBuffer();
        const base64Response = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
        
        return new Response(JSON.stringify({
            success: true,
            data: base64Response,
            protocol,
            timestamp: Date.now()
        }), {
            headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: `${protocol} tunnel error: ` + error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }
}

async function handleStatus(request) {
    const stats = {
        status: 'operational',
        service: 'advanced_tunnel',
        timestamp: Date.now(),
        version: '3.0',
        sessions: sessionManager.sessions.size,
        uptime: Math.floor(performance.now() / 1000),
        features: ['encryption', 'authentication', 'rate-limiting', 'sessions']
    };
    
    return new Response(JSON.stringify(stats), {
        headers: { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    });
}

async function handleAPIRequest(request) {
    // Handle regular API requests for the blog
    const path = new URL(request.url).pathname.replace(API_BASE, '');
    
    switch (path) {
        case 'stats':
            return await handleStatsAPI(request);
        case 'posts':
            return await handlePostsAPI(request);
        default:
            return new Response(JSON.stringify({ error: 'API endpoint not found' }), {
                status: 404,
                headers: { 'Content-Type': 'application/json' }
            });
    }
}

async function handleStatsAPI(request) {
    const stats = {
        visitors: Math.floor(Math.random() * 1000) + 500,
        pageViews: Math.floor(Math.random() * 5000) + 2000,
        activeUsers: Math.floor(Math.random() * 100) + 50,
        responseTime: Math.floor(Math.random() * 100) + 50
    };
    
    return new Response(JSON.stringify(stats), {
        headers: { 'Content-Type': 'application/json' }
    });
}

async function handlePostsAPI(request) {
    const posts = [
        {
            id: 1,
            title: "Understanding Modern Cryptography",
            excerpt: "Exploring the latest developments in cryptographic algorithms...",
            date: new Date().toISOString()
        },
        {
            id: 2,
            title: "Web Performance Optimization",
            excerpt: "Techniques for improving website loading times and user experience...",
            date: new Date(Date.now() - 86400000).toISOString()
        }
    ];
    
    return new Response(JSON.stringify(posts), {
        headers: { 'Content-Type': 'application/json' }
    });
}

function isValidTarget(url) {
    try {
        const parsed = new URL(url);
        // Add any domain restrictions here if needed
        return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
        return false;
    }
}

// Initialize crypto on startup
initializeCrypto().catch(console.error);
