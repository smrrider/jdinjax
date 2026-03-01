/**
 * JDINJAX eBay Listing Pro Console — Unified Server
 * Version: 3.4.5
 *
 * PURPOSE:
 *   Single entry point for Railway (and other cloud) deployments.
 *   Runs two servers in one process:
 *     1. Static file server  → serves index.html on $PORT (assigned by Railway)
 *     2. Gemini proxy server → secures API key on port 3001
 *
 * LOCAL USE: Continue using `node proxy.js` + open index.html directly.
 * RAILWAY:   Railway runs `npm start` which calls this file.
 */

const express    = require('express');
const cors       = require('cors');
const path       = require('path');
require('dotenv').config();

// ─── Validate API Key ──────────────────────────────────────────────────────────
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
if (!GEMINI_API_KEY) {
    console.error('\n[JDINJAX] ❌  GEMINI_API_KEY is not set.');
    console.error('[JDINJAX]    Add it as an environment variable in your Railway project dashboard.\n');
    process.exit(1);
}

// ─── Ports ────────────────────────────────────────────────────────────────────
// Railway assigns $PORT dynamically for the public-facing server.
// Proxy runs on 3001 internally — Railway exposes this via the same domain.
const STATIC_PORT = process.env.PORT  || 8080;
const PROXY_PORT  = process.env.PROXY_PORT || 3001;

// ══════════════════════════════════════════════════════════════════════════════
// SERVER 1 — Static File Server (serves index.html)
// ══════════════════════════════════════════════════════════════════════════════
const staticApp = express();
staticApp.use(express.static(path.join(__dirname)));

// Fallback: all routes serve index.html (single-page app)
staticApp.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

staticApp.listen(STATIC_PORT, () => {
    console.log(`[JDINJAX] 🌐  Static server → http://0.0.0.0:${STATIC_PORT}`);
});

// ══════════════════════════════════════════════════════════════════════════════
// SERVER 2 — Gemini Proxy (secures API key)
// ══════════════════════════════════════════════════════════════════════════════
const proxyApp = express();

// On Railway, the frontend and proxy share the same public domain.
// CORS must accept the Railway-assigned domain as a valid origin.
proxyApp.use(cors({
    origin: (origin, callback) => {
        // Allow: no origin (curl/health checks), localhost, Railway domains
        if (
            !origin ||
            origin.includes('localhost') ||
            origin.includes('127.0.0.1') ||
            origin.includes('railway.app') ||
            origin.includes('up.railway.app') ||
            origin === 'null' // file:// opened pages
        ) {
            callback(null, true);
        } else {
            console.warn(`[JDINJAX PROXY] ⚠️  Blocked origin: ${origin}`);
            callback(new Error('CORS: Origin not allowed'));
        }
    }
}));

proxyApp.use(express.json({ limit: '50mb' }));

// Health check
proxyApp.get('/health', (req, res) => {
    res.json({
        status: 'online',
        service: 'JDINJAX Proxy',
        version: '3.4.5',
        environment: process.env.RAILWAY_ENVIRONMENT || 'local',
        geminiKeyLoaded: !!GEMINI_API_KEY
    });
});

// Gemini forwarding endpoint
proxyApp.post('/api/gemini', async (req, res) => {
    const { model = 'gemini-2.5-flash', ...payload } = req.body;
    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${GEMINI_API_KEY}`;

    console.log(`[JDINJAX PROXY] → Forwarding to model: ${model}`);

    try {
        const response = await fetch(geminiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (!response.ok) {
            console.error('[JDINJAX PROXY] ❌  Gemini error:', data.error?.message);
            return res.status(response.status).json({ error: data.error || { message: response.statusText } });
        }

        console.log(`[JDINJAX PROXY] ✅  OK — status ${response.status}`);
        res.json(data);

    } catch (err) {
        console.error('[JDINJAX PROXY] ❌  Fetch error:', err.message);
        res.status(502).json({ error: { message: `Proxy fetch failed: ${err.message}` } });
    }
});

proxyApp.listen(PROXY_PORT, '0.0.0.0', () => {
    console.log(`[JDINJAX PROXY] 🔐  Proxy server  → http://0.0.0.0:${PROXY_PORT}`);
    console.log(`[JDINJAX PROXY]     Key: ${GEMINI_API_KEY.substring(0, 8)}... [SECURED]`);
    console.log(`\n[JDINJAX] ✅  All systems go.\n`);
});
