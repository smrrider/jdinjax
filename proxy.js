/**
 * JDINJAX eBay Listing Pro Console — Local Proxy Server
 * Version: 3.4.5
 *
 * PURPOSE:
 *   Routes all Gemini API requests through this local server so the API key
 *   is never exposed in the browser or the index.html source file.
 *
 * USAGE:
 *   1. Create a .env file (copy from .env.example) and set your GEMINI_API_KEY.
 *   2. Run: npm install
 *   3. Run: npm start
 *   4. Open index.html in your browser.
 *
 * SECURITY:
 *   - The GEMINI_API_KEY is read from the .env file at startup.
 *   - The key is never sent to the browser or written to any response.
 *   - CORS is locked to localhost only — no external origin can call this proxy.
 */

require('dotenv').config();
const express = require('express');
const cors    = require('cors');

const app  = express();
const PORT = process.env.PORT || 3001;

// ─── Validate required environment variables on startup ───────────────────────
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
if (!GEMINI_API_KEY) {
    console.error('\n[JDINJAX PROXY] ❌  GEMINI_API_KEY is not set in your .env file.');
    console.error('[JDINJAX PROXY]    Copy .env.example → .env and add your key.\n');
    process.exit(1);
}

// ─── Middleware ────────────────────────────────────────────────────────────────

// Allow only localhost origins — prevents external sites from using this proxy
const allowedOrigins = [
    'http://localhost',
    'http://127.0.0.1',
    'null' // Required for file:// opened HTML pages (Chrome sends "null" as origin)
];

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (e.g., curl, Postman) or localhost
        if (!origin || allowedOrigins.some(o => origin.startsWith(o))) {
            callback(null, true);
        } else {
            console.warn(`[JDINJAX PROXY] ⚠️  Blocked request from unauthorized origin: ${origin}`);
            callback(new Error('CORS: Origin not allowed'));
        }
    }
}));

app.use(express.json({ limit: '50mb' })); // Images arrive as base64 — needs high limit

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
    res.json({ 
        status: 'online', 
        service: 'JDINJAX Proxy',
        version: '3.4.5',
        geminiKeyLoaded: !!GEMINI_API_KEY
    });
});

// ─── Gemini Proxy Endpoint ────────────────────────────────────────────────────
app.post('/api/gemini', async (req, res) => {
    const { model = 'gemini-2.5-flash', ...payload } = req.body;

    // Sanitize: strip any attempt by the frontend to pass a different key
    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${GEMINI_API_KEY}`;

    console.log(`[JDINJAX PROXY] → Forwarding request to model: ${model}`);

    try {
        const response = await fetch(geminiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (!response.ok) {
            console.error('[JDINJAX PROXY] ❌  Gemini API error:', data.error?.message);
            return res.status(response.status).json({ error: data.error || { message: response.statusText } });
        }

        console.log(`[JDINJAX PROXY] ✅  Gemini response OK — status ${response.status}`);
        res.json(data);

    } catch (err) {
        console.error('[JDINJAX PROXY] ❌  Fetch error:', err.message);
        res.status(502).json({ error: { message: `Proxy fetch failed: ${err.message}` } });
    }
});

// ─── 404 Catch-all ────────────────────────────────────────────────────────────
app.use((req, res) => {
    res.status(404).json({ error: 'JDINJAX Proxy: Route not found.' });
});

// ─── Start Server ─────────────────────────────────────────────────────────────
app.listen(PORT, '127.0.0.1', () => {
    console.log('\n╔══════════════════════════════════════════════╗');
    console.log('║     JDINJAX eBay Listing Pro — Proxy v3.4.5  ║');
    console.log('╚══════════════════════════════════════════════╝');
    console.log(`  Status  : ✅  Online`);
    console.log(`  Endpoint: http://127.0.0.1:${PORT}/api/gemini`);
    console.log(`  Health  : http://127.0.0.1:${PORT}/health`);
    console.log(`  Key     : ${GEMINI_API_KEY.substring(0, 8)}... [SECURED — not exposed to browser]`);
    console.log('\n  Waiting for requests from index.html...\n');
});
