/**
 * JDINJAX eBay Listing Pro Console — Unified Single-Port Server
 * Version: 3.4.7
 *
 * All sensitive credentials (Gemini, Firebase, Cloudinary) are stored
 * as server-side environment variables. Nothing is hardcoded in source.
 *
 * Routes:
 *   GET  /            → serves index.html
 *   GET  /api/config  → serves Firebase + Cloudinary config from env vars
 *   GET  /health      → health check
 *   POST /api/gemini  → Gemini API proxy (key never sent to browser)
 */

require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3001;

// ─── Validate required env vars on startup ─────────────────────────────────
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
if (!GEMINI_API_KEY) {
    console.error('[JDINJAX] ❌  GEMINI_API_KEY not set. Add it in Railway → Variables.');
    process.exit(1);
}

const REQUIRED_FIREBASE_VARS = [
    'FIREBASE_API_KEY',
    'FIREBASE_AUTH_DOMAIN',
    'FIREBASE_PROJECT_ID',
    'FIREBASE_STORAGE_BUCKET',
    'FIREBASE_MESSAGING_SENDER_ID',
    'FIREBASE_APP_ID'
];
const missingVars = REQUIRED_FIREBASE_VARS.filter(v => !process.env[v]);
if (missingVars.length > 0) {
    console.error(`[JDINJAX] ❌  Missing env vars: ${missingVars.join(', ')}`);
    console.error('[JDINJAX]    Add them in Railway → Variables tab.');
    process.exit(1);
}

// ─── Middleware ────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname)));

// ─── /api/config — serves all frontend credentials from env ───────────────
// index.html fetches this on load. No credentials ever hardcoded in HTML/JS.
app.get('/api/config', (req, res) => {
    res.json({
        firebase: {
            apiKey:            process.env.FIREBASE_API_KEY,
            authDomain:        process.env.FIREBASE_AUTH_DOMAIN,
            projectId:         process.env.FIREBASE_PROJECT_ID,
            storageBucket:     process.env.FIREBASE_STORAGE_BUCKET,
            messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
            appId:             process.env.FIREBASE_APP_ID,
            measurementId:     process.env.FIREBASE_MEASUREMENT_ID || ''
        },
        cloudinary: {
            cloudName:    process.env.CLOUDINARY_CLOUD_NAME    || 'daeb6pcxf',
            uploadPreset: process.env.CLOUDINARY_UPLOAD_PRESET || 'jdinjax_unsigned'
        }
    });
});

// ─── /health ──────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
    res.json({
        status:          'online',
        service:         'JDINJAX',
        version:         '3.4.7',
        environment:     process.env.RAILWAY_ENVIRONMENT || 'local',
        geminiKeyLoaded: !!GEMINI_API_KEY,
        firebaseLoaded:  REQUIRED_FIREBASE_VARS.every(v => !!process.env[v])
    });
});

// ─── /api/gemini — Gemini proxy ───────────────────────────────────────────
app.post('/api/gemini', async (req, res) => {
    const { model = 'gemini-2.5-flash', ...payload } = req.body;
    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${GEMINI_API_KEY}`;

    console.log(`[JDINJAX] → Forwarding to model: ${model}`);

    try {
        const response = await fetch(geminiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await response.json();

        if (!response.ok) {
            console.error('[JDINJAX] ❌  Gemini error:', data.error?.message);
            return res.status(response.status).json({ error: data.error || { message: response.statusText } });
        }

        console.log(`[JDINJAX] ✅  Gemini OK — ${response.status}`);
        res.json(data);

    } catch (err) {
        console.error('[JDINJAX] ❌  Fetch error:', err.message);
        res.status(502).json({ error: { message: `Proxy fetch failed: ${err.message}` } });
    }
});

// ─── SPA fallback ─────────────────────────────────────────────────────────
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── Start ────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
    console.log('\n╔══════════════════════════════════════════════╗');
    console.log('║     JDINJAX eBay Listing Pro — v3.4.7        ║');
    console.log('╚══════════════════════════════════════════════╝');
    console.log(`  Port     : ${PORT}`);
    console.log(`  UI       : http://0.0.0.0:${PORT}/`);
    console.log(`  Config   : http://0.0.0.0:${PORT}/api/config`);
    console.log(`  Gemini   : http://0.0.0.0:${PORT}/api/gemini`);
    console.log(`  Health   : http://0.0.0.0:${PORT}/health`);
    console.log(`  Gemini K : ${GEMINI_API_KEY.substring(0, 8)}... [SECURED]`);
    console.log(`  Firebase : [SECURED via env vars]\n`);
});
