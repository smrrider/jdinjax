/**
 * JDINJAX eBay Listing Pro Console — Unified Single-Port Server
 * Version: 5.7
 * MISSION: Secure multi-user logistics, CSV mapping, and signed uploads.
 */

require('dotenv').config();
const admin     = require('firebase-admin');
const rateLimit = require('express-rate-limit');

// ─── Firebase Admin SDK init ─────────────────────────────────────────────────
let adminAuth = null;
let adminFirestore = null;
try {
    if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
        const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
        if (!admin.apps.length) {
            admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
        }
        adminAuth      = admin.auth();
        adminFirestore = admin.firestore();
        console.log('[Scout Recon] Firebase Admin SDK: Ready');
    } else {
        console.warn('[Scout Recon] FIREBASE_SERVICE_ACCOUNT_JSON not set — admin user creation disabled');
    }
} catch(e) {
    console.error('[Scout Recon] Firebase Admin init failed:', e.message);
}

const express = require('express');
const cors    = require('cors');
const path    = require('path');
const crypto  = require('crypto');
const https   = require('https');

// ── ebayFetch — wraps https.request to bypass undici's auto-injected headers ──
// Node 18's built-in fetch (undici) injects Accept-Language from the process
// locale and combines it with any explicit value, producing a string eBay
// rejects. Using https.request directly gives us full header control.
function ebayFetch(urlStr, { method = 'GET', headers = {}, body } = {}) {
    return new Promise((resolve, reject) => {
        const u = new URL(urlStr);
        const options = {
            hostname: u.hostname,
            path:     u.pathname + u.search,
            method,
            headers
        };
        const req = https.request(options, (res) => {
            let raw = '';
            res.on('data', chunk => raw += chunk);
            res.on('end', () => {
                resolve({
                    ok:     res.statusCode >= 200 && res.statusCode < 300,
                    status: res.statusCode,
                    json:   () => { try { return Promise.resolve(JSON.parse(raw)); } catch { return Promise.resolve({}); } },
                    text:   () => Promise.resolve(raw)
                });
            });
        });
        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
}

const app  = express();
const PORT = process.env.PORT || 3001;

// Railway (and most PaaS) sit behind a reverse proxy that sets X-Forwarded-For.
// Without this, express-rate-limit throws ERR_ERL_UNEXPECTED_X_FORWARDED_FOR and
// crashes the middleware chain before body-parser runs → req.body is undefined.
app.set('trust proxy', 1);
const APP_VERSION = "6.1.0";

// Owner email — drives server-side admin gate
const OWNER_EMAIL = process.env.OWNER_EMAIL || 'admin@scout-recon.com';

// ─── CATEGORY RESOLUTION ENGINE ─────────────────────────────────────────

const BKA_CATEGORY_MAP = {
    "73944":  "Sporting Goods > Hunting > Scopes, Optics & Lasers",
    "177882": "Sporting Goods > Hunting > Gun Parts > Scope Mounts & Accessories",
    "73943":  "Sporting Goods > Hunting > Gun Parts > Stocks, Grips & Foregrips",
    "73938":  "Sporting Goods > Hunting > Gun Parts > Magazines & Clips",
    "177891": "Sporting Goods > Hunting > Hunting Equipment > Cleaning Equipment",
    "73949":  "Sporting Goods > Hunting > Gun Parts > Slings & Swivels",
    "177895": "Sporting Goods > Hunting > Gun Parts > Lights, Lasers & Accessories",
    "73940":  "Sporting Goods > Hunting > Holsters, Belts & Pouches",
    "73936":  "Sporting Goods > Hunting > Gun Parts",
    "177885": "Sporting Goods > Hunting > Gun Parts > Handguards & Forends",
    "177887": "Sporting Goods > Hunting > Gun Parts > Triggers",
    "177889": "Sporting Goods > Hunting > Gun Parts > Barrels",
    "177893": "Sporting Goods > Hunting > Gun Parts > Suppressors & Silencers",
    "3259":   "Clothing, Shoes & Accessories > Men > Men's Clothing",
    "52387":  "Sporting Goods > Outdoor Sports > Camping & Hiking > Bags & Packs",
    "31771":  "Sporting Goods > Hunting > Tactical & Duty Gear",
    "57881":  "Consumer Electronics > Multipurpose Batteries & Power",
    "175759": "Sporting Goods > Hunting > Gun Storage",
    "20710":  "Home & Garden > Tools & Workshop Equipment > Tool Storage",
    "183446": "Home & Garden > Tools & Workshop Equipment",
    "79976":  "Sporting Goods > Hunting > Clothing, Shoes & Accessories > Hearing Protection",
    "185068": "Consumer Electronics > Portable Audio & Headphones > Headphones",
    "15052":  "Sporting Goods > Safety & Protection > Eye & Ear Protection",
    "11731":  "Home & Garden > Tools & Workshop Equipment > Safety Equipment > Ear Protection"
};

// ─── Startup env validation ───────────────────────────────────────────────
const REQUIRED_ENV = [
    'FIREBASE_API_KEY', 'FIREBASE_AUTH_DOMAIN', 'FIREBASE_PROJECT_ID',
    'GEMINI_API_KEY', 'CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET'
];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length > 0) {
    console.error(`[Scout Recon] ❌ MISSING ENV VARS: ${missingEnv.join(', ')}`);
    console.error('[Scout Recon] Server will start but affected endpoints will fail.');
}

// ─── Gemini model allowlist — prevent model injection via /api/gemini ─────
const ALLOWED_GEMINI_MODELS = new Set([
    'gemini-2.5-flash',
    'gemini-2.0-flash',
    'gemini-1.5-flash',
    'gemini-1.5-pro'
]);

// ─── SSRF allowlist — /api/proxy-image only fetches from these domains ────
const ALLOWED_IMAGE_HOSTS = new Set([
    'i.ebayimg.com',
    'm.media-amazon.com',
    'images-na.ssl-images-amazon.com',
    'serpapi.com',
    'encrypted-tbn0.gstatic.com',
    'encrypted-tbn1.gstatic.com',
    'encrypted-tbn2.gstatic.com',
    'encrypted-tbn3.gstatic.com',
    'shopping.googleapis.com',
    'res.cloudinary.com',       // AR images uploaded during recon → sent to processor
]);

// ─── Middleware ────────────────────────────────────────────────────────────
// CORS: lock to your Railway domain in production, allow localhost for dev
const allowedOrigins = [
    'https://scout-recon.com',
    'https://www.scout-recon.com',
    'https://scout-recon.up.railway.app',
    'https://ebay-scout.com',
    'https://www.ebay-scout.com',
    'https://ebay-lister.up.railway.app',
    'http://localhost:3001',
    'http://127.0.0.1:3001'
];
app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (same-origin, curl, Postman)
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        console.warn('[CORS] Blocked origin:', origin);
        callback(new Error(`CORS blocked: [${origin}]`));
    },
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.static(path.join(__dirname)));

// Route-specific body parsers — tighter limits where images aren't needed
const jsonSmall  = express.json({ limit: '64kb'  });   // text-only routes
const jsonImages = express.json({ limit: '50mb'  });   // Gemini image proxy

// ─── Rate limiters ────────────────────────────────────────────────────────────
// Standard: 60 req/min per IP — category, barcode, image proxy
const stdLimiter = rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true, legacyHeaders: false,
    message: { error: 'Too many requests — slow down.' } });
// Heavy: 20 req/min per IP — Gemini (expensive + quota-sensitive)
const heavyLimiter = rateLimit({ windowMs: 60_000, max: 20, standardHeaders: true, legacyHeaders: false,
    message: { error: 'Gemini rate limit reached — wait a moment.' } });

// ─── Admin auth gate — server-side owner verification ────────────────────────
// Verifies Firebase ID token from Authorization: Bearer <token> header.
// Returns 401 if missing/invalid, 403 if not owner, 503 if Admin SDK offline.
const requireOwner = async (req, res, next) => {
    if (!adminAuth) return res.status(503).json({ error: 'Admin SDK not configured. Add FIREBASE_SERVICE_ACCOUNT_JSON to Railway env vars.' });
    const header  = req.headers['authorization'] || '';
    const idToken = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!idToken) return res.status(401).json({ error: 'Authorization header required.' });
    try {
        const decoded = await adminAuth.verifyIdToken(idToken);
        if (decoded.email !== OWNER_EMAIL) {
            console.warn(`[Admin] Unauthorized attempt by ${decoded.email}`);
            return res.status(403).json({ error: 'Owner access required.' });
        }
        next();
    } catch(e) {
        return res.status(401).json({ error: 'Invalid or expired token.' });
    }
};

// ─── API Routes ───────────────────────────────────────────────────────────

/**
 * ACCESS CHECK ENDPOINT
 * Called by the frontend after Google sign-in instead of reading Firestore
 * directly (which requires deployed rules). Uses Admin SDK — bypasses all
 * Firestore security rules. Returns { allowed: true } for owner or whitelisted
 * users, { allowed: false, reason } otherwise.
 */
app.get('/api/check-access', async (req, res) => {
    if (!adminAuth || !adminFirestore) {
        // Admin SDK not configured — fall back to allow owner only via token email
        return res.status(503).json({ allowed: false, reason: 'Admin SDK not configured.' });
    }
    const header  = req.headers['authorization'] || '';
    const idToken = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!idToken) return res.status(401).json({ allowed: false, reason: 'No token.' });
    try {
        const decoded = await adminAuth.verifyIdToken(idToken);
        const email   = (decoded.email || '').toLowerCase();
        if (!email) return res.json({ allowed: false, reason: 'No email in token.' });
        // Owner always has access
        if (email === OWNER_EMAIL.toLowerCase()) return res.json({ allowed: true, owner: true });
        // Check Firestore whitelist via Admin SDK (bypasses client security rules)
        const snap = await adminFirestore
            .collection('system/access/approved')
            .doc(email)
            .get();
        if (snap.exists) {
            console.log(`[Access] Granted: ${email}`);
            return res.json({ allowed: true });
        }
        console.log(`[Access] Denied (not whitelisted): ${email}`);
        return res.json({ allowed: false, reason: 'Not approved.' });
    } catch(e) {
        console.error('[Access] Check failed:', e.message);
        return res.status(401).json({ allowed: false, reason: 'Invalid token.' });
    }
});

/**
 * CONFIG ENDPOINT
 * Safely shares PUBLIC keys with the frontend from Railway variables.
 */
app.get('/api/config', (req, res) => {
    res.json({
        firebase: {
            apiKey:            process.env.FIREBASE_API_KEY,
            authDomain:        process.env.FIREBASE_AUTH_DOMAIN,
            projectId:         process.env.FIREBASE_PROJECT_ID,
            storageBucket:     process.env.FIREBASE_STORAGE_BUCKET,
            messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
            appId:             process.env.FIREBASE_APP_ID
        },
        cloudinary: {
            cloudName:    process.env.CLOUDINARY_CLOUD_NAME,
            apiKey:       process.env.CLOUDINARY_API_KEY
        },
        ebay: {
            appId:   process.env.EBAY_APP_ID,
            ruName:  process.env.EBAY_RUNAME,
            env:     process.env.EBAY_ENV || 'sandbox',
            authUrl: process.env.EBAY_ENV === 'production'
                ? 'https://auth.ebay.com/oauth2/authorize'
                : 'https://auth.sandbox.ebay.com/oauth2/authorize',
            scopes: [
                'https://api.ebay.com/oauth/api_scope',
                'https://api.ebay.com/oauth/api_scope/sell.account',
                'https://api.ebay.com/oauth/api_scope/sell.inventory',
                'https://api.ebay.com/oauth/api_scope/sell.fulfillment',
                'https://api.ebay.com/oauth/api_scope/commerce.catalog.readonly',
                'https://api.ebay.com/oauth/api_scope/buy.browse',
            ].join(' ')
        }
    });
});

// ─── eBay API Integration ─────────────────────────────────────────────────────
const EBAY_ENV      = process.env.EBAY_ENV || 'sandbox';
const EBAY_APP_ID   = EBAY_ENV === 'production' ? process.env.EBAY_APP_ID_PROD  : process.env.EBAY_APP_ID;
const EBAY_CERT_ID  = EBAY_ENV === 'production' ? process.env.EBAY_CERT_ID_PROD : process.env.EBAY_CERT_ID;
const EBAY_RUNAME   = EBAY_ENV === 'production' ? process.env.EBAY_RUNAME_PROD  : process.env.EBAY_RUNAME;
const EBAY_API_BASE = EBAY_ENV === 'production' ? 'https://api.ebay.com'        : 'https://api.sandbox.ebay.com';
const EBAY_AUTH_URL = EBAY_ENV === 'production'
    ? 'https://auth.ebay.com/oauth2/authorize'
    : 'https://auth.sandbox.ebay.com/oauth2/authorize';
const EBAY_TOKEN_URL = `${EBAY_API_BASE}/identity/v1/oauth2/token`;
const EBAY_SCOPES = [
    'https://api.ebay.com/oauth/api_scope',
    'https://api.ebay.com/oauth/api_scope/sell.account',
    'https://api.ebay.com/oauth/api_scope/sell.account.readonly',
    'https://api.ebay.com/oauth/api_scope/sell.inventory',
    'https://api.ebay.com/oauth/api_scope/sell.inventory.readonly',
    'https://api.ebay.com/oauth/api_scope/sell.fulfillment',
    'https://api.ebay.com/oauth/api_scope/sell.fulfillment.readonly',
].join(' ');
console.log(`[eBay] env: ${EBAY_ENV} | app: ${EBAY_APP_ID ? EBAY_APP_ID.slice(0,8)+'...' : 'NOT SET'}`);

const requireUser = async (req, res, next) => {
    if (!adminAuth) return res.status(503).json({ error: 'Admin SDK not configured.' });
    const header  = req.headers['authorization'] || '';
    const idToken = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!idToken) return res.status(401).json({ error: 'Authorization required.' });
    try {
        const decoded = await adminAuth.verifyIdToken(idToken);
        req.uid = decoded.uid; req.email = decoded.email; next();
    } catch(e) { return res.status(401).json({ error: 'Invalid or expired token.' }); }
};

const refreshEbayToken = async (uid, rt) => {
    const creds = Buffer.from(`${EBAY_APP_ID}:${EBAY_CERT_ID}`).toString('base64');
    const r = await fetch(EBAY_TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${creds}` },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt, scope: EBAY_SCOPES })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(`Token refresh failed: ${d.error_description || d.error}`);
    const tokens = { accessToken: d.access_token, refreshToken: d.refresh_token || rt, expiresAt: Date.now() + d.expires_in * 1000, updatedAt: Date.now() };
    await adminFirestore.doc(`users/${uid}/ebay/tokens`).update(tokens);
    return tokens.accessToken;
};

const getEbayToken = async (uid) => {
    if (!adminFirestore) throw new Error('Firestore not available');
    const doc = await adminFirestore.doc(`users/${uid}/ebay/tokens`).get();
    if (!doc.exists) throw new Error('eBay account not connected');
    const d = doc.data();
    if (Date.now() >= d.expiresAt - 300_000) return await refreshEbayToken(uid, d.refreshToken);
    return d.accessToken;
};

app.get('/auth/ebay', (req, res) => {
    const { uid } = req.query;
    if (!uid) return res.status(400).send('Missing uid');
    const state  = Buffer.from(JSON.stringify({ uid, ts: Date.now() })).toString('base64');
    const params = new URLSearchParams({ client_id: EBAY_APP_ID, redirect_uri: EBAY_RUNAME, response_type: 'code', scope: EBAY_SCOPES, state });
    res.redirect(`${EBAY_AUTH_URL}?${params}`);
});

app.get('/auth/ebay/callback', async (req, res) => {
    const { code, state, error } = req.query;
    if (error) return res.redirect(`/?ebay_error=${encodeURIComponent(error)}`);
    if (!code || !state) return res.status(400).send('Invalid callback');
    let uid;
    try { const d = JSON.parse(Buffer.from(state, 'base64').toString()); uid = d.uid; if (Date.now() - d.ts > 600_000) throw new Error('Expired'); }
    catch(e) { return res.status(400).send('Invalid state'); }
    try {
        const creds = Buffer.from(`${EBAY_APP_ID}:${EBAY_CERT_ID}`).toString('base64');
        const tr = await fetch(EBAY_TOKEN_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${creds}` },
            body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: EBAY_RUNAME })
        });
        const td = await tr.json();
        if (!tr.ok) throw new Error(td.error_description || 'Token exchange failed');
        await adminFirestore.doc(`users/${uid}/ebay/tokens`).set({ accessToken: td.access_token, refreshToken: td.refresh_token, expiresAt: Date.now() + td.expires_in * 1000, scope: td.scope || EBAY_SCOPES, connectedAt: Date.now(), env: EBAY_ENV });
        console.log(`[eBay] User ${uid} connected (${EBAY_ENV})`);

        res.redirect('/?ebay_connected=1');
    } catch(e) { console.error('[eBay] Callback error:', e.message); res.redirect(`/?ebay_error=${encodeURIComponent(e.message)}`); }
});

app.post('/api/ebay/connect', requireUser, jsonSmall, async (req, res) => {
    try {
        if (!adminFirestore) return res.status(503).json({ error: 'Firestore not available' });
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
        await adminFirestore.doc(`users/${req.uid}/ebay/credentials`).set({ username, password, savedAt: Date.now() });
        const tokenDoc = await adminFirestore.doc(`users/${req.uid}/ebay/tokens`).get();
        if (tokenDoc.exists) {
            const d = tokenDoc.data();
            if (Date.now() < d.expiresAt - 300_000) return res.json({ connected: true, env: d.env, connectedAt: d.connectedAt });
            try { await refreshEbayToken(req.uid, d.refreshToken); return res.json({ connected: true, env: d.env, connectedAt: d.connectedAt }); }
            catch(e) { console.warn('[eBay] Silent refresh failed:', e.message); }
        }
        const state  = Buffer.from(JSON.stringify({ uid: req.uid, ts: Date.now() })).toString('base64');
        const params = new URLSearchParams({ client_id: EBAY_APP_ID, redirect_uri: EBAY_RUNAME, response_type: 'code', scope: EBAY_SCOPES, state, prompt: 'login', login_hint: username });
        res.json({ redirectUrl: `${EBAY_AUTH_URL}?${params}` });
    } catch(e) { console.error('[eBay] Connect error:', e.message); res.status(500).json({ error: e.message }); }
});

app.get('/api/ebay/status', requireUser, async (req, res) => {
    try {
        if (!adminFirestore) return res.status(503).json({ error: 'Firestore not available' });
        const doc = await adminFirestore.doc(`users/${req.uid}/ebay/tokens`).get();
        if (!doc.exists) return res.json({ connected: false });
        const d = doc.data();
        res.json({ connected: true, env: d.env, connectedAt: d.connectedAt, expired: Date.now() >= d.expiresAt });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ebay/disconnect', requireUser, jsonSmall, async (req, res) => {
    try {
        if (!adminFirestore) return res.status(503).json({ error: 'Firestore not available' });
        await adminFirestore.doc(`users/${req.uid}/ebay/tokens`).delete();
        res.json({ disconnected: true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ebay/policies', requireUser, async (req, res) => {
    try {
        const token   = await getEbayToken(req.uid);
        const headers = { 'Authorization': `Bearer ${token}`, 'X-EBAY-C-MARKETPLACE-ID': 'EBAY_US', 'Content-Type': 'application/json' };
        const [sr, pr, rr] = await Promise.all([
            fetch(`${EBAY_API_BASE}/sell/account/v1/fulfillment_policy?marketplace_id=EBAY_US`, { headers }),
            fetch(`${EBAY_API_BASE}/sell/account/v1/payment_policy?marketplace_id=EBAY_US`,     { headers }),
            fetch(`${EBAY_API_BASE}/sell/account/v1/return_policy?marketplace_id=EBAY_US`,      { headers })
        ]);
        const [s, p, r] = await Promise.all([sr.json(), pr.json(), rr.json()]);
        res.json({
            fulfillment: (s.fulfillmentPolicies || []).map(p => ({ id: p.fulfillmentPolicyId, name: p.name })),
            payment:     (p.paymentPolicies     || []).map(p => ({ id: p.paymentPolicyId,     name: p.name })),
            returns:     (r.returnPolicies       || []).map(p => ({ id: p.returnPolicyId,      name: p.name }))
        });
    } catch(e) { res.status(e.message.includes('not connected') ? 401 : 502).json({ error: e.message }); }
});

// ─── eBay Taxonomy API — Phase 3 ─────────────────────────────────────────────
// Uses Client Credentials Grant (no user OAuth needed) for read-only taxonomy calls.

let _ebayAppToken    = null;
let _ebayAppTokenExp = 0;
let _ebayTreeId      = null;

const getEbayAppToken = async () => {
    if (_ebayAppToken && Date.now() < _ebayAppTokenExp - 60_000) return _ebayAppToken;
    const creds = Buffer.from(`${EBAY_APP_ID}:${EBAY_CERT_ID}`).toString('base64');
    const r = await fetch(EBAY_TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${creds}` },
        body: new URLSearchParams({ grant_type: 'client_credentials', scope: 'https://api.ebay.com/oauth/api_scope' })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(`App token failed: ${d.error_description || d.error}`);
    _ebayAppToken    = d.access_token;
    _ebayAppTokenExp = Date.now() + d.expires_in * 1000;
    return _ebayAppToken;
};

// Production app token — always uses prod credentials regardless of EBAY_ENV.
// Browse API (price research) must query real eBay data; sandbox has no listings.
let _ebayProdAppToken    = null;
let _ebayProdAppTokenExp = 0;
const EBAY_PROD_API_BASE  = 'https://api.ebay.com';
const EBAY_PROD_TOKEN_URL = 'https://api.ebay.com/identity/v1/oauth2/token';
const getEbayProdAppToken = async () => {
    if (_ebayProdAppToken && Date.now() < _ebayProdAppTokenExp - 60_000) return _ebayProdAppToken;
    // Prefer explicit PROD vars; fall back to EBAY_APP_ID/EBAY_CERT_ID which in
    // production mode already resolve to the prod credentials (see top of file).
    const appId  = process.env.EBAY_APP_ID_PROD  || EBAY_APP_ID;
    const certId = process.env.EBAY_CERT_ID_PROD || EBAY_CERT_ID;
    if (!appId || !certId) throw new Error('No eBay production credentials available for Browse API');
    console.log(`[Price] Getting prod token — env:${EBAY_ENV} appId:${appId.slice(0,8)}...`);
    const creds = Buffer.from(`${appId}:${certId}`).toString('base64');
    const r = await fetch(EBAY_PROD_TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${creds}` },
        body: new URLSearchParams({ grant_type: 'client_credentials', scope: 'https://api.ebay.com/oauth/api_scope' })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(`Prod app token failed: ${d.error_description || d.error}`);
    _ebayProdAppToken    = d.access_token;
    _ebayProdAppTokenExp = Date.now() + d.expires_in * 1000;
    console.log(`[Price] Prod token OK, expires in ${d.expires_in}s`);
    return _ebayProdAppToken;
};

const getEbayCategoryTreeId = async () => {
    if (_ebayTreeId) return _ebayTreeId;
    const token = await getEbayAppToken();
    const r = await fetch(`${EBAY_API_BASE}/commerce/taxonomy/v1/get_default_category_tree_id?marketplace_id=EBAY_US`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Language': 'en-US' }
    });
    const d = await r.json();
    _ebayTreeId = d.categoryTreeId;
    console.log(`[eBay Taxonomy] Tree ID: ${_ebayTreeId}`);
    return _ebayTreeId;
};

// Cache for taxonomy calls (24h TTL — category tree rarely changes)
const _taxonomyCache = new Map();
const taxonomyCacheGet = (key) => { const e = _taxonomyCache.get(key); return (e && Date.now() < e.exp) ? e.val : null; };
const taxonomyCacheSet = (key, val) => _taxonomyCache.set(key, { val, exp: Date.now() + 86_400_000 });

// GET /api/ebay/category-suggest?q=... — eBay Taxonomy category suggestions
app.get('/api/ebay/category-suggest', async (req, res) => {
    try {
        const q = (req.query.q || '').trim();
        if (!q) return res.status(400).json({ error: 'q required' });
        const cacheKey = `suggest:${q.toLowerCase()}`;
        const cached = taxonomyCacheGet(cacheKey);
        if (cached) return res.json(cached);
        const [token, treeId] = await Promise.all([getEbayAppToken(), getEbayCategoryTreeId()]);
        const r = await fetch(`${EBAY_API_BASE}/commerce/taxonomy/v1/category_tree/${treeId}/get_category_suggestions?q=${encodeURIComponent(q)}`, {
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Language': 'en-US' }
        });
        const d = await r.json();
        const suggestions = (d.categorySuggestions || []).slice(0, 10).map(s => ({
            id:   s.category?.categoryId,
            name: s.category?.categoryName,
            path: s.categoryTreeNodeAncestors?.map(a => a.categoryName).reverse().join(' > ') + ' > ' + s.category?.categoryName
        }));
        taxonomyCacheSet(cacheKey, suggestions);
        res.json(suggestions);
    } catch(e) { res.status(502).json({ error: e.message }); }
});

// GET /api/ebay/category-validate?id=... — validate a category ID + get details
app.get('/api/ebay/category-validate', async (req, res) => {
    try {
        const id = (req.query.id || '').trim();
        if (!id) return res.status(400).json({ error: 'id required' });
        const cacheKey = `validate:${id}`;
        const cached = taxonomyCacheGet(cacheKey);
        if (cached) return res.json(cached);
        const [token, treeId] = await Promise.all([getEbayAppToken(), getEbayCategoryTreeId()]);
        const r = await fetch(`${EBAY_API_BASE}/commerce/taxonomy/v1/category_tree/${treeId}/get_category_subtree?category_id=${id}`, {
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Language': 'en-US' }
        });
        const d = await r.json();
        const result = { valid: r.ok && !!d.categorySubtreeNode, id, name: d.categorySubtreeNode?.category?.categoryName };
        taxonomyCacheSet(cacheKey, result);
        res.json(result);
    } catch(e) { res.status(502).json({ error: e.message }); }
});

// GET /api/ebay/category-specifics?id=... — mandatory item specifics for a category
app.get('/api/ebay/category-specifics', async (req, res) => {
    try {
        const id = (req.query.id || '').trim();
        if (!id) return res.status(400).json({ error: 'id required' });
        const cacheKey = `specifics:${id}`;
        const cached = taxonomyCacheGet(cacheKey);
        if (cached) return res.json(cached);
        const [token, treeId] = await Promise.all([getEbayAppToken(), getEbayCategoryTreeId()]);
        const r = await fetch(`${EBAY_API_BASE}/commerce/taxonomy/v1/category_tree/${treeId}/get_item_aspects_for_category?category_id=${id}`, {
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Language': 'en-US' }
        });
        const d = await r.json();
        const aspects = d.aspects || [];
        const mandatory = aspects
            .filter(a => a.aspectConstraint?.aspectRequired)
            .map(a => ({ name: a.localizedAspectName, values: (a.aspectValues || []).map(v => v.localizedValue) }));
        const optional = aspects
            .filter(a => !a.aspectConstraint?.aspectRequired)
            .map(a => ({ name: a.localizedAspectName, values: (a.aspectValues || []).map(v => v.localizedValue) }));
        const result = { categoryId: id, mandatory, optional };
        taxonomyCacheSet(cacheKey, result);
        res.json(result);
    } catch(e) { res.status(502).json({ error: e.message }); }
});

// GET /api/ebay/price-research-test — diagnostic endpoint, no auth required
// Hit this in the browser to verify Browse API connectivity and token acquisition.
// e.g. /api/ebay/price-research-test?q=wetsuit
// GET /api/ebay/sold-test?q=wetsuit&cond=1000 — SerpAPI sold listings diagnostic
app.get('/api/ebay/sold-test', async (req, res) => {
    try {
        const q          = req.query.q    || 'wetsuit';
        const condId      = parseInt(req.query.cond || '1000');
        const lhCondition = condId === 1000 ? '1000' : condId <= 2750 ? null : '3000';
        const serpKey    = process.env.SERPAPI_KEY;
        if (!serpKey) return res.status(500).json({ error: 'SERPAPI_KEY not set' });
        const serpBase   = { engine: 'ebay', _nkw: q, LH_Sold: '1', LH_Complete: '1', _ipg: '10', api_key: serpKey };
        if (lhCondition) serpBase.LH_ItemCondition = lhCondition;
        const serpParams = new URLSearchParams(serpBase);
        const sr    = await fetch(`https://serpapi.com/search?${serpParams}`);
        const sd    = await sr.json();
        const items = sd.organic_results || sd.search_results || [];
        res.json({
            httpStatus: sr.status, itemCount: items.length,
            serpError:  sd.error || null,
            samples:    items.slice(0, 5).map(i => ({
                title: i.title,
                price: i.price?.extracted ?? i.extracted_price ?? i.price?.raw
            })),
            rawKeys: items[0] ? Object.keys(items[0]) : []
        });
    } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ebay/price-research-test', async (req, res) => {
    try {
        const q = req.query.q || 'iPhone 15 Pro Max';
        const token = await getEbayProdAppToken();
        const safeParams = new URLSearchParams({ q, limit: '5' });
        const url = `${EBAY_PROD_API_BASE}/buy/browse/v1/item_summary/search?${safeParams}&filter=buyingOptions:{FIXED_PRICE}`;
        const r   = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}`, 'X-EBAY-C-MARKETPLACE-ID': 'EBAY_US' }
        });
        const d = await r.json();
        res.json({
            env:         EBAY_ENV,
            tokenOk:     !!token,
            status:      r.status,
            total:       d.total,
            items:       (d.itemSummaries || []).slice(0, 3).map(i => ({ title: i.title, price: i.price?.value })),
            errors:      d.errors || null
        });
    } catch(e) {
        res.status(500).json({ error: e.message });
    }
});

// In-memory cache for Finding API sold results — 6-hour TTL per search key.
// Prevents burning the low findCompletedItems quota on repeated Re-Price calls
// for the same item. Key = "searchQuery|conditionGroup".
const _soldCache = new Map(); // key → { prices: [], ts: Date.now() }
const SOLD_CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

const getCachedSoldPrices = (key) => {
    const entry = _soldCache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.ts > SOLD_CACHE_TTL_MS) { _soldCache.delete(key); return null; }
    return entry.prices;
};
const setCachedSoldPrices = (key, prices) => _soldCache.set(key, { prices, ts: Date.now() });

// POST /api/ebay/price-research — Phase 4 Live Price Intelligence
// Queries eBay Browse API (active listings) + Finding API (sold listings) in parallel.
// Returns active + sold price bands and three pricing strategy points.
app.post('/api/ebay/price-research', requireUser, express.json({ limit: '64kb' }), async (req, res) => {
    const MIN_COMPS = 4;
    const pct = (arr, p) => arr[Math.max(0, Math.min(arr.length - 1, Math.floor(arr.length * p)))];

    try {
        const { title, conditionId, categoryId, brand, model } = req.body;
        if (!title) return res.status(400).json({ error: 'title required' });

        const token = await getEbayProdAppToken();
        const words = title.split(/\s+/).filter(w => w.length > 1);
        const searchQuery = words.slice(0, 6).join(' ');

        // Sold query fallback chain — most precise first, broadening until MIN_COMPS found.
        // "Petzl RIG" (brand+model) may return 0 — sellers often omit model codes.
        // "Petzl Descender" (brand + product type word) matches how buyers/sellers
        // actually write eBay titles. Both are tried before falling back to title slices.
        const brandModel   = [brand, model].filter(Boolean).join(' ').trim();
        // Product type = last meaningful word in title that isn't the brand or model code
        const stopWords    = new Set(['and','the','with','for','new','set','kit','lot','in','of','a']);
        const typeWord     = [...words].reverse().find(w =>
            w.length > 3 &&
            !stopWords.has(w.toLowerCase()) &&
            w.toLowerCase() !== (brand || '').toLowerCase() &&
            w.toLowerCase() !== (model || '').toLowerCase()
        );
        const brandType = brand && typeWord ? `${brand} ${typeWord}` : '';
        const soldQueryFallbacks = [
            brandModel,                        // "Petzl RIG"
            brandType,                         // "Petzl Descender"
            words.slice(0, 3).join(' '),       // 3-word title slice
            words.slice(0, 5).join(' '),       // 5-word title slice
        ].filter((q, i, arr) => q && arr.indexOf(q) === i); // dedupe + remove empty

        // Map SR conditionId → eBay condition groups
        const cid = parseInt(conditionId || '3000');
        const lhCondition = cid === 1000 ? '1000' : cid <= 2750 ? null : '3000';
        let conditionFilter = '';
        let soldConditionFilter = '';  // Marketplace Insights API uses same filter syntax as Browse
        if (cid === 1000) {
            conditionFilter     = 'conditionIds:{1000}';
            soldConditionFilter = 'conditionIds:{1000}';
        } else if (cid >= 2000 && cid <= 2750) {
            conditionFilter     = 'conditionIds:{2000|2010|2020|2030|2500|2750}';
            soldConditionFilter = 'conditionIds:{2000|2010|2020|2030|2500|2750}';
        } else {
            conditionFilter     = 'conditionIds:{3000|4000|5000|6000|7000}';
            soldConditionFilter = 'conditionIds:{3000|4000|5000|6000|7000}';
        }

        // ── 1. Browse API — active fixed-price listings ───────────────────────
        const activeFilterStr = `buyingOptions:{FIXED_PRICE},${conditionFilter}`;
        const activeParams    = new URLSearchParams({ q: searchQuery, limit: '100' });
        if (categoryId) activeParams.set('category_ids', String(categoryId));
        const browseUrl = `${EBAY_PROD_API_BASE}/buy/browse/v1/item_summary/search?${activeParams}&filter=${activeFilterStr}`;

        // ── 2. Sold listings via SerpAPI — keyed by primary sold query ──────────
        // Cache key uses brandModel (most specific) so changing the search strategy
        // never serves stale empty results from a previous broader/failed attempt.
        console.log(`[Price] brand="${brand}" model="${model}" soldQueryFallbacks=${JSON.stringify(soldQueryFallbacks)}`);
        const soldCacheKey = `${soldQueryFallbacks[0]}|${soldConditionFilter}`;
        let soldPrices = getCachedSoldPrices(soldCacheKey);

        if (soldPrices === null) {
            // Use SerpAPI eBay engine with LH_Sold=1&LH_Complete=1 — same parameters
            // eBay uses internally for sold/completed view. No eBay quota consumed.
            // Marketplace Insights API (the native option) requires closed-beta allowlist.
            const serpKey = process.env.SERPAPI_KEY;
            if (!serpKey) {
                console.warn('[Price] SERPAPI_KEY not set — sold data unavailable');
                soldPrices = [];
            } else {
                try {
                    let quotaExhausted = false;
                    const fetchSoldItems = async (query, includeCondition) => {
                        if (quotaExhausted) return [];
                        const base = { engine: 'ebay', _nkw: query, LH_Sold: '1', LH_Complete: '1', api_key: serpKey };
                        if (includeCondition && lhCondition) base.LH_ItemCondition = lhCondition;
                        const sr  = await fetch(`https://serpapi.com/search?${new URLSearchParams(base)}`);
                        const sd  = await sr.json();
                        if (sd.error?.includes('run out of searches')) {
                            quotaExhausted = true;
                            console.warn('[Price] SerpAPI quota exhausted — sold data unavailable until plan renews');
                            return [];
                        }
                        const items = sd.organic_results || sd.search_results || sd.items_results || [];
                        return items
                            .map(i => {
                                const p = i.price;
                                if (typeof p === 'number') return p;
                                // SerpAPI sometimes returns { raw: "$49.95", extracted: 49.95 }
                                if (p && typeof p === 'object') return parseFloat(p.extracted ?? p.value ?? 0);
                                return parseFloat(String(p || '0').replace(/[^0-9.]/g, ''));
                            })
                            .filter(p => p > 0)
                            .sort((a, b) => a - b);
                    };

                    // Try progressively broader queries until MIN_COMPS sold prices found.
                    // Condition-filtered first, then without — bail entire loop if quota hit.
                    soldPrices = [];
                    for (const q of soldQueryFallbacks) {
                        if (soldPrices.length >= MIN_COMPS || quotaExhausted) break;
                        soldPrices = await fetchSoldItems(q, true);
                        if (soldPrices.length < MIN_COMPS && lhCondition && !quotaExhausted) {
                            soldPrices = await fetchSoldItems(q, false);
                        }
                        if (soldPrices.length < MIN_COMPS && !quotaExhausted) {
                            console.log(`[Price] Sold: ${soldPrices.length} for "${q}" — trying broader query`);
                        }
                    }

                    setCachedSoldPrices(soldCacheKey, soldPrices);
                    console.log(`[Price] SerpAPI sold → ${soldPrices.length} prices for "${soldQueryFallbacks[0]}"`);
                } catch(e) {
                    console.warn('[Price] SerpAPI sold fetch error:', e.message);
                    soldPrices = [];
                }
            }
        } else {
            console.log(`[Price] Sold prices from cache (${soldPrices.length}) for "${soldCacheKey}"`);
        }

        // ── Browse API — active fixed-price listings ──────────────────────────
        let activePrices = [];
        const browseRes = await fetch(browseUrl, {
            headers: { 'Authorization': `Bearer ${token}`, 'X-EBAY-C-MARKETPLACE-ID': 'EBAY_US', 'Content-Type': 'application/json' }
        }).then(r => r.json()).catch(() => null);
        if (browseRes && !browseRes.errors) {
            activePrices = (browseRes.itemSummaries || [])
                .map(i => parseFloat(i.price?.value))
                .filter(p => p > 0)
                .sort((a, b) => a - b);
        }

        console.log(`[Price] "${searchQuery}" — active: ${activePrices.length}, sold: ${soldPrices.length}`);

        // Need at least MIN_COMPS from active to proceed; sold is bonus data
        if (activePrices.length < MIN_COMPS) {
            return res.json({ source: 'insufficient', count: activePrices.length, searchQuery });
        }

        // ── Price bands ───────────────────────────────────────────────────────
        const active = {
            low:  parseFloat(pct(activePrices, 0.10).toFixed(2)),
            mid:  parseFloat(pct(activePrices, 0.50).toFixed(2)),
            high: parseFloat(pct(activePrices, 0.90).toFixed(2)),
            count: activePrices.length
        };

        const sold = soldPrices.length >= MIN_COMPS ? {
            low:  parseFloat(pct(soldPrices, 0.10).toFixed(2)),
            mid:  parseFloat(pct(soldPrices, 0.50).toFixed(2)),
            high: parseFloat(pct(soldPrices, 0.90).toFixed(2)),
            count: soldPrices.length
        } : null;

        // ── Pricing strategies ────────────────────────────────────────────────
        // Move It  — 10th pct of sold × 0.97 = fastest turnover price
        // Market   — 50th pct of sold (median transaction price)
        // Hold     — 90th pct of sold = premium but achievable; falls back to active high
        // Strategies are only computed when sold data backs them.
        // Hold = 90th pct of sold. If no sold baseline, return null so the
        // frontend falls back to the simple estimate view rather than showing
        // ask-price percentiles as if they were sold-based targets.
        const strategies = sold ? {
            moveIt: parseFloat((sold.low  * 0.97).toFixed(2)),
            market: parseFloat((sold.mid).toFixed(2)),
            hold:   parseFloat((sold.high).toFixed(2))
        } : null;

        const confidence   = activePrices.length >= 30 ? 'High' : activePrices.length >= 12 ? 'Medium' : 'Low';
        const condLabel    = conditionFilter.includes('1000') ? 'New' : 'Used/Similar';
        const soldCondNote = sold && soldPrices.length >= MIN_COMPS && !lhCondition ? ' · all conditions' : '';
        const basis        = sold
            ? `${active.count} active listings · ${sold.count} recent sales (${condLabel}${soldCondNote})`
            : `${active.count} active listings — no sold data found (${condLabel})`;

        res.json({
            source:     'ebay_browse',
            // legacy fields kept for backward compat — prefer sold percentiles when available
            low:        sold ? sold.low  : active.low,
            mid:        sold ? sold.mid  : active.mid,
            high:       sold ? sold.high : active.high,
            count:      active.count,
            confidence,
            basis,
            searchQuery,
            // new fields
            active,
            sold,
            strategies
        });
    } catch(e) {
        console.error('[Price] Research error:', e.message);
        res.status(502).json({ error: e.message, source: 'error' });
    }
});

// POST /api/ebay/spec-fill — Gemini fallback when text-scan can't match a mandatory spec value
// Called only when getSpecAutoFill can't find a valid match in eBay's allowed list.
// Body: { specName, values: string[], title, description }
// Returns: { value: string } — the best matching allowed value picked by Gemini
app.post('/api/ebay/spec-fill', requireUser, async (req, res) => {
    try {
        const { specName, values, title, description } = req.body;
        if (!specName || !Array.isArray(values) || !values.length || !title) {
            return res.status(400).json({ error: 'specName, values[], and title are required' });
        }
        const valueList = values.slice(0, 60).map((v, i) => `${i + 1}. ${v}`).join('\n');
        const prompt =
            `You are an expert eBay seller filling in item specifics for a listing.\n\n` +
            `LISTING TITLE: ${title}\n` +
            (description ? `DESCRIPTION (first 400 chars): ${description.slice(0, 400)}\n` : '') +
            `\nFor the eBay item specific "${specName}", choose the SINGLE best matching value from this list:\n` +
            valueList + '\n\n' +
            `Rules:\n` +
            `- Reply with ONLY the exact text of the chosen option — no punctuation, no explanation.\n` +
            `- If none of the options fits well, pick the closest/most general one.\n` +
            `- Never invent a value not in the list.`;
        const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`;
        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ contents: [{ role: 'user', parts: [{ text: prompt }] }] })
        });
        const d = await resp.json();
        const picked = (d.candidates?.[0]?.content?.parts?.[0]?.text || '').trim();
        // Verify it's actually in the list (case-insensitive); fall back to raw if not
        const confirmed = values.find(v => v.toLowerCase() === picked.toLowerCase()) || picked;
        console.log(`[eBay/spec-fill] "${specName}" → "${confirmed}" (raw: "${picked}")`);
        res.json({ value: confirmed });
    } catch(e) {
        console.error('[eBay/spec-fill] Error:', e.message);
        res.status(502).json({ error: e.message });
    }
});

// POST /api/ebay/list — Phase 5 Direct Listing Submission
// Three-step Sell Inventory API flow:
//   1. PUT  /sell/inventory/v1/inventory_item/{sku}  — create / update inventory item
//   2. POST /sell/inventory/v1/offer                 — create offer with price & policies
//   3. POST /sell/inventory/v1/offer/{offerId}/publish — make listing live on eBay
// Body: { sku, title, description, price, categoryId, conditionId, images[],
//         aspects{}, fulfillmentPolicyId, paymentPolicyId, returnPolicyId, listingDocId }
// Returns: { success, listingId, offerId, listingUrl }
app.post('/api/ebay/list', requireUser, express.json({ limit: '512kb' }), async (req, res) => {
    try {
        const {
            sku, title, description, price, categoryId,
            conditionId,           // SR integer string e.g. "3000"
            images,                // flat array of CDN image URLs
            aspects,               // { "Brand": ["Samsung"], "Type": ["DDR5 SDRAM"], … }
            fulfillmentPolicyId, paymentPolicyId, returnPolicyId,
            listingDocId           // Firestore doc ID to patch after publish
        } = req.body;

        if (!sku || !title || !price || !categoryId) {
            return res.status(400).json({ error: 'Missing required fields: sku, title, price, categoryId' });
        }
        if (!fulfillmentPolicyId || !paymentPolicyId || !returnPolicyId) {
            return res.status(400).json({ error: 'Missing policy IDs — configure eBay policies in Settings' });
        }

        const token  = await getEbayToken(req.uid);
        // Use ebayFetch (https.request) — NOT global fetch — so undici cannot
        // inject or modify any headers (specifically Accept-Language).
        const headers = {
            'Authorization':           `Bearer ${token}`,
            'X-EBAY-C-MARKETPLACE-ID': 'EBAY_US',
            'Content-Type':            'application/json',
            'Content-Language':        'en-US'
        };

        // SR conditionId integers → eBay Sell API condition enums
        const CONDITION_MAP = {
            '1000': 'NEW',
            '1500': 'NEW_OTHER',
            '1750': 'NEW_WITH_DEFECTS',
            '2000': 'LIKE_NEW',
            '2010': 'LIKE_NEW',
            '2020': 'LIKE_NEW',
            '2030': 'USED_EXCELLENT',
            '2500': 'USED_EXCELLENT',
            '2750': 'USED_VERY_GOOD',
            '3000': 'USED_EXCELLENT',
            '4000': 'USED_VERY_GOOD',
            '5000': 'USED_GOOD',
            '6000': 'USED_ACCEPTABLE',
            '7000': 'FOR_PARTS_OR_NOT_WORKING'
        };
        const conditionEnum = CONDITION_MAP[String(conditionId)] || 'USED_GOOD';

        // format + SKU must be derived before inventory_item PUT uses effectiveSku
        const listingFormat = (req.body.format === 'AUCTION') ? 'AUCTION' : 'FIXED_PRICE';
        const effectiveSku  = sku.replace(/-(FP|AUC)$/, '') + (listingFormat === 'AUCTION' ? '-AUC' : '-FP');

        // ── Sanitise payload before sending to eBay ──────────────────────────
        const safeTitle = (title || '').trim().slice(0, 80);
        if (!safeTitle) return res.status(400).json({ error: 'Listing title is empty' });

        // Strip aspects with missing/empty values — eBay rejects empty arrays
        const safeAspects = {};
        Object.entries(aspects || {}).forEach(([k, v]) => {
            const vals = (Array.isArray(v) ? v : [v]).map(s => String(s || '').trim()).filter(Boolean);
            if (k.trim() && vals.length) safeAspects[k.trim()] = vals;
        });

        // Filter blank/malformed image URLs
        const safeImages = (images || []).map(u => String(u || '').trim()).filter(u => u.startsWith('http')).slice(0, 12);

        // Description: strip null bytes
        // inventory item product.description max = 4,000 chars
        // offer listingDescription max = 500,000 chars (takes precedence over product.description)
        const safeDesc      = (description || '').replace(/\0/g, '').slice(0, 500000);
        const safeDescShort = safeDesc.slice(0, 4000);

        // ── Step 1: PUT inventory item ────────────────────────────────────────
        const inventoryItem = {
            availability: { shipToLocationAvailability: { quantity: 1 } },
            condition:    conditionEnum,
            product: {
                title:       safeTitle,
                description: safeDescShort,  // 4,000 char limit on inventory item
                imageUrls:   safeImages,
                aspects:     safeAspects
            }
        };

        console.log(`[eBay/list] PUT inventory_item payload: ${JSON.stringify(inventoryItem).slice(0, 800)}`);

        const putRes = await ebayFetch(
            `${EBAY_API_BASE}/sell/inventory/v1/inventory_item/${encodeURIComponent(effectiveSku)}`,
            { method: 'PUT', headers, body: JSON.stringify(inventoryItem) }
        );
        // 204 No Content = success; anything else is an error
        if (!putRes.ok) {
            const putErr = await putRes.json().catch(() => ({}));
            const msg = putErr.errors?.[0]?.message || `PUT inventory_item failed (${putRes.status})`;
            console.error('[eBay/list] PUT inventory_item failed:', JSON.stringify(putErr));
            return res.status(502).json({ error: msg, detail: putErr });
        }
        console.log(`[eBay/list] ✅ inventory_item: ${sku}`);

        // ── Resolve merchant location key ─────────────────────────────────────
        // eBay requires a merchantLocationKey on the offer to derive Item.Country.
        // GET existing locations — use first enabled one, or create SR_DEFAULT if none exist.
        let merchantLocationKey = 'SR_DEFAULT';
        try {
            const locRes  = await ebayFetch(`${EBAY_API_BASE}/sell/inventory/v1/location`, { method: 'GET', headers });
            const locData = await locRes.json();
            const locs    = locData.locations || [];
            const enabled = locs.find(l => l.merchantLocationStatus === 'ENABLED') || locs[0];
            if (enabled) {
                merchantLocationKey = enabled.merchantLocationKey;
                console.log(`[eBay/list] Using existing location: ${merchantLocationKey}`);
            } else {
                // No locations — create SR_DEFAULT with seller's country US
                const createRes = await ebayFetch(
                    `${EBAY_API_BASE}/sell/inventory/v1/location/SR_DEFAULT`,
                    {
                        method: 'POST', headers,
                        body: JSON.stringify({
                            location:               { address: { country: 'US' } },
                            locationType:           'WAREHOUSE',
                            merchantLocationStatus: 'ENABLED',
                            name:                   'Scout Recon Default Location'
                        })
                    }
                );
                console.log(`[eBay/list] Created SR_DEFAULT location (${createRes.status})`);
            }
        } catch(locErr) {
            console.warn('[eBay/list] Location lookup failed, proceeding without key:', locErr.message);
            merchantLocationKey = undefined;
        }

        // ── Step 2: POST offer ────────────────────────────────────────────────
        // Build pricingSummary based on format
        let pricingSummary;
        if (listingFormat === 'AUCTION') {
            const startPrice = Number(req.body.startPrice || 0.99).toFixed(2);
            pricingSummary = {
                auctionStartPrice: { currency: 'USD', value: startPrice }
            };
            if (req.body.reservePrice) {
                pricingSummary.auctionReservePrice = { currency: 'USD', value: Number(req.body.reservePrice).toFixed(2) };
            }
            const binPrice = Number(req.body.auctionBinPrice);
            console.log(`[eBay/list] auction BIN price received: ${JSON.stringify(req.body.auctionBinPrice)} → parsed: ${binPrice}`);
            if (binPrice > 0) {
                pricingSummary.buyItNowPrice = { currency: 'USD', value: binPrice.toFixed(2) };
            }
        } else {
            pricingSummary = { price: { currency: 'USD', value: Number(price).toFixed(2) } };
        }

        // Valid auction durations: DAYS_1 DAYS_3 DAYS_5 DAYS_7 DAYS_10
        const VALID_DURATIONS = new Set(['DAYS_1','DAYS_3','DAYS_5','DAYS_7','DAYS_10','GTC']);
        const listingDuration = VALID_DURATIONS.has(req.body.listingDuration) ? req.body.listingDuration
            : listingFormat === 'AUCTION' ? 'DAYS_7' : 'GTC';

        // Quantity — only applicable to FIXED_PRICE; auctions are always qty 1
        const quantity = listingFormat === 'FIXED_PRICE' ? Math.max(1, parseInt(req.body.quantity || 1)) : undefined;

        const offerPayload = {
            sku:                          effectiveSku,
            marketplaceId:                'EBAY_US',
            format:                       listingFormat,
            categoryId:                   String(categoryId),
            listingDescription:           safeDesc,   // 500K char limit; overrides product.description
            includeCatalogProductDetails: false,       // prevent eBay from silently overriding our content
            listingDuration,
            // Auction listings don't use a payment policy (they handle payment at checkout).
            // Including a paymentPolicyId that has "Immediate Payment Required" causes eBay
            // to demand a BIN price even when one isn't wanted — so omit it for auctions.
            listingPolicies: listingFormat === 'AUCTION'
                ? { fulfillmentPolicyId, returnPolicyId }
                : { fulfillmentPolicyId, paymentPolicyId, returnPolicyId },
            pricingSummary
        };
        if (quantity !== undefined)   offerPayload.availableQuantity  = quantity;
        if (merchantLocationKey)      offerPayload.merchantLocationKey = merchantLocationKey;

        // ── Step 2: POST offer — check for existing first to avoid "already exists" error ──
        // GET existing offers for this SKU; if found, UPDATE (PUT) instead of creating.
        let offerId;
        const getOffersRes  = await ebayFetch(
            `${EBAY_API_BASE}/sell/inventory/v1/offer?sku=${encodeURIComponent(effectiveSku)}`,
            { method: 'GET', headers }
        );
        const getOffersData = await getOffersRes.json();
        const existingOffer = (getOffersData.offers || [])[0];

        if (existingOffer) {
            offerId = existingOffer.offerId;
            const updateRes = await ebayFetch(
                `${EBAY_API_BASE}/sell/inventory/v1/offer/${offerId}`,
                { method: 'PUT', headers, body: JSON.stringify(offerPayload) }
            );
            if (updateRes.ok) {
                console.log(`[eBay/list] ✅ Updated existing offer: ${offerId}`);
            } else {
                // Incompatible offer (e.g. format mismatch) — delete and recreate
                console.warn(`[eBay/list] PUT offer failed, deleting and recreating: ${offerId}`);
                await ebayFetch(`${EBAY_API_BASE}/sell/inventory/v1/offer/${offerId}`, { method: 'DELETE', headers });
                offerId = null;
            }
        }

        if (!offerId) {
            const offerRes  = await ebayFetch(`${EBAY_API_BASE}/sell/inventory/v1/offer`,
                { method: 'POST', headers, body: JSON.stringify(offerPayload) }
            );
            const offerData = await offerRes.json();
            if (!offerRes.ok) {
                const msg = offerData.errors?.[0]?.message || `POST offer failed (${offerRes.status})`;
                console.error('[eBay/list] POST offer failed:', JSON.stringify(offerData));
                return res.status(502).json({ error: msg, detail: offerData });
            }
            offerId = offerData.offerId;
            console.log(`[eBay/list] ✅ Created offer: ${offerId}`);
        }

        // ── Step 3: Publish offer ─────────────────────────────────────────────
        const publishRes  = await ebayFetch(
            `${EBAY_API_BASE}/sell/inventory/v1/offer/${offerId}/publish`,
            { method: 'POST', headers }
        );
        const publishData = await publishRes.json();
        if (!publishRes.ok) {
            const msg = publishData.errors?.[0]?.message || `Publish failed (${publishRes.status})`;
            console.error('[eBay/list] Publish failed:', JSON.stringify(publishData));
            return res.status(502).json({ error: msg, detail: publishData });
        }
        const listingId  = publishData.listingId;
        const listingUrl = `https://www.ebay.com/itm/${listingId}`;
        console.log(`[eBay/list] 🚀 LIVE: listingId=${listingId} offerId=${offerId} sku=${sku}`);

        // ── Step 4: Volume discount promotion (FIXED_PRICE only, best-effort) ─
        const volumeDiscounts = (req.body.volumeDiscounts || [])
            .filter(d => d.minQty >= 2 && d.pctOff > 0 && d.pctOff < 100);
        if (listingFormat === 'FIXED_PRICE' && volumeDiscounts.length > 0) {
            try {
                const promoPayload = {
                    promotionType: 'VOLUME_DISCOUNT',
                    name:          `Multi-buy — ${safeTitle.slice(0, 50)}`,
                    marketplaceId: 'EBAY_US',
                    status:        'ACTIVE',
                    discountRules: volumeDiscounts.map((d, i) => ({
                        ruleOrder:       i + 1,
                        minQuantity:     d.minQty,
                        discountBenefit: { percentageOff: String(Number(d.pctOff).toFixed(1)) }
                    })),
                    inventoryCriteria: {
                        inventoryCriterionType: 'INVENTORY_BY_VALUE',
                        listingIds: [listingId]
                    }
                };
                const promoRes  = await ebayFetch(`${EBAY_API_BASE}/sell/marketing/v1/item_promotion`,
                    { method: 'POST', headers, body: JSON.stringify(promoPayload) }
                );
                const promoData = await promoRes.json();
                if (promoRes.ok) {
                    console.log(`[eBay/list] ✅ Volume discount promotion: ${promoData.promotionId}`);
                } else {
                    console.warn('[eBay/list] Volume discount skipped:', JSON.stringify(promoData));
                }
            } catch(e) {
                console.warn('[eBay/list] Volume discount error (non-fatal):', e.message);
            }
        }

        // ── Step 5: Patch Firestore doc (best-effort, non-blocking) ──────────
        if (listingDocId && adminFirestore) {
            adminFirestore.doc(`${EBAY_LISTINGS_COL(req.uid)}/${listingDocId}`).update({
                ebayListingId:  listingId,
                ebayOfferId:    offerId,
                ebaySku:        sku,
                ebayListingUrl: listingUrl,
                ebayStatus:     'live',
                ebayListedAt:   Date.now()
            }).catch(e => console.warn('[eBay/list] Firestore patch failed:', e.message));
        }

        res.json({ success: true, listingId, offerId, listingUrl });
    } catch(e) {
        console.error('[eBay/list] Error:', e.message);
        res.status(500).json({ error: e.message });
    }
});

// ─── Phase 6: eBay Inventory Sync ─────────────────────────────────────────────
// Helpers — the canonical Firestore path for a user's listings
const EBAY_LISTINGS_COL = (uid) => `artifacts/jdinjax-console/users/${uid}/listings`;

// POST /api/ebay/sync-status
// Body: { offerIds: string[] }  — up to 50
// Returns: { results: { [offerId]: { offerId, listingId, ebayStatus, price, quantity } } }
app.post('/api/ebay/sync-status', requireUser, express.json({ limit: '64kb' }), async (req, res) => {
    try {
        const rawIds = req.body.offerIds;
        if (!Array.isArray(rawIds) || rawIds.length === 0)
            return res.status(400).json({ error: 'offerIds array required' });

        const offerIds = rawIds.slice(0, 50).map(String).filter(Boolean);
        const token    = await getEbayToken(req.uid);
        const hdrs     = {
            'Authorization':           `Bearer ${token}`,
            'X-EBAY-C-MARKETPLACE-ID': 'EBAY_US',
            'Content-Type':            'application/json'
        };

        // Fan-out — one GET per offer; Promise.allSettled so a single 404 never aborts the rest
        const fetches = offerIds.map(async (offerId) => {
            try {
                const r = await ebayFetch(
                    `${EBAY_API_BASE}/sell/inventory/v1/offer/${encodeURIComponent(offerId)}`,
                    { method: 'GET', headers: hdrs }
                );
                if (r.status === 404) return { offerId, listingId: null, ebayStatus: 'ENDED', price: null, quantity: 0 };
                const d = await r.json();
                if (!r.ok) return { offerId, listingId: null, ebayStatus: 'ERROR', price: null, quantity: 0, error: d.errors?.[0]?.message };
                // offerStatus field: PUBLISHED | UNPUBLISHED | ENDED
                const ebayStatus = d.offerStatus || 'PUBLISHED';
                const price      = d.pricingSummary?.price?.value || d.pricingSummary?.auctionStartPrice?.value || null;
                return { offerId, listingId: d.listing?.listingId || null, ebayStatus, price, quantity: d.availableQuantity ?? 0 };
            } catch(e) {
                return { offerId, listingId: null, ebayStatus: 'ERROR', price: null, quantity: 0, error: e.message };
            }
        });

        const settled = await Promise.allSettled(fetches);
        const results = {};
        for (const o of settled) {
            if (o.status === 'fulfilled') results[o.value.offerId] = o.value;
        }

        // ── Orders API: detect sold items ────────────────────────────────────────
        // Fetch FULFILLED orders from the last 90 days and cross-reference listing IDs.
        // Filter syntax: orderfulfillmentstatus:{FULFILLED} — correct eBay pipe-separated set notation.
        const soldListingIds = new Set();
        const soldDetails    = {};  // listingId → { soldFor, soldTo }
        try {
            const since    = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
            const orderUrl = `${EBAY_API_BASE}/sell/fulfillment/v1/order`
                + `?filter=orderfulfillmentstatus%3A%7BFULFILLED%7D`
                + `&creationDateRange=%5B${encodeURIComponent(since)}..%5D`
                + `&limit=50`;
            const ordersR  = await ebayFetch(orderUrl, { method: 'GET', headers: hdrs });
            if (ordersR.ok) {
                const ordersData = await ordersR.json();
                for (const order of (ordersData.orders || [])) {
                    for (const item of (order.lineItems || [])) {
                        const lid = item.legacyItemId || item.itemId;
                        if (lid) {
                            soldListingIds.add(String(lid));
                            soldDetails[String(lid)] = {
                                soldFor: order.pricingSummary?.total?.value || null,
                                soldTo:  order.buyer?.username || null
                            };
                        }
                    }
                }
            } else {
                console.warn('[sync-status] Orders API HTTP', ordersR.status);
            }
        } catch(ordErr) {
            console.warn('[sync-status] Orders API skipped:', ordErr.message);
        }

        // Mark sold items in results
        for (const result of Object.values(results)) {
            if (result.listingId && soldListingIds.has(String(result.listingId))) {
                result.ebayStatus = 'SOLD';
                result.soldDetails = soldDetails[String(result.listingId)] || {};
            }
        }

        // ── Browse API: direct listing status check ───────────────────────────────
        // Queries the public Browse API by listingId to catch items deleted from eBay
        // or ended outside the Sell API (e.g. manually removed by seller).
        // Uses app token (no user-OAuth required).
        try {
            const appToken  = await getEbayAppToken();
            const browseHdr = { 'Authorization': `Bearer ${appToken}`, 'X-EBAY-C-MARKETPLACE-ID': 'EBAY_US' };
            const toCheck   = Object.values(results).filter(r => r.listingId && r.ebayStatus === 'PUBLISHED');
            await Promise.allSettled(toCheck.map(async (result) => {
                try {
                    const br = await ebayFetch(
                        `${EBAY_API_BASE}/buy/browse/v1/item/v1%7C${result.listingId}%7C0`,
                        { method: 'GET', headers: browseHdr }
                    );
                    if (br.status === 404) {
                        // Item is gone from eBay — treat as ended
                        result.ebayStatus = 'ENDED';
                    } else if (br.ok) {
                        const bd = await br.json();
                        // OUT_OF_STOCK with 0 available = sold out / ended
                        const avail = bd.estimatedAvailabilities?.[0]?.estimatedAvailabilityStatus;
                        if (avail === 'TEMPORARILY_UNAVAILABLE' || avail === 'UNAVAILABLE') {
                            result.ebayStatus = 'ENDED';
                        }
                        // If itemEndDate is in the past, listing has ended
                        if (bd.itemEndDate && new Date(bd.itemEndDate) < new Date()) {
                            result.ebayStatus = 'ENDED';
                        }
                    }
                } catch { /* individual item failures are non-fatal */ }
            }));
        } catch(browseErr) {
            console.warn('[sync-status] Browse API check skipped:', browseErr.message);
        }

        // ── Firestore writeback — persist resolved status ─────────────────────────
        if (adminFirestore) {
            try {
                const chunk = Object.keys(results).slice(0, 30);
                const snap  = await adminFirestore.collection(EBAY_LISTINGS_COL(req.uid))
                    .where('ebayOfferId', 'in', chunk)
                    .get();
                const batch = adminFirestore.batch();
                let dirty   = false;
                snap.docs.forEach(doc => {
                    const r = results[doc.data().ebayOfferId];
                    if (!r) return;
                    // UNPUBLISHED = offer exists but not yet live — don't overwrite existing status
                    if (r.ebayStatus === 'UNPUBLISHED') return;
                    const newStatus = r.ebayStatus === 'PUBLISHED' ? 'live'
                        : r.ebayStatus === 'SOLD'    ? 'sold'
                        :                              'ended';
                    if (doc.data().ebayStatus !== newStatus) {
                        const update = { ebayStatus: newStatus, ebaySyncedAt: Date.now() };
                        if (newStatus === 'sold' && r.soldDetails) {
                            update.ebaySoldFor = r.soldDetails.soldFor;
                            update.ebaySoldTo  = r.soldDetails.soldTo;
                            update.ebaySoldAt  = Date.now();
                        }
                        batch.update(doc.ref, update);
                        dirty = true;
                    }
                });
                if (dirty) await batch.commit();
            } catch(fsErr) {
                console.warn('[sync-status] Firestore update skipped:', fsErr.message);
            }
        }

        res.json({ results });
    } catch(e) {
        console.error('[eBay/sync-status]', e.message);
        res.status(500).json({ error: e.message });
    }
});

// POST /api/ebay/relist
// Body: { listingDocId }
// Loads the Firestore listing doc + settings, resolves policy IDs, then republishes
// as FIXED_PRICE using the same 3-step Sell Inventory API flow.
app.post('/api/ebay/relist', requireUser, express.json({ limit: '64kb' }), async (req, res) => {
    try {
        const { listingDocId } = req.body;
        if (!listingDocId)  return res.status(400).json({ error: 'listingDocId required' });
        if (!adminFirestore) return res.status(503).json({ error: 'Firestore not available' });

        // ── Load listing doc ────────────────────────────────────────────────────
        const docRef  = adminFirestore.doc(`${EBAY_LISTINGS_COL(req.uid)}/${listingDocId}`);
        const docSnap = await docRef.get();
        if (!docSnap.exists) return res.status(404).json({ error: 'Listing not found' });
        const l = docSnap.data();

        // ── Load user settings for policy names ─────────────────────────────────
        const settingsSnap = await adminFirestore
            .doc(`artifacts/jdinjax-console/users/${req.uid}/config/settings`)
            .get();
        const cfg = settingsSnap.exists ? settingsSnap.data() : {};
        if (!cfg.shippingProfile || !cfg.paymentProfile || !cfg.returnProfile)
            return res.status(400).json({ error: 'eBay policies not configured in Settings' });

        // ── eBay credentials ────────────────────────────────────────────────────
        const token   = await getEbayToken(req.uid);
        const headers = {
            'Authorization':           `Bearer ${token}`,
            'X-EBAY-C-MARKETPLACE-ID': 'EBAY_US',
            'Content-Type':            'application/json'
        };

        // ── Resolve policy names → IDs ──────────────────────────────────────────
        const [fpRes, ppRes, rpRes] = await Promise.all([
            ebayFetch(`${EBAY_API_BASE}/sell/account/v1/fulfillment_policy?marketplace_id=EBAY_US`, { method: 'GET', headers }),
            ebayFetch(`${EBAY_API_BASE}/sell/account/v1/payment_policy?marketplace_id=EBAY_US`,     { method: 'GET', headers }),
            ebayFetch(`${EBAY_API_BASE}/sell/account/v1/return_policy?marketplace_id=EBAY_US`,      { method: 'GET', headers })
        ]);
        const [fpData, ppData, rpData] = await Promise.all([fpRes.json(), ppRes.json(), rpRes.json()]);
        const fp = (fpData.fulfillmentPolicies || []).find(p => p.name === cfg.shippingProfile);
        const pp = (ppData.paymentPolicies     || []).find(p => p.name === cfg.paymentProfile);
        const rp = (rpData.returnPolicies       || []).find(p => p.name === cfg.returnProfile);
        if (!fp || !pp || !rp) return res.status(400).json({ error: 'eBay policy not found — check Settings' });

        const effectiveSku  = `SR-${listingDocId}-FP`;
        const safeTitle     = (l.title || '').trim().slice(0, 80);
        const safeDesc      = (l.description || l.markdownDescription || '').replace(/\0/g, '').slice(0, 500000);
        const safeDescShort = safeDesc.slice(0, 4000);
        const safeImages    = (l.images || []).map(u => String(u||'').trim()).filter(u => u.startsWith('http')).slice(0, 12);
        const safeAspects   = {};
        Object.entries(l).forEach(([k, v]) => {
            if (!k.startsWith('spec_') || !v) return;
            const name = k.slice(5).replace(/_/g, ' ');
            const vals = Array.isArray(v) ? v.filter(Boolean) : [String(v)];
            if (vals.length) safeAspects[name] = vals;
        });

        // ── Step 1: PUT inventory_item ──────────────────────────────────────────
        const invRes = await ebayFetch(
            `${EBAY_API_BASE}/sell/inventory/v1/inventory_item/${encodeURIComponent(effectiveSku)}`,
            {
                method: 'PUT', headers,
                body: JSON.stringify({
                    product: { title: safeTitle, description: safeDescShort, imageUrls: safeImages, aspects: safeAspects },
                    condition:    l.conditionId ? String(l.conditionId) : 'USED_GOOD',
                    availability: { shipToLocationAvailability: { quantity: 1 } }
                })
            }
        );
        if (!invRes.ok && invRes.status !== 204) {
            const invErr = await invRes.json();
            throw new Error(invErr.errors?.[0]?.message || `PUT inventory_item failed (${invRes.status})`);
        }

        // ── Step 2: Resolve merchant location ──────────────────────────────────
        let merchantLocationKey;
        try {
            const locData = await (await ebayFetch(`${EBAY_API_BASE}/sell/inventory/v1/location`, { method: 'GET', headers })).json();
            const locs    = locData.locations || [];
            merchantLocationKey = locs.find(x => x.merchantLocationStatus === 'ENABLED')?.merchantLocationKey || locs[0]?.merchantLocationKey;
            if (!merchantLocationKey) {
                const cr = await ebayFetch(`${EBAY_API_BASE}/sell/inventory/v1/location/SR_DEFAULT`, {
                    method: 'POST', headers,
                    body:   JSON.stringify({ location: { address: { country: 'US' } }, locationType: 'WAREHOUSE', merchantLocationStatus: 'ENABLED', name: 'Scout Recon Default Location' })
                });
                if (cr.ok || cr.status === 204) merchantLocationKey = 'SR_DEFAULT';
            }
        } catch(locErr) { console.warn('[eBay/relist] Location lookup skipped:', locErr.message); }

        // ── Step 3: Upsert offer ────────────────────────────────────────────────
        const offerPayload = {
            sku:                          effectiveSku,
            marketplaceId:                'EBAY_US',
            format:                       'FIXED_PRICE',
            categoryId:                   String(l.categoryId),
            listingDescription:           safeDesc,
            includeCatalogProductDetails: false,
            listingDuration:              'GTC',
            listingPolicies:              { fulfillmentPolicyId: fp.fulfillmentPolicyId, paymentPolicyId: pp.paymentPolicyId, returnPolicyId: rp.returnPolicyId },
            pricingSummary:               { price: { currency: 'USD', value: Number(l.buyItNowPrice || 0).toFixed(2) } },
            availableQuantity:            1
        };
        if (merchantLocationKey) offerPayload.merchantLocationKey = merchantLocationKey;

        let offerId;
        const existingOffers = await (await ebayFetch(
            `${EBAY_API_BASE}/sell/inventory/v1/offer?sku=${encodeURIComponent(effectiveSku)}`,
            { method: 'GET', headers }
        )).json();
        const existingOffer = (existingOffers.offers || [])[0];

        if (existingOffer) {
            offerId = existingOffer.offerId;
            const updRes = await ebayFetch(`${EBAY_API_BASE}/sell/inventory/v1/offer/${offerId}`, { method: 'PUT', headers, body: JSON.stringify(offerPayload) });
            if (!updRes.ok) {
                await ebayFetch(`${EBAY_API_BASE}/sell/inventory/v1/offer/${offerId}`, { method: 'DELETE', headers });
                offerId = null;
            }
        }
        if (!offerId) {
            const postData = await (await ebayFetch(`${EBAY_API_BASE}/sell/inventory/v1/offer`, { method: 'POST', headers, body: JSON.stringify(offerPayload) })).json();
            if (!postData.offerId) throw new Error(postData.errors?.[0]?.message || 'POST offer failed');
            offerId = postData.offerId;
        }

        // ── Step 4: Publish ─────────────────────────────────────────────────────
        const pubData = await (await ebayFetch(`${EBAY_API_BASE}/sell/inventory/v1/offer/${offerId}/publish`, { method: 'POST', headers, body: '{}' })).json();
        if (!pubData.listingId) throw new Error(pubData.errors?.[0]?.message || 'publish failed');

        const listingId  = pubData.listingId;
        const listingUrl = `https://www.ebay.com/itm/${listingId}`;

        // ── Step 5: Firestore update ────────────────────────────────────────────
        await docRef.update({ ebayListingId: listingId, ebayOfferId: offerId, ebaySku: effectiveSku, ebayListingUrl: listingUrl, ebayStatus: 'live', ebayListedAt: Date.now() });
        console.log(`[eBay/relist] ✅ Relisted: listingId=${listingId} offerId=${offerId}`);
        res.json({ success: true, listingId, offerId, listingUrl });
    } catch(e) {
        console.error('[eBay/relist]', e.message);
        res.status(500).json({ error: e.message });
    }
});

// eBay Platform Notification webhook — item sold / listing ended events
// GET  — eBay ownership challenge (same pattern as account-deletion)
// POST — live event payload
const EBAY_WEBHOOK_TOKEN    = process.env.EBAY_WEBHOOK_TOKEN    || '';
const EBAY_WEBHOOK_ENDPOINT = process.env.EBAY_WEBHOOK_ENDPOINT || 'https://scout-recon.up.railway.app/api/ebay/sync-webhook';

app.get('/api/ebay/sync-webhook', (req, res) => {
    const challengeCode = req.query.challenge_code;
    if (!challengeCode)      return res.status(400).json({ error: 'Missing challenge_code' });
    if (!EBAY_WEBHOOK_TOKEN) return res.status(503).json({ error: 'EBAY_WEBHOOK_TOKEN not configured' });
    const h = crypto.createHash('sha256');
    h.update(challengeCode);
    h.update(EBAY_WEBHOOK_TOKEN);
    h.update(EBAY_WEBHOOK_ENDPOINT);
    res.json({ challengeResponse: h.digest('hex') });
});

app.post('/api/ebay/sync-webhook', express.json({ limit: '64kb' }), async (req, res) => {
    res.status(200).json({ success: true }); // Acknowledge immediately — eBay retries if no 200 within 10s
    try {
        // Verify shared token appended to webhook URL (?token=EBAY_WEBHOOK_TOKEN).
        // Prevents arbitrary POST requests from mutating listing state.
        if (EBAY_WEBHOOK_TOKEN) {
            const provided = req.query.token || '';
            if (provided !== EBAY_WEBHOOK_TOKEN) {
                console.warn('[eBay/webhook] Rejected — invalid or missing token');
                return;
            }
        }
        const notification = req.body?.notification || req.body;
        const topic        = notification?.metadata?.topic || req.body?.topic || '';
        const data         = notification?.data || {};
        console.log(`[eBay/webhook] topic=${topic} itemId=${data.itemId || data.listingId || '—'}`);

        if (!adminFirestore) return;

        const SOLD_TOPICS = new Set(['MARKETPLACE_ITEM_SOLD','ITEM_SOLD','FIXED_PRICE_TRANSACTION','AUCTION_SOLD','CHECKOUT_BUYER_APPROVAL']);
        const ebayListingId = String(data.itemId || data.listingId || '');
        if (!ebayListingId) return;

        if (SOLD_TOPICS.has(topic)) {
            const snap = await adminFirestore.collectionGroup('listings').where('ebayListingId', '==', ebayListingId).limit(1).get();
            if (!snap.empty) {
                await snap.docs[0].ref.update({ ebayStatus: 'sold', ebaySoldAt: Date.now(), ebaySoldTo: data.buyerUsername || null, ebaySoldFor: data.price?.value || data.salePriceAmount?.value || null });
                console.log(`[eBay/webhook] Marked ${snap.docs[0].id} SOLD (${ebayListingId})`);
            }
        } else if (topic === 'LISTING_DELETED' || topic === 'OFFER_DELETED') {
            const snap = await adminFirestore.collectionGroup('listings').where('ebayListingId', '==', ebayListingId).limit(1).get();
            if (!snap.empty) {
                await snap.docs[0].ref.update({ ebayStatus: 'ended', ebaySyncedAt: Date.now() });
                console.log(`[eBay/webhook] Marked ${snap.docs[0].id} ENDED (${ebayListingId})`);
            }
        }
    } catch(e) { console.error('[eBay/webhook] Processing error:', e.message); }
});

// ─── eBay Marketplace Account Deletion Notifications ─────────────────────────
// Required for production API access. Handles eBay's ownership challenge (GET)
// and actual account deletion events (POST).
const EBAY_NOTIFICATION_ENDPOINT = process.env.EBAY_NOTIFICATION_ENDPOINT || 'https://scout-recon.up.railway.app/ebay/notifications/account-deletion';
const EBAY_NOTIFICATION_TOKEN    = process.env.EBAY_NOTIFICATION_TOKEN    || '';

// GET — eBay ownership challenge verification
app.get('/ebay/notifications/account-deletion', (req, res) => {
    const challengeCode = req.query.challenge_code;
    if (!challengeCode) return res.status(400).json({ error: 'Missing challenge_code' });
    if (!EBAY_NOTIFICATION_TOKEN) return res.status(503).json({ error: 'EBAY_NOTIFICATION_TOKEN not configured' });
    const hasher = crypto.createHash('sha256');
    hasher.update(challengeCode);
    hasher.update(EBAY_NOTIFICATION_TOKEN);
    hasher.update(EBAY_NOTIFICATION_ENDPOINT);
    const responseHash = hasher.digest('hex');
    console.log(`[eBay] Challenge — endpoint: ${EBAY_NOTIFICATION_ENDPOINT} | token[0:4]: ${EBAY_NOTIFICATION_TOKEN.slice(0,4)} | hash: ${responseHash.slice(0,8)}...`);
    res.json({ challengeResponse: responseHash });
});

// POST — all eBay Platform Notification events (account deletion + item sold + listing ended)
app.post('/ebay/notifications/account-deletion', express.json(), async (req, res) => {
    res.status(200).json({ success: true }); // Always acknowledge immediately
    try {
        // Verify shared token appended to notification URL (?token=EBAY_NOTIFICATION_TOKEN).
        if (EBAY_NOTIFICATION_TOKEN) {
            const provided = req.query.token || '';
            if (provided !== EBAY_NOTIFICATION_TOKEN) {
                console.warn('[eBay/notifications] Rejected — invalid or missing token');
                return;
            }
        }
        const notification = req.body?.notification || req.body || {};
        const topic        = notification?.metadata?.topic || notification?.topic || '';
        const data         = notification?.data || {};

        // ── Item sold (ORDER_CONFIRMATION fires when buyer completes checkout) ───
        const SOLD_TOPICS = new Set(['ORDER_CONFIRMATION','marketplace.item_sold','ITEM_SOLD','FIXED_PRICE_TRANSACTION','AUCTION_SOLD']);
        if (SOLD_TOPICS.has(topic)) {
            const ebayListingId = String(data.itemId || data.listingId || '');
            console.log(`[eBay] Item sold notification — listingId: ${ebayListingId}`);
            if (ebayListingId && adminFirestore) {
                const snap = await adminFirestore.collectionGroup('listings').where('ebayListingId', '==', ebayListingId).limit(1).get();
                if (!snap.empty) {
                    await snap.docs[0].ref.update({ ebayStatus: 'sold', ebaySoldAt: Date.now(), ebaySoldTo: data.buyerUsername || null, ebaySoldFor: data.price?.value || data.salePriceAmount?.value || null });
                    console.log(`[eBay] Marked listing ${snap.docs[0].id} as SOLD`);
                }
            }
            return;
        }

        // ── Listing deleted / ended ─────────────────────────────────────────────
        if (topic === 'marketplace.listing_deleted' || topic === 'LISTING_DELETED') {
            const ebayListingId = String(data.itemId || data.listingId || '');
            console.log(`[eBay] Listing ended notification — listingId: ${ebayListingId}`);
            if (ebayListingId && adminFirestore) {
                const snap = await adminFirestore.collectionGroup('listings').where('ebayListingId', '==', ebayListingId).limit(1).get();
                if (!snap.empty) {
                    await snap.docs[0].ref.update({ ebayStatus: 'ended', ebaySyncedAt: Date.now() });
                    console.log(`[eBay] Marked listing ${snap.docs[0].id} as ENDED`);
                }
            }
            return;
        }

        // ── Account deletion (original behaviour) ──────────────────────────────
        const ebayUserId = data.userId || data.username || 'unknown';
        console.log(`[eBay] Account deletion notification received — userId: ${ebayUserId}`);
        if (adminFirestore) {
            const usersSnap = await adminFirestore.collection('users').get();
            const deletions = [];
            for (const doc of usersSnap.docs) {
                const credSnap = await adminFirestore.doc(`users/${doc.id}/ebay/credentials`).get();
                if (credSnap.exists && credSnap.data()?.username === ebayUserId) {
                    deletions.push(
                        adminFirestore.doc(`users/${doc.id}/ebay/credentials`).delete(),
                        adminFirestore.doc(`users/${doc.id}/ebay/token`).delete()
                    );
                    console.log(`[eBay] Deleted eBay data for SR user ${doc.id}`);
                }
            }
            await Promise.all(deletions);
        }
    } catch(e) {
        console.error('[eBay] Notification handler error:', e.message);
    }
});

// ─── End eBay API Integration ──────────────────────────────────────────────────

/**
 * CLOUDINARY SIGNING ENGINE
 * Generates a HMAC-SHA1 signature for secure uploads.
 * Isolates files to: jdinjax/users/{userId}
 */
app.post('/api/sign-upload', requireUser, jsonSmall, (req, res) => {
    const { timestamp } = req.body;
    if (!timestamp) return res.status(400).json({ error: "Timestamp required." });

    // Always scope to the authenticated user — never trust a userId from the request body.
    const folder    = `jdinjax/users/${req.uid}`;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;

    const strToSign = `folder=${folder}&timestamp=${timestamp}${apiSecret}`;
    const signature = crypto.createHash('sha1').update(strToSign).digest('hex');

    res.json({ signature, folder });
});

// ─── CATEGORY RESOLUTION ENGINE v5 ─────────────────────────────────────────
// Strategy: SerpApi fetches LIVE eBay category candidates (flat sibling list)
// → Gemini selects the best match using item context.
// Fallback: Pure Gemini w/ BKA seed map if SerpApi unavailable.

// ── In-memory category cache ─────────────────────────────────────────────────
// Key: normalized title string  Value: { result, expiresAt }
// Max 200 entries, 2-hour TTL. Survives server restarts only in-process.
const CATEGORY_CACHE     = new Map();
const CACHE_TTL_MS       = 2 * 60 * 60 * 1000; // 2 hours
const CACHE_MAX_ENTRIES  = 200;

const cacheKey = (title) => title.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().substring(0, 80);

const cacheGet = (title) => {
    const key = cacheKey(title);
    const entry = CATEGORY_CACHE.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) { CATEGORY_CACHE.delete(key); return null; }
    return { ...entry.result, source: entry.result.source + " (cached)" };
};

const cacheSet = (title, result) => {
    const key = cacheKey(title);
    // Evict oldest entry if at cap
    if (CATEGORY_CACHE.size >= CACHE_MAX_ENTRIES) {
        CATEGORY_CACHE.delete(CATEGORY_CACHE.keys().next().value);
    }
    CATEGORY_CACHE.set(key, { result, expiresAt: Date.now() + CACHE_TTL_MS });
};

const geminiPick = async (title, keyFeatures, description, candidates) => {
    const candidateList = candidates.map(c => `- ${c.id} | ${c.name}`).join("\n");
    const prompt =
        "You are an eBay listing category expert.\n\n" +
        "ITEM: " + title + "\n" +
        "FEATURES: " + (keyFeatures.join(", ") || "N/A") + "\n" +
        "DESCRIPTION: " + (description || "").substring(0, 200) + "\n\n" +
        "LIVE EBAY CATEGORY CANDIDATES (ID | Name):\n" + candidateList + "\n\n" +
        "Select the SINGLE most appropriate category ID for listing this item on eBay. " +
        "Prefer the most specific subcategory. " +
        "CRITICAL RULES — follow these before selecting:\n" +
        "- NEVER assign firearms/gun-part categories (Scopes, Optics, Barrels, Triggers, Handguards, Stocks, Magazines, Suppressors, Gun Parts) to hearing protection, ear muffs, earmuffs, or general safety/PPE items.\n" +
        "- For ear muffs, hearing protection, or noise-reduction headwear → choose a Hearing Protection or Safety Equipment category.\n" +
        "- Only assign hunting-specific categories to items that are unambiguously hunting/firearms accessories.\n" +
        'Return ONLY valid JSON: {"categoryId": "<id>", "categoryPath": "<full path>", "confidence": "High", "source": "Hybrid"}';
    const url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" + process.env.GEMINI_API_KEY;
    const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            contents: [{ role: "user", parts: [{ text: prompt }] }],
            generationConfig: { responseMimeType: "application/json" }
        })
    });
    const d = await resp.json();
    const raw = (d.candidates?.[0]?.content?.parts?.[0]?.text || "").replace(/```json|```/g, "").trim();
    const result = JSON.parse(raw);
    if (BKA_CATEGORY_MAP[result.categoryId]) result.categoryPath = BKA_CATEGORY_MAP[result.categoryId];
    return result;
};

const fetchSerpApiCandidates = async (title) => {
    const key = process.env.SERPAPI_KEY;
    if (!key) throw new Error("SERPAPI_KEY not configured");
    const params = new URLSearchParams({ engine: "ebay", _nkw: title, ebay_domain: "ebay.com", api_key: key });
    // 12-second timeout — SerpAPI observed at ~7.7s, 12s gives reliable headroom
    const controller = new AbortController();
    const t0 = Date.now();
    const timeout = setTimeout(() => controller.abort(), 12000);
    let response;
    try {
        response = await fetch("https://serpapi.com/search?" + params.toString(), { signal: controller.signal });
    } finally {
        clearTimeout(timeout);
    }
    console.log("[Cat] SerpAPI responded in " + (Date.now() - t0) + "ms");
    if (!response.ok) throw new Error("SerpApi HTTP " + response.status);
    const data = await response.json();
    const cats = (data.categories || []).filter(c => c.id && c.name);
    if (!cats.length) throw new Error("SerpApi returned no category candidates");
    console.log("[Scout Recon] SerpApi candidates: " + cats.map(c => c.id + ":" + c.name).join(", "));
    return cats;
};

const resolveViaGeminiOnly = async (title, keyFeatures, description) => {
    // Try eBay Taxonomy suggestions first — gives Gemini eBay-validated candidates
    let candidates = [];
    try {
        const searchTerm = title.split(' ').slice(0, 4).join(' ');
        const [token, treeId] = await Promise.all([getEbayAppToken(), getEbayCategoryTreeId()]);
        const r = await fetch(`${EBAY_API_BASE}/commerce/taxonomy/v1/category_tree/${treeId}/get_category_suggestions?q=${encodeURIComponent(searchTerm)}`, {
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Language': 'en-US' }
        });
        const d = await r.json();
        candidates = (d.categorySuggestions || []).slice(0, 15).map(s => ({
            id:   s.category?.categoryId,
            name: (s.categoryTreeNodeAncestors?.map(a => a.categoryName).reverse().join(' > ') || '') + ' > ' + s.category?.categoryName
        })).filter(c => c.id);
        console.log(`[Cat] eBay Taxonomy candidates for "${searchTerm}": ${candidates.length}`);
    } catch(e) {
        console.warn('[Cat] Taxonomy suggest failed, falling back to BKA map:', e.message);
    }
    // Fallback to hardcoded map if taxonomy returned nothing
    if (!candidates.length) candidates = Object.entries(BKA_CATEGORY_MAP).map(([id, name]) => ({ id, name }));
    const result = await geminiPick(title, keyFeatures, description, candidates);
    result.source = "Gemini+Taxonomy";
    console.log("[Scout Recon] Gemini+Taxonomy: " + result.categoryId + " -> " + result.categoryPath);
    return result;
};

// In-flight request deduplication — bulk batches with similar titles share one API call
const _inflightCategoryReqs = new Map();

app.post("/api/category-resolve", stdLimiter, jsonSmall, async (req, res) => {
    const { title, keyFeatures = [], description = "" } = req.body;
    if (!title) return res.status(400).json({ error: "Title required." });

    // ── Cache hit — instant return, no API calls ──────────────────────────────
    const cached = cacheGet(title);
    if (cached) {
        console.log("[Cat] Cache hit: " + title.substring(0, 40));
        return res.json(cached);
    }

    // ── In-flight dedup — second request for same title waits on first ────────
    const key = cacheKey(title);
    if (_inflightCategoryReqs.has(key)) {
        console.log("[Cat] Dedup wait: " + title.substring(0, 40));
        try {
            const result = await _inflightCategoryReqs.get(key);
            return res.json(result);
        } catch(e) { /* fall through to fresh attempt */ }
    }

    // ── Stage 1: Hybrid (SerpApi 3s timeout + Gemini pick) ───────────────────
    const resolvePromise = (async () => {
        try {
            const candidates = await fetchSerpApiCandidates(title);
            const result = await geminiPick(title, keyFeatures, description, candidates);
            console.log("[Cat] Hybrid: " + result.categoryId + " " + result.categoryPath);
            cacheSet(title, result);
            return result;
        } catch (err) {
            console.warn("[Cat] Hybrid failed (" + err.message + ") — Gemini fallback");
        }

        // ── Stage 2: Pure Gemini fallback ────────────────────────────────────
        const result = await resolveViaGeminiOnly(title, keyFeatures, description);
        cacheSet(title, result);
        return result;
    })();

    _inflightCategoryReqs.set(key, resolvePromise);
    try {
        const result = await resolvePromise;
        return res.json(result);
    } catch (err) {
        res.status(502).json({ error: "Category resolution failed", detail: err.message });
    } finally {
        _inflightCategoryReqs.delete(key);
    }
});

/**
 * GEMINI PROXY
 */
// ── Barcode Search ────────────────────────────────────────────────────────────
app.post('/api/barcode-search', stdLimiter, jsonSmall, async (req, res) => {
    const { upc, engine = 'ebay' } = req.body;
    if (!upc) return res.status(400).json({ error: 'UPC required' });
    try {
        const params = new URLSearchParams({ api_key: process.env.SERPAPI_KEY });
        if (engine === 'amazon') {
            params.set('engine', 'amazon');
            params.set('k', upc);
            params.set('amazon_domain', 'amazon.com');
        } else {
            params.set('engine', 'ebay');
            params.set('_nkw', upc);
        }
        const barcodeCtrl = new AbortController();
        const barcodeTO = setTimeout(() => barcodeCtrl.abort(), 10000);
        let data;
        try {
            const barcodeResp = await fetch('https://serpapi.com/search?' + params.toString(), { signal: barcodeCtrl.signal });
            data = await barcodeResp.json();
        } finally {
            clearTimeout(barcodeTO);
        }
        console.log('[Barcode] engine=' + engine + ' upc=' + upc + ' keys=' + Object.keys(data).join(','));

        let results = [];
        if (engine === 'ebay') {
            const raw = data.organic_results || [];
            results = raw.slice(0, 6).map(function(r) {
                var priceStr = '';
                if (typeof r.price === 'string') priceStr = r.price;
                else if (r.price && r.price.extracted) priceStr = '$' + r.price.extracted;
                return { title: r.title || '', price: priceStr, image: r.thumbnail || '', condition: r.condition || '', url: r.link || '' };
            });
        } else {
            const raw = data.organic_results || [];
            results = raw.slice(0, 6).map(function(r) {
                return { title: r.title || '', price: r.price || '', image: r.thumbnail || '', condition: '', url: r.link || '' };
            });
        }
        if (results.length === 0) {
            console.warn('[Barcode] No results — snippet: ' + JSON.stringify(data).substring(0, 300));
        }
        res.json({ upc, engine, results });
    } catch(e) {
        console.error('[Barcode] Error:', e.message);
        res.status(500).json({ error: e.message });
    }
});

// ── Image Proxy (for barcode listing — fetch external image → b64 + Cloudinary) ─
app.post('/api/proxy-image', stdLimiter, jsonSmall, async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });
    // SSRF guard — only fetch from known image CDNs
    let parsedHost;
    try {
        parsedHost = new URL(url).hostname;
    } catch(e) {
        return res.status(400).json({ error: 'Invalid URL' });
    }
    if (!ALLOWED_IMAGE_HOSTS.has(parsedHost)) {
        console.warn('[ProxyImage] SSRF blocked:', parsedHost);
        return res.status(403).json({ error: 'Image host not permitted: ' + parsedHost });
    }
    try {
        const imgCtrl = new AbortController();
        const imgTO = setTimeout(() => imgCtrl.abort(), 8000);
        let imgRes;
        try {
            imgRes = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' }, signal: imgCtrl.signal });
        } finally {
            clearTimeout(imgTO);
        }
        if (!imgRes.ok) throw new Error('Image fetch failed: ' + imgRes.status);
        const arrayBuffer = await imgRes.arrayBuffer();
        const buffer = Buffer.from(arrayBuffer);
        const mimeType = imgRes.headers.get('content-type') || 'image/jpeg';
        const b64 = buffer.toString('base64');

        // Also upload to Cloudinary so the listing card has a persistent image
        let cloudinaryUrl = null;
        try {
            const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
            const apiKey    = process.env.CLOUDINARY_API_KEY;
            const apiSecret = process.env.CLOUDINARY_API_SECRET;
            if (cloudName && apiKey && apiSecret) {
                const timestamp = Math.round(Date.now() / 1000);
                const folder = 'jdinjax/barcode';
                const sigStr = 'folder=' + folder + '&timestamp=' + timestamp + apiSecret;
                const signature = crypto.createHash('sha1').update(sigStr).digest('hex');
                const form = new FormData();
                const blob = new Blob([buffer], { type: mimeType });
                form.append('file', blob, 'barcode-item.jpg');
                form.append('api_key', apiKey);
                form.append('timestamp', String(timestamp));
                form.append('signature', signature);
                form.append('folder', folder);
                const upRes = await fetch('https://api.cloudinary.com/v1_1/' + cloudName + '/image/upload', { method: 'POST', body: form });
                const upData = await upRes.json();
                if (upData.secure_url) cloudinaryUrl = upData.secure_url;
            }
        } catch(e) { console.warn('[ProxyImage] Cloudinary upload failed:', e.message); }

        res.json({ b64, mimeType, cloudinaryUrl });
    } catch(e) {
        console.error('[ProxyImage] Error:', e.message);
        res.status(500).json({ error: e.message });
    }
});

// ── Gemini Proxy ──────────────────────────────────────────────────────────────
app.post('/api/gemini', heavyLimiter, jsonImages, async (req, res) => {
    const { model = 'gemini-2.5-flash', ...payload } = req.body;
    // Model allowlist — prevent injection of arbitrary model strings into the API URL
    if (!ALLOWED_GEMINI_MODELS.has(model)) {
        return res.status(400).json({ error: `Model not permitted: ${model}` });
    }
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`;
    try {
        const gemCtrl = new AbortController();
        const gemTO = setTimeout(() => gemCtrl.abort(), 30000);
        let data;
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
                signal: gemCtrl.signal
            });
            data = await response.json();
        } finally {
            clearTimeout(gemTO);
        }
        // ── Fire-and-forget usage tracking ────────────────────────────────
        if (adminFirestore && data && data.usageMetadata) {
            const meta     = data.usageMetadata;
            const now      = new Date();
            const dayKey   = now.toISOString().slice(0, 10);  // YYYY-MM-DD
            const monthKey = now.toISOString().slice(0, 7);   // YYYY-MM
            const base     = adminFirestore.collection('system/usage/gemini');
            Promise.all([
                base.doc(dayKey).set({
                    requests:     admin.firestore.FieldValue.increment(1),
                    inputTokens:  admin.firestore.FieldValue.increment(meta.promptTokenCount     || 0),
                    outputTokens: admin.firestore.FieldValue.increment(meta.candidatesTokenCount || 0),
                }, { merge: true }),
                base.doc(monthKey).set({
                    requests:     admin.firestore.FieldValue.increment(1),
                    inputTokens:  admin.firestore.FieldValue.increment(meta.promptTokenCount     || 0),
                    outputTokens: admin.firestore.FieldValue.increment(meta.candidatesTokenCount || 0),
                }, { merge: true }),
            ]).catch(e => console.error('[Gemini] Usage tracking error:', e.message));
        }
        res.json(data);
    } catch (err) { res.status(502).json({ error: { message: err.message } }); }
});

// ── Admin: List all Firebase Auth users + whitelist status ────────────────────
app.get('/api/admin/list-users', requireOwner, async (req, res) => {
    if (!adminAuth || !adminFirestore) return res.status(503).json({ error: 'Firebase Admin SDK not configured.' });
    try {
        // Get all Firebase Auth users and whitelist entries in parallel
        const [listResult, wlSnap] = await Promise.all([
            adminAuth.listUsers(1000),
            adminFirestore.collection('system/access/approved').get()
        ]);

        // Build whitelist map: email (lowercase) → doc data
        const whitelistMap = {};
        wlSnap.docs.forEach(d => { whitelistMap[d.id] = d.data(); });

        // Firebase Auth users (registered — may or may not be whitelisted)
        const authEmails = new Set();
        const users = listResult.users.map(u => {
            const emailLower = (u.email || '').toLowerCase();
            authEmails.add(emailLower);
            return {
                email:       u.email,
                provider:    u.providerData[0]?.providerId === 'google.com' ? 'google' : 'email',
                disabled:    u.disabled,
                whitelisted: !!whitelistMap[emailLower],
                pending:     false,
                createdAt:   u.metadata.creationTime
            };
        });

        // Whitelist-only entries — approved but never signed in yet (no Auth account)
        Object.entries(whitelistMap).forEach(([email, data]) => {
            if (!authEmails.has(email)) {
                users.push({
                    email,
                    provider:    data.authMethod || 'google',
                    disabled:    false,
                    whitelisted: true,
                    pending:     true,   // approved, awaiting first sign-in
                    createdAt:   null
                });
            }
        });

        res.json({ users });
    } catch(e) {
        console.error('[Admin] List users failed:', e.message);
        res.status(500).json({ error: e.message });
    }
});

// ── Admin: Approve Google SSO user — whitelist only ───────────────────────────
// DO NOT pre-create a Firebase Auth account. A passwordless account blocks
// Google Sign-In (Firebase rejects the Google credential with
// auth/invalid-credential because the email exists without a Google provider).
// Firebase creates the Auth account automatically on the user's first Google
// sign-in. They appear in the admin list after that first sign-in.
app.post('/api/admin/approve-user', requireOwner, jsonSmall, async (req, res) => {
    const { email, addedBy } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    if (!adminAuth || !adminFirestore) return res.status(503).json({ error: 'Firebase Admin SDK not configured.' });
    try {
        // Clean up any orphaned passwordless accounts created by earlier broken
        // versions of this endpoint — they block Google Sign-In for this email.
        try {
            const existing = await adminAuth.getUserByEmail(email);
            const hasNoProviders = !existing.providerData || existing.providerData.length === 0;
            if (hasNoProviders) {
                await adminAuth.deleteUser(existing.uid);
                console.log(`[Admin] Removed orphaned passwordless account for ${email}`);
            }
        } catch(e) { /* auth/user-not-found is expected — nothing to clean up */ }

        // Whitelist via Admin SDK
        await adminFirestore.collection('system/access/approved').doc(email.toLowerCase()).set({
            addedBy: addedBy || 'owner',
            addedAt: Date.now(),
            authMethod: 'google'
        });
        console.log(`[Admin] Google access granted (whitelist): ${email}`);
        res.json({
            success: true,
            message: `${email} approved. They can now sign in with Google.`
        });
    } catch(e) {
        console.error('[Admin] Approve failed:', e.message);
        res.status(500).json({ error: e.message });
    }
});

// ── Admin: Enable / Disable / Delete Firebase Auth user ───────────────────────
app.post('/api/admin/update-user', requireOwner, jsonSmall, async (req, res) => {
    const { email, action } = req.body; // action: 'enable' | 'disable' | 'delete'
    if (!email || !action) return res.status(400).json({ error: 'Email and action required' });
    if (!adminAuth || !adminFirestore) return res.status(503).json({ error: 'Firebase Admin SDK not configured.' });
    try {
        const wlRef = adminFirestore.collection('system/access/approved').doc(email.toLowerCase());
        if (action === 'delete') {
            try { const u = await adminAuth.getUserByEmail(email); await adminAuth.deleteUser(u.uid); } catch(e) { if (e.code !== 'auth/user-not-found') throw e; }
            await wlRef.delete();
            console.log(`[Admin] Deleted: ${email}`);
            return res.json({ success: true });
        }
        if (action === 'disable') {
            try { const u = await adminAuth.getUserByEmail(email); await adminAuth.updateUser(u.uid, { disabled: true }); } catch(e) { if (e.code !== 'auth/user-not-found') throw e; }
            await wlRef.delete();
            console.log(`[Admin] Disabled: ${email}`);
            return res.json({ success: true });
        }
        if (action === 'enable') {
            try { const u = await adminAuth.getUserByEmail(email); await adminAuth.updateUser(u.uid, { disabled: false }); } catch(e) { if (e.code !== 'auth/user-not-found') throw e; }
            await wlRef.set({ addedBy: 'owner', addedAt: Date.now() }, { merge: true });
            console.log(`[Admin] Enabled: ${email}`);
            return res.json({ success: true });
        }
        res.status(400).json({ error: 'Unknown action' });
    } catch(e) {
        console.error(`[Admin] ${action} failed:`, e.message);
        res.status(400).json({ error: e.message });
    }
});

// ── Admin: Create email/password user ─────────────────────────────────────────
app.post('/api/admin/create-user', requireOwner, jsonSmall, async (req, res) => {
    const { email, requestedBy } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    if (!adminAuth) return res.status(503).json({ error: 'Firebase Admin SDK not configured. Add FIREBASE_SERVICE_ACCOUNT_JSON to Railway env vars.' });
    try {
        let resetLink = null;
        let authMethod = 'email';

        // Check if user already exists (e.g. signed in with Google before)
        let existingUser = null;
        try { existingUser = await adminAuth.getUserByEmail(email); } catch(e) { /* not found — will create */ }

        if (existingUser) {
            // Already in Firebase Auth (Google SSO user or prior account) — just whitelist them
            authMethod = existingUser.providerData?.[0]?.providerId === 'google.com' ? 'google' : 'email';
            console.log(`[Admin] User ${email} already exists (${authMethod}) — whitelisting only`);
        } else {
            // Brand new user — create email/password account and generate reset link
            const tempPassword = Math.random().toString(36).slice(-10) + Math.random().toString(36).slice(-6).toUpperCase() + '!';
            await adminAuth.createUser({ email, password: tempPassword, emailVerified: false });
            resetLink = await adminAuth.generatePasswordResetLink(email);
            console.log(`[Admin] Created + whitelisted ${email} (by ${requestedBy}) — reset link: ${resetLink}`);
        }

        // Whitelist via Admin SDK (client-side write is blocked by Firestore rules)
        await adminFirestore.collection('system/access/approved').doc(email.toLowerCase()).set({
            addedBy: requestedBy || 'owner',
            addedAt: Date.now(),
            authMethod
        });

        res.json({
            success: true,
            resetLink,
            alreadyExisted: !!existingUser,
            message: existingUser
                ? `${email} already had an account — access granted.`
                : `User ${email} created. Share the reset link to let them set their password.`
        });
    } catch(e) {
        console.error('[Admin] Create user failed:', e.message);
        res.status(400).json({ error: e.message });
    }
});

// ── Admin: Cloudinary storage purge ───────────────────────────────────────
// Lists all resources under jdinjax/ prefix, filters by age, deletes in batches.
// Body: { olderThanDays: number, preview: boolean }
// Returns: { deleted, freedBytes, previewCount, previewBytes }
app.post('/api/admin/cloudinary-purge', requireOwner, jsonSmall, async (req, res) => {
    const cloudName  = process.env.CLOUDINARY_CLOUD_NAME;
    const apiKey     = process.env.CLOUDINARY_API_KEY;
    const apiSecret  = process.env.CLOUDINARY_API_SECRET;
    if (!cloudName || !apiKey || !apiSecret)
        return res.status(503).json({ error: 'Cloudinary credentials not configured.' });

    const { olderThanDays = 30, preview = false } = req.body;
    const cutoff = new Date(Date.now() - olderThanDays * 24 * 60 * 60 * 1000);
    const auth   = Buffer.from(`${apiKey}:${apiSecret}`).toString('base64');
    const baseUrl = `https://api.cloudinary.com/v1_1/${cloudName}`;

    // Paginate through all resources under jdinjax/
    const toDelete = [];
    let nextCursor = null;
    do {
        const params = new URLSearchParams({ prefix: 'jdinjax/', max_results: '500', resource_type: 'image' });
        if (nextCursor) params.set('next_cursor', nextCursor);
        const listRes  = await fetch(`${baseUrl}/resources/image/upload?${params}`, {
            headers: { Authorization: `Basic ${auth}` }
        });
        const listData = await listRes.json();
        if (!listRes.ok) return res.status(502).json({ error: listData.error?.message || 'Cloudinary list failed' });
        for (const r of (listData.resources || [])) {
            if (new Date(r.created_at) < cutoff) toDelete.push({ public_id: r.public_id, bytes: r.bytes });
        }
        nextCursor = listData.next_cursor || null;
    } while (nextCursor);

    const totalBytes = toDelete.reduce((s, r) => s + r.bytes, 0);

    if (preview) {
        return res.json({ previewCount: toDelete.length, previewBytes: totalBytes });
    }

    // Delete in batches of 100 (Cloudinary API limit)
    let deleted = 0, freedBytes = 0;
    for (let i = 0; i < toDelete.length; i += 100) {
        const batch      = toDelete.slice(i, i + 100);
        const publicIds  = batch.map(r => r.public_id);
        const params     = new URLSearchParams();
        publicIds.forEach(id => params.append('public_ids[]', id));
        const delRes = await fetch(`${baseUrl}/resources/image/upload?${params}`, {
            method: 'DELETE',
            headers: { Authorization: `Basic ${auth}` }
        });
        const delData = await delRes.json();
        const deletedCount = Object.keys(delData.deleted || {}).length;
        deleted    += deletedCount;
        freedBytes += batch.slice(0, deletedCount).reduce((s, r) => s + r.bytes, 0);
    }
    console.log(`[Admin] Cloudinary purge: deleted ${deleted} images (${(freedBytes/1024/1024).toFixed(1)} MB), threshold ${olderThanDays}d`);
    res.json({ deleted, freedBytes });
});

// ── Admin: API usage — SerpAPI ────────────────────────────────────────────
app.get('/api/admin/usage/serpapi', requireOwner, async (req, res) => {
    const apiKey = process.env.SERPAPI_KEY;
    if (!apiKey) return res.json({ ok: false, error: 'SERPAPI_KEY not configured', fetchedAt: new Date().toISOString() });
    try {
        const r = await fetch(`https://serpapi.com/account?api_key=${apiKey}`);
        const d = await r.json();
        if (!r.ok) return res.json({ ok: false, error: d.error || 'SerpAPI error', fetchedAt: new Date().toISOString() });
        res.json({
            ok:               true,
            fetchedAt:        new Date().toISOString(),
            plan:             d.plan_name,
            accountEmail:     d.account_email,
            searchesPerMonth: d.searches_per_month,
            thisMonthUsage:   d.this_month_usage,
            searchesLeft:     d.plan_searches_left,
        });
    } catch (e) {
        res.json({ ok: false, error: e.message, fetchedAt: new Date().toISOString() });
    }
});

// ── Admin: API usage — Cloudinary ─────────────────────────────────────────
app.get('/api/admin/usage/cloudinary', requireOwner, async (req, res) => {
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    const apiKey    = process.env.CLOUDINARY_API_KEY;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;
    if (!cloudName || !apiKey || !apiSecret)
        return res.json({ ok: false, error: 'Cloudinary credentials not configured', fetchedAt: new Date().toISOString() });
    try {
        const auth = Buffer.from(`${apiKey}:${apiSecret}`).toString('base64');
        const r    = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/usage`, {
            headers: { Authorization: `Basic ${auth}` }
        });
        const d = await r.json();
        if (!r.ok) return res.json({ ok: false, error: d.error?.message || 'Cloudinary error', fetchedAt: new Date().toISOString() });
        res.json({
            ok:             true,
            fetchedAt:      new Date().toISOString(),
            plan:           d.plan,
            storageUsed:    d.storage?.usage    || 0,
            storageLimit:   d.storage?.limit    || 0,
            bandwidthUsed:  d.bandwidth?.usage  || 0,
            bandwidthLimit: d.bandwidth?.limit  || 0,
            resources:      d.resources         || 0,
            requests:       d.requests          || 0,
        });
    } catch (e) {
        res.json({ ok: false, error: e.message, fetchedAt: new Date().toISOString() });
    }
});

// ── Admin: API usage — Gemini (from Firestore accumulators) ───────────────
app.get('/api/admin/usage/gemini', requireOwner, async (req, res) => {
    if (!adminFirestore) return res.json({ ok: false, error: 'Firebase not configured', fetchedAt: new Date().toISOString() });
    try {
        const now      = new Date();
        const dayKey   = now.toISOString().slice(0, 10);  // YYYY-MM-DD
        const monthKey = now.toISOString().slice(0, 7);   // YYYY-MM
        const base = adminFirestore.collection('system/usage/gemini');
        const [daySnap, monthSnap] = await Promise.all([base.doc(dayKey).get(), base.doc(monthKey).get()]);
        const day   = daySnap.exists   ? daySnap.data()   : {};
        const month = monthSnap.exists ? monthSnap.data() : {};
        res.json({
            ok:                true,
            fetchedAt:         now.toISOString(),
            todayRequests:     day.requests     || 0,
            todayInputTokens:  day.inputTokens  || 0,
            todayOutputTokens: day.outputTokens || 0,
            monthRequests:     month.requests     || 0,
            monthInputTokens:  month.inputTokens  || 0,
            monthOutputTokens: month.outputTokens || 0,
        });
    } catch (e) {
        res.json({ ok: false, error: e.message, fetchedAt: new Date().toISOString() });
    }
});

// ── Admin: API usage — Server / Railway process metrics ───────────────────
app.get('/api/admin/usage/server', requireOwner, (req, res) => {
    const mem = process.memoryUsage();
    res.json({
        ok:            true,
        fetchedAt:     new Date().toISOString(),
        uptimeSeconds: Math.floor(process.uptime()),
        heapUsedMB:    (mem.heapUsed  / 1024 / 1024).toFixed(1),
        heapTotalMB:   (mem.heapTotal / 1024 / 1024).toFixed(1),
        rssMB:         (mem.rss       / 1024 / 1024).toFixed(1),
        nodeVersion:   process.version,
    });
});

// ── Health check — Railway/uptime monitors ────────────────────────────────
app.get('/health', (req, res) => {
    res.json({ status: 'ok', ts: new Date().toISOString() });
});

// ── Privacy Policy — required for eBay production API access ─────────────────
app.get('/privacy', (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Privacy Policy — Scout Recon</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 720px; margin: 60px auto; padding: 0 24px; color: #1e293b; line-height: 1.7; }
  h1 { font-size: 1.75rem; font-weight: 900; text-transform: uppercase; letter-spacing: -0.02em; margin-bottom: 4px; }
  h2 { font-size: 1rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 2rem; color: #475569; }
  p, li { font-size: 0.95rem; color: #334155; }
  ul { padding-left: 1.5rem; }
  .meta { font-size: 0.8rem; color: #94a3b8; margin-bottom: 2.5rem; }
  footer { margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid #e2e8f0; font-size: 0.8rem; color: #94a3b8; }
</style>
</head>
<body>
<h1>Privacy Policy</h1>
<p class="meta">Scout Recon &mdash; Effective: January 1, 2025 &mdash; Last updated: March 2026</p>

<h2>Overview</h2>
<p>Scout Recon is a private, invitation-only eBay resale management tool. This policy describes what data we collect, how it is used, and how it is protected.</p>

<h2>Data We Collect</h2>
<ul>
  <li><strong>Account information</strong> — email address and authentication credentials used to access the application (managed via Firebase Authentication).</li>
  <li><strong>eBay account data</strong> — OAuth access and refresh tokens required to connect your eBay seller account and submit listings on your behalf. Tokens are stored encrypted in Firestore and are never shared.</li>
  <li><strong>Listing data</strong> — item titles, descriptions, prices, images, and related metadata that you create or upload within the application.</li>
  <li><strong>Item images</strong> — uploaded photos stored via Cloudinary for use in eBay listings.</li>
  <li><strong>Usage data</strong> — basic server logs (request timestamps, endpoints accessed) for debugging and security purposes. No analytics or tracking pixels are used.</li>
</ul>

<h2>How We Use Your Data</h2>
<ul>
  <li>To authenticate you and maintain your session.</li>
  <li>To submit, manage, and sync listings to your eBay seller account via the eBay Sell APIs.</li>
  <li>To retrieve market pricing data from eBay on your behalf.</li>
  <li>To store your listing drafts and history securely in Firestore, scoped to your user account.</li>
</ul>

<h2>eBay Data</h2>
<p>Scout Recon connects to eBay's APIs using OAuth 2.0. We request only the scopes necessary to create, manage, and monitor listings on your behalf. Your eBay credentials are never stored in plaintext. You may disconnect your eBay account at any time from the Settings tab, which immediately revokes stored tokens.</p>

<h2>Data Sharing</h2>
<p>We do not sell, rent, or share your personal data with third parties. Data is shared only with the following service providers strictly to operate the application:</p>
<ul>
  <li><strong>Google Firebase</strong> — authentication and Firestore database</li>
  <li><strong>Cloudinary</strong> — image storage and delivery</li>
  <li><strong>eBay Inc.</strong> — listing submission and market data via eBay APIs</li>
  <li><strong>Google Gemini</strong> — AI-assisted item identification and listing generation (item images and titles only; no personal data)</li>
</ul>

<h2>eBay Marketplace Account Deletion</h2>
<p>In compliance with eBay's API requirements, we process eBay Marketplace Account Deletion notifications. Upon receiving a verified deletion request, all eBay-related data associated with the specified account is purged from our systems within 30 days.</p>

<h2>Data Retention</h2>
<p>Your data is retained for as long as your account is active. You may request deletion of your account and all associated data at any time by contacting us at the address below. eBay OAuth tokens are automatically invalidated upon disconnection.</p>

<h2>Security</h2>
<p>All data is transmitted over HTTPS. Firestore access is restricted by security rules that enforce per-user data isolation — no user can access another user's data. The application is access-controlled by an invitation-only whitelist.</p>

<h2>Contact</h2>
<p>For privacy questions or data deletion requests, contact: <strong>admin@scout-recon.com</strong></p>

<footer>Scout Recon &mdash; &copy; 2026</footer>
</body>
</html>`);
});

// ── Global JSON error handler — catches any next(err) and returns JSON ───────
// Must be registered BEFORE the catch-all so /api/* errors don't return HTML
app.use((err, req, res, next) => {
    console.error('[Server] Error:', err.status, err.message);
    res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
});

// ── SPA catch-all — serves index.html for any non-API route ──────────────
// Must be registered AFTER all API routes so /api/* are not intercepted
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Scout Recon] 🚀 Black Knight Command Center: v${APP_VERSION} active on port ${PORT}`);
    console.log(`[Scout Recon] 🛒 SerpApi Category Engine: ${process.env.SERPAPI_KEY ? 'Ready' : '⚠️  SERPAPI_KEY missing'}`);
});