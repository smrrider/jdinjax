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

const app  = express();
const PORT = process.env.PORT || 3001;
const APP_VERSION = "6.1.0";

// Owner email — drives server-side admin gate
const OWNER_EMAIL = process.env.OWNER_EMAIL || 'thedeboks@gmail.com';

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
    'https://api.ebay.com/oauth/api_scope/sell.inventory',
    'https://api.ebay.com/oauth/api_scope/sell.inventory.readonly',
    'https://api.ebay.com/oauth/api_scope/sell.marketing',
    'https://api.ebay.com/oauth/api_scope/sell.marketing.readonly',
    'https://api.ebay.com/oauth/api_scope/buy.order.readonly',
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

// ─── End eBay API Integration ──────────────────────────────────────────────────

/**
 * CLOUDINARY SIGNING ENGINE
 * Generates a HMAC-SHA1 signature for secure uploads.
 * Isolates files to: jdinjax/users/{userId}
 */
app.post('/api/sign-upload', jsonSmall, (req, res) => {
    const { userId, timestamp } = req.body;
    if (!userId || !timestamp) return res.status(400).json({ error: "Auth context required." });

    const folder = `jdinjax/users/${userId}`;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;

    // Cloudinary signing requirements
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
    const candidates = Object.entries(BKA_CATEGORY_MAP).map(([id, name]) => ({ id, name }));
    const result = await geminiPick(title, keyFeatures, description, candidates);
    result.source = "Gemini";
    console.log("[Scout Recon] Gemini-only: " + result.categoryId + " -> " + result.categoryPath);
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
        res.json(data);
    } catch (err) { res.status(502).json({ error: { message: err.message } }); }
});

// ── Admin: List all Firebase Auth users + whitelist status ────────────────────
app.get('/api/admin/list-users', requireOwner, async (req, res) => {
    if (!adminAuth || !adminFirestore) return res.status(503).json({ error: 'Firebase Admin SDK not configured.' });
    try {
        // Get all Firebase Auth users
        const listResult = await adminAuth.listUsers(1000);
        // Get Firestore whitelist
        const wlSnap = await adminFirestore.collection('system/access/approved').get();
        const whitelist = new Set(wlSnap.docs.map(d => d.id));
        const users = listResult.users.map(u => ({
            email:       u.email,
            provider:    u.providerData[0]?.providerId === 'google.com' ? 'google' : 'email',
            disabled:    u.disabled,
            whitelisted: whitelist.has(u.email),
            createdAt:   u.metadata.creationTime
        }));
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

// ── Health check — Railway/uptime monitors ────────────────────────────────
app.get('/health', (req, res) => {
    res.json({ status: 'ok', version: APP_VERSION, ts: new Date().toISOString() });
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