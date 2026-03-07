/**
 * JDINJAX eBay Listing Pro Console — Unified Single-Port Server
 * Version: 5.7
 * MISSION: Secure multi-user logistics, CSV mapping, and signed uploads.
 */

require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3001;
const APP_VERSION = "5.6.0";

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
    "183446": "Home & Garden > Tools & Workshop Equipment"
};

// ─── Startup env validation ───────────────────────────────────────────────
const REQUIRED_ENV = [
    'FIREBASE_API_KEY', 'FIREBASE_AUTH_DOMAIN', 'FIREBASE_PROJECT_ID',
    'GEMINI_API_KEY', 'CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET'
];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length > 0) {
    console.error(`[eBay Scout] ❌ MISSING ENV VARS: ${missingEnv.join(', ')}`);
    console.error('[eBay Scout] Server will start but affected endpoints will fail.');
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
    'https://ebay-lister.up.railway.app',
    'http://localhost:3001',
    'http://127.0.0.1:3001'
];
app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (same-origin, curl, Postman)
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        console.warn('[CORS] Blocked origin:', origin);
        callback(new Error('CORS: origin not allowed'));
    },
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type']
}));
app.use(express.static(path.join(__dirname)));

// Route-specific body parsers — tighter limits where images aren't needed
const jsonSmall  = express.json({ limit: '64kb'  });   // text-only routes
const jsonImages = express.json({ limit: '50mb'  });   // Gemini image proxy

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
        }
    });
});

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
    console.log("[eBay Scout] SerpApi candidates: " + cats.map(c => c.id + ":" + c.name).join(", "));
    return cats;
};

const resolveViaGeminiOnly = async (title, keyFeatures, description) => {
    const candidates = Object.entries(BKA_CATEGORY_MAP).map(([id, name]) => ({ id, name }));
    const result = await geminiPick(title, keyFeatures, description, candidates);
    result.source = "Gemini";
    console.log("[eBay Scout] Gemini-only: " + result.categoryId + " -> " + result.categoryPath);
    return result;
};

// In-flight request deduplication — bulk batches with similar titles share one API call
const _inflightCategoryReqs = new Map();

app.post("/api/category-resolve", jsonSmall, async (req, res) => {
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
app.post('/api/barcode-search', jsonSmall, async (req, res) => {
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
app.post('/api/proxy-image', jsonSmall, async (req, res) => {
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
app.post('/api/gemini', jsonImages, async (req, res) => {
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

// ── SPA catch-all — serves index.html for any non-API route ──────────────
// Must be registered AFTER all API routes so /api/* are not intercepted
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[eBay Scout] 🚀 Black Knight Command Center: v${APP_VERSION} active on port ${PORT}`);
    console.log(`[eBay Scout] 🛒 SerpApi Category Engine: ${process.env.SERPAPI_KEY ? 'Ready' : '⚠️  SERPAPI_KEY missing'}`);
});