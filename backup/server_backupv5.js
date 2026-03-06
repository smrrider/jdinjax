/**
 * JDINJAX eBay Listing Pro Console — Unified Single-Port Server
 * Version: 5.4.0 (Image Compression + Category Cache)
 * MISSION: Secure multi-user logistics, CSV mapping, and signed uploads.
 */

require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3001;
const APP_VERSION = "5.4.0";

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

// ─── Middleware ────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname)));

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
app.post('/api/sign-upload', (req, res) => {
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
    const response = await fetch("https://serpapi.com/search?" + params.toString());
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

app.post("/api/category-resolve", async (req, res) => {
    const { title, keyFeatures = [], description = "" } = req.body;
    if (!title) return res.status(400).json({ error: "Title required." });

    // ── Cache hit — instant return, no API calls ──────────────────────────────
    const cached = cacheGet(title);
    if (cached) {
        console.log("[eBay Scout] Cache hit: " + title.substring(0, 40) + " → " + cached.categoryId);
        return res.json(cached);
    }

    // ── Stage 1: Hybrid (SerpApi candidates + Gemini selection) ──────────────
    try {
        const candidates = await fetchSerpApiCandidates(title);
        const result = await geminiPick(title, keyFeatures, description, candidates);
        console.log("[eBay Scout] Hybrid result: " + result.categoryId + " -> " + result.categoryPath);
        cacheSet(title, result);
        return res.json(result);
    } catch (err) {
        console.warn("[eBay Scout] Hybrid failed (" + err.message + ") — Gemini-only fallback");
    }

    // ── Stage 2: Pure Gemini fallback ────────────────────────────────────────
    try {
        const result = await resolveViaGeminiOnly(title, keyFeatures, description);
        cacheSet(title, result);
        return res.json(result);
    } catch (err) {
        res.status(502).json({ error: "Category resolution failed", detail: err.message });
    }
});

/**
 * GEMINI PROXY
 */
app.post('/api/gemini', async (req, res) => {
    const { model = 'gemini-2.5-flash', ...payload } = req.body;
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`;
    try {
        const response = await fetch(url, { 
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' }, 
            body: JSON.stringify(payload) 
        });
        const data = await response.json();
        res.json(data);
    } catch (err) { res.status(502).json({ error: { message: err.message } }); }
});

// Start Logistics Engine
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[eBay Scout] 🚀 Black Knight Command Center: v${APP_VERSION} active on port ${PORT}`);
    console.log(`[eBay Scout] 🛒 SerpApi Category Engine: ${process.env.SERPAPI_KEY ? 'Ready' : '⚠️  SERPAPI_KEY missing — Gemini fallback only'}`);
});