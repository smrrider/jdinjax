/**
 * JDINJAX eBay Listing Pro Console — Unified Single-Port Server
 * Version: 5.2.0 (SerpApi Category Resolution + Gemini Fallback)
 * MISSION: Secure multi-user logistics, CSV mapping, and signed uploads.
 */

require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3001;
const APP_VERSION = "5.2.0";

// ─── CATEGORY RESOLUTION ENGINE ─────────────────────────────────────────

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

// ─── CATEGORY RESOLUTION ENGINE v4 ─────────────────────────────────────────

const resolveViaSerpApi = async (title) => {
    const key = process.env.SERPAPI_KEY;
    if (!key) throw new Error("SERPAPI_KEY not configured");
    const params = new URLSearchParams({
        engine: "ebay", _nkw: title, ebay_domain: "ebay.com", api_key: key
    });
    const response = await fetch("https://serpapi.com/search?" + params.toString());
    if (!response.ok) throw new Error("SerpApi HTTP " + response.status);
    const data = await response.json();
    const cats = (data.categories || []).filter(c => c.id);
    if (!cats.length) throw new Error("SerpApi returned no category IDs");
    const best = cats[cats.length - 1]; // last = most specific leaf
    const categoryId = String(best.id);
    const categoryPath = BKA_CATEGORY_MAP[categoryId] || best.name || ("eBay Category " + categoryId);
    console.log("[eBay Scout] SerpApi: ID " + categoryId + " -> " + categoryPath);
    return { categoryId, categoryPath, confidence: "High", source: "SerpApi" };
};

const resolveViaGemini = async (title, keyFeatures, description) => {
    const seed = Object.entries(BKA_CATEGORY_MAP).map(([id,p]) => "- " + id + " | " + p).join("\n");
    const prompt = "You are an eBay category expert.\n\nITEM: " + title +
        "\nFEATURES: " + (keyFeatures.join(", ") || "N/A") +
        "\nDESCRIPTION: " + (description || "").substring(0,200) +
        "\n\nKNOWN BKA CATEGORIES:\n" + seed +
        "\n\nReturn ONLY JSON: {categoryId, categoryPath, confidence, source:\"Gemini\"}";
    const url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" + process.env.GEMINI_API_KEY;
    const resp = await fetch(url, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: prompt }] }], generationConfig: { responseMimeType: "application/json" } })
    });
    const d = await resp.json();
    const raw = (d.candidates?.[0]?.content?.parts?.[0]?.text || "").replace(/```json|```/g, "").trim();
    const result = JSON.parse(raw);
    console.log("[eBay Scout] Gemini fallback: " + result.categoryPath);
    return { ...result, source: "Gemini" };
};

app.post("/api/category-resolve", async (req, res) => {
    const { title, keyFeatures = [], description = "" } = req.body;
    if (!title) return res.status(400).json({ error: "Title required." });
    try {
        return res.json(await resolveViaSerpApi(title));
    } catch (serpErr) {
        console.warn("[eBay Scout] SerpApi failed (" + serpErr.message + ") — Gemini fallback");
    }
    try {
        return res.json(await resolveViaGemini(title, keyFeatures, description));
    } catch (err) {
        res.status(502).json({ error: "Category resolution failed", detail: err.message });
    }
});

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