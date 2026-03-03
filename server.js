/**
 * JDINJAX eBay Listing Pro Console — Unified Single-Port Server
 * Version: 5.1.0 (Gemini Two-Stage Category Resolution)
 * MISSION: Secure multi-user logistics, CSV mapping, and signed uploads.
 */

require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3001;
const APP_VERSION = "5.1.0";

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

/**
 * CATEGORY RESOLUTION ENGINE v3 — Gemini Two-Stage
 * Dedicated AI call focused purely on eBay category classification.
 * Seeded with BKA known-good category map for firearms/tactical inventory.
 * Falls back to Gemini general knowledge for out-of-scope items.
 */

const BKA_CATEGORY_SEED = `
KNOWN eBay LEAF CATEGORIES FOR FIREARMS & TACTICAL GEAR (use these when applicable):
- 73944  | Sporting Goods > Hunting > Scopes, Sights & Optics
- 177882 | Sporting Goods > Hunting > Mounts & Rings
- 73943  | Sporting Goods > Hunting > Stocks, Grips & Forends
- 73938  | Sporting Goods > Hunting > Magazines & Clips
- 177891 | Sporting Goods > Hunting > Cleaning Equipment & Supplies
- 73949  | Sporting Goods > Hunting > Slings & Swivels
- 177895 | Sporting Goods > Hunting > Lights, Lasers & Accessories
- 73940  | Sporting Goods > Hunting > Holsters
- 73936  | Sporting Goods > Hunting > Gun Parts
- 177885 | Sporting Goods > Hunting > Handguards & Rail Systems
- 177887 | Sporting Goods > Hunting > Triggers
- 177889 | Sporting Goods > Hunting > Barrels
- 177893 | Sporting Goods > Hunting > Suppressors & Silencers
- 3259   | Sporting Goods > Hunting > Clothing & Footwear
- 52387  | Sporting Goods > Hunting > Bags, Packs & Cases
- 31771  | Sporting Goods > Tactical & Duty Gear
- 57881  | Consumer Electronics > Batteries & Power Accessories
- 175759 | Computers/Tablets > Cases, Bags & Covers
- 20710  | Tools & Home Improvement > Tool Storage
- 183446 | Home & Garden > Tools & Workshop Equipment
`.trim();

app.post('/api/category-resolve', async (req, res) => {
    const { title, keyFeatures = [], description = '' } = req.body;
    if (!title) return res.status(400).json({ error: "Title required." });

    const prompt = `You are an eBay category classification expert specializing in firearms accessories, tactical gear, and general merchandise.

Your task: Identify the single most accurate eBay LEAF category for the item described below.

ITEM TITLE: ${title}
KEY FEATURES: ${keyFeatures.join(', ') || 'N/A'}
DESCRIPTION CONTEXT: ${description.substring(0, 200) || 'N/A'}

${BKA_CATEGORY_SEED}

INSTRUCTIONS:
1. Reason step by step about what this item is and what category best fits
2. Prefer the most specific LEAF category — never use a parent/broad category
3. If the item matches a known category above, use it exactly
4. If not, provide the correct eBay leaf category from your knowledge
5. Return ONLY valid JSON — no markdown, no preamble

Return JSON with exactly these keys:
{
  "categoryId": "string — numeric eBay category ID",
  "categoryPath": "string — full path e.g. Sporting Goods > Hunting > Scopes, Sights & Optics",
  "confidence": "High | Medium | Low",
  "reasoning": "one sentence explaining the classification"
}`;

    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`;
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ role: 'user', parts: [{ text: prompt }] }],
                generationConfig: { responseMimeType: 'application/json' }
            })
        });
        const data = await response.json();
        const raw = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
        const clean = raw.replace(/```json|```/g, '').trim();
        const result = JSON.parse(clean);
        console.log(`[eBay Scout] 🎯 Category resolved: "${result.categoryPath}" (${result.confidence}) for: "${title}"`);
        res.json(result);
    } catch (err) {
        console.error(`[eBay Scout] ❌ Category resolve failed for "${title}": ${err.message}`);
        res.status(502).json({ error: 'Category resolution failed', detail: err.message });
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
    console.log(`[eBay Scout] 🎯 Gemini Category Resolution Engine: Ready`);
});