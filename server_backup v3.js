/**
 * JDINJAX eBay Listing Pro Console — Unified Single-Port Server
 * Version: 4.0.0 (Production Baseline)
 * MISSION: Secure multi-user logistics, CSV mapping, and signed uploads.
 */

require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3001;
const APP_VERSION = "4.0.0";

// ─── INTERNAL CATEGORY DATABASE ───────────────────────────────────────────
let EBAY_CATEGORY_DB = [];

const loadCategoryDatabase = () => {
    try {
        const csvPath = path.join(__dirname, 'CategoryIDs-US.csv');
        if (!fs.existsSync(csvPath)) {
            console.error('[JDINJAX] ❌ CategoryIDs-US.csv NOT FOUND.');
            return;
        }
        const data = fs.readFileSync(csvPath, 'utf8');
        const lines = data.split(/\r?\n/);
        EBAY_CATEGORY_DB = lines.slice(1).filter(line => line.trim()).map(line => {
            const match = line.match(/^(\d+),"(.*)"$/) || line.match(/^(\d+),(.*)$/);
            if (match) {
                return { 
                    id: match[1], 
                    path: match[2], 
                    normalizedPath: match[2].toLowerCase().replace(/&/g, 'and').replace(/[^a-z0-9]/g, '').trim() 
                };
            }
            return null;
        }).filter(Boolean);
        console.log(`[JDINJAX] 📦 Category Mapping Engine: Online.`);
    } catch (err) { console.error('[JDINJAX] ❌ DB Error:', err.message); }
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

/**
 * CATEGORY LOOKUP ENGINE
 * Matches AI Predicted Path to CSV verified ID.
 */
app.get('/api/category-lookup', (req, res) => {
    const { predictedPath } = req.query;
    const aiPathNorm = (predictedPath || '').toLowerCase().replace(/&/g, 'and').replace(/[^a-z0-9]/g, '').trim();
    const match = EBAY_CATEGORY_DB.find(cat => cat.normalizedPath === aiPathNorm);
    if (match) return res.json({ categoryId: match.id, categoryPath: match.path });
    res.status(404).json({ error: "Mapping failed" });
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
loadCategoryDatabase();
app.listen(PORT, '0.0.0.0', () => {
    console.log(`[JDINJAX] 🚀 Black Knight Command Center: v${APP_VERSION} active on port ${PORT}`);
});