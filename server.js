/**
 * JDINJAX eBay Listing Pro Console — Unified Single-Port Server
 * Version: 3.5.0 (Local Database Edition)
 *
 * MISSION: Use CategoryIDs-US.csv as the authoritative source for IDs.
 * Bypasses all web-scraping dependencies for category matching.
 */

require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const fs      = require('fs');

const app  = express();
const PORT = process.env.PORT || 3001;

// ─── INTERNAL CATEGORY DATABASE ───────────────────────────────────────────
let EBAY_CATEGORY_DB = [];

const loadCategoryDatabase = () => {
    try {
        const csvPath = path.join(__dirname, 'CategoryIDs-US.csv');
        if (!fs.existsSync(csvPath)) {
            console.error('[JDINJAX] ❌ CategoryIDs-US.csv NOT FOUND. Auto-lookup will fail.');
            return;
        }
        const data = fs.readFileSync(csvPath, 'utf8');
        const lines = data.split(/\r?\n/);
        
        // Skip header, parse lines
        EBAY_CATEGORY_DB = lines.slice(1).filter(line => line.trim()).map(line => {
            // Regex to handle CSV quoting: ID,"Path > Path"
            const match = line.match(/^(\d+),"(.*)"$/) || line.match(/^(\d+),(.*)$/);
            if (match) {
                return { id: match[1], path: match[2] };
            }
            return null;
        }).filter(Boolean);

        console.log(`[JDINJAX] 📦 Database Loaded: ${EBAY_CATEGORY_DB.length} eBay Categories cached.`);
    } catch (err) {
        console.error('[JDINJAX] ❌ Error loading Category DB:', err.message);
    }
};

// ─── Validate env vars ───────────────────────────────────────────────────
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const REQUIRED_FIREBASE_VARS = ['FIREBASE_API_KEY', 'FIREBASE_AUTH_DOMAIN', 'FIREBASE_PROJECT_ID', 'FIREBASE_APP_ID'];

if (!GEMINI_API_KEY || !REQUIRED_FIREBASE_VARS.every(v => !!process.env[v])) {
    console.error('[JDINJAX] ❌ Missing Critical Env Vars. Check .env file.');
    process.exit(1);
}

// ─── Middleware ────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname)));

// ─── API Routes ───────────────────────────────────────────────────────────

app.get('/api/config', (req, res) => {
    res.json({
        firebase: {
            apiKey: process.env.FIREBASE_API_KEY,
            authDomain: process.env.FIREBASE_AUTH_DOMAIN,
            projectId: process.env.FIREBASE_PROJECT_ID,
            storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
            messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
            appId: process.env.FIREBASE_APP_ID
        },
        cloudinary: {
            cloudName: process.env.CLOUDINARY_CLOUD_NAME || 'daeb6pcxf',
            uploadPreset: process.env.CLOUDINARY_UPLOAD_PRESET || 'jdinjax_unsigned'
        }
    });
});

/**
 * HIGH-SPEED CATEGORY LOOKUP
 * Logic: Fuzzy keyword matching against the local CSV database.
 */
app.get('/api/category-lookup', (req, res) => {
    const { title, predictedPath } = req.query;
    if (!title) return res.status(400).json({ error: "Context required" });

    console.log(`[JDINJAX] 🔍 Searching local DB for: "${title}"`);

    // Normalize input keywords
    const searchTerms = `${title} ${predictedPath || ''}`.toLowerCase().replace(/[^a-z0-9 ]/g, '').split(' ').filter(w => w.length > 2);

    let bestMatch = null;
    let highestScore = 0;

    // Search Database
    EBAY_CATEGORY_DB.forEach(cat => {
        let score = 0;
        const catPathLower = cat.path.toLowerCase();
        
        searchTerms.forEach(term => {
            if (catPathLower.includes(term)) {
                score += 1;
                // Extra weight for specific matches in deeper categories
                if (catPathLower.split('>').pop().includes(term)) score += 2;
            }
        });

        if (score > highestScore) {
            highestScore = score;
            bestMatch = cat;
        }
    });

    if (bestMatch && highestScore > 0) {
        console.log(`[JDINJAX] ✅ Best Match Found: [${bestMatch.id}] ${bestMatch.path} (Score: ${highestScore})`);
        res.json({ categoryId: bestMatch.id, categoryPath: bestMatch.path });
    } else {
        res.status(404).json({ error: "No confident match in local DB." });
    }
});

app.post('/api/gemini', async (req, res) => {
    const { model = 'gemini-2.5-flash', ...payload } = req.body;
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${GEMINI_API_KEY}`;
    try {
        const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        const data = await response.json();
        res.json(data);
    } catch (err) {
        res.status(502).json({ error: { message: err.message } });
    }
});

app.get('/health', (req, res) => res.json({ status: 'online', dbSize: EBAY_CATEGORY_DB.length }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Initialize and Start
loadCategoryDatabase();
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n╔══════════════════════════════════════════════╗`);
    console.log(`║     JDINJAX eBay Factory — v3.5.0            ║`);
    console.log(`╚══════════════════════════════════════════════╝`);
    console.log(`  Port     : ${PORT}`);
    console.log(`  Database : LOCAL CSV (ACTIVE)`);
    console.log(`  UI       : http://localhost:${PORT}/\n`);
});