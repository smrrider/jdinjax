# Scout Recon — Claude Code Project Context

## Deployment
This is a **Railway-deployed Node.js + Express server application** (`server.js`) with a single-page React frontend (`index.html`). It is not a local dev server project.

## Preview / Verification
**Do not use `preview_start` or require a local dev server.** This project cannot be run locally without production credentials (Firebase Admin SDK, eBay API keys, Gemini API, Cloudinary, SerpAPI) that are only available in Railway environment variables.

Code verification is performed by:
1. Reviewing the diff before committing
2. Pushing to `main` via `git push origin main`
3. Checking Railway deployment logs for startup errors

The `[Preview Required]` stop hook feedback does not apply to this project and can be safely ignored.

## Stack
- **Backend**: Node.js / Express on Railway (`server.js`)
- **Frontend**: Single `index.html` — React via CDN, Tailwind via CDN
- **Database**: Firebase Firestore (Admin SDK on server, client SDK in browser)
- **Auth**: Firebase Auth
- **Storage**: Cloudinary (images)
- **AI**: Google Gemini 2.5 Flash (item processing, category resolution, price estimation)
- **eBay**: Sell Inventory API, Browse API, Finding API (price research)
- **Search**: SerpAPI (category resolution, sold price data)

## Key Files
- `server.js` — Express API server, all `/api/*` routes
- `index.html` — entire frontend SPA (React CDN, no build step)
- `firestore.rules` — Firestore security rules
- `firebase.json` — Firebase CLI config

## Commit Convention
Commit directly to `main` and push. No PR workflow needed.
