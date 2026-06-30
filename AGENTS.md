# Central Alberta After Dark - Agent Memory

## Project Overview
**Platform**: Platonic friendship app for night shift workers in Central Alberta
**Stack**: Node.js/Express, SQLite, Stripe, Cloudinary
**Focus**: 100% platonic friendships - no dating, no romantic content

## Starting Point (June 30, 2026)
- **Git Tag**: `snapshot-2026-06-30-start`
- **Commit**: `8bd448b4c0aba9b3349926f975ff5cc63d492478`
- **Server**: Running on port 3000

## Premium Features
- Profile views (who viewed your profile)
- Who liked me (see who liked you)
- Private messaging
- Ad removal
- Priority placement

## Free Features
- Profile browsing
- Category filtering (All Night Owls, Night Shift Workers, Fishing Buddies, etc.)
- Likes
- Public chat ticker

## Key Files
- `server.js` - Main Express server
- `public/index.html` - Main SPA frontend
- `public/client.js` - Client-side JavaScript
- `PREMIUM_TEST_CHECKLIST.md` - Comprehensive test checklist

## Configuration
- Session secret: `central-alberta-after-dark-dev-secret-2026`
- Database: SQLite in `data/` directory
- Uploads: `public/uploads/`
- Cloudinary: Pre-configured with demo credentials

## Testing
See `PREMIUM_TEST_CHECKLIST.md` for full test suite organized by:
1. Free User Baseline
2. Premium Subscription Flow
3. Premium Feature Activation
4. Platonic Nature Enforcement
5. Security & Performance
6. Mobile Responsive
7. Cross-Browser
8. Subscription Management
