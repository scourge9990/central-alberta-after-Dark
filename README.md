# Central Alberta After Dark 🌙

A dating app for night shift workers, oil patch crews, nurses, truckers, and anyone who thinks 2am is prime time.

---

## Environment Variables

Copy `.env.example` to `.env` and fill in the values before running locally.

| Variable | Required | Description |
|---|---|---|
| `SESSION_SECRET` | ✅ | Long random string for signing session cookies |
| `NODE_ENV` | ✅ prod | Set to `production` to enable HTTPS redirect & secure cookies |
| `APP_URL` | ✅ | Full public URL, e.g. `https://www.centralalbertaafterdark.com` |
| `STRIPE_SECRET_KEY` | ✅ | Stripe secret key (`sk_live_…`) |
| `STRIPE_WEBHOOK_SECRET` | ✅ | Stripe webhook signing secret (`whsec_…`) |
| `SMTP_HOST` | ✅ | SMTP server hostname |
| `SMTP_PORT` | ✅ | SMTP port (usually `587` for TLS, `465` for SSL) |
| `SMTP_SECURE` | | `true` for port 465 SSL, omit/`false` for STARTTLS |
| `SMTP_USER` | ✅ | SMTP username / email address |
| `SMTP_PASS` | ✅ | SMTP password or app-specific password |
| `FROM_EMAIL` | | Sender address for outgoing emails (defaults to `noreply@centralalbertaafterdark.com`) |
| `PORT` | | HTTP port (defaults to `3000`) |

---

## Running Locally

```bash
npm install
SESSION_SECRET=changeme node server.js
```

---

## Database

The app uses **SQLite** and creates `database.sqlite` in the project root on first run. A separate `sessions.sqlite` file stores session data.

### Tables

| Table | Purpose |
|---|---|
| `users` | Accounts with lockout columns (`failed_login_attempts`, `locked_until`) |
| `profiles` | Extended profile data (interests, photos) |
| `likes` | Like actions between users |
| `matches` | Mutual likes |
| `email_verifications` | Pending email verification tokens (24 h TTL) |
| `password_resets` | Password reset tokens (1 h TTL, single-use) |
| `audit_logs` | Immutable record of security-relevant actions |

### ⚠️ Database Backups

**SQLite stores all data in a single file. Back it up regularly to prevent data loss.**

On Railway, the `/app` directory is ephemeral by default. To persist data:

1. **Mount a Railway Volume** at `/app` (or at least `/app/database.sqlite`).
2. **Scheduled backup script** – run `backup.sh` via cron or a Railway cron job:

```bash
#!/bin/bash
# backup.sh – copy database to a timestamped backup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
cp /app/database.sqlite /backups/database_${TIMESTAMP}.sqlite
# Optionally upload to S3:
# aws s3 cp /app/database.sqlite s3://your-bucket/backups/database_${TIMESTAMP}.sqlite
```

3. **SQLite online backup** (zero-downtime):

```bash
sqlite3 /app/database.sqlite ".backup '/backups/database_backup.sqlite'"
```

---

## Security Features

| # | Feature | Implementation |
|---|---|---|
| 1 | **Persistent session store** | `connect-sqlite3` – no memory leaks, survives restarts |
| 2 | **CSRF protection** | `sameSite: strict` cookies + JSON API (no form-action endpoints) |
| 3 | **Email verification** | `email_verifications` table; login blocked until verified |
| 4 | **Password reset** | `password_resets` table; 1-hour single-use tokens via email |
| 5 | **Stripe webhook verification** | `stripe.webhooks.constructEvent` with `STRIPE_WEBHOOK_SECRET` |
| 6 | **Registration rate limiting** | 3 registrations per hour per IP |
| 7 | **Session fixation prevention** | `req.session.regenerate()` called on every successful login |
| 8 | **HTTPS enforcement** | HTTP → HTTPS redirect in production; `secure: true` cookies |
| 9 | **Account lockout** | 5 failed attempts → 15-minute lockout; counter reset on success |
| 10 | **Audit logging** | `audit_logs` table records register, login, logout, reset, payment |
| 11 | **Database backups** | See backup instructions above |
| 12 | **Input sanitization** | Strict XSS whitelist on all `req.body` string fields |

---

## Stripe Webhook Setup

1. In the Stripe Dashboard → Developers → Webhooks, add an endpoint:
   - URL: `https://www.centralalbertaafterdark.com/webhook/stripe`
   - Events: `checkout.session.completed`, `customer.subscription.deleted`
2. Copy the **Signing secret** (`whsec_…`) into `STRIPE_WEBHOOK_SECRET`.

---

## Deployment (Railway)

1. Set all environment variables in the Railway service settings.
2. Add a **Volume** mounted at `/app` to persist `database.sqlite` and `sessions.sqlite`.
3. The `start` script is `node server.js` – no build step required.
