const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss');
const { body, validationResult } = require('express-validator');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

const SESSION_SECRET = process.env.SESSION_SECRET || 'central-alberta-night-life-secret-key';

// ---------------------------------------------------------------------------
// 8. HTTPS enforcement – redirect HTTP → HTTPS in production
// ---------------------------------------------------------------------------
if (IS_PROD) {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
    next();
  });
}

// ---------------------------------------------------------------------------
// Helmet – security headers
// ---------------------------------------------------------------------------
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// ---------------------------------------------------------------------------
// Rate limiters
// ---------------------------------------------------------------------------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests from this IP.' },
});

// 6. Dedicated rate limiter for registration – 3 attempts per hour per IP
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { error: 'Too many registration attempts. Try again in an hour.' },
});

app.use('/api/login', loginLimiter);
app.use('/api/register', registerLimiter);
app.use('/api/', apiLimiter);

// ---------------------------------------------------------------------------
// Body parsers – Stripe webhook needs raw body, so register it BEFORE json()
// ---------------------------------------------------------------------------
app.use('/webhook/stripe', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static('public'));

// ---------------------------------------------------------------------------
// 1. Session store – SQLiteStore instead of in-memory MemoryStore
// ---------------------------------------------------------------------------
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: './' }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'sessionId',
  cookie: {
    // 8. secure: true so cookies are only sent over HTTPS in production
    secure: IS_PROD,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'strict',
  },
}));

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) {
    console.error('Failed to open database:', err.message);
    process.exit(1);
  }
  console.log('Connected to SQLite database.');
});

db.serialize(() => {
  db.run('PRAGMA foreign_keys = ON');

  // Core users table – includes 9. account-lockout columns
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    age INTEGER CHECK(age >= 18 AND age <= 120),
    location TEXT,
    bio TEXT,
    shift_schedule TEXT,
    email_verified INTEGER DEFAULT 0,
    is_premium INTEGER DEFAULT 0,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until DATETIME DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS profiles (
    user_id INTEGER PRIMARY KEY,
    interests TEXT,
    looking_for TEXT,
    photos TEXT DEFAULT '[]',
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    liker_id INTEGER,
    liked_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(liker_id, liked_id),
    FOREIGN KEY(liker_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(liked_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user1_id INTEGER,
    user2_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user1_id, user2_id),
    FOREIGN KEY(user1_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(user2_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // 3. Email verification tokens
  db.run(`CREATE TABLE IF NOT EXISTS email_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // 4. Password reset tokens
  db.run(`CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // 10. Audit log
  db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    ip_address TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  console.log('Database tables initialized.');
});

// ---------------------------------------------------------------------------
// 10. Audit logging helper
// ---------------------------------------------------------------------------
function auditLog(userId, action, ipAddress, details = null) {
  db.run(
    `INSERT INTO audit_logs (user_id, action, ip_address, details) VALUES (?, ?, ?, ?)`,
    [userId || null, action, ipAddress || null, details ? JSON.stringify(details) : null],
    (err) => { if (err) console.error('Audit log error:', err); }
  );
}

// ---------------------------------------------------------------------------
// 12. Input sanitization – strict XSS whitelist, applied per-field
// ---------------------------------------------------------------------------
const xssOptions = {
  whiteList: {},
  stripIgnoreTag: true,
  stripIgnoreTagBody: ['script', 'style', 'iframe', 'object', 'embed'],
  escapeHtml: (str) => str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;'),
};

function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return xss(input.trim(), xssOptions);
}

// Sanitize all string fields in req.body
app.use((req, res, next) => {
  if (req.body && typeof req.body === 'object') {
    try {
      const sanitize = (obj) => {
        for (const key of Object.keys(obj)) {
          if (typeof obj[key] === 'string') {
            obj[key] = sanitizeInput(obj[key]);
          } else if (obj[key] && typeof obj[key] === 'object') {
            sanitize(obj[key]);
          }
        }
      };
      sanitize(req.body);
    } catch (e) {
      console.error('Sanitization error:', e);
    }
  }
  next();
});

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------
const requireAuth = (req, res, next) => {
  if (req.session?.userId) {
    next();
  } else {
    return res.status(401).json({ error: 'Unauthorized - please log in.' });
  }
};

// ---------------------------------------------------------------------------
// Email transport (nodemailer)
// ---------------------------------------------------------------------------
const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.ethereal.email',
  port: parseInt(process.env.SMTP_PORT || '587', 10),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
  },
});

const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;
const FROM_EMAIL = process.env.FROM_EMAIL || 'noreply@centralalbertaafterdark.com';

async function sendVerificationEmail(toEmail, token) {
  const link = `${APP_URL}/api/verify-email/${token}`;
  await mailer.sendMail({
    from: FROM_EMAIL,
    to: toEmail,
    subject: 'Verify your Central Alberta After Dark account',
    text: `Welcome! Please verify your email by visiting:\n\n${link}\n\nThis link expires in 24 hours.`,
    html: `<p>Welcome to <strong>Central Alberta After Dark</strong>!</p>
           <p>Please verify your email address by clicking the link below:</p>
           <p><a href="${link}">${link}</a></p>
           <p>This link expires in 24 hours.</p>`,
  });
}

async function sendPasswordResetEmail(toEmail, token) {
  const link = `${APP_URL}/reset-password.html?token=${token}`;
  await mailer.sendMail({
    from: FROM_EMAIL,
    to: toEmail,
    subject: 'Reset your Central Alberta After Dark password',
    text: `You requested a password reset. Visit:\n\n${link}\n\nThis link expires in 1 hour. If you did not request this, ignore this email.`,
    html: `<p>You requested a password reset for your <strong>Central Alberta After Dark</strong> account.</p>
           <p><a href="${link}">Reset my password</a></p>
           <p>This link expires in 1 hour. If you did not request this, you can safely ignore this email.</p>`,
  });
}

// ---------------------------------------------------------------------------
// 3. Registration – send verification email, do NOT auto-login
// ---------------------------------------------------------------------------
app.post('/api/register',
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('username')
      .isLength({ min: 3, max: 20 })
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage('Username: 3-20 chars, letters/numbers/underscore only'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('age').optional().isInt({ min: 18, max: 120 }).withMessage('Age must be 18-120'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
    }

    const { email, username, password, age, location } = req.body;

    try {
      const hashedPassword = await bcrypt.hash(password, 12);
      const verifyToken = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

      db.run(
        `INSERT INTO users (email, username, password_hash, age, location, email_verified)
         VALUES (?, ?, ?, ?, ?, 0)`,
        [email.toLowerCase(), username, hashedPassword, age || null, location || null],
        function(err) {
          if (err) {
            if (err.message?.includes('UNIQUE constraint failed')) {
              return res.status(400).json({ error: 'Email or username already taken.' });
            }
            console.error('DB Error:', err);
            return res.status(500).json({ error: 'Database error' });
          }

          const userId = this.lastID;

          db.run(
            `INSERT INTO email_verifications (user_id, token, expires_at) VALUES (?, ?, ?)`,
            [userId, verifyToken, expiresAt],
            async (verifyErr) => {
              if (verifyErr) {
                console.error('Verification token error:', verifyErr);
                return res.status(500).json({ error: 'Could not create verification token' });
              }

              try {
                await sendVerificationEmail(email, verifyToken);
              } catch (mailErr) {
                console.error('Email send error:', mailErr);
                // Don't block registration if email fails – log it
              }

              auditLog(userId, 'register', req.ip, { username, email });

              res.status(201).json({
                success: true,
                message: 'Account created! Please check your email to verify your address before logging in.',
              });
            }
          );
        }
      );
    } catch (error) {
      console.error('Server Error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// ---------------------------------------------------------------------------
// 3. Email verification endpoint
// ---------------------------------------------------------------------------
app.get('/api/verify-email/:token', (req, res) => {
  const { token } = req.params;

  db.get(
    `SELECT ev.user_id, ev.expires_at, u.email
     FROM email_verifications ev
     JOIN users u ON u.id = ev.user_id
     WHERE ev.token = ?`,
    [token],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!row) return res.status(400).json({ error: 'Invalid or already-used verification link.' });

      if (new Date(row.expires_at) < new Date()) {
        return res.status(400).json({ error: 'Verification link has expired. Please register again.' });
      }

      db.run(`UPDATE users SET email_verified = 1 WHERE id = ?`, [row.user_id], (updateErr) => {
        if (updateErr) return res.status(500).json({ error: 'Database error' });

        db.run(`DELETE FROM email_verifications WHERE token = ?`, [token]);
        auditLog(row.user_id, 'email_verified', req.ip);

        // Redirect to the main page with a success flag
        res.redirect('/?verified=1');
      });
    }
  );
});

// ---------------------------------------------------------------------------
// Login – 7. session regeneration, 9. account lockout, 10. audit log
// ---------------------------------------------------------------------------
app.post('/api/login',
  body('username').isLength({ min: 3 }).withMessage('Invalid username'),
  body('password').exists().withMessage('Password required'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
    }

    const { username, password } = req.body;

    db.get(
      `SELECT id, username, password_hash, email_verified, failed_login_attempts, locked_until
       FROM users WHERE username = ?`,
      [username],
      async (err, user) => {
        if (err) {
          console.error('DB Error:', err);
          return res.status(500).json({ error: 'Database error' });
        }

        // Use a generic message to avoid username enumeration
        if (!user) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        // 9. Check account lockout
        if (user.locked_until && new Date(user.locked_until) > new Date()) {
          const minutesLeft = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
          auditLog(user.id, 'login_blocked_lockout', req.ip);
          return res.status(423).json({
            error: `Account temporarily locked due to too many failed attempts. Try again in ${minutesLeft} minute(s).`,
          });
        }

        // 3. Require email verification before login
        if (!user.email_verified) {
          return res.status(403).json({
            error: 'Please verify your email address before logging in. Check your inbox.',
          });
        }

        try {
          const match = await bcrypt.compare(password, user.password_hash);

          if (!match) {
            // 9. Increment failed attempts; lock after 5
            const newAttempts = (user.failed_login_attempts || 0) + 1;
            const lockUntil = newAttempts >= 5
              ? new Date(Date.now() + 15 * 60 * 1000).toISOString()
              : null;

            db.run(
              `UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?`,
              [newAttempts, lockUntil, user.id]
            );

            auditLog(user.id, 'login_failed', req.ip, { attempts: newAttempts });

            if (lockUntil) {
              return res.status(423).json({
                error: 'Too many failed attempts. Account locked for 15 minutes.',
              });
            }
            return res.status(401).json({ error: 'Invalid credentials' });
          }

          // Successful login – reset lockout counter
          db.run(
            `UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?`,
            [user.id]
          );

          // 7. Regenerate session ID to prevent session fixation
          req.session.regenerate((regenErr) => {
            if (regenErr) {
              console.error('Session regeneration error:', regenErr);
              return res.status(500).json({ error: 'Session error' });
            }
            req.session.userId = user.id;
            req.session.username = user.username;

            auditLog(user.id, 'login_success', req.ip);
            res.json({ success: true, username: user.username });
          });
        } catch (error) {
          console.error('Bcrypt Error:', error);
          res.status(500).json({ error: 'Server error' });
        }
      }
    );
  }
);

// ---------------------------------------------------------------------------
// Logout – 10. audit log
// ---------------------------------------------------------------------------
app.post('/api/logout', (req, res) => {
  const userId = req.session?.userId;
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed.' });
    }
    auditLog(userId, 'logout', req.ip);
    res.clearCookie('sessionId');
    res.json({ success: true, message: 'Logged out.' });
  });
});

// ---------------------------------------------------------------------------
// 4. Forgot password
// ---------------------------------------------------------------------------
app.post('/api/forgot-password',
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
    }

    const { email } = req.body;

    // Always return success to prevent email enumeration
    db.get(`SELECT id FROM users WHERE email = ?`, [email.toLowerCase()], async (err, user) => {
      if (err) console.error('DB Error:', err);

      if (user) {
        const resetToken = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour

        db.run(
          `INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)`,
          [user.id, resetToken, expiresAt],
          async (insertErr) => {
            if (insertErr) {
              console.error('Password reset token error:', insertErr);
              return;
            }
            try {
              await sendPasswordResetEmail(email, resetToken);
              auditLog(user.id, 'password_reset_requested', req.ip);
            } catch (mailErr) {
              console.error('Password reset email error:', mailErr);
            }
          }
        );
      }

      // Always respond the same way
      res.json({ success: true, message: 'If that email is registered, a reset link has been sent.' });
    });
  }
);

// ---------------------------------------------------------------------------
// 4. Reset password
// ---------------------------------------------------------------------------
app.post('/api/reset-password/:token',
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
    }

    const { token } = req.params;
    const { password } = req.body;

    db.get(
      `SELECT pr.user_id, pr.expires_at, pr.used
       FROM password_resets pr
       WHERE pr.token = ?`,
      [token],
      async (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!row || row.used) return res.status(400).json({ error: 'Invalid or already-used reset link.' });
        if (new Date(row.expires_at) < new Date()) {
          return res.status(400).json({ error: 'Reset link has expired. Please request a new one.' });
        }

        try {
          const hashedPassword = await bcrypt.hash(password, 12);

          db.run(`UPDATE users SET password_hash = ?, failed_login_attempts = 0, locked_until = NULL WHERE id = ?`,
            [hashedPassword, row.user_id],
            (updateErr) => {
              if (updateErr) return res.status(500).json({ error: 'Database error' });

              db.run(`UPDATE password_resets SET used = 1 WHERE token = ?`, [token]);
              auditLog(row.user_id, 'password_reset_completed', req.ip);

              res.json({ success: true, message: 'Password updated. You can now log in.' });
            }
          );
        } catch (hashErr) {
          console.error('Hash error:', hashErr);
          res.status(500).json({ error: 'Server error' });
        }
      }
    );
  }
);

// ---------------------------------------------------------------------------
// Profile & social endpoints
// ---------------------------------------------------------------------------
app.get('/api/me', requireAuth, (req, res) => {
  db.get(
    `SELECT id, username, email, age, location, is_premium, created_at FROM users WHERE id = ?`,
    [req.session.userId],
    (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!user) return res.status(404).json({ error: 'User not found' });
      res.json(user);
    }
  );
});

app.get('/api/profiles', (req, res) => {
  db.all(
    `SELECT id, username, age, location, bio FROM users WHERE email_verified = 1 AND (id != ? OR ? IS NULL)`,
    [req.session?.userId || null, req.session?.userId || null],
    (err, rows) => {
      if (err) {
        console.error('DB Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(rows);
    }
  );
});

app.post('/api/like/:id', requireAuth, (req, res) => {
  const likedId = parseInt(req.params.id, 10);
  const likerId = req.session.userId;

  if (likedId === likerId) {
    return res.status(400).json({ error: 'Cannot like yourself' });
  }

  db.run(
    `INSERT OR IGNORE INTO likes (liker_id, liked_id) VALUES (?, ?)`, [likerId, likedId],
    function(err) {
      if (err) {
        console.error('DB Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      db.get(
        `SELECT * FROM likes WHERE liker_id = ? AND liked_id = ?`, [likedId, likerId],
        (err, reciprocal) => {
          if (err) {
            console.error('DB Error:', err);
            return res.status(500).json({ error: 'Database error' });
          }

          if (reciprocal) {
            const user1 = Math.min(likerId, likedId);
            const user2 = Math.max(likerId, likedId);

            db.run(
              `INSERT OR IGNORE INTO matches (user1_id, user2_id) VALUES (?, ?)`,
              [user1, user2],
              (matchErr) => {
                if (matchErr) console.error('Match creation error:', matchErr);
              }
            );

            auditLog(likerId, 'match_created', req.ip, { with: likedId });
            return res.json({ success: true, match: true, message: "It's a match!" });
          }

          res.json({ success: true, match: false, message: 'Liked!' });
        }
      );
    }
  );
});

// ---------------------------------------------------------------------------
// Stripe checkout
// ---------------------------------------------------------------------------
app.post('/create-checkout-session', requireAuth, async (req, res) => {
  try {
    const prices = await stripe.prices.list({
      lookup_keys: [req.body.lookup_key],
      expand: ['data.product'],
    });

    if (!prices.data.length) {
      return res.status(400).json({ error: 'Invalid price lookup key.' });
    }

    const checkoutSession = await stripe.checkout.sessions.create({
      billing_address_collection: 'auto',
      line_items: [{ price: prices.data[0].id, quantity: 1 }],
      mode: 'subscription',
      metadata: { userId: String(req.session.userId) },
      success_url: `${APP_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${APP_URL}/cancel.html`,
    });

    auditLog(req.session.userId, 'checkout_initiated', req.ip, { priceId: prices.data[0].id });
    res.redirect(303, checkoutSession.url);
  } catch (err) {
    console.error('Stripe checkout error:', err);
    res.status(500).json({ error: 'Could not create checkout session.' });
  }
});

// ---------------------------------------------------------------------------
// 5. Stripe webhook – verify signature, update premium on payment confirmed
// ---------------------------------------------------------------------------
app.post('/webhook/stripe', (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!webhookSecret) {
    console.error('STRIPE_WEBHOOK_SECRET not set');
    return res.status(500).send('Webhook secret not configured');
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const checkoutSession = event.data.object;
    const userId = checkoutSession.metadata?.userId;

    if (userId) {
      db.run(`UPDATE users SET is_premium = 1 WHERE id = ?`, [parseInt(userId, 10)], (err) => {
        if (err) console.error('Premium upgrade error:', err);
        else auditLog(parseInt(userId, 10), 'premium_activated', null, { stripeSessionId: checkoutSession.id });
      });
    }
  }

  if (event.type === 'customer.subscription.deleted') {
    const subscription = event.data.object;
    // Look up user by Stripe customer ID if stored, or via metadata
    const userId = subscription.metadata?.userId;
    if (userId) {
      db.run(`UPDATE users SET is_premium = 0 WHERE id = ?`, [parseInt(userId, 10)], (err) => {
        if (err) console.error('Premium downgrade error:', err);
        else auditLog(parseInt(userId, 10), 'premium_cancelled', null, { stripeSubscriptionId: subscription.id });
      });
    }
  }

  res.json({ received: true });
});

// ---------------------------------------------------------------------------
// Static page routes
// ---------------------------------------------------------------------------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------------------------------------------------------------------------
// Global error handler
// ---------------------------------------------------------------------------
app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Central Alberta Night Life server running on port ${PORT}`);
});
