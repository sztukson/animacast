const express = require('express');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const ALLOWED_EMAIL = process.env.ADMIN_EMAIL || 'sztukjakub@gmail.com';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// ── PostgreSQL ──────────────────────────────────────────────────────

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

async function initDb() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS inquiries (
      id SERIAL PRIMARY KEY,
      animal_name TEXT NOT NULL,
      animal_species TEXT,
      animal_location TEXT,
      price_day TEXT,
      date_from DATE,
      date_to DATE,
      production_type TEXT,
      notes TEXT,
      contact_name TEXT NOT NULL,
      contact_email TEXT NOT NULL,
      contact_phone TEXT,
      status TEXT DEFAULT 'nowe',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
}

// ── Google OAuth ────────────────────────────────────────────────────

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${BASE_URL}/auth/google/callback`,
}, (accessToken, refreshToken, profile, done) => {
  const email = profile.emails?.[0]?.value;
  if (email === ALLOWED_EMAIL) {
    return done(null, { email, name: profile.displayName });
  }
  return done(null, false);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.set('trust proxy', 1);

app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || 'animacast-dev-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  },
}));

app.use(passport.initialize());
app.use(passport.session());

// ── Auth middleware ─────────────────────────────────────────────────

function requireAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  res.redirect('/login');
}

// ── Public routes (bez logowania) ──────────────────────────────────

app.get('/login', (req, res) => {
  const error = req.query.error;
  res.send(`<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AnimaCast — logowanie</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a0b;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
  .card{background:#111;border:1px solid #1e1e1e;border-radius:16px;padding:48px 40px;width:100%;max-width:380px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.6)}
  .logo{font-size:26px;font-weight:800;margin-bottom:6px}.logo span{color:#c8903a}
  p{font-size:13px;color:#555;margin-bottom:32px}
  .btn-google{display:flex;align-items:center;justify-content:center;gap:12px;background:#fff;color:#1e293b;border:none;border-radius:10px;padding:13px 20px;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none;transition:opacity .15s;width:100%}
  .btn-google:hover{opacity:.9}
  .error{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5;border-radius:8px;padding:10px 14px;font-size:12px;margin-bottom:20px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">Anima<span>Cast</span></div>
  <p>Strona w przygotowaniu — dostęp dla autoryzowanych</p>
  ${error ? '<div class="error">Brak dostępu. Tylko autoryzowane konto.</div>' : ''}
  <a href="/auth/google" class="btn-google">
    <svg width="18" height="18" viewBox="0 0 18 18"><path fill="#4285F4" d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.717v2.258h2.908c1.702-1.567 2.684-3.875 2.684-6.615z"/><path fill="#34A853" d="M9 18c2.43 0 4.467-.806 5.956-2.184l-2.908-2.258c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18z"/><path fill="#FBBC05" d="M3.964 10.707A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.707V4.961H.957A8.996 8.996 0 0 0 0 9c0 1.452.348 2.827.957 4.039l3.007-2.332z"/><path fill="#EA4335" d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.961L3.964 6.293C4.672 4.166 6.656 3.58 9 3.58z"/></svg>
    Zaloguj się przez Google
  </a>
</div>
</body>
</html>`);
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login?error=1' }),
  (req, res) => res.redirect('/')
);

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/login'));
});

// ── Wszystkie poniższe routes wymagają logowania ────────────────────

app.use(requireAuth);

// ── API ─────────────────────────────────────────────────────────────

// POST /api/inquiries — wyślij zapytanie
app.post('/api/inquiries', async (req, res) => {
  const {
    animal_name, animal_species, animal_location, price_day,
    date_from, date_to, production_type, notes,
    contact_name, contact_email, contact_phone,
  } = req.body;

  if (!animal_name || !contact_name || !contact_email) {
    return res.status(400).json({ error: 'Brakuje wymaganych pól: zwierzę, imię i e-mail' });
  }

  const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRx.test(contact_email)) {
    return res.status(400).json({ error: 'Nieprawidłowy adres e-mail' });
  }

  try {
    const { rows } = await db.query(`
      INSERT INTO inquiries
        (animal_name, animal_species, animal_location, price_day,
         date_from, date_to, production_type, notes,
         contact_name, contact_email, contact_phone)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      RETURNING id
    `, [
      animal_name, animal_species || null, animal_location || null, price_day || null,
      date_from || null, date_to || null, production_type || null, notes || null,
      contact_name, contact_email, contact_phone || null,
    ]);
    res.json({ ok: true, id: rows[0].id });
  } catch (e) {
    console.error('POST /api/inquiries error:', e);
    res.status(500).json({ error: 'Błąd serwera' });
  }
});

// GET /admin — panel admina
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// GET /api/admin/inquiries — lista zapytań
app.get('/api/admin/inquiries', async (req, res) => {
  try {
    const { status } = req.query;
    let q = 'SELECT * FROM inquiries';
    const params = [];
    if (status && status !== 'all') {
      q += ' WHERE status = $1';
      params.push(status);
    }
    q += ' ORDER BY created_at DESC';
    const { rows } = await db.query(q, params);
    res.json(rows);
  } catch (e) {
    console.error('GET /api/admin/inquiries error:', e);
    res.status(500).json({ error: 'DB error' });
  }
});

// PATCH /api/admin/inquiries/:id — zmień status
app.patch('/api/admin/inquiries/:id', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const allowed = ['nowe', 'w_realizacji', 'zakonczone', 'odrzucone'];
  if (!allowed.includes(status)) return res.status(400).json({ error: 'Nieprawidłowy status' });
  try {
    await db.query('UPDATE inquiries SET status=$1 WHERE id=$2', [status, id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('PATCH /api/admin/inquiries error:', e);
    res.status(500).json({ error: 'DB error' });
  }
});

// GET /api/admin/stats
app.get('/api/admin/stats', async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT
        COUNT(*) FILTER (WHERE status = 'nowe') AS nowe,
        COUNT(*) FILTER (WHERE status = 'w_realizacji') AS w_realizacji,
        COUNT(*) FILTER (WHERE status = 'zakonczone') AS zakonczone,
        COUNT(*) FILTER (WHERE status = 'odrzucone') AS odrzucone,
        COUNT(*) AS total
      FROM inquiries
    `);
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'DB error' });
  }
});

// ── Static / main page ──────────────────────────────────────────────

app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'animacast.html'));
});

// ── Start ───────────────────────────────────────────────────────────

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`AnimaCast running on port ${PORT}`));
  })
  .catch(err => {
    console.error('DB init failed:', err);
    process.exit(1);
  });
