const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── DB ───────────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

// ─── SERVE FRONTEND ───────────────────────────────────────────────────────────
// Serves index.html (the RazerLock frontend) at the root URL
app.get('/', (req, res) => {
  const htmlPath = path.join(__dirname, 'index.html');
  if (fs.existsSync(htmlPath)) {
    res.sendFile(htmlPath);
  } else {
    res.json({ app: 'RazerLock API', version: '1.0.0', note: 'Place index.html in the same folder to serve the frontend.' });
  }
});

// ─── OWNER CONFIG ─────────────────────────────────────────────────────────────
const OWNER_EMAIL = 'isaactressler09@gmail.com';

async function ensureOwnerPlan(userId, email) {
  if (email === OWNER_EMAIL) {
    await pool.query(`UPDATE users SET plan='dev' WHERE id=$1`, [userId]);
  }
}

function ownerOnly(req, res, next) {
  if (req.user.email !== OWNER_EMAIL) return res.status(403).json({ error: 'Owner only' });
  next();
}

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ─── INIT DB ──────────────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      plan TEXT DEFAULT 'free',
      grad_from TEXT DEFAULT '#001a0f',
      grad_to TEXT DEFAULT '#001a2e',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS vaults (
      id SERIAL PRIMARY KEY,
      user_id INT REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      icon TEXT DEFAULT '🏠',
      lock_method TEXT DEFAULT 'Master Password',
      is_family BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS passwords (
      id SERIAL PRIMARY KEY,
      vault_id INT REFERENCES vaults(id) ON DELETE CASCADE,
      user_id INT REFERENCES users(id) ON DELETE CASCADE,
      site TEXT NOT NULL,
      icon TEXT DEFAULT '🔑',
      url TEXT,
      username TEXT NOT NULL,
      encrypted_password TEXT NOT NULL,
      notes TEXT,
      last_changed TIMESTAMPTZ DEFAULT NOW(),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS family_members (
      id SERIAL PRIMARY KEY,
      vault_id INT REFERENCES vaults(id) ON DELETE CASCADE,
      user_id INT REFERENCES users(id) ON DELETE CASCADE,
      role TEXT DEFAULT 'member',
      last_seen TIMESTAMPTZ DEFAULT NOW(),
      joined_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(vault_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS family_passwords (
      id SERIAL PRIMARY KEY,
      vault_id INT REFERENCES vaults(id) ON DELETE CASCADE,
      added_by INT REFERENCES users(id) ON DELETE CASCADE,
      site TEXT NOT NULL,
      icon TEXT DEFAULT '🔑',
      url TEXT,
      username TEXT NOT NULL,
      encrypted_password TEXT NOT NULL,
      notes TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS share_links (
      id SERIAL PRIMARY KEY,
      password_id INT REFERENCES passwords(id) ON DELETE CASCADE,
      created_by INT REFERENCES users(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL,
      recipient_email TEXT,
      expires_at TIMESTAMPTZ NOT NULL,
      max_views INT DEFAULT 1,
      views INT DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS totp_accounts (
      id SERIAL PRIMARY KEY,
      user_id INT REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      icon TEXT DEFAULT '🔑',
      secret TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS activity_log (
      id SERIAL PRIMARY KEY,
      user_id INT REFERENCES users(id) ON DELETE CASCADE,
      icon TEXT,
      type TEXT,
      message TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  // Migrations — safely add new columns to existing tables
  await pool.query(`ALTER TABLE family_members ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ DEFAULT NOW()`);
  await pool.query(`ALTER TABLE family_passwords ADD COLUMN IF NOT EXISTS icon TEXT DEFAULT '🔑'`).catch(()=>{});
  console.log('✅ Database initialized');
}

// ─── HELPERS ──────────────────────────────────────────────────────────────────
async function logActivity(userId, icon, type, message) {
  await pool.query(
    `INSERT INTO activity_log (user_id, icon, type, message) VALUES ($1,$2,$3,$4)`,
    [userId, icon, type, message]
  ).catch(() => {});
}

// ─── ROUTES: AUTH ─────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      `INSERT INTO users (name, email, password_hash, plan) VALUES ($1,$2,$3,'free') RETURNING id, name, email, plan`,
      [name, email, hash]
    );
    const user = rows[0];
    await ensureOwnerPlan(user.id, email);
    await pool.query(`INSERT INTO vaults (user_id, name, icon) VALUES ($1,'Personal','🏠')`, [user.id]);
    await logActivity(user.id, '🎉', 'green', 'Account created');
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: email === OWNER_EMAIL ? 'dev' : user.plan } });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Email already registered' });
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await pool.query(`SELECT * FROM users WHERE email=$1`, [email]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    await ensureOwnerPlan(user.id, email);
    await pool.query(`UPDATE family_members SET last_seen=NOW() WHERE user_id=$1`, [user.id]);
    await logActivity(user.id, '🔍', 'blue', 'Signed in');
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    const finalPlan = email === OWNER_EMAIL ? 'dev' : user.plan;
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: finalPlan, grad_from: user.grad_from, grad_to: user.grad_to } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── ROUTES: USER ─────────────────────────────────────────────────────────────
app.get('/api/user/me', auth, async (req, res) => {
  const { rows } = await pool.query(`SELECT id, name, email, plan, grad_from, grad_to, created_at FROM users WHERE id=$1`, [req.user.id]);
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  const u = rows[0];
  if (u.email === OWNER_EMAIL) u.plan = 'dev';
  res.json(u);
});

app.put('/api/user/theme', auth, async (req, res) => {
  const { grad_from, grad_to } = req.body;
  await pool.query(`UPDATE users SET grad_from=$1, grad_to=$2 WHERE id=$3`, [grad_from, grad_to, req.user.id]);
  res.json({ success: true });
});

app.put('/api/user/profile', auth, async (req, res) => {
  const { name, email } = req.body;
  const { rows } = await pool.query(
    `UPDATE users SET name=COALESCE($1,name), email=COALESCE($2,email) WHERE id=$3 RETURNING id,name,email,plan`,
    [name, email, req.user.id]
  );
  res.json(rows[0]);
});

app.put('/api/user/password', auth, async (req, res) => {
  const { current_password, new_password } = req.body;
  const { rows } = await pool.query(`SELECT password_hash FROM users WHERE id=$1`, [req.user.id]);
  const valid = await bcrypt.compare(current_password, rows[0].password_hash);
  if (!valid) return res.status(401).json({ error: 'Current password incorrect' });
  const hash = await bcrypt.hash(new_password, 12);
  await pool.query(`UPDATE users SET password_hash=$1 WHERE id=$2`, [hash, req.user.id]);
  await logActivity(req.user.id, '🔑', 'yellow', 'Master password changed');
  res.json({ success: true });
});

// ─── ROUTES: VAULTS ───────────────────────────────────────────────────────────
app.get('/api/vaults', auth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT v.*, COUNT(p.id)::int AS password_count
     FROM vaults v LEFT JOIN passwords p ON p.vault_id = v.id
     WHERE v.user_id = $1 GROUP BY v.id ORDER BY v.created_at ASC`,
    [req.user.id]
  );
  res.json(rows);
});

app.post('/api/vaults', auth, async (req, res) => {
  const { name, icon, lock_method } = req.body;
  const { rows: userRows } = await pool.query(`SELECT plan FROM users WHERE id=$1`, [req.user.id]);
  const plan = req.user.email === OWNER_EMAIL ? 'dev' : userRows[0].plan;
  if (req.user.email !== OWNER_EMAIL) {
    const { rows: countRows } = await pool.query(`SELECT COUNT(*) FROM vaults WHERE user_id=$1 AND is_family=false`, [req.user.id]);
    const limit = plan === 'pro' || plan === 'dev' ? 10 : 5;
    if (parseInt(countRows[0].count) >= limit) return res.status(403).json({ error: `Vault limit reached (${limit} for your plan)` });
  }
  const { rows } = await pool.query(
    `INSERT INTO vaults (user_id, name, icon, lock_method) VALUES ($1,$2,$3,$4) RETURNING *`,
    [req.user.id, name, icon || '🏠', lock_method || 'Master Password']
  );
  await logActivity(req.user.id, '🗄️', 'green', `Vault "${name}" created`);
  res.json(rows[0]);
});

app.delete('/api/vaults/:id', auth, async (req, res) => {
  const { rows } = await pool.query(`SELECT name FROM vaults WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  await pool.query(`DELETE FROM vaults WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
  await logActivity(req.user.id, '🗑️', 'red', `Vault "${rows[0].name}" deleted`);
  res.json({ success: true });
});

// ─── ROUTES: PASSWORDS ────────────────────────────────────────────────────────
app.get('/api/passwords', auth, async (req, res) => {
  const { vault_id } = req.query;
  let query = `SELECT p.*, v.name AS vault_name FROM passwords p JOIN vaults v ON v.id=p.vault_id WHERE p.user_id=$1`;
  const params = [req.user.id];
  if (vault_id) { query += ` AND p.vault_id=$2`; params.push(vault_id); }
  query += ` ORDER BY p.created_at DESC`;
  const { rows } = await pool.query(query, params);
  res.json(rows);
});

app.post('/api/passwords', auth, async (req, res) => {
  const { vault_id, site, icon, url, username, password, notes } = req.body;
  if (!vault_id || !site || !username || !password) return res.status(400).json({ error: 'Missing required fields' });
  const encrypted = Buffer.from(password).toString('base64');
  const { rows } = await pool.query(
    `INSERT INTO passwords (vault_id, user_id, site, icon, url, username, encrypted_password, notes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [vault_id, req.user.id, site, icon || '🔑', url, username, encrypted, notes]
  );
  await logActivity(req.user.id, '🔑', 'green', `Password added for "${site}"`);
  res.json({ ...rows[0], password });
});

app.put('/api/passwords/:id', auth, async (req, res) => {
  const { site, icon, url, username, password, notes } = req.body;
  const encrypted = password ? Buffer.from(password).toString('base64') : undefined;
  const { rows } = await pool.query(
    `UPDATE passwords SET site=COALESCE($1,site), icon=COALESCE($2,icon), url=COALESCE($3,url),
     username=COALESCE($4,username), encrypted_password=COALESCE($5,encrypted_password),
     notes=COALESCE($6,notes), last_changed=NOW() WHERE id=$7 AND user_id=$8 RETURNING *`,
    [site, icon, url, username, encrypted, notes, req.params.id, req.user.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  await logActivity(req.user.id, '✏️', 'blue', `Password updated for "${rows[0].site}"`);
  res.json(rows[0]);
});

app.delete('/api/passwords/:id', auth, async (req, res) => {
  const { rows } = await pool.query(`SELECT site FROM passwords WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  await pool.query(`DELETE FROM passwords WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
  await logActivity(req.user.id, '🗑️', 'red', `Password deleted for "${rows[0].site}"`);
  res.json({ success: true });
});

// ─── ROUTES: FAMILY ───────────────────────────────────────────────────────────
app.get('/api/family/vault', auth, async (req, res) => {
  const { rows: vaultRows } = await pool.query(
    `SELECT v.* FROM vaults v
     LEFT JOIN family_members fm ON fm.vault_id=v.id
     WHERE v.is_family=true AND (v.user_id=$1 OR fm.user_id=$1) LIMIT 1`,
    [req.user.id]
  );
  if (!vaultRows.length) return res.json(null);
  const vault = vaultRows[0];

  // Members with online status (active in last 10 min)
  const { rows: members } = await pool.query(
    `SELECT u.id, u.name, u.email, fm.role, fm.last_seen,
      CASE WHEN u.id=$1 THEN true ELSE false END AS is_you,
      CASE WHEN fm.last_seen > NOW() - INTERVAL '10 minutes' THEN true ELSE false END AS online
     FROM family_members fm JOIN users u ON u.id=fm.user_id
     WHERE fm.vault_id=$2
     ORDER BY fm.role='owner' DESC, u.name ASC`,
    [req.user.id, vault.id]
  );

  // Family passwords
  const { rows: pws } = await pool.query(
    `SELECT fp.*, u.name AS added_by_name FROM family_passwords fp
     JOIN users u ON u.id=fp.added_by WHERE fp.vault_id=$1
     ORDER BY fp.created_at DESC`,
    [vault.id]
  );

  res.json({ vault, members, passwords: pws });
});

app.post('/api/family/vault', auth, async (req, res) => {
  const { rows: userRows } = await pool.query(`SELECT plan FROM users WHERE id=$1`, [req.user.id]);
  const plan = req.user.email === OWNER_EMAIL ? 'dev' : userRows[0].plan;
  if (plan !== 'pro' && plan !== 'dev') return res.status(403).json({ error: 'Pro membership required for family vault' });

  // Check if already has one
  const { rows: existing } = await pool.query(
    `SELECT v.id FROM vaults v LEFT JOIN family_members fm ON fm.vault_id=v.id
     WHERE v.is_family=true AND (v.user_id=$1 OR fm.user_id=$1)`, [req.user.id]
  );
  if (existing.length) return res.status(409).json({ error: 'You already have a family vault' });

  const { rows } = await pool.query(
    `INSERT INTO vaults (user_id, name, icon, is_family) VALUES ($1,'Family Vault','👨‍👩‍👧‍👦',true) RETURNING *`,
    [req.user.id]
  );
  await pool.query(`INSERT INTO family_members (vault_id, user_id, role) VALUES ($1,$2,'owner')`, [rows[0].id, req.user.id]);
  await logActivity(req.user.id, '👨‍👩‍👧‍👦', 'green', 'Family vault created');
  res.json(rows[0]);
});

app.post('/api/family/invite', auth, async (req, res) => {
  const { email, vault_id, role } = req.body;
  const { rows: invitee } = await pool.query(`SELECT id, name FROM users WHERE email=$1`, [email]);
  if (!invitee.length) return res.status(404).json({ error: 'No RazerLock account found for that email. They need to register first.' });
  try {
    await pool.query(
      `INSERT INTO family_members (vault_id, user_id, role) VALUES ($1,$2,$3)`,
      [vault_id, invitee[0].id, role || 'member']
    );
    await logActivity(req.user.id, '👤', 'blue', `Invited ${email} to family vault`);
    res.json({ success: true, name: invitee[0].name });
  } catch(e) {
    if (e.code === '23505') return res.status(409).json({ error: 'That person is already in the family vault' });
    throw e;
  }
});

app.delete('/api/family/member/:userId', auth, async (req, res) => {
  const { rows: vault } = await pool.query(
    `SELECT id FROM vaults WHERE is_family=true AND user_id=$1`, [req.user.id]
  );
  if (!vault.length) return res.status(403).json({ error: 'Only vault owner can remove members' });
  await pool.query(`DELETE FROM family_members WHERE vault_id=$1 AND user_id=$2`, [vault[0].id, req.params.userId]);
  await logActivity(req.user.id, '👤', 'red', 'Family member removed');
  res.json({ success: true });
});

// Family passwords
app.post('/api/family/passwords', auth, async (req, res) => {
  const { vault_id, site, icon, url, username, password, notes } = req.body;
  if (!vault_id || !site || !username || !password) return res.status(400).json({ error: 'Missing required fields' });

  // Verify user is a member
  const { rows: membership } = await pool.query(
    `SELECT id FROM family_members WHERE vault_id=$1 AND user_id=$2`, [vault_id, req.user.id]
  );
  if (!membership.length) return res.status(403).json({ error: 'Not a member of this family vault' });

  const encrypted = Buffer.from(password).toString('base64');
  const { rows } = await pool.query(
    `INSERT INTO family_passwords (vault_id, added_by, site, icon, url, username, encrypted_password, notes)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [vault_id, req.user.id, site, icon || '🔑', url, username, encrypted, notes]
  );
  await logActivity(req.user.id, '🔑', 'green', `Shared "${site}" to family vault`);
  res.json(rows[0]);
});

app.delete('/api/family/passwords/:id', auth, async (req, res) => {
  // Can delete if you added it or you own the vault
  const { rows } = await pool.query(
    `SELECT fp.site, fp.added_by, v.user_id AS owner_id FROM family_passwords fp
     JOIN vaults v ON v.id=fp.vault_id WHERE fp.id=$1`, [req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  if (rows[0].added_by !== req.user.id && rows[0].owner_id !== req.user.id) {
    return res.status(403).json({ error: 'Only the person who added this or the vault owner can delete it' });
  }
  await pool.query(`DELETE FROM family_passwords WHERE id=$1`, [req.params.id]);
  await logActivity(req.user.id, '🗑️', 'red', `Removed "${rows[0].site}" from family vault`);
  res.json({ success: true });
});

// ─── ROUTES: SHARE LINKS ─────────────────────────────────────────────────────
app.post('/api/share', auth, async (req, res) => {
  const { password_id, recipient_email, expires_hours, max_views } = req.body;
  const crypto = require('crypto');
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + (expires_hours || 24) * 3600 * 1000);
  const { rows } = await pool.query(
    `INSERT INTO share_links (password_id, created_by, token, recipient_email, expires_at, max_views)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [password_id, req.user.id, token, recipient_email, expires, max_views || 1]
  );
  await logActivity(req.user.id, '🔗', 'blue', 'Secure share link created');
  res.json({ ...rows[0], url: `${req.protocol}://${req.get('host')}/share/${token}` });
});

app.get('/api/share/:token', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT sl.*, p.site, p.username, p.encrypted_password, p.icon
     FROM share_links sl JOIN passwords p ON p.id=sl.password_id
     WHERE sl.token=$1 AND sl.expires_at > NOW() AND sl.views < sl.max_views`,
    [req.params.token]
  );
  if (!rows.length) return res.status(404).json({ error: 'Link expired or invalid' });
  await pool.query(`UPDATE share_links SET views=views+1 WHERE token=$1`, [req.params.token]);
  const pw = Buffer.from(rows[0].encrypted_password, 'base64').toString();
  res.json({ site: rows[0].site, username: rows[0].username, password: pw, icon: rows[0].icon });
});

app.get('/api/share', auth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT sl.*, p.site FROM share_links sl JOIN passwords p ON p.id=sl.password_id
     WHERE sl.created_by=$1 ORDER BY sl.created_at DESC`,
    [req.user.id]
  );
  res.json(rows);
});

app.delete('/api/share/:id', auth, async (req, res) => {
  await pool.query(`DELETE FROM share_links WHERE id=$1 AND created_by=$2`, [req.params.id, req.user.id]);
  res.json({ success: true });
});

// ─── ROUTES: 2FA ─────────────────────────────────────────────────────────────
app.get('/api/totp', auth, async (req, res) => {
  const { rows } = await pool.query(`SELECT id, name, icon, created_at FROM totp_accounts WHERE user_id=$1`, [req.user.id]);
  res.json(rows);
});

app.post('/api/totp', auth, async (req, res) => {
  const { name, icon, secret } = req.body;
  const { rows } = await pool.query(
    `INSERT INTO totp_accounts (user_id, name, icon, secret) VALUES ($1,$2,$3,$4) RETURNING id,name,icon`,
    [req.user.id, name, icon || '🔑', secret]
  );
  res.json(rows[0]);
});

app.delete('/api/totp/:id', auth, async (req, res) => {
  await pool.query(`DELETE FROM totp_accounts WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
  res.json({ success: true });
});

// ─── ROUTES: ACTIVITY ─────────────────────────────────────────────────────────
app.get('/api/activity', auth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM activity_log WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`,
    [req.user.id]
  );
  res.json(rows);
});

// ─── ROUTES: ADMIN ────────────────────────────────────────────────────────────
app.get('/api/admin/users', auth, ownerOnly, async (req, res) => {
  const { rows: users } = await pool.query(
    `SELECT id, name, email, plan, created_at FROM users ORDER BY created_at DESC`
  );
  const { rows: pwCount } = await pool.query(`SELECT COUNT(*) FROM passwords`);
  res.json({ users, total_passwords: parseInt(pwCount[0].count) });
});

app.post('/api/admin/grant-pro', auth, ownerOnly, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const { rows } = await pool.query(
    `UPDATE users SET plan='pro' WHERE email=$1 RETURNING id, name, email, plan`, [email]
  );
  if (!rows.length) return res.status(404).json({ error: 'User not found' });
  await logActivity(req.user.id, '💎', 'green', `Granted Pro to ${email}`);
  res.json({ success: true, user: rows[0] });
});

app.post('/api/admin/revoke-pro', auth, ownerOnly, async (req, res) => {
  const { email } = req.body;
  if (email === OWNER_EMAIL) return res.status(400).json({ error: 'Cannot revoke owner' });
  const { rows } = await pool.query(
    `UPDATE users SET plan='free' WHERE email=$1 RETURNING id, name, email, plan`, [email]
  );
  if (!rows.length) return res.status(404).json({ error: 'User not found' });
  await logActivity(req.user.id, '🔄', 'yellow', `Revoked Pro from ${email}`);
  res.json({ success: true, user: rows[0] });
});

// ─── ROUTES: HEALTH ───────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

// ─── START ────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`🔐 RazerLock running on port ${PORT}`));
}).catch(err => {
  console.error('DB init failed:', err);
  process.exit(1);
});
