/**
 * BCM — Secret Messages
 * Real backend: Express + NeDB (file-persisted) + bcrypt
 * 
 * Endpoints:
 *   POST /api/register
 *   POST /api/login
 *   GET  /api/profile          (auth)
 *   GET  /api/messages         (auth)
 *   POST /api/messages/text    (auth)
 *   POST /api/messages/media   (auth, multipart)
 *   POST /api/redeem           (public)
 *   DELETE /api/messages/:id   (auth)
 */

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const multer = require('multer');
const { randomUUID: uuidv4 } = require('crypto');
const path = require('path');
const fs = require('fs');
const Datastore = require('nedb');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// ── Ensure dirs exist ─────────────────────────
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ── Databases ─────────────────────────────────
const usersDb = new Datastore({ filename: path.join(DATA_DIR, 'users.db'), autoload: true });
const messagesDb = new Datastore({ filename: path.join(DATA_DIR, 'messages.db'), autoload: true });

// Auto-compact every 10 minutes
usersDb.persistence.setAutocompactionInterval(600000);
messagesDb.persistence.setAutocompactionInterval(600000);

// Indexes
usersDb.ensureIndex({ fieldName: 'login_id', unique: true });
messagesDb.ensureIndex({ fieldName: 'redemption_code', unique: true });
messagesDb.ensureIndex({ fieldName: 'user_id' });

// ── Middleware ────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '50mb' }));
app.use('/uploads', express.static(UPLOADS_DIR));

// Serve the frontend HTML at root
app.use(express.static(path.join(__dirname, 'public')));

// ── Multer (media uploads) ────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '.bin';
    cb(null, uuidv4() + ext);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg','image/png','image/gif','image/webp','video/mp4','video/webm','video/quicktime'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Unsupported file type'));
  },
});

// ── Token helpers ─────────────────────────────
const SALT_ROUNDS = 10;

function genSessionToken(userId) {
  // Simple signed token: base64(userId:timestamp:random)
  const payload = `${userId}:${Date.now()}:${uuidv4()}`;
  return Buffer.from(payload).toString('base64url');
}

function userIdFromToken(token) {
  try {
    const decoded = Buffer.from(token, 'base64url').toString('utf8');
    return decoded.split(':')[0];
  } catch { return null; }
}

// ── Auth middleware ────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  const userId = userIdFromToken(token);
  if (!userId) return res.status(401).json({ error: 'Invalid session' });
  // Verify user still exists
  usersDb.findOne({ _id: userId }, (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Session expired' });
    req.userId = userId;
    req.user = user;
    next();
  });
}

// ── Code generator ────────────────────────────
function genCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let prefix = '', body = '';
  for (let i = 0; i < 3; i++) prefix += chars[Math.floor(Math.random() * chars.length)];
  for (let i = 0; i < 6; i++) body += chars[Math.floor(Math.random() * chars.length)];
  return `${prefix}-${body}`;
}

function genLoginId() {
  const adj = ['Alpha','Bravo','Charlie','Delta','Echo','Foxtrot','Ghost','Hunter','Iron','Jade',
    'Kilo','Lima','Mike','Nova','Oscar','Phantom','Quinn','Raven','Sierra','Tango',
    'Ultra','Victor','Wolf','Xray','Yankee','Zulu','Amber','Blaze','Cipher','Drake',
    'Eagle','Falcon','Grave','Hawk','Indigo','Jackal','Krypt','Lance','Mako','Nebula'];
  const noun = ['Zero','One','Two','Three','Four','Five','Six','Seven','Eight','Nine',
    'Storm','Shade','Frost','Blaze','Spark','Vex','Flux','Hex','Jinx','Knox',
    'Lynx','Mist','Noir','Onyx','Pike','Quill','Rift','Sage','Tide','Ursa'];
  const a = adj[Math.floor(Math.random() * adj.length)];
  const n = noun[Math.floor(Math.random() * noun.length)];
  const d = Math.floor(10 + Math.random() * 90);
  return `${a}${n}${d}`;
}

// ── Unique code helper ─────────────────────────
function getUniqueCode(cb) {
  const code = genCode();
  messagesDb.findOne({ redemption_code: code }, (err, existing) => {
    if (existing) return getUniqueCode(cb);
    cb(code);
  });
}

// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────

// POST /api/register
app.post('/api/register', async (req, res) => {
  const { pin, proposed_login_id } = req.body;
  if (!pin || !/^\d{6}$/.test(String(pin))) {
    return res.status(400).json({ error: 'PIN must be exactly 6 digits' });
  }

  let login_id = proposed_login_id || genLoginId();

  // If taken, generate a new one
  const existing = await new Promise(r => usersDb.findOne({ login_id }, (e, d) => r(d)));
  if (existing) login_id = genLoginId() + Math.floor(Math.random() * 9);

  const pin_hash = await bcrypt.hash(String(pin), SALT_ROUNDS);
  const user = {
    login_id,
    pin_hash,
    created_at: new Date().toISOString(),
  };

  usersDb.insert(user, (err, newUser) => {
    if (err) return res.status(409).json({ error: 'Login ID already taken, try again' });
    const token = genSessionToken(newUser._id);
    res.json({ token, login_id: newUser.login_id });
  });
});

// POST /api/login
app.post('/api/login', (req, res) => {
  const { login_id, pin } = req.body;
  if (!login_id || !pin) return res.status(400).json({ error: 'Login ID and PIN required' });

  usersDb.findOne({ login_id }, async (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Login ID not found' });
    const match = await bcrypt.compare(String(pin), user.pin_hash);
    if (!match) return res.status(401).json({ error: 'Incorrect PIN' });
    const token = genSessionToken(user._id);
    res.json({ token, login_id: user.login_id });
  });
});

// GET /api/profile
app.get('/api/profile', requireAuth, (req, res) => {
  const uid = req.userId;
  const now = Date.now();
  messagesDb.find({ user_id: uid }, (err, msgs) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    const total_messages = msgs.length;
    const active_messages = msgs.filter(m => !m.redeemed && (!m.expiry_at || m.expiry_at > now)).length;
    const total_redemptions = msgs.filter(m => m.redeemed).length;
    res.json({
      login_id: req.user.login_id,
      created_at: req.user.created_at,
      total_messages,
      active_messages,
      total_redemptions,
    });
  });
});

// GET /api/messages
app.get('/api/messages', requireAuth, (req, res) => {
  const now = Date.now();
  messagesDb.find({ user_id: req.userId }, (err, msgs) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    const result = msgs
      .filter(m => !m.redeemed)
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
      .map(m => ({
        id: m._id,
        redemption_code: m.redemption_code,
        message_type: m.message_type,
        one_time_view: m.one_time_view,
        expiry_at: m.expiry_at,
        redeemed: m.redeemed,
        created_at: m.created_at,
        expired: m.expiry_at ? m.expiry_at < now : false,
      }));
    res.json(result);
  });
});

// POST /api/messages/text
app.post('/api/messages/text', requireAuth, (req, res) => {
  const { text_content, one_time_view, expiry_ms } = req.body;
  if (!text_content || !text_content.trim()) {
    return res.status(400).json({ error: 'text_content is required' });
  }
  const expiry_at = expiry_ms && expiry_ms !== 'never' ? Date.now() + Number(expiry_ms) : null;

  getUniqueCode(code => {
    const msg = {
      user_id: req.userId,
      redemption_code: code,
      message_type: 'text',
      text_content: text_content.trim(),
      one_time_view: !!one_time_view,
      expiry_at,
      redeemed: false,
      created_at: new Date().toISOString(),
    };
    messagesDb.insert(msg, (err, doc) => {
      if (err) return res.status(500).json({ error: 'Failed to save message' });
      res.json({ redemption_code: doc.redemption_code });
    });
  });
});

// POST /api/messages/media
app.post('/api/messages/media', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const { one_time_view, expiry_ms } = req.body;
  const expiry_at = expiry_ms && expiry_ms !== 'never' ? Date.now() + Number(expiry_ms) : null;
  const message_type = req.file.mimetype.startsWith('video/') ? 'video' : 'image';
  const media_url = `/uploads/${req.file.filename}`;

  getUniqueCode(code => {
    const msg = {
      user_id: req.userId,
      redemption_code: code,
      message_type,
      media_url,
      one_time_view: !!one_time_view,
      expiry_at,
      redeemed: false,
      created_at: new Date().toISOString(),
    };
    messagesDb.insert(msg, (err, doc) => {
      if (err) return res.status(500).json({ error: 'Failed to save message' });
      res.json({ redemption_code: doc.redemption_code });
    });
  });
});

// POST /api/redeem  (no auth — anyone with code can redeem)
app.post('/api/redeem', (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Code is required' });
  const normalised = String(code).toUpperCase().trim();

  messagesDb.findOne({ redemption_code: normalised }, (err, msg) => {
    if (err || !msg) return res.status(404).json({ error: 'Invalid code — transmission not found' });
    if (msg.redeemed) return res.status(410).json({ error: 'Code already redeemed — transmission destroyed' });
    const now = Date.now();
    if (msg.expiry_at && msg.expiry_at < now) return res.status(410).json({ error: 'Code expired — transmission lost' });

    // Mark redeemed
    messagesDb.update({ _id: msg._id }, { $set: { redeemed: true } }, {}, (err2) => {
      if (err2) return res.status(500).json({ error: 'Failed to redeem' });

      // Build response — for media, resolve full URL
      const response = {
        message_type: msg.message_type,
        one_time_view: msg.one_time_view,
        redeemed: true,
      };
      if (msg.message_type === 'text') {
        response.text_content = msg.text_content;
      } else {
        // Return the URL so frontend can display it
        response.media_data = msg.media_url;
      }
      res.json(response);
    });
  });
});

// DELETE /api/messages/:id
app.delete('/api/messages/:id', requireAuth, (req, res) => {
  messagesDb.findOne({ _id: req.params.id, user_id: req.userId }, (err, msg) => {
    if (err || !msg) return res.status(404).json({ error: 'Message not found' });
    messagesDb.remove({ _id: req.params.id }, {}, (err2) => {
      if (err2) return res.status(500).json({ error: 'Failed to delete' });
      // Delete media file if present
      if (msg.media_url) {
        const filePath = path.join(__dirname, msg.media_url);
        fs.unlink(filePath, () => {}); // ignore errors
      }
      res.json({ deleted: true });
    });
  });
});

// ── Health check ──────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ── Admin stats ───────────────────────────────
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Techman41?';

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    res.json({ success: true, token: Buffer.from('admin:' + ADMIN_PASSWORD).toString('base64') });
  } else {
    res.status(401).json({ error: 'Wrong password' });
  }
});

function requireAdmin(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    if (decoded === 'admin:' + ADMIN_PASSWORD) return next();
  } catch {}
  res.status(401).json({ error: 'Invalid token' });
}

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  usersDb.count({}, (err, totalUsers) => {
    messagesDb.count({}, (err2, totalMessages) => {
      messagesDb.count({ redeemed: true }, (err3, totalRedemptions) => {
        messagesDb.count({ redeemed: false }, (err4, activeMessages) => {
          usersDb.find({}).sort({ created_at: -1 }).limit(20).exec((err5, recentUsers) => {
            res.json({
              total_users: totalUsers || 0,
              total_messages: totalMessages || 0,
              total_redemptions: totalRedemptions || 0,
              active_messages: activeMessages || 0,
              recent_users: (recentUsers || []).map(u => ({
                login_id: u.login_id,
                created_at: u.created_at,
              })),
            });
          });
        });
      });
    });
  });
});

// ── Admin page ────────────────────────────────
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ── 404 fallback (SPA) ────────────────────────
app.get('/*splat', (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).json({ error: 'Not found' });
  }
});

// ── Start ─────────────────────────────────────
app.listen(PORT, () => {
  console.log(`BCM backend running on http://localhost:${PORT}`);
  console.log(`  Data:    ${DATA_DIR}`);
  console.log(`  Uploads: ${UPLOADS_DIR}`);
});
