const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const ROOT = __dirname;
const DATA = path.join(ROOT, 'data', 'db.json');
const UP = path.join(ROOT, 'uploads');

fs.mkdirSync(path.dirname(DATA), { recursive: true });
fs.mkdirSync(UP, { recursive: true });
if (!fs.existsSync(DATA)) {
  fs.writeFileSync(DATA, JSON.stringify({
    users: [],
    products: [],
    sessions: {},
    favorites: [],
    clicks: []
  }, null, 2));
}

function readDB() {
  try {
    return JSON.parse(fs.readFileSync(DATA, 'utf8'));
  } catch (e) {
    return { users: [], products: [], sessions: {}, favorites: [], clicks: [] };
  }
}

function writeDB(db) {
  fs.writeFileSync(DATA, JSON.stringify(db, null, 2));
}

function send(res, status, data, type = 'application/json') {
  res.writeHead(status, {
    'Content-Type': type,
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Credentials': 'true'
  });
  res.end(type === 'application/json' ? JSON.stringify(data) : data);
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(x => {
    const i = x.indexOf('=');
    if (i > 0) out[x.slice(0, i).trim()] = decodeURIComponent(x.slice(i + 1).trim());
  });
  return out;
}

function auth(req, db) {
  const token = parseCookies(req).ds_session;
  if (!token || !db.sessions[token]) return null;
  return db.users.find(u => u.id === db.sessions[token].userId) || null;
}

function hash(p, salt = crypto.randomBytes(16).toString('hex')) {
  return salt + ':' + crypto.scryptSync(p, salt, 64).toString('hex');
}

function check(p, stored) {
  const [salt, hex] = String(stored).split(':');
  if (!salt || !hex) return false;
  const a = Buffer.from(hex, 'hex');
  const b = crypto.scryptSync(p, salt, 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function id() {
  return crypto.randomUUID();
}

function safeUser(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role, avatar: u.avatar || '' };
}

function jsonBody(req) {
  return new Promise((resolve, reject) => {
    let s = '';
    req.on('data', c => {
      s += c;
      if (s.length > 6e6) req.destroy();
    });
    req.on('end', () => {
      try {
        resolve(s ? JSON.parse(s) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

function session(res, db, user) {
  const t = crypto.randomBytes(32).toString('hex');
  db.sessions[t] = { userId: user.id, created: Date.now() };
  writeDB(db);
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `ds_session=${encodeURIComponent(t)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000${secure}`);
}

function clearSession(res) {
  res.setHeader('Set-Cookie', 'ds_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
}

/** Normalize image value: store only filename, never full path */
function normalizeImage(val) {
  if (!val) return '';
  const s = String(val).trim();
  if (!s) return '';
  const base = path.basename(s.split('?')[0]);
  return base && base !== 'uploads' ? base : '';
}

function productOut(p) {
  return {
    ...p,
    image: p.image ? '/uploads/' + p.image : ''
  };
}

async function api(req, res) {
  const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const db = readDB();
  db.favorites = db.favorites || [];
  db.clicks = db.clicks || [];
  const method = req.method;

  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Credentials': 'true'
    });
    return res.end();
  }

  try {
    // ── Auth ──────────────────────────────────────────────
    if (u.pathname === '/api/me' && method === 'GET') {
      const user = auth(req, db);
      return send(res, 200, { user: user ? safeUser(user) : null });
    }

    if (u.pathname === '/api/signup' && method === 'POST') {
      const b = await jsonBody(req);
      const name = String(b.name || '').trim();
      const email = String(b.email || '').trim().toLowerCase();
      const pass = String(b.password || '');
      if (!name || !email || pass.length < 4) {
        return send(res, 400, { error: 'Name, email aur 4+ character password required.' });
      }
      if (db.users.some(x => x.email === email)) {
        return send(res, 409, { error: 'Email already registered.' });
      }
      const user = {
        id: id(),
        name,
        email,
        password: hash(pass),
        role: db.users.length === 0 ? 'admin' : 'user',
        avatar: '',
        createdAt: Date.now()
      };
      db.users.push(user);
      session(res, db, user);
      return send(res, 201, { user: safeUser(user) });
    }

    if (u.pathname === '/api/login' && method === 'POST') {
      const b = await jsonBody(req);
      const email = String(b.email || '').trim().toLowerCase();
      const pass = String(b.password || '');
      const user = db.users.find(x => x.email === email);
      if (!user || !check(pass, user.password)) {
        return send(res, 401, { error: 'Email ya password galat hai.' });
      }
      session(res, db, user);
      return send(res, 200, { user: safeUser(user) });
    }

    if (u.pathname === '/api/logout' && method === 'POST') {
      const token = parseCookies(req).ds_session;
      if (token) delete db.sessions[token];
      writeDB(db);
      clearSession(res);
      return send(res, 200, { ok: true });
    }

    // ── Products ──────────────────────────────────────────
    if (u.pathname === '/api/products' && method === 'GET') {
      const me = auth(req, db);
      let list = db.products.filter(p => p.status === 'approved' || (me && p.ownerId === me.id));
      const q = (u.searchParams.get('q') || '').toLowerCase();
      const cat = u.searchParams.get('category') || '';
      if (q) {
        list = list.filter(p =>
          (p.title + ' ' + p.description + ' ' + p.tags + ' ' + p.store).toLowerCase().includes(q)
        );
      }
      if (cat && cat !== 'All') list = list.filter(p => p.category === cat);
      return send(res, 200, { products: list.map(productOut) });
    }

    if (u.pathname === '/api/products' && method === 'POST') {
      const me = auth(req, db);
      if (!me) return send(res, 401, { error: 'Login required.' });
      const b = await jsonBody(req);
      if (!b.title || !b.price) return send(res, 400, { error: 'Title and price required.' });
      const p = {
        id: id(),
        ownerId: me.id,
        title: String(b.title).trim(),
        price: Number(b.price),
        mrp: b.mrp ? Number(b.mrp) : null,
        rating: b.rating ? Number(b.rating) : null,
        discount: b.discount ? Number(b.discount) : null,
        profit: String(b.profit || ''),
        store: String(b.store || ''),
        category: String(b.category || 'Other'),
        delivery: String(b.delivery || ''),
        colors: String(b.colors || ''),
        sizes: String(b.sizes || ''),
        features: String(b.features || ''),
        description: String(b.description || ''),
        tags: String(b.tags || ''),
        affiliate_url: String(b.affiliate_url || ''),
        image: normalizeImage(b.image),
        status: 'pending',
        createdAt: Date.now()
      };
      db.products.unshift(p);
      writeDB(db);
      return send(res, 201, { product: productOut(p) });
    }

    const pm = u.pathname.match(/^\/api\/products\/([^/]+)$/);
    if (pm) {
      const p = db.products.find(x => x.id === pm[1]);
      if (!p) return send(res, 404, { error: 'Product not found.' });
      const me = auth(req, db);

      if (method === 'GET') return send(res, 200, { product: productOut(p) });

      if (!me) return send(res, 401, { error: 'Login required.' });
      if (me.role !== 'admin' && p.ownerId !== me.id) return send(res, 403, { error: 'Not allowed.' });

      if (method === 'DELETE') {
        if (p.image) {
          const imgPath = path.join(UP, p.image);
          if (fs.existsSync(imgPath)) try { fs.unlinkSync(imgPath); } catch (_) {}
        }
        db.products = db.products.filter(x => x.id !== p.id);
        db.favorites = db.favorites.filter(x => x.productId !== p.id);
        writeDB(db);
        return send(res, 200, { ok: true });
      }

      if (method === 'PUT') {
        const b = await jsonBody(req);
        Object.assign(p, {
          title: b.title !== undefined ? String(b.title).trim() : p.title,
          price: b.price !== undefined ? Number(b.price) : p.price,
          mrp: b.mrp !== undefined ? (b.mrp ? Number(b.mrp) : null) : p.mrp,
          description: b.description !== undefined ? String(b.description) : p.description,
          affiliate_url: b.affiliate_url !== undefined ? String(b.affiliate_url) : p.affiliate_url,
          category: b.category !== undefined ? String(b.category) : p.category,
          store: b.store !== undefined ? String(b.store) : p.store,
          rating: b.rating !== undefined ? Number(b.rating) : p.rating,
          discount: b.discount !== undefined ? Number(b.discount) : p.discount,
          profit: b.profit !== undefined ? String(b.profit) : p.profit,
          delivery: b.delivery !== undefined ? String(b.delivery) : p.delivery,
          colors: b.colors !== undefined ? String(b.colors) : p.colors,
          sizes: b.sizes !== undefined ? String(b.sizes) : p.sizes,
          features: b.features !== undefined ? String(b.features) : p.features,
          tags: b.tags !== undefined ? String(b.tags) : p.tags
        });
        if (b.image !== undefined) {
          const newImg = normalizeImage(b.image);
          if (newImg) p.image = newImg;
        }
        if (me.role !== 'admin') p.status = 'pending';
        writeDB(db);
        return send(res, 200, { product: productOut(p) });
      }
    }

    // ── Admin ─────────────────────────────────────────────
    if (u.pathname === '/api/admin/products' && method === 'GET') {
      const me = auth(req, db);
      if (!me || me.role !== 'admin') return send(res, 403, { error: 'Admin access required.' });
      return send(res, 200, { products: db.products.map(productOut) });
    }

    const am = u.pathname.match(/^\/api\/admin\/products\/([^/]+)$/);
    if (am && method === 'PUT') {
      const me = auth(req, db);
      if (!me || me.role !== 'admin') return send(res, 403, { error: 'Admin access required.' });
      const p = db.products.find(x => x.id === am[1]);
      if (!p) return send(res, 404, { error: 'Not found' });
      const b = await jsonBody(req);
      if (['approved', 'rejected', 'pending'].includes(b.status)) p.status = b.status;
      writeDB(db);
      return send(res, 200, { product: productOut(p) });
    }

    // ── Favorites ─────────────────────────────────────────
    if (u.pathname === '/api/favorites' && method === 'GET') {
      const me = auth(req, db);
      if (!me) return send(res, 401, { error: 'Login required.' });
      return send(res, 200, {
        ids: db.favorites.filter(x => x.userId === me.id).map(x => x.productId)
      });
    }

    if (u.pathname === '/api/favorites' && method === 'POST') {
      const me = auth(req, db);
      if (!me) return send(res, 401, { error: 'Login required.' });
      const b = await jsonBody(req);
      if (!db.products.some(x => x.id === b.productId)) {
        return send(res, 404, { error: 'Product not found' });
      }
      if (!db.favorites.some(x => x.userId === me.id && x.productId === b.productId)) {
        db.favorites.push({ userId: me.id, productId: b.productId });
      }
      writeDB(db);
      return send(res, 200, { ok: true });
    }

    if (u.pathname === '/api/favorites' && method === 'DELETE') {
      const me = auth(req, db);
      if (!me) return send(res, 401, { error: 'Login required.' });
      const b = await jsonBody(req);
      db.favorites = db.favorites.filter(x => !(x.userId === me.id && x.productId === b.productId));
      writeDB(db);
      return send(res, 200, { ok: true });
    }

    // ── Clicks (affiliate tracking) ───────────────────────
    if (u.pathname === '/api/clicks' && method === 'POST') {
      const me = auth(req, db);
      const b = await jsonBody(req);
      if (!db.products.some(x => x.id === b.productId)) {
        return send(res, 404, { error: 'Product not found' });
      }
      db.clicks.push({
        id: id(),
        productId: b.productId,
        userId: me ? me.id : null,
        createdAt: Date.now()
      });
      writeDB(db);
      return send(res, 201, { ok: true });
    }

    if (u.pathname === '/api/clicks/mine' && method === 'GET') {
      const me = auth(req, db);
      if (!me) return send(res, 401, { error: 'Login required.' });
      const own = new Set(db.products.filter(p => p.ownerId === me.id).map(p => p.id));
      return send(res, 200, {
        count: db.clicks.filter(c => own.has(c.productId)).length
      });
    }

    // ── Profile ───────────────────────────────────────────
    if (u.pathname === '/api/profile' && method === 'PUT') {
      const me = auth(req, db);
      if (!me) return send(res, 401, { error: 'Login required.' });
      const b = await jsonBody(req);
      me.name = String(b.name || me.name).trim();
      me.avatar = String(b.avatar || me.avatar || '');
      writeDB(db);
      return send(res, 200, { user: safeUser(me) });
    }

    // ── Image upload ──────────────────────────────────────
    if (u.pathname === '/api/upload' && method === 'POST') {
      const me = auth(req, db);
      if (!me) return send(res, 401, { error: 'Login required.' });
      const b = await jsonBody(req);
      if (!b.data || !/^data:image\/(png|jpeg|jpg|webp);base64,/.test(b.data)) {
        return send(res, 400, { error: 'Only image data accepted (png/jpeg/webp).' });
      }
      const raw = b.data.split(',')[1];
      const buf = Buffer.from(raw, 'base64');
      if (buf.length > 5 * 1024 * 1024) {
        return send(res, 413, { error: 'Image too large (max 5MB).' });
      }
      const ext = (b.data.match(/^data:image\/(png|jpeg|jpg|webp)/) || [])[1] || 'png';
      const name = id() + '.' + (ext === 'jpeg' ? 'jpg' : ext);
      fs.writeFileSync(path.join(UP, name), buf);
      return send(res, 201, { url: '/uploads/' + name, file: name });
    }

    return send(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error(e);
    return send(res, 500, { error: 'Server error' });
  }
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

const server = http.createServer((req, res) => {
  if (req.url.startsWith('/api/')) return api(req, res);

  const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  // Serve uploaded images
  if (u.pathname.startsWith('/uploads/')) {
    const f = path.join(UP, path.basename(u.pathname));
    if (fs.existsSync(f) && fs.statSync(f).isFile()) {
      const ext = path.extname(f).toLowerCase();
      return send(res, 200, fs.readFileSync(f), MIME[ext] || 'application/octet-stream');
    }
    return send(res, 404, 'Not found', 'text/plain');
  }

  // Serve static files from public/
  let file = path.join(ROOT, 'public', u.pathname === '/' ? 'index.html' : u.pathname);
  if (!file.startsWith(path.join(ROOT, 'public'))) {
    return send(res, 403, 'Forbidden', 'text/plain');
  }
  if (fs.existsSync(file) && fs.statSync(file).isFile()) {
    const ext = path.extname(file).toLowerCase();
    return send(res, 200, fs.readFileSync(file), MIME[ext] || 'application/octet-stream');
  }

  // SPA fallback
  const index = path.join(ROOT, 'public', 'index.html');
  if (fs.existsSync(index)) {
    return send(res, 200, fs.readFileSync(index), 'text/html; charset=utf-8');
  }
  return send(res, 404, 'Not found', 'text/plain');
});

server.listen(PORT, HOST, () => {
  console.log(`DealShare backend running on http://${HOST}:${PORT}`);
});
