// Bharat Maker Mandi — backend (Cloudflare Pages advanced mode: _worker.js)
// Needs: D1 binding "DB". Variables: GOOGLE_CLIENT_ID, ADMIN_EMAILS (comma separated).
// Optional: GRIEVANCE_EMAIL. DEV_LOGIN=1 only for local testing — never set it on the live site.

const MAX_IMG_BYTES = 700 * 1024;      // one compressed photo
const MAX_PRODUCT_IMGS = 6;
const MAX_PROOF_IMGS = 8;
const MAX_PRODUCTS_PER_SELLER = 300;
const SESSION_DAYS = 60;
const ONLINE_MS = 3 * 60 * 1000;   // someone counts as online if their page was open in the last 3 minutes
const FOUNDING_LIMIT = 500;
const CATEGORY_COUNT = 67;

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, email TEXT, name TEXT, picture TEXT, created_at INTEGER, last_seen INTEGER)`,
  `CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id TEXT, created_at INTEGER, expires_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS sellers(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT UNIQUE, code TEXT UNIQUE, slug TEXT, type TEXT, name TEXT, biz_name TEXT, mobile TEXT, maker_type TEXT, town TEXT, district TEXT, state TEXT, pin TEXT, makes TEXT, aadhaar4 TEXT, pan TEXT, bank TEXT, ifsc TEXT, extra TEXT, proof TEXT, status TEXT, verified INTEGER DEFAULT 0, founding INTEGER DEFAULT 0, referred_by TEXT, admin_note TEXT, created_at INTEGER, updated_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS products(id TEXT PRIMARY KEY, seller_id INTEGER, title TEXT, description TEXT, category INTEGER, place TEXT, seedha INTEGER, market INTEGER, images TEXT, status TEXT, featured TEXT, views INTEGER DEFAULT 0, wa INTEGER DEFAULT 0, calls INTEGER DEFAULT 0, created_at INTEGER, updated_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS products_seller ON products(seller_id)`,
  `CREATE TABLE IF NOT EXISTS images(id TEXT PRIMARY KEY, owner TEXT, kind TEXT, mime TEXT, data TEXT, created_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS leads(id INTEGER PRIMARY KEY AUTOINCREMENT, product_id TEXT, seller_id INTEGER, type TEXT, created_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS leads_seller ON leads(seller_id, created_at)`,
  `CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT, product_id TEXT, seller_id INTEGER, reason TEXT, note TEXT, user_id TEXT, status TEXT, created_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS requirements(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, title TEXT, description TEXT, budget TEXT, contact TEXT, status TEXT, created_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS visits(day TEXT, vid TEXT, PRIMARY KEY(day, vid))`,
  `CREATE TABLE IF NOT EXISTS pageviews(day TEXT PRIMARY KEY, n INTEGER)`,
  `CREATE TABLE IF NOT EXISTS allvids(vid TEXT PRIMARY KEY, first INTEGER)`,
  `CREATE TABLE IF NOT EXISTS online(vid TEXT PRIMARY KEY, last INTEGER)`,
  `CREATE TABLE IF NOT EXISTS counters(k TEXT PRIMARY KEY, n INTEGER)`,
  `CREATE TABLE IF NOT EXISTS installs(vid TEXT PRIMARY KEY, how TEXT, at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS complaints(id INTEGER PRIMARY KEY AUTOINCREMENT, topic TEXT, name TEXT, contact TEXT, message TEXT, user_id TEXT, ip TEXT, status TEXT, created_at INTEGER)`,
];

let schemaReady = false;
let pubCache = { at: 0, data: null };   // short cache of the public product list (saves database reads)
let jwksCache = null;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith('/api/')) return await api(request, env, url, ctx);
      if (url.pathname.startsWith('/img/')) return await serveImage(request, env, url);
      if (url.pathname === '/robots.txt') return text(`User-agent: *\nAllow: /\nDisallow: /api/\nSitemap: ${url.origin}/sitemap.xml\n`, 'text/plain');
      if (url.pathname === '/sitemap.xml') return await sitemap(env, url);
      const res = await env.ASSETS.fetch(request);
      const out = new Response(res.body, res);
      out.headers.set('x-content-type-options', 'nosniff');
      out.headers.set('referrer-policy', 'strict-origin-when-cross-origin');
      out.headers.set('permissions-policy', 'camera=(self), microphone=(), geolocation=()');
      return out;
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status);
      console.log('ERR', e && e.stack || e);
      return json({ error: 'Server error. Please try again.' }, 500);
    }
  },
};

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const fail = (status, msg) => { throw new HttpError(status, msg); };

function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });
}
function text(s, type) { return new Response(s, { headers: { 'content-type': type + '; charset=utf-8', 'cache-control': 'public, max-age=3600' } }); }

const now = () => Date.now();
function randHex(n) { const b = new Uint8Array(n); crypto.getRandomValues(b); return [...b].map((x) => x.toString(16).padStart(2, '0')).join(''); }
const clean = (s, max) => String(s == null ? '' : s).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim().slice(0, max);
const int = (v, min, max) => { const n = Math.round(Number(v)); if (!Number.isFinite(n)) return null; return Math.min(max, Math.max(min, n)); };
const slugify = (s) => (s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 24).replace(/-+$/, '') || 'maker';

async function ensureSchema(env) {
  if (schemaReady) return;
  if (!env.DB) fail(500, 'Database not connected. Add the D1 binding named DB in Cloudflare Pages settings.');
  await env.DB.batch(SCHEMA.map((s) => env.DB.prepare(s)));
  schemaReady = true;
}

// ---------- sessions ----------
function getCookie(request, name) {
  const c = request.headers.get('cookie') || '';
  for (const part of c.split(/;\s*/)) { const i = part.indexOf('='); if (i > 0 && part.slice(0, i) === name) return decodeURIComponent(part.slice(i + 1)); }
  return null;
}
function sessionCookie(url, token, maxAge) {
  const secure = url.protocol === 'https:' ? '; Secure' : '';
  return `bmm_s=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}
function adminEmails(env) { return String(env.ADMIN_EMAILS || '').toLowerCase().split(/[\s,;]+/).filter(Boolean); }
async function currentUser(request, env) {
  const token = getCookie(request, 'bmm_s');
  if (!token || !/^[0-9a-f]{64}$/.test(token)) return null;
  const row = await env.DB.prepare(`SELECT u.*, s.expires_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?`).bind(token).first();
  if (!row || row.expires_at < now()) return null;
  row.isAdmin = adminEmails(env).includes(String(row.email || '').toLowerCase());
  row.token = token;
  return row;
}
async function requireUser(request, env) { const u = await currentUser(request, env); if (!u) fail(401, 'Please log in with Google first.'); return u; }
async function requireAdmin(request, env) { const u = await requireUser(request, env); if (!u.isAdmin) fail(403, 'Admin only.'); return u; }

// ---------- Google ID token ----------
function b64urlBytes(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const bin = atob(s); const b = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i); return b; }
async function getJwks(env, force) {
  if (!force && jwksCache && jwksCache.exp > now()) return jwksCache.keys;
  const r = await fetch(env.GOOGLE_JWKS_URL || 'https://www.googleapis.com/oauth2/v3/certs');
  if (!r.ok) fail(502, 'Could not reach Google. Try again.');
  const j = await r.json();
  jwksCache = { keys: j.keys || [], exp: now() + 3600 * 1000 };
  return jwksCache.keys;
}
async function verifyGoogleToken(idToken, env) {
  if (!env.GOOGLE_CLIENT_ID) fail(500, 'Google login is not set up yet (GOOGLE_CLIENT_ID missing).');
  const parts = String(idToken || '').split('.');
  if (parts.length !== 3) fail(400, 'Bad login token.');
  const dec = new TextDecoder();
  const header = JSON.parse(dec.decode(b64urlBytes(parts[0])));
  const payload = JSON.parse(dec.decode(b64urlBytes(parts[1])));
  if (header.alg !== 'RS256') fail(400, 'Bad login token.');
  let keys = await getJwks(env);
  let jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) { keys = await getJwks(env, true); jwk = keys.find((k) => k.kid === header.kid); }
  if (!jwk) fail(401, 'Login token could not be checked. Try again.');
  const key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlBytes(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1]));
  if (!ok) fail(401, 'Login token is not valid.');
  if (!['accounts.google.com', 'https://accounts.google.com'].includes(payload.iss)) fail(401, 'Login token is not from Google.');
  if (payload.aud !== env.GOOGLE_CLIENT_ID) fail(401, 'Login token is for a different site.');
  if (!payload.exp || payload.exp * 1000 < now() - 60000) fail(401, 'Login expired. Try again.');
  if (!payload.email || payload.email_verified === false || payload.email_verified === 'false') fail(401, 'Your Google email is not verified.');
  return payload;
}
async function startSession(env, url, profile) {
  const t = now();
  await env.DB.prepare(`INSERT INTO users(id,email,name,picture,created_at,last_seen) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET email=excluded.email, name=excluded.name, picture=excluded.picture, last_seen=excluded.last_seen`)
    .bind(profile.sub, clean(profile.email, 200), clean(profile.name || profile.email, 120), clean(profile.picture, 500), t, t).run();
  const token = randHex(32);
  await env.DB.prepare(`INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)`).bind(token, profile.sub, t, t + SESSION_DAYS * 864e5).run();
  return sessionCookie(url, token, SESSION_DAYS * 86400);
}

// ---------- images ----------
function parseDataUrl(d) {
  const m = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(String(d || ''));
  if (!m) return null;
  const bytes = Math.floor(m[2].length * 3 / 4);
  if (bytes > MAX_IMG_BYTES) fail(413, 'A photo is too large. Please use a smaller photo.');
  return { mime: m[1], data: m[2] };
}
// list = image ids. Each id must be one we had before, or a photo this user uploaded via /api/upload.
async function saveImageList(env, list, ownerId, kind, max, previous) {
  if (!Array.isArray(list)) list = [];
  list = [...new Set(list.filter((x) => typeof x === 'string' && /^[0-9a-f]{24}$/.test(x)))];
  if (list.length > max) fail(400, `Up to ${max} photos allowed.`);
  const prev = new Set(previous || []);
  const fresh = list.filter((id) => !prev.has(id));
  const ok = new Set([...prev]);
  if (fresh.length) {
    const rows = (await env.DB.prepare(`SELECT id FROM images WHERE owner=? AND kind=? AND id IN (${fresh.map(() => '?').join(',')})`).bind(ownerId, kind, ...fresh).all()).results;
    rows.forEach((r) => ok.add(r.id));
  }
  const out = list.filter((id) => ok.has(id));
  const removed = [...prev].filter((id) => !out.includes(id));
  if (removed.length) await env.DB.batch(removed.map((id) => env.DB.prepare(`DELETE FROM images WHERE id=?`).bind(id)));
  return out;
}
async function serveImage(request, env, url) {
  await ensureSchema(env);
  const id = url.pathname.slice(5);
  if (!/^[0-9a-f]{24}$/.test(id)) return new Response('Not found', { status: 404 });
  const edge = typeof caches !== 'undefined' ? caches.default : null;
  if (edge) { try { const hit = await edge.match(request); if (hit) return hit; } catch (e) { } }
  const row = await env.DB.prepare(`SELECT owner, kind, mime, data FROM images WHERE id=?`).bind(id).first();
  if (!row) return new Response('Not found', { status: 404 });
  if (row.kind !== 'product') {
    const u = await currentUser(request, env);
    if (!u || (!u.isAdmin && u.id !== row.owner)) return new Response('Not allowed', { status: 403 });
  }
  const bin = atob(row.data); const b = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  const resp = new Response(b, { headers: { 'content-type': row.mime, 'cache-control': row.kind === 'product' ? 'public, max-age=31536000, immutable' : 'private, no-store', 'x-content-type-options': 'nosniff' } });
  if (edge && row.kind === 'product') { try { await edge.put(request, resp.clone()); } catch (e) { } }
  return resp;
}

// ---------- PIN code -> district / state (India Post open API) ----------
const PIN_STATES = ['Andhra Pradesh','Arunachal Pradesh','Assam','Bihar','Chhattisgarh','Goa','Gujarat','Haryana','Himachal Pradesh','Jharkhand','Karnataka','Kerala','Madhya Pradesh','Maharashtra','Manipur','Meghalaya','Mizoram','Nagaland','Odisha','Punjab','Rajasthan','Sikkim','Tamil Nadu','Telangana','Tripura','Uttar Pradesh','Uttarakhand','West Bengal','Andaman and Nicobar Islands','Chandigarh','Dadra and Nagar Haveli and Daman and Diu','Delhi','Jammu and Kashmir','Ladakh','Lakshadweep','Puducherry'];
function pinState(raw) {
  const k = String(raw || '').toLowerCase().replace(/&/g, 'and').replace(/[^a-z]/g, '');
  if (!k) return '';
  if (k.startsWith('dadra') || k.startsWith('daman')) return 'Dadra and Nagar Haveli and Daman and Diu';
  if (k.includes('delhi')) return 'Delhi';
  if (k === 'pondicherry') return 'Puducherry';
  if (k === 'orissa') return 'Odisha';
  return PIN_STATES.find((s) => s.toLowerCase().replace(/[^a-z]/g, '') === k) || '';
}
async function pinLookup(pin, ctx) {
  const edge = typeof caches !== 'undefined' ? caches.default : null;
  const key = new Request('https://pin.cache/' + pin);
  if (edge) { try { const hit = await edge.match(key); if (hit) return hit; } catch (e) { } }
  let out = { pin, state: '', district: '', places: [] };
  try {
    const r = await fetch('https://api.postalpincode.in/pincode/' + pin, { headers: { accept: 'application/json' }, cf: { cacheTtl: 2592000 } });
    const j = await r.json();
    const list = (Array.isArray(j) && j[0] && Array.isArray(j[0].PostOffice)) ? j[0].PostOffice : [];
    if (list.length) {
      const count = (f) => { const c = {}; list.forEach((o) => { const v = String(o[f] || '').trim(); if (v) c[v] = (c[v] || 0) + 1; }); return Object.keys(c).sort((a, b) => c[b] - c[a])[0] || ''; };
      out = { pin, state: pinState(count('State')), district: count('District'), places: [...new Set(list.map((o) => String(o.Name || '').trim()).filter(Boolean))].slice(0, 40) };
    }
  } catch (e) { return json({ error: 'Could not look up this PIN code. Please type your district.' }, 502); }
  const resp = json(out, 200, { 'cache-control': 'public, max-age=2592000' });
  if (edge && out.district) { try { const put = edge.put(key, resp.clone()); ctx && ctx.waitUntil ? ctx.waitUntil(put) : await put; } catch (e) { } }
  return resp;
}

// ---------- shaping ----------
function badgeOf(s) {
  if (!s) return 'pending';
  if (s.verified) return 'verified';
  if (s.status === 'approved') return 'seller';
  return 'pending';
}
function sellerOut(s, full) {
  if (!s) return null;
  const extra = safeJson(s.extra, {});
  const o = {
    id: s.id, code: s.code, slug: s.slug, shop: s.biz_name || s.name, name: s.name, type: s.type, makerType: s.maker_type, biz: bizList(s.biz),
    town: s.town, district: s.district, state: s.state, makes: s.makes, status: s.status, verification: badgeOf(s), founding: !!s.founding,
    mobile: s.mobile,
  };
  if (full) Object.assign(o, { pin: s.pin, aadhaar4: s.aadhaar4, pan: s.pan, bank: s.bank, ifsc: s.ifsc, extra, proof: safeJson(s.proof, []), referredBy: s.referred_by, adminNote: s.admin_note, createdAt: s.created_at, updatedAt: s.updated_at, userId: s.user_id });
  return o;
}
function productOut(p, s) {
  return {
    id: p.id, title: p.title, desc: p.description, cat: p.category, sub: p.sub || '', attrs: safeJson(p.attrs, {}), place: p.place, seedha: p.seedha, market: p.market,
    imgs: safeJson(p.images, []), status: p.status, feat: safeJson(p.featured, []), views: p.views, wa: p.wa, calls: p.calls, created: p.created_at,
    seller: s ? { id: s.id, shop: s.biz_name || s.name, town: s.town, district: s.district || '', state: s.state, badge: badgeOf(s), makerType: s.maker_type, biz: bizList(s.biz), mobile: s.mobile, code: s.code, slug: s.slug } : null,
  };
}
// India date (UTC+5:30), daysAgo = 0 for today
function istDay(daysAgo) { return new Date(Date.now() + 330 * 60000 - daysAgo * 864e5).toISOString().slice(0, 10); }
async function sha(t) { const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t)); return [...new Uint8Array(h)].slice(0, 12).map((x) => x.toString(16).padStart(2, '0')).join(''); }
function changed(res) { return !!(res && res.meta && res.meta.changes > 0); }
function safeJson(s, d) { try { const v = JSON.parse(s); return v == null ? d : v; } catch (e) { return d; } }
const PRODUCT_JOIN = `SELECT p.*, s.biz AS s_biz, s.district AS s_district, s.id AS s_id, s.name AS s_name, s.biz_name AS s_biz_name, s.town AS s_town, s.state AS s_state, s.status AS s_status, s.verified AS s_verified, s.maker_type AS s_maker_type, s.mobile AS s_mobile, s.code AS s_code, s.slug AS s_slug FROM products p JOIN sellers s ON s.id = p.seller_id`;
function splitJoin(r) {
  const s = { biz: r.s_biz, district: r.s_district, id: r.s_id, name: r.s_name, biz_name: r.s_biz_name, town: r.s_town, state: r.s_state, status: r.s_status, verified: r.s_verified, maker_type: r.s_maker_type, mobile: r.s_mobile, code: r.s_code, slug: r.s_slug };
  return productOut(r, s);
}

async function stats(env) {
  const r = await env.DB.batch([
    env.DB.prepare(`SELECT COUNT(*) AS n FROM sellers WHERE status='approved'`),
    env.DB.prepare(`SELECT COUNT(*) AS n FROM users WHERE id NOT IN (SELECT user_id FROM sellers)`),
    env.DB.prepare(`SELECT COUNT(*) AS n FROM products p JOIN sellers s ON s.id=p.seller_id WHERE p.status='live' AND s.status='approved'`),
  ]);
  return { sellers: r[0].results[0].n, buyers: r[1].results[0].n, items: r[2].results[0].n };
}

async function publicData(env) {
  if (pubCache.data && now() - pubCache.at < 30000) return pubCache.data;
  const rows = (await env.DB.prepare(`${PRODUCT_JOIN} WHERE p.status='live' AND s.status='approved' ORDER BY p.created_at DESC LIMIT 2000`).all()).results;
  pubCache = { at: now(), data: { products: rows.map(splitJoin), stats: await stats(env) } };
  return pubCache.data;
}
async function readBody(request) {
  const len = Number(request.headers.get('content-length') || 0);
  if (len > 2 * 1024 * 1024) fail(413, 'Too much data. Use a smaller photo.');
  const ct = request.headers.get('content-type') || '';
  if (!ct.includes('application/json')) fail(415, 'Expected JSON.');
  try { return await request.json(); } catch (e) { fail(400, 'Bad request.'); }
}

// ---------- API ----------
async function api(request, env, url, ctx) {
  await ensureSchema(env);
  await migrateV2(env);
  const m = request.method, p = url.pathname;
  { const pr = await pushRoutes(request, env, ctx, url, p, m); if (pr) return pr; }
  if (p === '/api/ping' || p === '/api/admin/live') drainSoon(env, ctx, url);
  if (m !== 'GET' && m !== 'HEAD') {
    if (!['/api/lead', '/api/visit', '/api/complaint', '/api/ping', '/api/installed'].includes(p) && !p.startsWith('/api/push/')) pubCache.at = 0;
    // 'stamp' changes whenever data changes, so the admin panel knows when to reload its lists
    if (!['/api/lead', '/api/visit', '/api/ping', '/api/installed'].includes(p) && !p.startsWith('/api/push/')) await env.DB.prepare(`INSERT INTO counters(k,n) VALUES('stamp',?) ON CONFLICT(k) DO UPDATE SET n=excluded.n`).bind(now()).run();
    const origin = request.headers.get('origin');
    if (origin && origin !== url.origin) fail(403, 'Blocked request from another site.');
  }

  if (p === '/api/pin' && m === 'GET') {
    const pin = String(url.searchParams.get('pin') || '');
    if (!/^[1-9]\d{5}$/.test(pin)) fail(400, 'PIN code must be 6 digits.');
    return await pinLookup(pin, ctx);
  }

  if (p === '/api/config' && m === 'GET') {
    const row = await env.DB.prepare(`SELECT value FROM config WHERE key='layout'`).first();
    return json({ clientId: env.GOOGLE_CLIENT_ID || '', layout: row ? safeJson(row.value, null) : null,  devLogin: env.DEV_LOGIN === '1', stats: (await publicData(env)).stats });
  }

  if (p === '/api/upload' && m === 'POST') {
    const u = await requireUser(request, env);
    const b = await readBody(request);
    const kind = b.kind === 'proof' ? 'proof' : 'product';
    const img = parseDataUrl(b.data);
    if (!img) fail(400, 'Photo must be a JPG, PNG or WebP image.');
    const recent = (await env.DB.prepare(`SELECT COUNT(*) AS n FROM images WHERE owner=? AND created_at>?`).bind(u.id, now() - 864e5).first()).n;
    if (recent >= 300) fail(429, 'Too many photos today. Please try again tomorrow.');
    const id = randHex(12);
    await env.DB.prepare(`INSERT INTO images(id,owner,kind,mime,data,created_at) VALUES(?,?,?,?,?,?)`).bind(id, u.id, kind, img.mime, img.data, now()).run();
    return json({ id });
  }

  if (p === '/api/products' && m === 'GET') return json(await publicData(env));

  if (p === '/api/shop' && m === 'GET') {
    const key = clean(url.searchParams.get('key'), 60).toLowerCase();
    const tail = (key.match(/-(\d{1,4})$/) || [])[1];
    if (!tail) fail(404, 'Shop not found.');
    const slug = key.slice(0, key.length - tail.length - 1);
    const s = await env.DB.prepare(`SELECT * FROM sellers WHERE slug=? AND substr(code,-4)=? AND status='approved'`).bind(slug, tail.padStart(4, '0').slice(-4)).first();
    if (!s) fail(404, 'This shop is not live yet.');
    const rows = (await env.DB.prepare(`${PRODUCT_JOIN} WHERE p.seller_id=? AND p.status='live' ORDER BY p.created_at DESC`).bind(s.id).all()).results;
    return json({ seller: sellerOut(s, false), products: rows.map(splitJoin) });
  }

  if (p === '/api/auth/google' && m === 'POST') {
    const b = await readBody(request);
    const profile = await verifyGoogleToken(b.credential, env);
    const cookie = await startSession(env, url, profile);
    return json({ ok: true }, 200, { 'set-cookie': cookie });
  }
  if (p === '/api/auth/dev' && m === 'POST') {
    if (env.DEV_LOGIN !== '1') fail(404, 'Not found.');
    const b = await readBody(request);
    const email = clean(b.email, 200).toLowerCase();
    if (!/^[^@\s]+@[^@\s]+$/.test(email)) fail(400, 'Bad email.');
    const cookie = await startSession(env, url, { sub: 'dev-' + email, email, name: clean(b.name, 80) || email.split('@')[0], picture: '' });
    return json({ ok: true }, 200, { 'set-cookie': cookie });
  }
  if (p === '/api/auth/logout' && m === 'POST') {
    const token = getCookie(request, 'bmm_s');
    if (token) await env.DB.prepare(`DELETE FROM sessions WHERE token=?`).bind(token).run();
    return json({ ok: true }, 200, { 'set-cookie': sessionCookie(url, '', 0) });
  }

  if (p === '/api/me' && m === 'GET') {
    const u = await currentUser(request, env);
    if (!u) return json({ user: null });
    await env.DB.prepare(`UPDATE users SET last_seen=? WHERE id=?`).bind(now(), u.id).run();
    const s = await env.DB.prepare(`SELECT * FROM sellers WHERE user_id=?`).bind(u.id).first();
    let products = [], leads = [];
    if (s) {
      products = (await env.DB.prepare(`${PRODUCT_JOIN} WHERE p.seller_id=? AND p.status!='removed' ORDER BY p.created_at DESC`).bind(s.id).all()).results.map(splitJoin);
      leads = (await env.DB.prepare(`SELECT l.type, l.created_at, p.title FROM leads l LEFT JOIN products p ON p.id=l.product_id WHERE l.seller_id=? ORDER BY l.created_at DESC LIMIT 200`).bind(s.id).all()).results;
    }
    return json({ user: { id: u.id, email: u.email, name: u.name, picture: u.picture, isAdmin: u.isAdmin }, seller: sellerOut(s, true), products, leads });
  }

  if (p === '/api/me/delete' && m === 'POST') {
    const u = await requireUser(request, env);
    const s = await env.DB.prepare(`SELECT id FROM sellers WHERE user_id=?`).bind(u.id).first();
    const stmts = [];
    if (s) {
      stmts.push(env.DB.prepare(`DELETE FROM products WHERE seller_id=?`).bind(s.id));
      stmts.push(env.DB.prepare(`DELETE FROM leads WHERE seller_id=?`).bind(s.id));
      stmts.push(env.DB.prepare(`DELETE FROM sellers WHERE id=?`).bind(s.id));
    }
    stmts.push(env.DB.prepare(`DELETE FROM images WHERE owner=?`).bind(u.id));
    stmts.push(env.DB.prepare(`DELETE FROM requirements WHERE user_id=?`).bind(u.id));
    stmts.push(env.DB.prepare(`UPDATE complaints SET user_id=NULL WHERE user_id=?`).bind(u.id));
    stmts.push(env.DB.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(u.id));
    stmts.push(env.DB.prepare(`DELETE FROM users WHERE id=?`).bind(u.id));
    await env.DB.batch(stmts);
    return json({ ok: true }, 200, { 'set-cookie': sessionCookie(url, '', 0) });
  }

  if (p === '/api/seller' && m === 'POST') {
    const u = await requireUser(request, env);
    const b = await readBody(request);
    const e = {};
    const name = clean(b.name, 80), mobile = String(b.mobile || '').replace(/\D/g, '').slice(-10);
    const makerType = ['make', 'factory', 'group', 'farmer'].includes(b.makerType) ? b.makerType : null;
    const type = b.type === 'business' ? 'business' : 'individual';
    const town = clean(b.town, 80), district = clean(b.district, 80), state = clean(b.state, 60), pin = clean(b.pin, 6), makes = clean(b.makes, 200);
    const aadhaar4 = clean(b.aadhaar4, 4), bizName = clean(b.bizName, 100);
    const biz = JSON.stringify(bizList(b.biz));
    const ex = b.extra && typeof b.extra === 'object' ? b.extra : {};
    const idType = ['gst', 'pan', 'none'].includes(ex.idType) ? ex.idType : (aadhaar4 ? 'none' : null);
    const gstin = clean(ex.gstin, 15).toUpperCase();
    const cat = ex.cat === null || ex.cat === undefined || ex.cat === '' ? null : int(ex.cat, 0, CATEGORY_COUNT - 1);
    const fssaiNo = clean(ex.fssaiNo, 14), udyamNo = clean(ex.udyamNo, 19).toUpperCase();
    if (!name) e.name = 'Enter your full name.';
    if (!/^[6-9]\d{9}$/.test(mobile)) e.mobile = 'Enter a valid 10-digit Indian mobile number.';
    if (!idType) e.idType = 'Choose GSTIN, PAN or Aadhaar.';
    if (idType === 'gst' && !/^\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/.test(gstin)) e.gstin = 'GSTIN must be 15 characters, e.g. 13ABCDE1234F1Z5.';
    if (idType === 'none' && !/^\d{4}$/.test(aadhaar4)) e.aadhaar4 = 'Enter the last 4 digits of your Aadhaar.';
    if (!makerType) e.makerType = 'Choose how you make your products.';
    if (cat === null) e.cat = 'Choose your main category.';
    if (fssaiNo && !/^\d{14}$/.test(fssaiNo)) e.fssaiNo = 'FSSAI number must be 14 digits.';
    if ((cat === 2 || cat === 3) && !fssaiNo) e.fssaiNo = 'FSSAI number is needed to sell food.';
    if (udyamNo && !/^UDYAM-[A-Z]{2}-\d{2}-\d{7}$/.test(udyamNo)) e.udyamNo = 'Udyam number looks like UDYAM-NL-01-0001234.';
    if (!town) e.town = 'Enter your village / town.';
    if (!district) e.district = 'Enter your district.';
    if (!state) e.state = 'Choose your state.';
    if (!/^[1-9]\d{5}$/.test(pin)) e.pin = 'PIN code must be 6 digits.';
    if (!makes) e.makes = 'Tell buyers what you make or sell.';
    if (type === 'business' && !bizName) e.bizName = makerType === 'group' ? "Enter your group's name." : 'Enter your business name.';
    if (Object.keys(e).length) return json({ error: 'Please fix the highlighted items.', fields: e }, 400);
    const extra = JSON.stringify({
      video: !!ex.video, wantCall: !!ex.wantCall, callSlot: clean(ex.callSlot, 40), artisanCard: !!ex.artisanCard,
      group: !!ex.group, farmDoc: !!ex.farmDoc, addrDiff: !!ex.addrDiff, idType, gstin: idType === 'gst' ? gstin : '', gst: idType === 'gst',
      panKind: /^[A-Z]$/.test(String(ex.panKind || '')) ? ex.panKind : '', cat, sub: clean(ex.sub, 80),
      fssaiNo, fssai: !!fssaiNo, udyamNo, udyam: !!udyamNo,
    });
    const existing = await env.DB.prepare(`SELECT * FROM sellers WHERE user_id=?`).bind(u.id).first();
    // PAN / bank are optional and only stored masked. If not sent while editing, keep what we had.
    const pan = 'pan' in b ? (/^XXXXX\d{4}X$/.test(String(b.pan || '')) ? b.pan : null) : (existing ? existing.pan : null);
    const bank = 'bank' in b ? (/^XXXX\d{4}$/.test(String(b.bank || '')) ? b.bank : null) : (existing ? existing.bank : null);
    const ifsc = 'bank' in b ? (bank && /^[A-Z]{4}0[A-Z0-9]{6}$/.test(String(b.ifsc || '')) ? b.ifsc : null) : (existing ? existing.ifsc : null);
    const proof = await saveImageList(env, b.proof, u.id, 'proof', MAX_PROOF_IMGS, existing ? safeJson(existing.proof, []) : []);
    if (idType === 'pan' && !pan) return json({ error: 'Please fix the highlighted items.', fields: { pan: 'Enter your PAN, e.g. ABCDE1234F.' } }, 400);
    if (proof.length < 2) return json({ error: 'Add at least 2 photos of your workspace and making.', fields: { photos: 'Add at least 2 photos of your workspace and making.' } }, 400);
    const t = now();
    const slug = slugify(type === 'business' && bizName ? bizName : name);
    if (existing) {
      const status = existing.status === 'rejected' ? 'pending' : existing.status;
      await env.DB.prepare(`UPDATE sellers SET slug=?,type=?,name=?,biz_name=?,mobile=?,maker_type=?,town=?,district=?,state=?,pin=?,makes=?,aadhaar4=?,pan=?,bank=?,ifsc=?,extra=?,proof=?,status=?,updated_at=?,biz=? WHERE id=?`)
        .bind(slug, type, name, bizName || null, mobile, makerType, town, district, state, pin, makes, aadhaar4, pan, bank, ifsc, extra, JSON.stringify(proof), status, t, biz, existing.id).run();
    } else {
      const count = (await env.DB.prepare(`SELECT COUNT(*) AS n FROM sellers`).first()).n;
      let code;
      for (let k = 0; k < 8; k++) {
        code = 'BMM-' + ((name.replace(/[^A-Za-z]/g, '').toUpperCase().slice(0, 4)) || 'MKR') + '-' + String(1000 + Math.floor(Math.random() * 9000));
        if (!(await env.DB.prepare(`SELECT 1 FROM sellers WHERE code=?`).bind(code).first())) break;
      }
      const ref = clean(b.referredBy, 20).toUpperCase().replace(/[^A-Z0-9-]/g, '') || null;
      await env.DB.prepare(`INSERT INTO sellers(user_id,code,slug,type,name,biz_name,mobile,maker_type,town,district,state,pin,makes,aadhaar4,pan,bank,ifsc,extra,proof,status,verified,founding,referred_by,created_at,updated_at,biz) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?,?,?)`)
        .bind(u.id, code, slug, type, name, bizName || null, mobile, makerType, town, district, state, pin, makes, aadhaar4, pan, bank, ifsc, extra, JSON.stringify(proof), 'pending', count < FOUNDING_LIMIT ? 1 : 0, ref, t, t, biz).run();
    }
    const s = await env.DB.prepare(`SELECT * FROM sellers WHERE user_id=?`).bind(u.id).first();
    return json({ seller: sellerOut(s, true) });
  }

  if (p === '/api/products' && m === 'POST') {
    const u = await requireUser(request, env);
    const s = await env.DB.prepare(`SELECT * FROM sellers WHERE user_id=?`).bind(u.id).first();
    if (!s) fail(403, 'Register as a seller first.');
    if (s.status === 'blocked') fail(403, 'Your shop is blocked. Contact support.');
    const n = (await env.DB.prepare(`SELECT COUNT(*) AS n FROM products WHERE seller_id=? AND status!='removed'`).bind(s.id).first()).n;
    if (n >= MAX_PRODUCTS_PER_SELLER) fail(400, 'Product limit reached.');
    const b = await readBody(request);
    const f = productFields(b);
    const id = 'p' + randHex(8);
    const imgs = await saveImageList(env, b.images, u.id, 'product', MAX_PRODUCT_IMGS, []);
    if (!imgs.length) fail(400, 'Add at least 1 photo of the product.');
    await env.DB.prepare(`INSERT INTO products(id,seller_id,title,description,category,place,seedha,market,images,status,featured,created_at,updated_at,sub,attrs) VALUES(?,?,?,?,?,?,?,?,?,'live','[]',?,?,?,?)`)
      .bind(id, s.id, f.title, f.desc, f.cat, f.place || s.town, f.seedha, f.market, JSON.stringify(imgs), now(), now(), f.sub, f.attrs).run();
    // Phone alert to everyone who switched alerts on (only when the shop is live)
    if (s.status === 'approved') await queueAlert(env, ctx, url, 'New: ' + f.title, (s.biz_name || s.name) + (s.town ? ' \u2022 ' + s.town : '') + ' \u2022 \u20b9' + f.seedha, '/?p=' + id);
    return json({ ok: true, id });
  }

  const pm = /^\/api\/products\/(p[0-9a-f]{16})(\/hide)?$/.exec(p);
  if (pm) {
    const u = await requireUser(request, env);
    const row = await env.DB.prepare(`SELECT p.*, s.user_id AS owner FROM products p JOIN sellers s ON s.id=p.seller_id WHERE p.id=?`).bind(pm[1]).first();
    if (!row || row.status === 'removed') fail(404, 'Product not found.');
    if (row.owner !== u.id && !u.isAdmin) fail(403, 'Not your product.');
    if (pm[2] && m === 'POST') {
      const st = row.status === 'live' ? 'hidden' : 'live';
      await env.DB.prepare(`UPDATE products SET status=?, updated_at=? WHERE id=?`).bind(st, now(), row.id).run();
      return json({ ok: true, status: st });
    }
    if (m === 'PUT') {
      const b = await readBody(request);
      const f = productFields(b);
      const imgs = await saveImageList(env, b.images, row.owner, 'product', MAX_PRODUCT_IMGS, safeJson(row.images, []));
      if (!imgs.length) fail(400, 'Add at least 1 photo of the product.');
      await env.DB.prepare(`UPDATE products SET title=?,description=?,category=?,place=?,seedha=?,market=?,images=?,updated_at=?,sub=?,attrs=? WHERE id=?`)
        .bind(f.title, f.desc, f.cat, f.place || row.place, f.seedha, f.market, JSON.stringify(imgs), now(), f.sub, f.attrs, row.id).run();
      return json({ ok: true });
    }
    if (m === 'DELETE') {
      const ids = safeJson(row.images, []);
      await env.DB.batch([env.DB.prepare(`UPDATE products SET status='removed', images='[]', updated_at=? WHERE id=?`).bind(now(), row.id), ...ids.map((id) => env.DB.prepare(`DELETE FROM images WHERE id=?`).bind(id))]);
      return json({ ok: true });
    }
  }

  if (p === '/api/lead' && m === 'POST') {
    const b = await readBody(request);
    const type = ['wa', 'call', 'view'].includes(b.type) ? b.type : null;
    const pid = /^p[0-9a-f]{16}$/.test(String(b.pid || '')) ? b.pid : null;
    if (!type || !pid) return json({ ok: false });
    const row = await env.DB.prepare(`SELECT seller_id FROM products WHERE id=?`).bind(pid).first();
    if (!row) return json({ ok: false });
    const col = type === 'wa' ? 'wa' : type === 'call' ? 'calls' : 'views';
    const stmts = [env.DB.prepare(`UPDATE products SET ${col}=${col}+1 WHERE id=?`).bind(pid)];
    if (type !== 'view') stmts.push(env.DB.prepare(`INSERT INTO leads(product_id,seller_id,type,created_at) VALUES(?,?,?,?)`).bind(pid, row.seller_id, type, now()));
    await env.DB.batch(stmts);
    return json({ ok: true });
  }

  if (p === '/api/visit' && m === 'POST') {
    const b = await readBody(request);
    const vid = String(b.vid || '');
    if (!/^[a-z0-9]{8,40}$/.test(vid)) return json({ ok: false });
    const day = istDay(0);
    const r = await env.DB.batch([
      env.DB.prepare(`INSERT OR IGNORE INTO visits(day,vid) VALUES(?,?)`).bind(day, vid),
      env.DB.prepare(`INSERT OR IGNORE INTO allvids(vid,first) VALUES(?,?)`).bind(vid, now()),
      env.DB.prepare(`INSERT INTO pageviews(day,n) VALUES(?,1) ON CONFLICT(day) DO UPDATE SET n=n+1`).bind(day),
      env.DB.prepare(`INSERT INTO online(vid,last) VALUES(?,?) ON CONFLICT(vid) DO UPDATE SET last=excluded.last`).bind(vid, now()),
    ]);
    const st = [];
    if (changed(r[0])) st.push(env.DB.prepare(`INSERT INTO counters(k,n) VALUES(?,1) ON CONFLICT(k) DO UPDATE SET n=n+1`).bind('day:' + day));
    if (changed(r[1])) st.push(env.DB.prepare(`INSERT INTO counters(k,n) VALUES('visitors_all',1) ON CONFLICT(k) DO UPDATE SET n=n+1`));
    if (st.length) await env.DB.batch(st);
    return json({ ok: true });
  }

  if (p === '/api/installed' && m === 'POST') {
    const b = await readBody(request);
    const vid = String(b.vid || '');
    if (!/^[a-z0-9]{8,40}$/.test(vid)) return json({ ok: false });
    const r = await env.DB.prepare(`INSERT OR IGNORE INTO installs(vid,how,at) VALUES(?,?,?)`).bind(vid, b.how === 'opened' ? 'opened' : 'installed', now()).run();
    if (changed(r)) await env.DB.prepare(`INSERT INTO counters(k,n) VALUES('installs',1) ON CONFLICT(k) DO UPDATE SET n=n+1`).run();
    return json({ ok: true });
  }

  if (p === '/api/ping' && m === 'POST') {
    const b = await readBody(request);
    const vid = String(b.vid || '');
    if (!/^[a-z0-9]{8,40}$/.test(vid)) return json({ ok: false });
    await env.DB.prepare(`INSERT INTO online(vid,last) VALUES(?,?) ON CONFLICT(vid) DO UPDATE SET last=excluded.last`).bind(vid, now()).run();
    if (Math.random() < 0.05) await env.DB.prepare(`DELETE FROM online WHERE last<?`).bind(now() - 3600e3).run();
    return json({ ok: true });
  }

  if (p === '/api/admin/live' && m === 'GET') {
    await requireAdmin(request, env);
    const r = await env.DB.batch([
      env.DB.prepare(`SELECT COUNT(*) AS n FROM online WHERE last>?`).bind(now() - ONLINE_MS),
      env.DB.prepare(`SELECT k, n FROM counters WHERE k IN ('stamp','visitors_all','installs',?)`).bind('day:' + istDay(0)),
      env.DB.prepare(`SELECT (SELECT COUNT(*) FROM sellers) AS sellers, (SELECT COUNT(*) FROM products WHERE status!='removed') AS items, (SELECT COUNT(*) FROM users WHERE id NOT IN (SELECT user_id FROM sellers)) AS buyers`),
    ]);
    const c = Object.fromEntries(r[1].results.map((x) => [x.k, x.n]));
    const t = r[2].results[0];
    return json({ online: r[0].results[0].n, today: c['day:' + istDay(0)] || 0, allTime: c.visitors_all || 0, stamp: c.stamp || 0, installs: c.installs || 0, sellers: t.sellers, items: t.items, buyers: t.buyers });
  }

  if (p === '/api/complaint' && m === 'POST') {
    const b = await readBody(request);
    const u = await currentUser(request, env);
    const message = clean(b.message, 2000);
    if (message.length < 5) fail(400, 'Please write your complaint.');
    const ip = await sha(String(request.headers.get('cf-connecting-ip') || 'x') + istDay(0));
    const n = (await env.DB.prepare(`SELECT COUNT(*) AS n FROM complaints WHERE ip=? AND created_at>?`).bind(ip, now() - 864e5).first()).n;
    if (n >= 10) fail(429, 'Too many messages today. Please try again tomorrow.');
    const r = await env.DB.prepare(`INSERT INTO complaints(topic,name,contact,message,user_id,ip,status,created_at) VALUES(?,?,?,?,?,?,'open',?)`)
      .bind(clean(b.topic, 60) || 'Other', clean(b.name, 80), clean(b.contact, 100), message, u ? u.id : null, ip, now()).run();
    return json({ ok: true, id: r.meta && r.meta.last_row_id });
  }

  if (p === '/api/report' && m === 'POST') {
    const b = await readBody(request);
    const u = await currentUser(request, env);
    const reason = clean(b.reason, 80);
    if (!reason) fail(400, 'Choose a reason.');
    const pid = /^p[0-9a-f]{16}$/.test(String(b.pid || '')) ? b.pid : null;
    const row = pid ? await env.DB.prepare(`SELECT seller_id FROM products WHERE id=?`).bind(pid).first() : null;
    await env.DB.prepare(`INSERT INTO reports(product_id,seller_id,reason,note,user_id,status,created_at) VALUES(?,?,?,?,?,'open',?)`).bind(pid, row ? row.seller_id : null, reason, clean(b.note, 600), u ? u.id : null, now()).run();
    return json({ ok: true });
  }

  if (p === '/api/requirement' && m === 'POST') {
    const u = await requireUser(request, env);
    const b = await readBody(request);
    const title = clean(b.title, 120);
    if (!title) fail(400, 'Enter what you need.');
    await env.DB.prepare(`INSERT INTO requirements(user_id,title,description,budget,contact,status,created_at) VALUES(?,?,?,?,?,'open',?)`).bind(u.id, title, clean(b.description, 1000), clean(b.budget, 60), clean(b.contact, 60), now()).run();
    return json({ ok: true });
  }

  // ----- admin -----
  if (p === '/api/admin/overview' && m === 'GET') {
    await requireAdmin(request, env);
    const r = await env.DB.batch([
      env.DB.prepare(`SELECT s.*, u.email AS email, (SELECT COUNT(*) FROM products p WHERE p.seller_id=s.id AND p.status!='removed') AS products FROM sellers s LEFT JOIN users u ON u.id=s.user_id ORDER BY CASE s.status WHEN 'pending' THEN 0 ELSE 1 END, s.updated_at DESC LIMIT 500`),
      env.DB.prepare(`${PRODUCT_JOIN} WHERE p.status!='removed' ORDER BY p.created_at DESC LIMIT 500`),
      env.DB.prepare(`SELECT r.*, p.title AS title FROM reports r LEFT JOIN products p ON p.id=r.product_id ORDER BY CASE r.status WHEN 'open' THEN 0 ELSE 1 END, r.created_at DESC LIMIT 300`),
      env.DB.prepare(`SELECT q.*, u.email AS email, u.name AS uname FROM requirements q LEFT JOIN users u ON u.id=q.user_id ORDER BY q.created_at DESC LIMIT 300`),
      env.DB.prepare(`SELECT c.id, c.topic, c.name, c.contact, c.message, c.status, c.created_at, u.email AS email FROM complaints c LEFT JOIN users u ON u.id=c.user_id ORDER BY CASE c.status WHEN 'open' THEN 0 ELSE 1 END, c.created_at DESC LIMIT 300`),
      env.DB.prepare(`SELECT day, COUNT(*) AS v FROM visits WHERE day>=? GROUP BY day`).bind(istDay(29)),
      env.DB.prepare(`SELECT day, n FROM pageviews WHERE day>=?`).bind(istDay(29)),
      env.DB.prepare(`SELECT COUNT(DISTINCT vid) AS v FROM visits`),
      env.DB.prepare(`SELECT COALESCE(SUM(n),0) AS n FROM pageviews`),
      env.DB.prepare(`SELECT (SELECT COUNT(*) FROM sellers) AS sellers, (SELECT COUNT(*) FROM products WHERE status!='removed') AS items, (SELECT n FROM counters WHERE k='stamp') AS stamp`),
    ]);
    const vmap = Object.fromEntries(r[5].results.map((x) => [x.day, x.v])), pmap = Object.fromEntries(r[6].results.map((x) => [x.day, x.n]));
    const days = []; for (let k = 0; k < 30; k++) { const d = istDay(k); days.push({ day: d, visitors: vmap[d] || 0, views: pmap[d] || 0 }); }
    const sum = (n, key) => days.slice(0, n).reduce((a, x) => a + x[key], 0);
    const visitors = { today: days[0], last7: { visitors: sum(7, 'visitors'), views: sum(7, 'views') }, last30: { visitors: sum(30, 'visitors'), views: sum(30, 'views') }, total: { visitors: r[7].results[0].v, views: r[8].results[0].n }, days: days.slice(0, 14) };
    return json({
      sellers: r[0].results.map((s) => ({ ...sellerOut(s, true), email: s.email, products: s.products })),
      products: r[1].results.map(splitJoin), reports: r[2].results, requirements: r[3].results, complaints: r[4].results, visitors, totals: r[9].results[0], stats: await stats(env),
    });
  }
  const sm = /^\/api\/admin\/seller\/(\d+)$/.exec(p);
  if (sm && m === 'POST') {
    await requireAdmin(request, env);
    const b = await readBody(request);
    const st = ['pending', 'approved', 'rejected', 'blocked'].includes(b.status) ? b.status : null;
    if (!st) fail(400, 'Bad status.');
    const before = await env.DB.prepare(`SELECT status, biz_name, name, town FROM sellers WHERE id=?`).bind(Number(sm[1])).first();
    await env.DB.prepare(`UPDATE sellers SET status=?, verified=?, admin_note=?, updated_at=? WHERE id=?`).bind(st, b.verified && st === 'approved' ? 1 : 0, clean(b.note, 300), now(), Number(sm[1])).run();
    if (st === 'approved' && before && before.status !== 'approved') {
      const np = await env.DB.prepare(`SELECT id, title FROM products WHERE seller_id=? AND status='live' ORDER BY created_at DESC LIMIT 1`).bind(Number(sm[1])).first();
      if (np) await queueAlert(env, ctx, url, 'New shop: ' + (before.biz_name || before.name), np.title + (before.town ? ' \u2022 ' + before.town : ''), '/?p=' + np.id);
    }
    return json({ ok: true });
  }
  const am = /^\/api\/admin\/product\/(p[0-9a-f]{16})$/.exec(p);
  if (am && m === 'POST') {
    await requireAdmin(request, env);
    const b = await readBody(request);
    const sets = [], vals = [];
    if (['live', 'hidden'].includes(b.status)) { sets.push('status=?'); vals.push(b.status); }
    if (Array.isArray(b.feat)) { sets.push('featured=?'); vals.push(JSON.stringify(b.feat.filter((x) => /^s[1-9]$/.test(x)).slice(0, 9))); }
    if (!sets.length) fail(400, 'Nothing to change.');
    await env.DB.prepare(`UPDATE products SET ${sets.join(',')}, updated_at=? WHERE id=?`).bind(...vals, now(), am[1]).run();
    return json({ ok: true });
  }
  const rm = /^\/api\/admin\/(report|requirement|complaint)\/(\d+)$/.exec(p);
  if (rm && m === 'POST') {
    await requireAdmin(request, env);
    const b = await readBody(request);
    const st = ['open', 'done'].includes(b.status) ? b.status : 'done';
    await env.DB.prepare(`UPDATE ${({ report: 'reports', requirement: 'requirements', complaint: 'complaints' })[rm[1]]} SET status=? WHERE id=?`).bind(st, Number(rm[2])).run();
    return json({ ok: true });
  }
  if (p === '/api/admin/layout' && m === 'PUT') {
    await requireAdmin(request, env);
    const raw = await request.text();
    if (raw.length > 400000) fail(413, 'Layout too large.');
    let b; try { b = JSON.parse(raw); } catch (e) { fail(400, 'Bad layout.'); }
    if (!b || typeof b.layout !== 'object') fail(400, 'Bad layout.');
    await env.DB.prepare(`INSERT INTO config(key,value,updated_at) VALUES('layout',?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`).bind(JSON.stringify(b.layout), now()).run();
    return json({ ok: true });
  }

  fail(404, 'Not found.');
}

// ===== Added: master categories, filters, phone alerts =====================
// Old 56 categories -> new 67 master categories (product.category is the index).
const OLD_TO_NEW_CAT = [9,13,48,13,31,31,46,48,48,47,58,48,17,32,48,48,56,45,35,7,30,33,38,36,28,7,43,12,48,35,49,0,17,10,23,18,4,10,5,28,30,10,63,8,18,13,19,12,6,1,31,27,24,19,32,11];
const BIZ_TYPES = ['manufacturer','maker','farmer','wholesaler','supplier','distributor','dealer','service','oem','odm','exporter'];
const SELL_TYPES = ['b2b','b2c','wholesale','retail','bulk','custom'];
const ATTR_KEYS = ['gst','mii','handmade','organic','customizable','ready','export'];
let migrated = false;
async function migrateV2(env) {
  if (migrated) return;
  for (const sql of [`ALTER TABLE products ADD COLUMN sub TEXT`, `ALTER TABLE products ADD COLUMN attrs TEXT`, `ALTER TABLE sellers ADD COLUMN biz TEXT`]) {
    try { await env.DB.prepare(sql).run(); } catch (e) { /* column already there */ }
  }
  const done = await env.DB.prepare(`SELECT value FROM config WHERE key='catv2'`).first();
  if (!done) {
    const cases = OLD_TO_NEW_CAT.map((n, o) => `WHEN ${o} THEN ${n}`).join(' ');
    await env.DB.batch([
      env.DB.prepare(`UPDATE products SET category = CASE category ${cases} ELSE -1 END WHERE category IS NOT NULL AND category >= 0`),
      env.DB.prepare(`INSERT OR REPLACE INTO config(key,value,updated_at) VALUES('catv2','1',?)`).bind(now()),
    ]);
  }
  migrated = true;
}
function bizList(v) { const a = Array.isArray(v) ? v : safeJson(v, []); return (Array.isArray(a) ? a : []).filter((x, i, s) => BIZ_TYPES.includes(x) && s.indexOf(x) === i); }
function attrsClean(v) {
  const a = v && typeof v === 'object' ? v : {};
  const o = { sell: (Array.isArray(a.sell) ? a.sell : []).filter((x, i, s) => SELL_TYPES.includes(x) && s.indexOf(x) === i) };
  const moq = int(a.moq, 0, 1000000000); if (moq) { o.moq = moq; o.moqUnit = clean(a.moqUnit, 20) || 'pieces'; }
  ATTR_KEYS.forEach((k) => { if (a[k]) o[k] = true; });
  return o;
}

// ---- Phone alerts (Web Push) for new products, also when the app is closed ----
const PUSH_BATCH = 25;
const PUSH_HOSTS = /(^|\.)(fcm\.googleapis\.com|push\.services\.mozilla\.com|push\.apple\.com|notify\.windows\.com)$/i;
let pushReady = null, pushKeys = null, pushJwt = {}, pushCheckAt = 0;
function b64u(bytes) { let s = ''; const b = new Uint8Array(bytes); for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
async function pushTables(env) {
  if (!pushReady) {
    pushReady = env.DB.batch([
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS push_keys(id INTEGER PRIMARY KEY, pub TEXT, priv TEXT, created_at INTEGER)`),
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS push_subs(endpoint TEXT PRIMARY KEY, vid TEXT, created_at INTEGER, ok_at INTEGER, fails INTEGER DEFAULT 0)`),
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS push_events(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, body TEXT, url TEXT, created_at INTEGER, cursor TEXT DEFAULT '', done INTEGER DEFAULT 0, sent INTEGER DEFAULT 0, lease INTEGER DEFAULT 0)`),
    ]).catch((e) => { pushReady = null; throw e; });
  }
  return pushReady;
}
async function getPushKeys(env) {
  if (pushKeys) return pushKeys;
  await pushTables(env);
  let row = await env.DB.prepare(`SELECT pub, priv FROM push_keys WHERE id=1`).first();
  if (!row) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pub = b64u(await crypto.subtle.exportKey('raw', kp.publicKey));
    const priv = JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey));
    await env.DB.prepare(`INSERT OR IGNORE INTO push_keys(id,pub,priv,created_at) VALUES(1,?,?,?)`).bind(pub, priv, now()).run();
    row = await env.DB.prepare(`SELECT pub, priv FROM push_keys WHERE id=1`).first();
  }
  const j = JSON.parse(row.priv);
  const key = await crypto.subtle.importKey('jwk', { kty: j.kty, crv: j.crv, x: j.x, y: j.y, d: j.d }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  pushKeys = { pub: row.pub, key };
  return pushKeys;
}
async function pushAuth(keys, endpoint, site) {
  const aud = new URL(endpoint).origin, t = Math.floor(now() / 1000);
  const c = pushJwt[aud]; if (c && c.exp - t > 3600) return c.h;
  const enc = (o) => b64u(new TextEncoder().encode(JSON.stringify(o)));
  const exp = t + 6 * 3600, un = enc({ typ: 'JWT', alg: 'ES256' }) + '.' + enc({ aud, exp, sub: site });
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.key, new TextEncoder().encode(un));
  const h = 'vapid t=' + un + '.' + b64u(sig) + ', k=' + keys.pub;
  pushJwt[aud] = { exp, h }; return h;
}
const siteOf = (url) => (/^https:/.test(url.origin) ? url.origin : 'https://bharatmakermandi.com');
async function queueAlert(env, ctx, url, title, body, link) {
  try {
    await pushTables(env);
    await env.DB.prepare(`INSERT INTO push_events(title,body,url,created_at) VALUES(?,?,?,?)`).bind(clean(title, 90), clean(body, 140), link, now()).run();
    pushCheckAt = 0;
    const job = drainAlerts(env, url).catch(() => {});
    if (ctx && ctx.waitUntil) ctx.waitUntil(job);
  } catch (e) {}
}
async function drainAlerts(env, url) {
  await pushTables(env);
  const t = now();
  const ev = await env.DB.prepare(`SELECT id, cursor FROM push_events WHERE done=0 ORDER BY id LIMIT 1`).first();
  if (!ev) return 0;
  const got = await env.DB.prepare(`UPDATE push_events SET lease=? WHERE id=? AND lease<?`).bind(t + 30000, ev.id, t).run();
  if (!got || !got.meta || !got.meta.changes) return 0;
  let last = ev.cursor || '', sent = 0;
  try {
    const subs = (await env.DB.prepare(`SELECT endpoint FROM push_subs WHERE endpoint>? ORDER BY endpoint LIMIT ?`).bind(last, PUSH_BATCH).all()).results || [];
    if (subs.length) {
      const keys = await getPushKeys(env), site = siteOf(url), gone = [], ok = [], bad = [];
      await Promise.all(subs.map(async (s) => {
        try {
          const r = await fetch(s.endpoint, { method: 'POST', headers: { Authorization: await pushAuth(keys, s.endpoint, site), TTL: '86400', Urgency: 'normal', Topic: 'bmm-new', 'Content-Length': '0' } });
          if (r.status === 404 || r.status === 410) gone.push(s.endpoint); else if (r.ok) ok.push(s.endpoint); else bad.push(s.endpoint);
        } catch (e) { bad.push(s.endpoint); }
      }));
      sent = ok.length; last = subs[subs.length - 1].endpoint;
      const st = [];
      gone.forEach((e) => st.push(env.DB.prepare(`DELETE FROM push_subs WHERE endpoint=?`).bind(e)));
      bad.forEach((e) => st.push(env.DB.prepare(`UPDATE push_subs SET fails=fails+1 WHERE endpoint=?`).bind(e)));
      if (ok.length) st.push(env.DB.prepare(`UPDATE push_subs SET fails=0, ok_at=? WHERE endpoint IN (${ok.map(() => '?').join(',')})`).bind(now(), ...ok));
      st.push(env.DB.prepare(`DELETE FROM push_subs WHERE fails>=5`));
      await env.DB.batch(st);
    }
    await env.DB.prepare(`UPDATE push_events SET cursor=?, done=?, sent=sent+?, lease=0 WHERE id=?`).bind(last, subs.length < PUSH_BATCH ? 1 : 0, sent, ev.id).run();
  } catch (e) { try { await env.DB.prepare(`UPDATE push_events SET lease=0 WHERE id=?`).bind(ev.id).run(); } catch (e2) {} }
  return sent;
}
function drainSoon(env, ctx, url) {
  const t = now();
  if (t - pushCheckAt < 15000 || !ctx || !ctx.waitUntil) return;
  pushCheckAt = t;
  ctx.waitUntil(drainAlerts(env, url).catch(() => {}));
}
async function pushRoutes(request, env, ctx, url, p, m) {
  if (!p.startsWith('/api/push/')) return null;
  await pushTables(env);
  if (p === '/api/push/key' && m === 'GET') return json({ publicKey: (await getPushKeys(env)).pub });
  if (p === '/api/push/subscribe' && m === 'POST') {
    const b = await readBody(request);
    const ep = String((b.subscription && b.subscription.endpoint) || '');
    let host = ''; try { const u = new URL(ep); if (u.protocol === 'https:') host = u.hostname; } catch (e) {}
    if (!host || ep.length > 1000 || !PUSH_HOSTS.test(host)) fail(400, 'This browser cannot get alerts.');
    if (b.oldEndpoint && b.oldEndpoint !== ep) await env.DB.prepare(`DELETE FROM push_subs WHERE endpoint=?`).bind(String(b.oldEndpoint)).run();
    const vid = /^[a-z0-9]{8,40}$/.test(String(b.vid || '')) ? b.vid : '';
    await env.DB.prepare(`INSERT INTO push_subs(endpoint,vid,created_at,ok_at,fails) VALUES(?,?,?,?,0) ON CONFLICT(endpoint) DO UPDATE SET vid=excluded.vid, fails=0`).bind(ep, vid, now(), now()).run();
    return json({ ok: true });
  }
  if (p === '/api/push/unsubscribe' && m === 'POST') {
    const b = await readBody(request);
    if (b.endpoint) await env.DB.prepare(`DELETE FROM push_subs WHERE endpoint=?`).bind(String(b.endpoint)).run();
    return json({ ok: true });
  }
  if (p === '/api/push/latest' && m === 'GET') {
    drainSoon(env, ctx, url);
    const ev = await env.DB.prepare(`SELECT id, title, body, url FROM push_events ORDER BY id DESC LIMIT 1`).first();
    if (!ev) return json({ alert: null });
    const n = await env.DB.prepare(`SELECT COUNT(*) AS n FROM push_events WHERE created_at>=?`).bind(now() - 30 * 60000).first();
    return json({ alert: { id: ev.id, title: ev.title, body: ev.body, url: ev.url, more: Math.max(0, ((n && n.n) || 1) - 1) } });
  }
  return null;
}
// ===== end added =====

function productFields(b) {
  const title = clean(b.title, 120);
  if (!title) fail(400, 'Enter the product title.');
  const seedha = int(b.seedha, 1, 100000000), market = int(b.market, 0, 100000000);
  if (!seedha) fail(400, 'Enter your price.');
  let cat = int(b.cat, -1, CATEGORY_COUNT - 1); if (cat === null) cat = -1;
  return { title, desc: clean(b.desc, 2000), cat, sub: cat >= 0 ? clean(b.sub, 80) : '', attrs: JSON.stringify(attrsClean(b.attrs)), place: clean(b.place, 80), seedha, market: market && market >= seedha ? market : seedha };
}

async function sitemap(env, url) {
  await ensureSchema(env);
  const rows = (await env.DB.prepare(`SELECT slug, code, updated_at FROM sellers WHERE status='approved' LIMIT 5000`).all()).results;
  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;');
  const items = [`<url><loc>${url.origin}/</loc></url>`, ...rows.map((r) => `<url><loc>${esc(url.origin + '/?shop=' + r.slug + '-' + String(r.code).slice(-4))}</loc></url>`)];
  return text(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${items.join('')}</urlset>`, 'application/xml');
}
