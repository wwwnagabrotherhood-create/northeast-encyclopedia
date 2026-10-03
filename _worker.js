
// V26 WRAPPER TOLERANCE - ASSETS ONLY, NOT FOR /api/*
// Handles mobile desktop-site uploads that create wrapper folders like MyFiles/1000174040
async function fetchAssetWithWrapperFallback(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  // Cloudflare's static-asset binding does an exact lookup and does not tolerate
  // a query string on the request URL (e.g. "/?neadmin=1" fails to resolve to
  // "/index.html"). Strip the query string for the ASSETS lookup only - the
  // browser's own address bar / window.location is untouched by this, so any
  // client-side code reading the query string still sees it normally.
  const assetLookupUrl = new URL(url.pathname, url.origin);
  const assetLookupRequest = new Request(assetLookupUrl, request);
  try {
    let res = await env.ASSETS.fetch(assetLookupRequest);
    if (res.status !== 404) return res;
  } catch(e) {}
  // Only for assets, never for API
  if (path.startsWith('/api/')) {
    return new Response('Not found: '+path, {status:404});
  }
  
  const file = path === '/' ? '/index.html' : path;
  // Known wrappers from mobile uploads
  const wrappers = [
    '/NE-V25-CLEAN-ROOT-4FILES',
    '/NE-V25-WRAPPER-TOLERANT-CLEAN-ROOT',
    '/MyFiles/1000174040',
    '/1000174040',
    '/MyFiles',
    '/NE-V26-CLEAN-ROOT',
    '/NE-V25-CLEAN-ROOT-4FILES.zip',
    '/NE-V31-CLEAN-ROOT-4FILES',
    '/NE-V31-CLEAN-ROOT',
    '/NE-V32-CLEAN-ROOT-4FILES',
    '/NE-V32-CLEAN-ROOT',
    '/NE-V33-CLEAN-ROOT-5FILES',
    '/NE-V33-CLEAN-ROOT'
  ];
  
  for (const w of wrappers) {
    try {
      const candidate = w + file;
      const r = await env.ASSETS.fetch(new Request(new URL(candidate, url.origin), request));
      if (r.status !== 404) {
        if (candidate.endsWith('.html')) {
          const b = await r.arrayBuffer();
          return new Response(b, { headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'no-cache', 'X-V26-Wrapper-Fix': w } });
        }
        return r;
      }
    } catch(e) {}
  }
  // If still not found and root, try original ASSETS again (query-string-stripped)
  try {
    return await env.ASSETS.fetch(assetLookupRequest);
  } catch(e) {
    return new Response('V26 Asset not found: '+path, {status:404});
  }
}

// NE FINAL V5 - AUTH ONLY FIX - PBKDF2 100k + env.JWT_SECRET + env.SALT + KV same record
// Requirements: No hardcoded fallback password usage when env exists, no silent user recreation on login, JWT same secret, ne_auth_token compatible

const FALLBACK_SALT = "NE_SECURE_SALT_51780b3815759ff5_prod_v2";
const FALLBACK_JWT = "NE_JWT_SUPER_SECURE_2024_BENYANTHAN_64CHARS_SECRET_KEY_FOR_SIGNING";
// NE CONTRIBUTOR V1 (test-project only) - Google OAuth Client ID is public by design, safe to embed
const NE_CONTRIB_GOOGLE_CLIENT_ID = "917861607184-7s2ru1dnajfh8a0jare7ae54oa6evpcr.apps.googleusercontent.com";

function getSalt(env){
  if(env){
    if(env.NE_SALT) return env.NE_SALT;
    if(env.SALT) return env.SALT;
  }
  return FALLBACK_SALT;
}
function getJwtSecret(env){
  if(env){
    if(env.JWT_SECRET) return env.JWT_SECRET;
    if(env.JWT_SECRET_KEY) return env.JWT_SECRET_KEY;
  }
  return FALLBACK_JWT;
}
function b64urlEncode(str){
  return btoa(str).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64urlEncodeBytes(bytes){
  let bin=''; for(let i=0;i<bytes.length;i++) bin+=String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64urlDecodeToBytes(str){
  str=str.replace(/-/g,'+').replace(/_/g,'/');
  while(str.length%4) str+='=';
  const bin=atob(str);
  const out=new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i);
  return out;
}
function b64urlDecode(str){
  str=str.replace(/-/g,'+').replace(/_/g,'/');
  while(str.length%4) str+='=';
  try{ return atob(str); }catch{ return null; }
}

async function pbkdf2Hash(password, salt){
  const enc=new TextEncoder();
  const keyMaterial=await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveBits']);
  const bits=await crypto.subtle.deriveBits({name:'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash:'SHA-256'}, keyMaterial, 256);
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

async function signJWT(payload, secret){
  const header={alg:'HS256',typ:'JWT'};
  const h=b64urlEncode(JSON.stringify(header));
  const p=b64urlEncode(JSON.stringify(payload));
  const data=h+'.'+p;
  const key=await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  const sig=await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return data+'.'+b64urlEncodeBytes(new Uint8Array(sig));
}

async function verifyJWT(token, secret, env){
  try{
    const parts=token.split('.');
    if(parts.length!==3) return null;
    const [h,p,s]=parts;
    const key=await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), {name:'HMAC',hash:'SHA-256'}, false, ['verify']);
    const data=h+'.'+p;
    const sigBytes=b64urlDecodeToBytes(s);
    const valid=await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(data));
    if(!valid) return null;
    const payloadStr=b64urlDecode(p);
    if(!payloadStr) return null;
    const payload=JSON.parse(payloadStr);
    if(payload.exp && Date.now()/1000 > payload.exp) return null;
    // tokenVersion check for invalidation after password change
    if(payload.username && env && env.NE_USERS_KV){
      try{
        const us=await env.NE_USERS_KV.get('user_'+payload.username.toLowerCase());
        if(us){
          const u=JSON.parse(us);
          if(typeof u.tokenVersion==='number' && typeof payload.tokenVersion==='number'){
            if(payload.tokenVersion !== u.tokenVersion) return null;
          }
        }
      }catch(e){}
    }
    return payload;
  }catch{ return null; }
}

// Issue-3 fix (read-only audit follow-up): peeks at a token's OWN CLAIMED
// role without verifying its signature. This never makes or changes any
// authorization decision -- verifyJWT() above remains the only function
// that decides isSuperAdmin/isContributor, and JWT signing, verification,
// expiry and tokenVersion semantics are completely unchanged. This exists
// solely so a route can tell "a token that claims to be staff was rejected"
// apart from "a token that claims to be a Contributor was rejected" or "no
// token at all", so the frontend can distinguish a stale Super Admin
// session (which should force re-login) from an ordinary public/Contributor
// request (which must never be interrupted with a login prompt).
function peekUnverifiedTokenRole(token){
  try{
    const parts = token.split('.');
    if(parts.length!==3) return null;
    const payloadStr = b64urlDecode(parts[1]);
    if(!payloadStr) return null;
    const payload = JSON.parse(payloadStr);
    return (payload && payload.role) ? payload.role : null;
  }catch(e){ return null; }
}

function getTokenFromRequest(req){
  const auth=req.headers.get('Authorization');
  if(auth && auth.toLowerCase().startsWith('bearer ')) return auth.slice(7).trim();
  const cookie=req.headers.get('Cookie')||'';
  const m=cookie.match(/(?:^|;\s*)ne_token=([^;]+)/);
  if(m) return m[1];
  // also support legacy token param from frontend
  try{
    const url=new URL(req.url);
    const q=url.searchParams.get('token');
    if(q) return q;
  }catch{}
  return null;
}

function jsonResponse(obj, status=200, extraHeaders={}){
  return new Response(JSON.stringify(obj),{
    status,
    headers:{
      'Content-Type':'application/json',
      'Access-Control-Allow-Origin':'*',
      'Access-Control-Allow-Methods':'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers':'Content-Type,Authorization',
      ...extraHeaders
    }
  });
}


// --- NE CONTRIBUTOR V1 helpers (test-project only, additive) ---

async function logContributorAudit(d1, actor, actorRole, action, affectedRecord, summary){
  // Audit logging must never break the calling flow, so all errors are swallowed.
  try{
    if(!d1) return;
    await d1.prepare(
      "INSERT INTO contributor_audit_logs (id,actor,actorRole,action,affectedRecord,summary,timestamp) VALUES (?,?,?,?,?,?,?)"
    ).bind(
      'log'+Date.now()+Math.random().toString(36).slice(2,8),
      actor||'', actorRole||'', action||'', affectedRecord||'', summary||'', new Date().toISOString()
    ).run();
  }catch(e){}
}

// Lazy expiry sweep for time-limited Suspend/Block restrictions. There is no
// background cron here (static Pages + Worker), so this runs on-demand: call
// it at the top of any admin route that reads contributor status, and any
// SUSPENDED/BLOCKED contributor whose statusExpiresAt has passed is flipped
// back to ACTIVE right then, before the caller's own query runs. A Permanent
// Block (statusPermanent=1) is never touched here - only a manual Unblock
// can clear it. Uses the existing contributor_audit_logs table for the
// expiry record (action='contributor_status_auto_expired') - this is a
// different action value from 'contributor_status_changed', so it does NOT
// affect the existing Suspended/Blocked-count queries, which only count
// 'contributor_status_changed' rows.
async function expireContributorStatuses(d1){
  try{
    if(!d1) return 0;
    const nowIso = new Date().toISOString();
    const rows = await d1.prepare(
      "SELECT id,status FROM contributors WHERE status IN ('SUSPENDED','BLOCKED') AND (statusPermanent IS NULL OR statusPermanent=0) AND statusExpiresAt IS NOT NULL AND statusExpiresAt<=?"
    ).bind(nowIso).all();
    const expired = rows.results || [];
    for(const row of expired){
      try{
        await d1.prepare(
          "UPDATE contributors SET status='ACTIVE', statusSince=NULL, statusExpiresAt=NULL, statusPermanent=0 WHERE id=?"
        ).bind(row.id).run();
        await logContributorAudit(d1, 'SYSTEM', 'SYSTEM', 'contributor_status_auto_expired', row.id, row.status);
      }catch(e){}
    }
    return expired.length;
  }catch(e){ return 0; }
}

// Verifies a Google Identity Services ID token entirely server-side against
// Google's published public keys. No client secret is needed for this flow -
// only the (public) Client ID, checked against the token's `aud` claim.
async function verifyGoogleIdToken(idToken, expectedClientId){
  try{
    if(!idToken || typeof idToken !== 'string'){ console.log('[NE-GSI-DEBUG] fail: idToken missing or not a string'); return null; }
    const parts = idToken.split('.');
    if(parts.length !== 3){ console.log('[NE-GSI-DEBUG] fail: idToken does not have 3 dot-separated parts'); return null; }
    const [h, p, s] = parts;

    const headerStr = b64urlDecode(h);
    const payloadStr = b64urlDecode(p);
    if(!headerStr || !payloadStr){ console.log('[NE-GSI-DEBUG] fail: could not base64url-decode header/payload'); return null; }
    const header = JSON.parse(headerStr);
    const payload = JSON.parse(payloadStr);

    if(header.alg !== 'RS256'){ console.log('[NE-GSI-DEBUG] fail: header.alg is not RS256, got', header.alg); return null; }

    // Basic claim checks before doing any network/crypto work
    if(!payload.exp || Date.now()/1000 > payload.exp){ console.log('[NE-GSI-DEBUG] fail: token missing exp or expired'); return null; }
    if(payload.aud !== expectedClientId){ console.log('[NE-GSI-DEBUG] fail: aud mismatch. token aud=', payload.aud, 'expected=', expectedClientId); return null; }
    if(payload.iss !== 'accounts.google.com' && payload.iss !== 'https://accounts.google.com'){ console.log('[NE-GSI-DEBUG] fail: iss mismatch, got', payload.iss); return null; }
    if(payload.email_verified === false){ console.log('[NE-GSI-DEBUG] fail: email_verified is false'); return null; }
    if(!payload.sub){ console.log('[NE-GSI-DEBUG] fail: token missing sub'); return null; }

    // Fetch Google's current public keys and find the one matching this token's kid
    const jwksRes = await fetch('https://www.googleapis.com/oauth2/v3/certs');
    if(!jwksRes.ok){ console.log('[NE-GSI-DEBUG] fail: JWKS fetch failed, status', jwksRes.status); return null; }
    const jwks = await jwksRes.json();
    const jwk = (jwks.keys||[]).find(k => k.kid === header.kid);
    if(!jwk){ console.log('[NE-GSI-DEBUG] fail: no JWKS key matches token kid', header.kid); return null; }

    const key = await crypto.subtle.importKey(
      'jwk', jwk, {name:'RSASSA-PKCS1-v1_5', hash:'SHA-256'}, false, ['verify']
    );
    const signedData = new TextEncoder().encode(h+'.'+p);
    const sigBytes = b64urlDecodeToBytes(s);
    const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sigBytes, signedData);
    if(!valid){ console.log('[NE-GSI-DEBUG] fail: RSA signature verification failed'); return null; }

    console.log('[NE-GSI-DEBUG] success: token verified for sub', payload.sub);
    return payload; // contains sub, email, name, picture, email_verified, etc.
  }catch(e){ console.log('[NE-GSI-DEBUG] fail: exception thrown', e && e.message); return null; }
}

// --- D1 Helpers ---
async function initD1Tables(d1){
  try{
    const statements = `-- Northeast Encyclopedia D1 Schema
-- Database name: northeast-encyclopedia-d1
-- Binding: NE_ENCYCLOPEDIA_D1

CREATE TABLE IF NOT EXISTS articles (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  slug TEXT NOT NULL,
  state TEXT,
  intro TEXT,
  content TEXT,
  categories TEXT,
  tags TEXT,
  references_list TEXT,
  imageUrl TEXT,
  imageCaption TEXT,
  imageCredit TEXT,
  infobox TEXT,
  authorId TEXT,
  authorName TEXT,
  createdAt TEXT,
  updatedAt TEXT,
  verified INTEGER DEFAULT 1,
  views INTEGER DEFAULT 0,
  relatedIds TEXT
);

CREATE TABLE IF NOT EXISTS tribes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  altNames TEXT,
  state TEXT,
  district TEXT,
  language TEXT,
  history TEXT,
  culture TEXT,
  festivals TEXT,
  food TEXT,
  clothing TEXT,
  arts TEXT,
  population TEXT,
  references_list TEXT,
  imageUrl TEXT,
  createdAt TEXT,
  updatedAt TEXT
);

CREATE TABLE IF NOT EXISTS people (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  role TEXT,
  state TEXT,
  bio TEXT,
  achievements TEXT,
  imageUrl TEXT,
  createdAt TEXT,
  updatedAt TEXT
);

CREATE TABLE IF NOT EXISTS places (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT,
  state TEXT,
  district TEXT,
  description TEXT,
  significance TEXT,
  imageUrl TEXT,
  createdAt TEXT,
  updatedAt TEXT
);

CREATE TABLE IF NOT EXISTS dictionary (
  id TEXT PRIMARY KEY,
  word TEXT NOT NULL,
  language TEXT,
  tribe TEXT,
  state TEXT,
  meaning TEXT,
  example TEXT,
  pronunciation TEXT,
  altSpelling TEXT,
  contributor TEXT,
  source TEXT,
  dateAdded TEXT
);

CREATE TABLE IF NOT EXISTS stories (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  state TEXT,
  intro TEXT,
  content TEXT,
  authorId TEXT,
  authorName TEXT,
  imageUrl TEXT,
  imageCaption TEXT,
  imageCredit TEXT,
  createdAt TEXT,
  updatedAt TEXT,
  verified INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS submissions (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  action TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  articleId TEXT,
  data TEXT NOT NULL,
  prevData TEXT,
  userId TEXT,
  username TEXT,
  userRole TEXT,
  timestamp TEXT,
  summary TEXT
);

CREATE TABLE IF NOT EXISTS revisions (
  id TEXT PRIMARY KEY,
  articleId TEXT NOT NULL,
  userId TEXT,
  username TEXT,
  timestamp TEXT,
  summary TEXT,
  prevContent TEXT,
  newContent TEXT
);

CREATE TABLE IF NOT EXISTS contributors (
  id TEXT PRIMARY KEY,
  googleSub TEXT UNIQUE NOT NULL,
  displayName TEXT,
  email TEXT,
  profilePhoto TEXT,
  country TEXT,
  stateRegion TEXT,
  languages TEXT,
  joinedAt TEXT,
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  contributionCount INTEGER NOT NULL DEFAULT 0,
  lastActiveAt TEXT
);

CREATE TABLE IF NOT EXISTS suggestions (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  contributorId TEXT,
  name TEXT,
  email TEXT,
  category TEXT,
  content TEXT NOT NULL,
  sourceRef TEXT,
  status TEXT NOT NULL DEFAULT 'NEW',
  timestamp TEXT
);

CREATE TABLE IF NOT EXISTS contributor_audit_logs (
  id TEXT PRIMARY KEY,
  actor TEXT,
  actorRole TEXT,
  action TEXT,
  affectedRecord TEXT,
  summary TEXT,
  timestamp TEXT
);

CREATE TABLE IF NOT EXISTS media (
  id TEXT PRIMARY KEY,
  title TEXT,
  fileData TEXT,
  caption TEXT,
  credit TEXT,
  category TEXT,
  authorId TEXT,
  authorName TEXT,
  createdAt TEXT,
  updatedAt TEXT,
  verified INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS categories (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  masterOrder INTEGER,
  inQuickAccess INTEGER DEFAULT 0,
  quickAccessLabel TEXT,
  quickAccessOrder INTEGER,
  isHidden INTEGER DEFAULT 0,
  createdAt TEXT,
  updatedAt TEXT
);

CREATE INDEX IF NOT EXISTS idx_articles_state ON articles(state);
CREATE INDEX IF NOT EXISTS idx_articles_title ON articles(title);
CREATE INDEX IF NOT EXISTS idx_articles_verified ON articles(verified);
CREATE INDEX IF NOT EXISTS idx_tribes_state ON tribes(state);
CREATE INDEX IF NOT EXISTS idx_dictionary_word ON dictionary(word);
CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
CREATE INDEX IF NOT EXISTS idx_revisions_articleId ON revisions(articleId);
CREATE INDEX IF NOT EXISTS idx_contributors_googleSub ON contributors(googleSub);
CREATE INDEX IF NOT EXISTS idx_contributors_status ON contributors(status);
CREATE INDEX IF NOT EXISTS idx_submissions_userId ON submissions(userId);
CREATE INDEX IF NOT EXISTS idx_suggestions_status ON suggestions(status);
CREATE INDEX IF NOT EXISTS idx_categories_name ON categories(name);
CREATE INDEX IF NOT EXISTS idx_categories_masterOrder ON categories(masterOrder);
ALTER TABLE submissions ADD COLUMN reviewReason TEXT;

-- NE MASTER IMPLEMENTATION PASS (additive, backward-compatible):
-- Safe ALTER TABLE ADD COLUMN migrations. Each runs as its own statement and
-- initD1Tables already swallows per-statement errors (e.g. "duplicate column
-- name") into initErrors without throwing, so re-running this on a database
-- that already has these columns is a harmless no-op. No existing column is
-- ever dropped or renamed, and no existing row is touched.
ALTER TABLE categories ADD COLUMN description TEXT;
ALTER TABLE categories ADD COLUMN isActive INTEGER DEFAULT 1;
ALTER TABLE tribes ADD COLUMN authorId TEXT;
ALTER TABLE tribes ADD COLUMN authorName TEXT;
ALTER TABLE people ADD COLUMN authorId TEXT;
ALTER TABLE people ADD COLUMN authorName TEXT;
ALTER TABLE places ADD COLUMN authorId TEXT;
ALTER TABLE places ADD COLUMN authorName TEXT;
ALTER TABLE contributors ADD COLUMN statusSince TEXT;
ALTER TABLE contributors ADD COLUMN statusExpiresAt TEXT;
ALTER TABLE contributors ADD COLUMN statusPermanent INTEGER DEFAULT 0;
-- D1 audit correction pass: real, online donation records. A donation row
-- is created as 'pending' the moment someone opens the QR/UPI flow with a
-- confirmed amount - never as 'successful', since this site has no payment
-- gateway/webhook to confirm a real UPI transfer. No status here is ever
-- invented; it only reflects what was actually entered.
CREATE TABLE IF NOT EXISTS donations (
  id TEXT PRIMARY KEY,
  amount REAL,
  status TEXT NOT NULL DEFAULT 'pending',
  transactionId TEXT,
  donor TEXT,
  upiId TEXT,
  createdAt TEXT,
  updatedAt TEXT
);
CREATE INDEX IF NOT EXISTS idx_donations_status ON donations(status);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  updatedAt TEXT,
  updatedBy TEXT
);

-- Final-pre-LIVE pass (additive, backward-compatible): universal anonymous
-- posting, engagement (like/dislike/comments), and real visitor/session
-- tracking. No existing table/column is dropped or renamed.
ALTER TABLE stories ADD COLUMN isAnonymous INTEGER DEFAULT 0;
ALTER TABLE dictionary ADD COLUMN isAnonymous INTEGER DEFAULT 0;

-- One shared reactions table for Like/Dislike across every content type
-- (contentType: 'article'|'story'|'word'|'media'). actorKey uniquely
-- identifies the voter: 'c:'+contributorId for a logged-in Contributor,
-- 'a:'+username for Super Admin. Login is REQUIRED to react -- there is no
-- anonymous/visitor actorKey any more (a logged-out visitor cannot write a
-- row here at all -- see /api/engagement/react). The UNIQUE index is the
-- actual duplicate-vote prevention mechanism -- enforced in D1, not just
-- client-side.
CREATE TABLE IF NOT EXISTS reactions (
  id TEXT PRIMARY KEY,
  contentType TEXT NOT NULL,
  contentId TEXT NOT NULL,
  actorKey TEXT NOT NULL,
  reactionType TEXT NOT NULL,
  createdAt TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_reactions_unique ON reactions(contentType,contentId,actorKey);
CREATE INDEX IF NOT EXISTS idx_reactions_content ON reactions(contentType,contentId,reactionType);

-- One shared comments table. actorId/actorType/displayName are ALWAYS
-- stored (same pattern as Article's isAnonymous infobox flag) so Super
-- Admin and the comment's own author can always be identified internally;
-- isAnonymous only controls what the PUBLIC read endpoint shows. Soft
-- delete via deletedAt keeps moderation history instead of destroying rows.
CREATE TABLE IF NOT EXISTS comments (
  id TEXT PRIMARY KEY,
  contentType TEXT NOT NULL,
  contentId TEXT NOT NULL,
  actorId TEXT NOT NULL,
  actorType TEXT NOT NULL,
  displayName TEXT NOT NULL,
  isAnonymous INTEGER DEFAULT 0,
  text TEXT NOT NULL,
  createdAt TEXT,
  deletedAt TEXT
);
CREATE INDEX IF NOT EXISTS idx_comments_content ON comments(contentType,contentId,createdAt);

-- Real visitor/session tracking (replaces the hardcoded "Visitors: N/A").
-- One row per browser session (sessionId is a random client-generated
-- token, the same category of mechanism as the existing ne_auth_token
-- already kept in localStorage -- it is a session pointer, not a stored
-- identity -- the actual counts/durations live here in D1). lastSeenAt is
-- advanced by a heartbeat the server timestamps itself (never trusts a
-- client-reported duration), so activeSeconds reflects real elapsed time
-- between heartbeats, capped per-tick to avoid inflating it across a
-- sleeping laptop or a backgrounded tab.
CREATE TABLE IF NOT EXISTS visitor_sessions (
  sessionId TEXT PRIMARY KEY,
  userType TEXT NOT NULL,
  contributorId TEXT,
  firstSeenAt TEXT,
  lastSeenAt TEXT,
  activeSeconds INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_visitor_sessions_lastSeen ON visitor_sessions(lastSeenAt);
`.split(';');
    const initErrors = [];
    for(let stmt of statements){
      stmt = stmt.trim();
      if(!stmt) continue;
      try{ await d1.prepare(stmt).run(); }catch(e){ initErrors.push({stmt: stmt.split('\n')[0].slice(0,80), error: e.message}); }
    }
    return { ok: true, errors: initErrors };
  }catch(e){ return { ok: false, errors: [{stmt:'(outer)', error: e.message}] }; }
}

async function d1GetAllData(env){
  if(!env.NE_ENCYCLOPEDIA_D1) return null;
  const d1 = env.NE_ENCYCLOPEDIA_D1;
  let neInit=null;
  try{
    neInit = await initD1Tables(d1);
    const articles = await d1.prepare("SELECT * FROM articles ORDER BY updatedAt DESC").all();
    const tribes = await d1.prepare("SELECT * FROM tribes ORDER BY name ASC").all();
    const people = await d1.prepare("SELECT * FROM people ORDER BY name ASC").all();
    const places = await d1.prepare("SELECT * FROM places ORDER BY name ASC").all();
    const dict = await d1.prepare("SELECT * FROM dictionary ORDER BY word ASC").all();
    const stories = await d1.prepare("SELECT * FROM stories ORDER BY updatedAt DESC").all();
    const submissions = await d1.prepare("SELECT * FROM submissions WHERE status='pending' ORDER BY timestamp DESC").all();
    const revisions = await d1.prepare("SELECT * FROM revisions ORDER BY timestamp DESC LIMIT 100").all();
    const donations = await d1.prepare("SELECT * FROM donations ORDER BY createdAt DESC LIMIT 200").all();
    return {
      articles: articles.results || [],
      tribes: tribes.results || [],
      people: people.results || [],
      places: places.results || [],
      dict: dict.results || [],
      stories: stories.results || [],
      submissions: submissions.results || [],
      revisions: revisions.results || [],
      donations: donations.results || []
    };
  }catch(e){ return {error: e.message, initErrors: neInit?neInit.errors:null}; }
}

// --- Issue-1 correction pass: privacy projection for Articles/Stories/
// Dictionary Words. Mirrors the exact security principle already used
// correctly by GET /api/engagement/comments (publicName vs realDisplayName,
// gated on a verified SUPER_ADMIN JWT) -- extended with one addition: the
// Contributor who actually owns an anonymous item keeps their own real id
// (never their own real NAME) in the response, because the existing
// Contributor Dashboard ("My Articles"/"My Stories"/"My Dictionary Words")
// and the inline Edit/Remove buttons on the public list views both match
// on authorId/contributor === the logged-in Contributor's own id. Without
// that exception a Contributor would lose the ability to manage their own
// anonymous content, which would break existing Contributor ownership.
// D1 itself is never touched here -- authorId/authorName/contributor/
// source stay in the database forever; only what this HTTP response
// contains is filtered. Tribes/People/Places/Submissions/Revisions/
// Donations are never passed through this function and are untouched.
function neProjectContentRow(row, kind, isSuperAdmin, viewerContributorId){
  if(!row) return row;
  let anon=false, ownerId='', nameField='', idField='';
  if(kind==='article'){
    let infobox={};
    try{ infobox = row.infobox ? JSON.parse(row.infobox) : {}; }catch(e){ infobox={}; }
    anon = !!infobox.isAnonymous; ownerId = row.authorId||''; nameField='authorName'; idField='authorId';
  } else if(kind==='story'){
    anon = !!row.isAnonymous; ownerId = row.authorId||''; nameField='authorName'; idField='authorId';
  } else if(kind==='dictionary'){
    anon = !!row.isAnonymous; ownerId = row.contributor||''; nameField='source'; idField='contributor';
  } else {
    return row;
  }
  if(!anon) return row;
  const isOwner = !!(viewerContributorId && ownerId && viewerContributorId===ownerId);
  if(isSuperAdmin){
    // Full reveal for moderation. realAuthorId/realAuthorName are explicit
    // fields (same shape as comments' realActorId/realDisplayName) so the
    // admin UI never has to guess which raw field to trust; the normal
    // display field is still kept as the public-safe value so any
    // unconditional "Anonymous Contributor" ternary elsewhere in the
    // frontend keeps rendering correctly even for a Super Admin viewer.
    return {...row, [nameField]:'Anonymous Contributor', realAuthorId: ownerId, realAuthorName: row[nameField]||''};
  }
  if(isOwner){
    // The Contributor who wrote it keeps their own id (ownership checks /
    // their own dashboard / their own Edit-Remove buttons) but never their
    // own real display name back from the server.
    return {...row, [nameField]:'Anonymous Contributor'};
  }
  // Visitor, or a different Contributor: strip both the id and the name.
  return {...row, [idField]:'', [nameField]:'Anonymous Contributor'};
}

export default {

 async fetch(request, env, ctx){
  const url=new URL(request.url);
  const path=url.pathname;

  if(request.method==='OPTIONS'){
    return new Response(null,{headers:{
      'Access-Control-Allow-Origin':'*',
      'Access-Control-Allow-Methods':'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers':'Content-Type,Authorization',
      'Access-Control-Allow-Credentials':'true'
    }});
  }

  // --- SAFE RECOVERY: Reset Super Admin via SETUP_TOKEN (server-side, no password exposure) ---
  // Support both /api/setup (used by setup.html) and /api/reset-benjamin
  if((path==='/api/reset-benjamin' || path==='/api/setup') && request.method==='POST'){
    try{
      if(!env.SETUP_TOKEN){
        return jsonResponse({success:false,error:'SETUP_TOKEN not configured in environment'},500);
      }
      const body=await request.json().catch(()=>({}));
      if(!body.setupToken || body.setupToken!==env.SETUP_TOKEN){
        return jsonResponse({success:false,error:'Invalid SETUP_TOKEN'},401);
      }
      const newPass=body.newPassword || body.newPassword || body.password;
      const requestedUsername=(body.username||'benjamin').toString().trim().toLowerCase() || 'benjamin';
      // Security: only allow benjamin to be reset via this endpoint
      if(requestedUsername!=='benjamin'){
        return jsonResponse({success:false,error:'Only benjamin can be reset via setup'},403);
      }
      if(body.confirmPassword && body.confirmPassword!==newPass){ return jsonResponse({success:false,error:'Passwords do not match'},400); }
      if(!newPass || typeof newPass!=='string' || newPass.length<8){
        return jsonResponse({success:false,error:'New password must be at least 8 characters'},400);
      }
      const salt=getSalt(env);
      const hashed=await pbkdf2Hash(newPass, salt);
      let existing=null;
      try{ const s=await env.NE_USERS_KV.get('user_benjamin'); if(s) existing=JSON.parse(s);}catch{}
      const newUser={
        username:'benjamin',
        displayName: existing?.displayName || 'Ben Yanthan',
        role: existing?.role || 'SUPER_ADMIN',
        passwordHash: hashed, // unified field
        hash: hashed, // keep legacy field for compatibility
        saltVersion: 'pbkdf2-100k-sha256',
        tokenVersion: (typeof existing?.tokenVersion==='number' ? existing.tokenVersion+1 : 1),
        updatedAt: Date.now()
      };
      await env.NE_USERS_KV.put('user_benjamin', JSON.stringify(newUser));
      return jsonResponse({success:true,message:'Super Admin password reset. All old sessions invalidated. Login with new password.', username:'benjamin'});
    }catch(e){
      return jsonResponse({success:false,error:e.message},500);
    }
  }

  // --- LOGOUT: clear cookie server-side (frontend also clears localStorage ne_auth_token) ---
  if(path==='/api/setup' && request.method!=='POST'){
    return jsonResponse({success:false,error:'Method not allowed - use POST'},405);
  }
  if(path==='/api/reset-benjamin' && request.method!=='POST'){
    return jsonResponse({success:false,error:'Method not allowed - use POST'},405);
  }
  
  // --- D1 ONLINE API ---
  if(path==='/api/d1/init' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 binding NE_ENCYCLOPEDIA_D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      return jsonResponse({success:true,message:'D1 tables initialized'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/all-data' && request.method==='GET'){
    try{
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured - using localStorage fallback'},503);
      const data = await d1GetAllData(env);
      if(data && data.error) return jsonResponse({success:false,error:data.error,initErrors:data.initErrors||null},500);
      // Issue-1 correction pass: privacy-project Articles/Stories/
      // Dictionary Words only. Every other content type this already
      // returns (tribes/people/places/submissions/revisions/donations) is
      // passed through completely untouched, exactly as d1GetAllData()
      // built it -- no unrelated field is added, removed or renamed.
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      const isSuperAdmin = !!(payload && payload.role==='SUPER_ADMIN');
      // Issue-3 fix: a token was presented but verifyJWT rejected it (expired,
      // bad signature, or invalidated tokenVersion) AND it claims to be a
      // staff/SUPER_ADMIN token -- this is the "stale Super Admin session"
      // case the read-only audit identified. A rejected Contributor token,
      // or no token at all, must never set this (ordinary public/Contributor
      // requests are completely unaffected).
      const staffAuthInvalid = !!(token && !payload && peekUnverifiedTokenRole(token)==='SUPER_ADMIN');
      const actor = await neResolveActor(request, env);
      const viewerContributorId = (actor && actor.actorType==='contributor') ? actor.actorId : '';
      const projected = {
        ...data,
        articles: (data.articles||[]).map((r)=>neProjectContentRow(r,'article',isSuperAdmin,viewerContributorId)),
        stories: (data.stories||[]).map((r)=>neProjectContentRow(r,'story',isSuperAdmin,viewerContributorId)),
        dict: (data.dict||[]).map((r)=>neProjectContentRow(r,'dictionary',isSuperAdmin,viewerContributorId))
      };
      return jsonResponse({success:true,data:projected,staffAuthInvalid});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/articles' && request.method==='GET'){
    try{
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},503);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const result = await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT * FROM articles WHERE verified=1 ORDER BY updatedAt DESC").all();
      // Issue-1 correction pass: same privacy projection as /api/d1/all-data.
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      const isSuperAdmin = !!(payload && payload.role==='SUPER_ADMIN');
      // Issue-3 fix: see matching comment in /api/d1/all-data above.
      const staffAuthInvalid = !!(token && !payload && peekUnverifiedTokenRole(token)==='SUPER_ADMIN');
      const actor = await neResolveActor(request, env);
      const viewerContributorId = (actor && actor.actorType==='contributor') ? actor.actorId : '';
      const articles = (result.results||[]).map((r)=>neProjectContentRow(r,'article',isSuperAdmin,viewerContributorId));
      return jsonResponse({success:true,articles,staffAuthInvalid});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/save-article' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const a=body.article;
      if(!a || !a.id || !a.title) return jsonResponse({success:false,error:'Article id and title required'},400);
      if(a.imageUrl && a.imageUrl.length > 1000000) return jsonResponse({success:false,error:'Photo too large for D1 (must be <1MB). Gallery upload auto-compresses.'},400);
      // Identity-preservation fix (Round 20f): for an EXISTING Article, D1
      // stays authoritative for authorId/authorName/infobox.isAnonymous --
      // never trust these from the client, which may be holding a privacy-
      // projected copy (authorName already overwritten to the public
      // placeholder for display, and a client-reconstructed infobox could
      // in principle omit or flip isAnonymous). A genuinely new Article (no
      // existing row) keeps today's server-derived-at-creation behavior
      // unchanged. Other infobox fields the client legitimately edited are
      // preserved -- only the isAnonymous key within infobox is pinned to
      // the existing D1 value.
      const existingArticle = await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT authorId, authorName, infobox FROM articles WHERE id=?").bind(a.id).first();
      let finalAuthorId, finalAuthorName, finalInfobox;
      if(existingArticle){
        finalAuthorId = existingArticle.authorId;
        finalAuthorName = existingArticle.authorName;
        let existingInfobox={}; try{ existingInfobox = existingArticle.infobox ? JSON.parse(existingArticle.infobox) : {}; }catch(e){ existingInfobox={}; }
        finalInfobox = {...(a.infobox||{}), isAnonymous: !!existingInfobox.isAnonymous};
      } else {
        finalAuthorId = a.authorId||payload.username;
        finalAuthorName = a.authorName||payload.displayName;
        finalInfobox = a.infobox||{};
      }
      await env.NE_ENCYCLOPEDIA_D1.prepare(
        "INSERT OR REPLACE INTO articles (id,title,slug,state,intro,content,categories,tags,references_list,imageUrl,imageCaption,imageCredit,infobox,authorId,authorName,createdAt,updatedAt,verified,views,relatedIds) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        a.id, a.title, a.slug||a.title.toLowerCase().replace(/\s+/g,'-'), a.state||'', a.intro||'', a.content||'',
        JSON.stringify(a.categories||[]), JSON.stringify(a.tags||[]), JSON.stringify(a.references||a.references_list||[]),
        a.imageUrl||'', a.imageCaption||'', a.imageCredit||'', JSON.stringify(finalInfobox),
        finalAuthorId, finalAuthorName, a.createdAt||new Date().toISOString(), new Date().toISOString(),
        1, a.views||0, JSON.stringify(a.relatedIds||[])
      ).run();
      return jsonResponse({success:true,message:'Article saved to D1 online'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  // D1 audit correction pass: every article content change (a normal edit,
  // or a Restore of an older version) now logs a real row here, and reads
  // it back via d1GetAllData() -> j.data.revisions on the frontend, so
  // History/Restore survives a refresh and shows the same list on any
  // device. SUPER_ADMIN only, same as save-article.
  if(path==='/api/d1/save-revision' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const r=body.revision;
      if(!r || !r.articleId || typeof r.prevContent!=='string' || typeof r.newContent!=='string') return jsonResponse({success:false,error:'articleId, prevContent and newContent required'},400);
      const id='rev'+Date.now()+Math.random().toString(36).slice(2,8);
      const timestamp=new Date().toISOString();
      await env.NE_ENCYCLOPEDIA_D1.prepare(
        "INSERT INTO revisions (id,articleId,userId,username,timestamp,summary,prevContent,newContent) VALUES (?,?,?,?,?,?,?,?)"
      ).bind(id, r.articleId, payload.username, payload.displayName||payload.username, timestamp, (r.summary||'Edited').toString().slice(0,300), r.prevContent, r.newContent).run();
      return jsonResponse({success:true, id, timestamp});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  // D1 audit correction pass: a real, online donation record - created the
  // moment the Donate QR/UPI flow is opened with a confirmed amount. This
  // route is intentionally public (no login required), matching the public
  // Donate page and the same pattern already used by /api/suggestions.
  // Status is always what was actually entered ('pending' from the current
  // flow, since there is still no payment gateway/webhook on this site) -
  // nothing here ever marks a donation 'successful' on its own.
  if(path==='/api/d1/save-donation' && request.method==='POST'){
    try{
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const don=body.donation;
      if(!don || !don.id || typeof don.amount!=='number' || !(don.amount>0)) return jsonResponse({success:false,error:'Valid donation id and amount required'},400);
      const status=['pending','successful','failed'].includes(don.status) ? don.status : 'pending';
      const nowIso=new Date().toISOString();
      await env.NE_ENCYCLOPEDIA_D1.prepare(
        "INSERT OR REPLACE INTO donations (id,amount,status,transactionId,donor,upiId,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?,?)"
      ).bind(
        don.id.toString().slice(0,100), don.amount, status,
        (don.transactionId||'').toString().slice(0,200), (don.donor||'Anonymous').toString().slice(0,200), (don.upiId||'').toString().slice(0,200),
        (don.date||nowIso), nowIso
      ).run();
      return jsonResponse({success:true});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/save-dictionary' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const w=body.word;
      if(!w || !w.id || !w.word || !w.meaning) return jsonResponse({success:false,error:'Word id, word and meaning required'},400);
      // Identity-preservation fix (Round 20f): for an EXISTING Dictionary
      // row, D1 stays authoritative for contributor/source/isAnonymous --
      // never trust these from the client, which may be holding a privacy-
      // projected copy (source already overwritten to the public placeholder
      // for display). A genuinely new word keeps today's server-derived
      // creation behavior unchanged. isAnonymous is also now explicitly
      // included below, so INSERT OR REPLACE no longer resets it to its
      // column default on every save.
      const existingWord = await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT contributor, source, isAnonymous FROM dictionary WHERE id=?").bind(w.id).first();
      let finalContributor, finalSource, finalIsAnonymous;
      if(existingWord){
        finalContributor = existingWord.contributor;
        finalSource = existingWord.source;
        finalIsAnonymous = existingWord.isAnonymous?1:0;
      } else {
        finalContributor = w.contributor||payload.username;
        finalSource = w.source||payload.displayName;
        finalIsAnonymous = w.isAnonymous?1:0;
      }
      await env.NE_ENCYCLOPEDIA_D1.prepare(
        "INSERT OR REPLACE INTO dictionary (id,word,language,tribe,state,meaning,example,pronunciation,altSpelling,contributor,source,dateAdded,isAnonymous) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        w.id, w.word, w.language||'', w.tribe||'', w.state||'', w.meaning, w.example||'', w.pronunciation||'', w.altSpelling||'',
        finalContributor, finalSource, w.dateAdded||new Date().toISOString(), finalIsAnonymous
      ).run();
      return jsonResponse({success:true,message:'Word saved to D1 online'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/save-story' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const st=body.story;
      if(!st || !st.id || !st.title || !st.content) return jsonResponse({success:false,error:'Story id, title and content required'},400);
      if(st.imageUrl && st.imageUrl.length > 1000000) return jsonResponse({success:false,error:'Photo too large for D1 (must be <1MB). Gallery upload auto-compresses.'},400);
      // Identity-preservation fix (Round 20f): for an EXISTING Story, D1
      // stays authoritative for authorId/authorName/isAnonymous -- never
      // trust these from the client, which may be holding a privacy-
      // projected copy (authorName already overwritten to the public
      // placeholder for display). A genuinely new Story keeps today's
      // server-derived creation behavior unchanged. isAnonymous is also now
      // explicitly included below, so INSERT OR REPLACE no longer resets it
      // to its column default on every save.
      const existingStory = await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT authorId, authorName, isAnonymous FROM stories WHERE id=?").bind(st.id).first();
      let finalAuthorId, finalAuthorName, finalIsAnonymous;
      if(existingStory){
        finalAuthorId = existingStory.authorId;
        finalAuthorName = existingStory.authorName;
        finalIsAnonymous = existingStory.isAnonymous?1:0;
      } else {
        finalAuthorId = st.authorId||payload.username;
        finalAuthorName = st.authorName||payload.displayName;
        finalIsAnonymous = st.isAnonymous?1:0;
      }
      await env.NE_ENCYCLOPEDIA_D1.prepare(
        "INSERT OR REPLACE INTO stories (id,title,state,intro,content,authorId,authorName,imageUrl,imageCaption,imageCredit,createdAt,updatedAt,verified,isAnonymous) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        st.id, st.title, st.state||'', st.intro||'', st.content, finalAuthorId, finalAuthorName,
        st.imageUrl||'', st.imageCaption||'', st.imageCredit||'', st.createdAt||new Date().toISOString(), new Date().toISOString(), 1, finalIsAnonymous
      ).run();
      return jsonResponse({success:true,message:'Story saved to D1 online'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/delete-article' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || !['SUPER_ADMIN','ADMIN','MODERATOR','EDITOR','CONTRIBUTOR'].includes(payload.role)) return jsonResponse({success:false,error:'Editor role required'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const id=body.id;
      if(!id) return jsonResponse({success:false,error:'Article id required'},400);
      const existing=await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT id, authorId FROM articles WHERE id=?").bind(id).first();
      if(!existing) return jsonResponse({success:false,error:'Article not found'},404);
      if(payload.role!=='SUPER_ADMIN' && existing.authorId!==payload.username && existing.authorId!==payload.contributorId){
        return jsonResponse({success:false,error:'You can only delete content you authored'},403);
      }
      await env.NE_ENCYCLOPEDIA_D1.prepare("DELETE FROM articles WHERE id=?").bind(id).run();
      return jsonResponse({success:true,message:'Article deleted from D1'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/delete-dictionary' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || !['SUPER_ADMIN','ADMIN','MODERATOR','EDITOR','CONTRIBUTOR'].includes(payload.role)) return jsonResponse({success:false,error:'Editor role required'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const id=body.id;
      if(!id) return jsonResponse({success:false,error:'Word id required'},400);
      const existing=await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT id, contributor FROM dictionary WHERE id=?").bind(id).first();
      if(!existing) return jsonResponse({success:false,error:'Word not found'},404);
      if(payload.role!=='SUPER_ADMIN' && existing.contributor!==payload.username && existing.contributor!==payload.contributorId){
        return jsonResponse({success:false,error:'You can only delete content you authored'},403);
      }
      await env.NE_ENCYCLOPEDIA_D1.prepare("DELETE FROM dictionary WHERE id=?").bind(id).run();
      return jsonResponse({success:true,message:'Word deleted from D1'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/delete-story' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || !['SUPER_ADMIN','ADMIN','MODERATOR','EDITOR','CONTRIBUTOR'].includes(payload.role)) return jsonResponse({success:false,error:'Editor role required'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const id=body.id;
      if(!id) return jsonResponse({success:false,error:'Story id required'},400);
      const existing=await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT id, authorId FROM stories WHERE id=?").bind(id).first();
      if(!existing) return jsonResponse({success:false,error:'Story not found'},404);
      if(payload.role!=='SUPER_ADMIN' && existing.authorId!==payload.username && existing.authorId!==payload.contributorId){
        return jsonResponse({success:false,error:'You can only delete content you authored'},403);
      }
      await env.NE_ENCYCLOPEDIA_D1.prepare("DELETE FROM stories WHERE id=?").bind(id).run();
      return jsonResponse({success:true,message:'Story deleted from D1'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/save-tribe' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const t=body.tribe;
      if(!t || !t.id || !t.name) return jsonResponse({success:false,error:'Tribe id and name required'},400);
      const existing=await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT createdAt FROM tribes WHERE id=?").bind(t.id).first();
      await env.NE_ENCYCLOPEDIA_D1.prepare(
        "INSERT OR REPLACE INTO tribes (id,name,altNames,state,district,language,history,culture,festivals,food,clothing,arts,population,references_list,imageUrl,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        t.id, t.name, JSON.stringify(t.altNames||[]), t.state||'', t.district||'', t.language||'', t.history||'', t.culture||'',
        t.festivals||'', t.food||'', t.clothing||'', t.arts||'', t.population||'', JSON.stringify(t.references||[]), t.imageUrl||'',
        (existing&&existing.createdAt)||t.createdAt||new Date().toISOString(), new Date().toISOString()
      ).run();
      return jsonResponse({success:true,message:'Tribe saved to D1 online'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/delete-tribe' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const id=body.id;
      if(!id) return jsonResponse({success:false,error:'Tribe id required'},400);
      if(id==='t1790448180936') return jsonResponse({success:false,error:'This is the protected TEST verification tribe and cannot be deleted.'},403);
      const existing=await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT id FROM tribes WHERE id=?").bind(id).first();
      if(!existing) return jsonResponse({success:false,error:'Tribe not found'},404);
      await env.NE_ENCYCLOPEDIA_D1.prepare("DELETE FROM tribes WHERE id=?").bind(id).run();
      return jsonResponse({success:true,message:'Tribe deleted from D1'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  // --- NE MASTER IMPLEMENTATION PASS: People management (mirrors save-tribe/delete-tribe exactly) ---
  if(path==='/api/d1/people' && request.method==='GET'){
    try{
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},503);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const result = await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT * FROM people ORDER BY name ASC").all();
      return jsonResponse({success:true,people: result.results||[]});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/save-person' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const p=body.person;
      if(!p || !p.id || !p.name) return jsonResponse({success:false,error:'Person id and name required'},400);
      if(p.imageUrl && p.imageUrl.length > 1000000) return jsonResponse({success:false,error:'Photo too large for D1 (must be <1MB).'},400);
      const existing=await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT createdAt, authorId, authorName FROM people WHERE id=?").bind(p.id).first();
      await env.NE_ENCYCLOPEDIA_D1.prepare(
        "INSERT OR REPLACE INTO people (id,name,role,state,bio,achievements,imageUrl,authorId,authorName,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        p.id, p.name, p.role||'', p.state||'', p.bio||'', p.achievements||'', p.imageUrl||'',
        (existing&&existing.authorId)||payload.username, (existing&&existing.authorName)||payload.displayName,
        (existing&&existing.createdAt)||p.createdAt||new Date().toISOString(), new Date().toISOString()
      ).run();
      return jsonResponse({success:true,message:'Person saved to D1 online'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/delete-person' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const id=body.id;
      if(!id) return jsonResponse({success:false,error:'Person id required'},400);
      const existing=await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT id FROM people WHERE id=?").bind(id).first();
      if(!existing) return jsonResponse({success:false,error:'Person not found'},404);
      await env.NE_ENCYCLOPEDIA_D1.prepare("DELETE FROM people WHERE id=?").bind(id).run();
      return jsonResponse({success:true,message:'Person deleted from D1'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // --- NE MASTER IMPLEMENTATION PASS: Places management (mirrors save-tribe/delete-tribe exactly) ---
  if(path==='/api/d1/places' && request.method==='GET'){
    try{
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},503);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const result = await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT * FROM places ORDER BY name ASC").all();
      return jsonResponse({success:true,places: result.results||[]});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/save-place' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const pl=body.place;
      if(!pl || !pl.id || !pl.name) return jsonResponse({success:false,error:'Place id and name required'},400);
      if(pl.imageUrl && pl.imageUrl.length > 1000000) return jsonResponse({success:false,error:'Photo too large for D1 (must be <1MB).'},400);
      const existing=await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT createdAt, authorId, authorName FROM places WHERE id=?").bind(pl.id).first();
      await env.NE_ENCYCLOPEDIA_D1.prepare(
        "INSERT OR REPLACE INTO places (id,name,type,state,district,description,significance,imageUrl,authorId,authorName,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        pl.id, pl.name, pl.type||'', pl.state||'', pl.district||'', pl.description||'', pl.significance||'', pl.imageUrl||'',
        (existing&&existing.authorId)||payload.username, (existing&&existing.authorName)||payload.displayName,
        (existing&&existing.createdAt)||pl.createdAt||new Date().toISOString(), new Date().toISOString()
      ).run();
      return jsonResponse({success:true,message:'Place saved to D1 online'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/delete-place' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const id=body.id;
      if(!id) return jsonResponse({success:false,error:'Place id required'},400);
      const existing=await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT id FROM places WHERE id=?").bind(id).first();
      if(!existing) return jsonResponse({success:false,error:'Place not found'},404);
      await env.NE_ENCYCLOPEDIA_D1.prepare("DELETE FROM places WHERE id=?").bind(id).run();
      return jsonResponse({success:true,message:'Place deleted from D1'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  if(path==='/api/d1/save-media' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || !['SUPER_ADMIN','ADMIN','MODERATOR','EDITOR'].includes(payload.role)) return jsonResponse({success:false,error:'Editor role required'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const m=body.media;
      if(!m || !m.id || !m.title) return jsonResponse({success:false,error:'Media id and title required'},400);
      if(!m.fileData) return jsonResponse({success:false,error:'Photo required'},400);
      if(m.fileData.length > 1000000) return jsonResponse({success:false,error:'Photo too large for D1 (must be <1MB). Gallery upload auto-compresses.'},400);
      const existing=await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT authorId FROM media WHERE id=?").bind(m.id).first();
      if(existing && payload.role!=='SUPER_ADMIN' && existing.authorId!==payload.username){
        return jsonResponse({success:false,error:'You can only edit media you authored'},403);
      }
      await env.NE_ENCYCLOPEDIA_D1.prepare(
        "INSERT OR REPLACE INTO media (id,title,fileData,caption,credit,category,authorId,authorName,createdAt,updatedAt,verified) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        m.id, m.title, m.fileData, m.caption||'', m.credit||'', m.category||'Community Photos',
        existing? existing.authorId : payload.username, m.authorName||payload.displayName,
        m.createdAt||new Date().toISOString(), new Date().toISOString(), 1
      ).run();
      return jsonResponse({success:true,message:'Photo saved to D1 online'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  // NE MASTER IMPLEMENTATION PASS: the frontend's photo gallery "Remove" button
  // has always been intentionally disconnected ("Remove isn't connected to a
  // real backend delete endpoint yet"). This adds the real route it needs,
  // matching the ownership rule already used by delete-article/delete-story.
  if(path==='/api/d1/delete-media' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || !['SUPER_ADMIN','ADMIN','MODERATOR','EDITOR'].includes(payload.role)) return jsonResponse({success:false,error:'Editor role required'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const id=body.id;
      if(!id) return jsonResponse({success:false,error:'Media id required'},400);
      const existing=await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT id, authorId FROM media WHERE id=?").bind(id).first();
      if(!existing) return jsonResponse({success:false,error:'Photo not found'},404);
      if(payload.role!=='SUPER_ADMIN' && existing.authorId!==payload.username){
        return jsonResponse({success:false,error:'You can only delete photos you authored'},403);
      }
      await env.NE_ENCYCLOPEDIA_D1.prepare("DELETE FROM media WHERE id=?").bind(id).run();
      return jsonResponse({success:true,message:'Photo deleted from D1'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/media' && request.method==='GET'){
    let neInit=null;
    try{
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},503);
      neInit = await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const result = await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT * FROM media WHERE verified=1 ORDER BY updatedAt DESC").all();
      return jsonResponse({success:true,media: result.results||[]});
    }catch(e){ return jsonResponse({success:false,error:e.message,initErrors:neInit?neInit.errors:null},500); }
  }
  if(path==='/api/d1/submit' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || !['SUPER_ADMIN','ADMIN','MODERATOR','EDITOR'].includes(payload.role)) return jsonResponse({success:false,error:'Editor role required'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const sub=body.submission;
      if(!sub) return jsonResponse({success:false,error:'Submission data required'},400);
      if(sub.data && sub.data.imageUrl && sub.data.imageUrl.length > 1000000) return jsonResponse({success:false,error:'Photo too large'},400);
      await env.NE_ENCYCLOPEDIA_D1.prepare(
        "INSERT INTO submissions (id,type,action,status,articleId,data,prevData,userId,username,userRole,timestamp,summary) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        sub.id||'sub'+Date.now(), sub.type||'article', sub.action||'create', 'pending',
        sub.articleId||null, JSON.stringify(sub.data||{}), JSON.stringify(sub.prevData||null),
        payload.username, payload.displayName, payload.role, new Date().toISOString(), sub.summary||''
      ).run();
      return jsonResponse({success:true,message:'Submission saved to D1 pending'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/approve' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const body=await request.json().catch(()=>({}));
      const subId=body.submissionId;
      if(!subId) return jsonResponse({success:false,error:'submissionId required'},400);
      const subResult = await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT * FROM submissions WHERE id=?").bind(subId).first();
      if(!subResult) return jsonResponse({success:false,error:'Submission not found'},404);
      let data; try{ data=JSON.parse(subResult.data); }catch{ data={}; }
      // Generate the article id exactly once, up front, so both statements below use the identical id.
      const newArticleId = data.id || subResult.articleId || 'a'+Date.now()+Math.random().toString(36).slice(2,6);
      const insertArticleStmt = env.NE_ENCYCLOPEDIA_D1.prepare(
        "INSERT OR REPLACE INTO articles (id,title,slug,state,intro,content,categories,tags,references_list,imageUrl,imageCaption,imageCredit,infobox,authorId,authorName,createdAt,updatedAt,verified,views,relatedIds) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        newArticleId, data.title||'Untitled', data.slug||(data.title||'').toLowerCase().replace(/\s+/g,'-'), data.state||'', data.intro||'', data.content||'',
        JSON.stringify(data.categories||[]), JSON.stringify(data.tags||[]), JSON.stringify(data.references||[]), data.imageUrl||'', data.imageCaption||'', data.imageCredit||'', JSON.stringify(data.infobox||{}),
        subResult.userId||data.authorId, data.authorName||subResult.username, data.createdAt||new Date().toISOString(), new Date().toISOString(), 1, data.views||0, JSON.stringify(data.relatedIds||[])
      );
      const updateSubmissionStmt = env.NE_ENCYCLOPEDIA_D1.prepare(
        "UPDATE submissions SET status='approved', articleId=? WHERE id=?"
      ).bind(newArticleId, subId);
      // Atomic: article creation and submission approval/linking either both commit or neither does.
      await env.NE_ENCYCLOPEDIA_D1.batch([insertArticleStmt, updateSubmissionStmt]);
      // NE CONTRIBUTOR V1: if this submission came from a contributor, bump their stats and log it.
      if(subResult.userRole === 'CONTRIBUTOR'){
        try{
          await env.NE_ENCYCLOPEDIA_D1.prepare("UPDATE contributors SET contributionCount=contributionCount+1, lastActiveAt=? WHERE id=?")
            .bind(new Date().toISOString(), subResult.userId).run();
        }catch(e){}
        await logContributorAudit(env.NE_ENCYCLOPEDIA_D1, payload.username||'SUPER_ADMIN', 'SUPER_ADMIN', 'submission_approved', subId, subResult.type);
      }
      return jsonResponse({success:true,message:'Approved and published to D1'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/reject' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const body=await request.json().catch(()=>({}));
      const subId=body.submissionId;
      const reason=(body.reason||'').toString().slice(0,1000);
      if(!subId) return jsonResponse({success:false,error:'submissionId required'},400);
      const subForReject = await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT userRole,userId,type FROM submissions WHERE id=?").bind(subId).first();
      try{
        await env.NE_ENCYCLOPEDIA_D1.prepare("UPDATE submissions SET status='rejected', reviewReason=? WHERE id=?").bind(reason, subId).run();
      }catch(e){
        // reviewReason column may not exist yet on an older DB - fall back without it
        await env.NE_ENCYCLOPEDIA_D1.prepare("UPDATE submissions SET status='rejected' WHERE id=?").bind(subId).run();
      }
      if(subForReject && subForReject.userRole === 'CONTRIBUTOR'){
        await logContributorAudit(env.NE_ENCYCLOPEDIA_D1, payload.username||'SUPER_ADMIN', 'SUPER_ADMIN', 'submission_rejected', subId, reason||subForReject.type);
      }
      return jsonResponse({success:true,message:'Rejected'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/migrate' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const body=await request.json().catch(()=>({}));
      const dump=body.dump;
      if(!dump) return jsonResponse({success:false,error:'dump required'},400);
      let count=0;
      // Identity-preservation fix (Round 20h, same invariant as Round 20f's
      // save-article): for an EXISTING Article row, D1 stays authoritative
      // for authorId/authorName/infobox.isAnonymous -- a migration dump may
      // be a stale or privacy-projected export, so its identity fields are
      // never trusted for a row that already exists. A genuinely new
      // Article (no existing row) keeps today's dump-controlled behavior
      // unchanged -- see Round 20h report for why this is left as-is here.
      if(dump.articles) for(let a of dump.articles){ if(a.imageUrl && a.imageUrl.length > 1000000) continue; try{
        const existingMigArt = await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT authorId, authorName, infobox FROM articles WHERE id=?").bind(a.id).first();
        let migAuthorId, migAuthorName, migInfobox;
        if(existingMigArt){
          migAuthorId = existingMigArt.authorId;
          migAuthorName = existingMigArt.authorName;
          let existingMigInfobox={}; try{ existingMigInfobox = existingMigArt.infobox ? JSON.parse(existingMigArt.infobox) : {}; }catch(e){ existingMigInfobox={}; }
          migInfobox = {...(a.infobox||{}), isAnonymous: !!existingMigInfobox.isAnonymous};
        } else {
          migAuthorId = a.authorId||'';
          migAuthorName = a.authorName||'';
          migInfobox = a.infobox||{};
        }
        await env.NE_ENCYCLOPEDIA_D1.prepare("INSERT OR REPLACE INTO articles (id,title,slug,state,intro,content,categories,tags,references_list,imageUrl,imageCaption,imageCredit,infobox,authorId,authorName,createdAt,updatedAt,verified,views,relatedIds) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(a.id,a.title,a.slug||'',a.state||'',a.intro||'',a.content||'',JSON.stringify(a.categories||[]),JSON.stringify(a.tags||[]),JSON.stringify(a.references||[]),a.imageUrl||'',a.imageCaption||'',a.imageCredit||'',JSON.stringify(migInfobox),migAuthorId,migAuthorName,a.createdAt||new Date().toISOString(),a.updatedAt||new Date().toISOString(),1,a.views||0,JSON.stringify(a.relatedIds||[])).run(); count++; }catch{} }
      if(dump.tribes) for(let t of dump.tribes){ try{ await env.NE_ENCYCLOPEDIA_D1.prepare("INSERT OR REPLACE INTO tribes (id,name,altNames,state,district,language,history,culture,festivals,food,clothing,arts,population,references_list,imageUrl) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(t.id,t.name,JSON.stringify(t.altNames||[]),t.state||'',t.district||'',t.language||'',t.history||'',t.culture||'',t.festivals||'',t.food||'',t.clothing||'',t.arts||'',t.population||'',JSON.stringify(t.references||[]),t.imageUrl||'').run(); count++; }catch{} }
      // Identity-preservation fix (Round 20h, same invariant as Round 20f's
      // save-dictionary): for an EXISTING Dictionary row, D1 stays
      // authoritative for contributor/source/isAnonymous -- never trust a
      // migration dump's values for a row that already exists. isAnonymous
      // is now explicitly included in the write so INSERT OR REPLACE no
      // longer silently resets it to its column default. A genuinely new
      // word keeps today's dump-controlled behavior unchanged.
      if(dump.dict) for(let d of dump.dict){ try{
        const existingMigWord = await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT contributor, source, isAnonymous FROM dictionary WHERE id=?").bind(d.id).first();
        let migContributor, migSource, migIsAnonymous;
        if(existingMigWord){
          migContributor = existingMigWord.contributor;
          migSource = existingMigWord.source;
          migIsAnonymous = existingMigWord.isAnonymous?1:0;
        } else {
          migContributor = d.contributor||'';
          migSource = d.source||'';
          migIsAnonymous = d.isAnonymous?1:0;
        }
        await env.NE_ENCYCLOPEDIA_D1.prepare("INSERT OR REPLACE INTO dictionary (id,word,language,tribe,state,meaning,example,pronunciation,altSpelling,contributor,source,dateAdded,isAnonymous) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(d.id,d.word,d.language||'',d.tribe||'',d.state||'',d.meaning||'',d.example||'',d.pronunciation||'',d.altSpelling||'',migContributor,migSource,d.dateAdded||new Date().toISOString(),migIsAnonymous).run(); count++; }catch{} }
      if(dump.people) for(let p of dump.people){ try{ await env.NE_ENCYCLOPEDIA_D1.prepare("INSERT OR REPLACE INTO people (id,name,role,state,bio,achievements,imageUrl) VALUES (?,?,?,?,?,?,?)").bind(p.id,p.name,p.role||'',p.state||'',p.bio||'',p.achievements||'',p.imageUrl||'').run(); count++; }catch{} }
      if(dump.places) for(let pl of dump.places){ try{ await env.NE_ENCYCLOPEDIA_D1.prepare("INSERT OR REPLACE INTO places (id,name,type,state,district,description,significance,imageUrl) VALUES (?,?,?,?,?,?,?,?)").bind(pl.id,pl.name,pl.type||'',pl.state||'',pl.district||'',pl.description||'',pl.significance||'',pl.imageUrl||'').run(); count++; }catch{} }
      return jsonResponse({success:true,message:`Migrated ${count} items to D1. localStorage NOT deleted - remains as backup.`});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }


  if(path==='/api/logout'){
    return new Response(JSON.stringify({success:true,message:'Logged out'}),{
      headers:{
        'Content-Type':'application/json',
        'Access-Control-Allow-Origin':'*',
        'Set-Cookie': 'ne_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
      }
    });
  }

  // --- VERIFY TOKEN - for persistence on reload ---
  if(path==='/api/verify' && request.method==='POST'){
    try{
      const body=await request.json().catch(()=>({}));
      const token=body.token || getTokenFromRequest(request);
      if(!token) return jsonResponse({valid:false},200);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload) return jsonResponse({valid:false},200);
      return jsonResponse({valid:true,user:{username:payload.username,displayName:payload.displayName,role:payload.role,tokenVersion:payload.tokenVersion}},200);
    }catch(e){
      return jsonResponse({valid:false,error:e.message},200);
    }
  }
  if(path==='/api/verify' && request.method==='GET'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({valid:false},200);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload) return jsonResponse({valid:false},200);
      return jsonResponse({valid:true,user:{username:payload.username,displayName:payload.displayName,role:payload.role}},200);
    }catch(e){ return jsonResponse({valid:false},200); }
  }

  // --- ADMIN USER MANAGEMENT: Separate passwords per user (V23C AUTH ONLY) ---
  if(path==='/api/admin/create-user' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      const body=await request.json().catch(()=>({}));
      const username=(body.username||'').toString().trim().toLowerCase();
      const displayName=(body.displayName||body.username||'').toString().trim();
      const role=(body.role||'EDITOR').toString().trim().toUpperCase();
      const password=(body.password||'').toString();
      if(!username || !password) return jsonResponse({success:false,error:'Username and password required'},400);
      if(password.length<6) return jsonResponse({success:false,error:'Password must be at least 6 chars'},400);
      if(!['SUPER_ADMIN','ADMIN','MODERATOR','EDITOR','CONTRIBUTOR','REGISTERED'].includes(role)) return jsonResponse({success:false,error:'Invalid role'},400);
      if(username==='benjamin') return jsonResponse({success:false,error:'Use /api/reset-benjamin for SUPER_ADMIN'},403);
      const key='user_'+username;
      const existing=await env.NE_USERS_KV.get(key);
      if(existing) return jsonResponse({success:false,error:'User already exists. Use set-password'},409);
      const salt=getSalt(env);
      const hashed=await pbkdf2Hash(password, salt);
      const newUser={username:username,displayName:displayName||username,role:role,passwordHash:hashed,hash:hashed,saltVersion:'pbkdf2-100k-sha256',tokenVersion:0,createdAt:Date.now(),updatedAt:Date.now(),createdBy:payload.username};
      await env.NE_USERS_KV.put(key, JSON.stringify(newUser));
      return jsonResponse({success:true,message:'User created',username:username,role:role,displayName:displayName});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/admin/set-password' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      const body=await request.json().catch(()=>({}));
      const target=(body.targetUsername||body.username||'').toString().trim().toLowerCase();
      const newPassword=(body.newPassword||body.password||'').toString();
      if(!target || !newPassword) return jsonResponse({success:false,error:'Target and new password required'},400);
      if(newPassword.length<6) return jsonResponse({success:false,error:'Password must be at least 6 chars'},400);
      if(target==='benjamin') return jsonResponse({success:false,error:'Use /api/reset-benjamin with SETUP_TOKEN'},403);
      const key='user_'+target;
      let userStr=await env.NE_USERS_KV.get(key);
      if(!userStr) return jsonResponse({success:false,error:'User not found. Create first'},404);
      let user=JSON.parse(userStr);
      const salt=getSalt(env);
      const hashed=await pbkdf2Hash(newPassword, salt);
      user.passwordHash=hashed;
      user.hash=hashed;
      user.tokenVersion=typeof user.tokenVersion==='number'?user.tokenVersion+1:1;
      user.updatedAt=Date.now();
      user.updatedBy=payload.username;
      await env.NE_USERS_KV.put(key, JSON.stringify(user));
      return jsonResponse({success:true,message:'Password updated',username:target,tokenVersion:user.tokenVersion});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/admin/list-users' && request.method==='GET'){
    try{
      const token=getTokenFromRequest(request);
      if(!token) return jsonResponse({success:false,error:'Auth required'},401);
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      const usernames=['benjamin','admin1','rini','editor_khasi'];
      let out=[];
      for(let u of usernames){
        let s=await env.NE_USERS_KV.get('user_'+u);
        if(s){ try{ let j=JSON.parse(s); out.push({username:j.username,displayName:j.displayName,role:j.role,createdAt:j.createdAt,tokenVersion:j.tokenVersion}); }catch{} }
      }
      return jsonResponse({success:true,users:out});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // --- LOGIN: MUST use same KV record and same PBKDF2 method as change-password ---

  // ================= NE CONTRIBUTOR V1 (test-project only, additive) =================

  // --- Google sign-in: verify token server-side, create/locate contributor, issue our own JWT ---
  if(path==='/api/contributor/google-signin' && request.method==='POST'){
    try{
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const body = await request.json().catch(()=>({}));
      const credential = body.credential;
      if(!credential) return jsonResponse({success:false,error:'Missing Google credential'},400);

      const g = await verifyGoogleIdToken(credential, NE_CONTRIB_GOOGLE_CLIENT_ID);
      if(!g) return jsonResponse({success:false,error:'Google sign-in verification failed'},401);

      const googleSub = g.sub; // stable permanent identity - never use email as the id
      let row = await d1.prepare("SELECT * FROM contributors WHERE googleSub=?").bind(googleSub).first();
      const now = new Date().toISOString();
      let isNew = false;

      if(!row){
        isNew = true;
        const id = 'c'+Date.now()+Math.random().toString(36).slice(2,6);
        await d1.prepare(
          "INSERT INTO contributors (id,googleSub,displayName,email,profilePhoto,country,stateRegion,languages,joinedAt,status,contributionCount,lastActiveAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
        ).bind(id, googleSub, g.name||'', g.email||'', g.picture||'', null, null, '[]', now, 'ACTIVE', 0, now).run();
        row = await d1.prepare("SELECT * FROM contributors WHERE id=?").bind(id).first();
        await logContributorAudit(d1, row.id, 'CONTRIBUTOR', 'contributor_registered', row.id, 'New contributor via Google sign-in');
      } else {
        await d1.prepare("UPDATE contributors SET lastActiveAt=?, displayName=?, profilePhoto=? WHERE id=?")
          .bind(now, g.name||row.displayName, g.picture||row.profilePhoto, row.id).run();
        row.lastActiveAt = now;
        await logContributorAudit(d1, row.id, 'CONTRIBUTOR', 'contributor_login', row.id, 'Google sign-in');
      }

      // Contributor JWTs deliberately omit `username` so verifyJWT's KV-based
      // tokenVersion check (built for the password-login system) is skipped.
      const tokenPayload = {
        contributorId: row.id,
        googleSub: row.googleSub,
        displayName: row.displayName,
        role: 'CONTRIBUTOR',
        status: row.status,
        iat: Math.floor(Date.now()/1000),
        exp: Math.floor(Date.now()/1000) + 7*24*3600
      };
      const secret = getJwtSecret(env);
      const token = await signJWT(tokenPayload, secret);

      return jsonResponse({
        success:true,
        isNew,
        token,
        contributor:{
          id: row.id, displayName: row.displayName, email: row.email, profilePhoto: row.profilePhoto,
          country: row.country, stateRegion: row.stateRegion, languages: row.languages,
          joinedAt: row.joinedAt, status: row.status, contributionCount: row.contributionCount, lastActiveAt: row.lastActiveAt
        }
      });
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // --- Helper: authenticate a contributor request, re-checking live status in D1 (not just the token) ---
  async function requireActiveContributor(request, env){
    const token = getTokenFromRequest(request);
    if(!token) return {error: jsonResponse({success:false,error:'Auth required'},401)};
    const payload = await verifyJWT(token, getJwtSecret(env), env);
    if(!payload || payload.role !== 'CONTRIBUTOR') return {error: jsonResponse({success:false,error:'Contributor auth required'},403)};
    if(!env.NE_ENCYCLOPEDIA_D1) return {error: jsonResponse({success:false,error:'D1 not configured'},500)};
    const d1 = env.NE_ENCYCLOPEDIA_D1;
    const row = await d1.prepare("SELECT * FROM contributors WHERE id=?").bind(payload.contributorId).first();
    if(!row) return {error: jsonResponse({success:false,error:'Contributor not found'},404)};
    if(row.status !== 'ACTIVE') return {error: jsonResponse({success:false,error:'Account is '+row.status.toLowerCase()},403)};
    return {payload, contributor: row, d1};
  }

  if(path==='/api/contributor/me' && request.method==='GET'){
    const auth = await requireActiveContributor(request, env);
    if(auth.error) return auth.error;
    const c = auth.contributor;
    return jsonResponse({success:true, contributor:{
      id:c.id, displayName:c.displayName, email:c.email, profilePhoto:c.profilePhoto,
      country:c.country, stateRegion:c.stateRegion, languages:c.languages,
      joinedAt:c.joinedAt, status:c.status, contributionCount:c.contributionCount, lastActiveAt:c.lastActiveAt
    }});
  }

  // --- Contributor submits any of the six contribution types. Never publishes directly. ---
  const NE_CONTRIB_TYPES = ['contributor_article','contributor_correction','contributor_dictionary','contributor_translation','contributor_story','contributor_photo'];
  if(path==='/api/contributor/submit' && request.method==='POST'){
    try{
      const auth = await requireActiveContributor(request, env);
      if(auth.error) return auth.error;
      const { contributor, d1 } = auth;
      const body = await request.json().catch(()=>({}));
      const type = body.type;
      if(!NE_CONTRIB_TYPES.includes(type)) return jsonResponse({success:false,error:'Invalid contribution type'},400);
      const data = body.data || {};
      if(data.imageUrl && data.imageUrl.length > 1000000) return jsonResponse({success:false,error:'Photo too large'},400);

      // Direct-publish path for Contributors: they publish immediately, same as
      // Super Admin's save-article, but authorId/authorName always come from the
      // authenticated session (never trusted from the frontend), and ownership
      // is re-checked on every edit so a contributor can only update their own work.
      if(type === 'contributor_article'){
        const a = data;
        if(!a.title) return jsonResponse({success:false,error:'Title required'},400);
        let articleId = body.articleId || a.id;
        if(articleId){
          const existingArt = await d1.prepare("SELECT authorId FROM articles WHERE id=?").bind(articleId).first();
          if(existingArt && existingArt.authorId !== contributor.id) return jsonResponse({success:false,error:'You can only edit your own content'},403);
        } else {
          articleId = 'a'+Date.now()+Math.random().toString(36).slice(2,6);
        }
        await d1.prepare(
          "INSERT OR REPLACE INTO articles (id,title,slug,state,intro,content,categories,tags,references_list,imageUrl,imageCaption,imageCredit,infobox,authorId,authorName,createdAt,updatedAt,verified,views,relatedIds) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        ).bind(
          articleId, a.title, a.slug||a.title.toLowerCase().replace(/\s+/g,'-'), a.state||'', a.intro||'', a.content||'',
          JSON.stringify(a.categories||[]), JSON.stringify(a.tags||[]), JSON.stringify(a.references||[]),
          a.imageUrl||'', a.imageCaption||'', a.imageCredit||'', JSON.stringify(a.infobox||{}),
          contributor.id, contributor.displayName, a.createdAt||new Date().toISOString(), new Date().toISOString(),
          1, a.views||0, JSON.stringify(a.relatedIds||[])
        ).run();
        await logContributorAudit(d1, contributor.id, 'CONTRIBUTOR', body.articleId?'contributor_article_updated':'contributor_article_published', articleId, a.title);
        return jsonResponse({success:true, id:articleId, message:'Published to D1'});
      }

      // Direct-publish path for Contributor dictionary words. Uses the existing
      // dictionary table exactly as-is. Ownership is tracked via the `contributor`
      // column (the contributor's own id), so an edit can only touch their own word.
      if(type === 'contributor_dictionary'){
        const w = data;
        if(!w.word) return jsonResponse({success:false,error:'Word is required'},400);
        if(!w.meaning) return jsonResponse({success:false,error:'Meaning is required'},400);
        let wordId = body.articleId || w.id;
        if(wordId){
          const existingWord = await d1.prepare("SELECT contributor FROM dictionary WHERE id=?").bind(wordId).first();
          if(existingWord && existingWord.contributor !== contributor.id) return jsonResponse({success:false,error:'You can only edit your own content'},403);
        } else {
          wordId = 'w'+Date.now()+Math.random().toString(36).slice(2,6);
        }
        await d1.prepare(
          "INSERT OR REPLACE INTO dictionary (id,word,language,tribe,state,meaning,example,pronunciation,altSpelling,contributor,source,dateAdded,isAnonymous) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
        ).bind(
          wordId, w.word, w.language||'', w.tribe||'', w.state||'', w.meaning, w.example||'', w.pronunciation||'', w.altSpelling||'',
          contributor.id, w.source||contributor.displayName, w.dateAdded||new Date().toISOString(), w.isAnonymous?1:0
        ).run();
        await logContributorAudit(d1, contributor.id, 'CONTRIBUTOR', body.articleId?'contributor_word_updated':'contributor_word_published', wordId, w.word);
        return jsonResponse({success:true, id:wordId, message:'Published to D1'});
      }

      // Direct-publish path for Contributor stories. Uses the existing stories
      // table exactly as-is (same authorId/authorName pattern as articles), so
      // ownership on edit is checked the same way.
      if(type === 'contributor_story'){
        const st = data;
        if(!st.title) return jsonResponse({success:false,error:'Title is required'},400);
        if(!st.content) return jsonResponse({success:false,error:'Story content is required'},400);
        let storyId = body.articleId || st.id;
        if(storyId){
          const existingStory = await d1.prepare("SELECT authorId FROM stories WHERE id=?").bind(storyId).first();
          if(existingStory && existingStory.authorId !== contributor.id) return jsonResponse({success:false,error:'You can only edit your own content'},403);
        } else {
          storyId = 's'+Date.now()+Math.random().toString(36).slice(2,6);
        }
        await d1.prepare(
          "INSERT OR REPLACE INTO stories (id,title,state,intro,content,authorId,authorName,imageUrl,imageCaption,imageCredit,createdAt,updatedAt,verified,isAnonymous) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        ).bind(
          storyId, st.title, st.state||'', st.intro||'', st.content, contributor.id, contributor.displayName,
          st.imageUrl||'', st.imageCaption||'', st.imageCredit||'', st.createdAt||new Date().toISOString(), new Date().toISOString(), 1, st.isAnonymous?1:0
        ).run();
        await logContributorAudit(d1, contributor.id, 'CONTRIBUTOR', body.articleId?'contributor_story_updated':'contributor_story_published', storyId, st.title);
        return jsonResponse({success:true, id:storyId, message:'Published to D1'});
      }

      const id = 'sub'+Date.now()+Math.random().toString(36).slice(2,6);
      await d1.prepare(
        "INSERT INTO submissions (id,type,action,status,articleId,data,prevData,userId,username,userRole,timestamp,summary) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        id, type, body.action||'create', 'pending', body.articleId||null,
        JSON.stringify(data), JSON.stringify(body.prevData||null),
        contributor.id, contributor.displayName, 'CONTRIBUTOR', new Date().toISOString(), body.summary||''
      ).run();

      await logContributorAudit(d1, contributor.id, 'CONTRIBUTOR', 'submission_created', id, type);
      return jsonResponse({success:true, submissionId:id, message:'Submitted for review'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // --- Final-pre-LIVE pass: shared engagement (Like/Dislike/Comments) and
  // real visitor/session tracking, for every applicable content type. One
  // actor-resolution helper is reused by every route below, instead of each
  // route inventing its own identity logic. ---
  const NE_ENGAGEMENT_CONTENT_TYPES = ['article','story','word','media'];
  const NE_REACTION_TYPES = ['like','dislike'];

  // Resolves WHO is acting, without ever trusting a client-asserted
  // identity: only a server-verified bearer token (Contributor or Super
  // Admin JWT) resolves to an actor; returns null otherwise. Login is
  // required for BOTH reactions and comments -- there is no anonymous
  // fallback for either. Every caller of this function (react, comment)
  // must reject the request (401) when it returns null.
  async function neResolveActor(request, env){
    const token = getTokenFromRequest(request);
    if(token){
      const payload = await verifyJWT(token, getJwtSecret(env), env);
      if(payload && payload.role==='CONTRIBUTOR' && env.NE_ENCYCLOPEDIA_D1){
        const row = await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT * FROM contributors WHERE id=?").bind(payload.contributorId).first();
        if(row && row.status==='ACTIVE'){
          return {actorType:'contributor', actorId:row.id, displayName:row.displayName, actorKey:'c:'+row.id};
        }
      } else if(payload && payload.role==='SUPER_ADMIN'){
        return {actorType:'admin', actorId:payload.username, displayName:payload.username, actorKey:'a:'+payload.username};
      }
    }
    return null;
  }

  // --- Like/Dislike: toggle-on, toggle-off, or switch type. The UNIQUE
  // index on (contentType,contentId,actorKey) is the real duplicate-vote
  // guard -- enforced in D1, not just in the UI. Login is REQUIRED: a
  // logged-out visitor can read counts (via the public summary endpoint
  // below) but cannot react. There is no anonymous/visitorId fallback here
  // any more -- neResolveActor() is the only source of actorKey, and it
  // verifies a real Contributor or Super Admin JWT server-side, so hiding
  // the button in the UI is not what enforces this. ---
  if(path==='/api/engagement/react' && request.method==='POST'){
    try{
      const actor = await neResolveActor(request, env);
      if(!actor) return jsonResponse({success:false,error:'Login required to react'},401);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const body = await request.json().catch(()=>({}));
      const contentType = body.contentType;
      const contentId = (body.contentId||'').toString();
      const reactionType = body.reactionType;
      if(!NE_ENGAGEMENT_CONTENT_TYPES.includes(contentType)) return jsonResponse({success:false,error:'Invalid contentType'},400);
      if(!contentId) return jsonResponse({success:false,error:'contentId required'},400);
      if(!NE_REACTION_TYPES.includes(reactionType)) return jsonResponse({success:false,error:'Invalid reactionType'},400);

      const actorKey = actor.actorKey;
      const existing = await d1.prepare("SELECT id,reactionType FROM reactions WHERE contentType=? AND contentId=? AND actorKey=?").bind(contentType,contentId,actorKey).first();
      let myReaction = null;
      if(existing && existing.reactionType===reactionType){
        // Same button clicked again -> toggle off (un-react).
        await d1.prepare("DELETE FROM reactions WHERE id=?").bind(existing.id).run();
        myReaction = null;
      } else if(existing){
        // Switching Like<->Dislike -> update in place.
        await d1.prepare("UPDATE reactions SET reactionType=?, createdAt=? WHERE id=?").bind(reactionType, new Date().toISOString(), existing.id).run();
        myReaction = reactionType;
      } else {
        const id = 'rx'+Date.now()+Math.random().toString(36).slice(2,8);
        await d1.prepare("INSERT INTO reactions (id,contentType,contentId,actorKey,reactionType,createdAt) VALUES (?,?,?,?,?,?)").bind(id,contentType,contentId,actorKey,reactionType,new Date().toISOString()).run();
        myReaction = reactionType;
      }
      const counts = await d1.prepare("SELECT reactionType, COUNT(*) as n FROM reactions WHERE contentType=? AND contentId=? GROUP BY reactionType").bind(contentType,contentId).all();
      let likes=0, dislikes=0;
      for(const row of (counts.results||[])){ if(row.reactionType==='like') likes=row.n; if(row.reactionType==='dislike') dislikes=row.n; }
      return jsonResponse({success:true, likes, dislikes, myReaction});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // --- Public read of like/dislike counts (+ the caller's own current
  // reaction, ONLY when a real login resolves -- no auth required to read
  // the counts themselves, but there is no client-supplied visitorId
  // lookup any more since anonymous visitors can never have a reaction row
  // to find). ---
  if(path==='/api/engagement/summary' && request.method==='GET'){
    try{
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const contentType = url.searchParams.get('contentType');
      const contentId = (url.searchParams.get('contentId')||'').toString();
      if(!NE_ENGAGEMENT_CONTENT_TYPES.includes(contentType) || !contentId) return jsonResponse({success:false,error:'contentType and contentId required'},400);
      const counts = await d1.prepare("SELECT reactionType, COUNT(*) as n FROM reactions WHERE contentType=? AND contentId=? GROUP BY reactionType").bind(contentType,contentId).all();
      let likes=0, dislikes=0;
      for(const row of (counts.results||[])){ if(row.reactionType==='like') likes=row.n; if(row.reactionType==='dislike') dislikes=row.n; }
      let myReaction = null;
      const actor = await neResolveActor(request, env);
      if(actor){
        const mine = await d1.prepare("SELECT reactionType FROM reactions WHERE contentType=? AND contentId=? AND actorKey=?").bind(contentType,contentId,actor.actorKey).first();
        myReaction = mine ? mine.reactionType : null;
      }
      return jsonResponse({success:true, likes, dislikes, myReaction});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // --- Comments: still requires real login (same expectation the old
  // in-memory Talk tab had), now Contributor-OR-Super-Admin instead of
  // Super-Admin-only, genuinely D1-persisted, and with the same
  // Post-as-Me/Post-Anonymously choice as Articles. The real actor is
  // ALWAYS stored; isAnonymous only changes what the public read below
  // returns. ---
  if(path==='/api/engagement/comment' && request.method==='POST'){
    try{
      const actor = await neResolveActor(request, env);
      if(!actor) return jsonResponse({success:false,error:'Login required to comment'},401);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const body = await request.json().catch(()=>({}));
      const contentType = body.contentType;
      const contentId = (body.contentId||'').toString();
      const text = (body.text||'').toString().trim();
      if(!NE_ENGAGEMENT_CONTENT_TYPES.includes(contentType)) return jsonResponse({success:false,error:'Invalid contentType'},400);
      if(!contentId) return jsonResponse({success:false,error:'contentId required'},400);
      if(!text) return jsonResponse({success:false,error:'Comment text required'},400);
      if(text.length>2000) return jsonResponse({success:false,error:'Comment too long (max 2000 characters)'},400);
      const id = 'cm'+Date.now()+Math.random().toString(36).slice(2,8);
      const isAnonymous = body.isAnonymous ? 1 : 0;
      const now = new Date().toISOString();
      await d1.prepare("INSERT INTO comments (id,contentType,contentId,actorId,actorType,displayName,isAnonymous,text,createdAt) VALUES (?,?,?,?,?,?,?,?,?)")
        .bind(id, contentType, contentId, actor.actorId, actor.actorType, actor.displayName, isAnonymous, text, now).run();
      return jsonResponse({success:true, comment:{id, publicName: isAnonymous?'Anonymous Contributor':actor.displayName, isAnonymous:!!isAnonymous, text, createdAt:now}});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // --- Public read of comments. Only ever exposes the public-safe
  // projection (publicName, never the raw actorId/actorType) UNLESS the
  // caller is Super Admin, mirroring the studioConfig/publicHomeDesign
  // split already used elsewhere -- so moderation stays possible without
  // widening what ordinary visitors can see. ---
  if(path==='/api/engagement/comments' && request.method==='GET'){
    try{
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const contentType = url.searchParams.get('contentType');
      const contentId = (url.searchParams.get('contentId')||'').toString();
      if(!NE_ENGAGEMENT_CONTENT_TYPES.includes(contentType) || !contentId) return jsonResponse({success:false,error:'contentType and contentId required'},400);
      const res = await d1.prepare("SELECT id,actorId,actorType,displayName,isAnonymous,text,createdAt FROM comments WHERE contentType=? AND contentId=? AND deletedAt IS NULL ORDER BY createdAt ASC").bind(contentType,contentId).all();
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      const isSuperAdmin = !!(payload && payload.role==='SUPER_ADMIN');
      const actor = await neResolveActor(request, env);
      const rows = (res.results||[]).map((r)=>({
        id:r.id,
        publicName: r.isAnonymous? 'Anonymous Contributor' : r.displayName,
        isAnonymous: !!r.isAnonymous,
        text:r.text,
        createdAt:r.createdAt,
        isMine: !!(actor && actor.actorId===r.actorId && actor.actorType===r.actorType),
        // Real identity is included ONLY for Super Admin moderation -- never
        // sent to an ordinary visitor, matching the public-projection
        // pattern used for studioConfig/publicHomeDesign.
        ...(isSuperAdmin?{realActorId:r.actorId, realActorType:r.actorType, realDisplayName:r.displayName}:{})
      }));
      return jsonResponse({success:true, comments:rows});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // --- Delete a comment: the comment's own author, or Super Admin. Soft
  // delete (deletedAt) preserves the moderation trail instead of destroying
  // the row outright. ---
  if(path==='/api/engagement/comment/delete' && request.method==='POST'){
    try{
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      const body = await request.json().catch(()=>({}));
      const id = (body.id||'').toString();
      if(!id) return jsonResponse({success:false,error:'id required'},400);
      const row = await d1.prepare("SELECT actorId,actorType FROM comments WHERE id=?").bind(id).first();
      if(!row) return jsonResponse({success:false,error:'Comment not found'},404);
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      const isSuperAdmin = !!(payload && payload.role==='SUPER_ADMIN');
      const actor = await neResolveActor(request, env);
      const isOwner = !!(actor && actor.actorId===row.actorId && actor.actorType===row.actorType);
      if(!isSuperAdmin && !isOwner) return jsonResponse({success:false,error:'You can only remove your own comment'},403);
      await d1.prepare("UPDATE comments SET deletedAt=? WHERE id=?").bind(new Date().toISOString(), id).run();
      return jsonResponse({success:true});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // --- Visitor/session heartbeat. Public (works for anonymous visitors);
  // if a valid token IS present, the verified identity always overrides
  // whatever the client claims about itself. Elapsed time since this
  // session's last heartbeat is computed server-side from the stored
  // lastSeenAt, never trusted from the client, and capped per tick so a
  // sleeping laptop or backgrounded tab can't inflate "time on site". ---
  if(path==='/api/track/heartbeat' && request.method==='POST'){
    try{
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const body = await request.json().catch(()=>({}));
      const sessionId = (body.sessionId||'').toString();
      if(!sessionId || sessionId.length<8 || sessionId.length>128 || !/^[a-zA-Z0-9_-]+$/.test(sessionId)) return jsonResponse({success:false,error:'Invalid sessionId'},400);

      let userType = 'visitor';
      let contributorId = null;
      const actor = await neResolveActor(request, env);
      if(actor && actor.actorType==='contributor'){ userType='contributor'; contributorId=actor.actorId; }
      else if(actor && actor.actorType==='admin'){ userType='admin'; }

      const now = new Date();
      const nowIso = now.toISOString();
      const existing = await d1.prepare("SELECT lastSeenAt,activeSeconds FROM visitor_sessions WHERE sessionId=?").bind(sessionId).first();
      const HEARTBEAT_CAP_SECONDS = 90; // ~2x the expected client heartbeat interval
      if(existing){
        const elapsedMs = now - new Date(existing.lastSeenAt);
        const elapsedSeconds = Math.max(0, Math.min(HEARTBEAT_CAP_SECONDS, Math.round(elapsedMs/1000)));
        await d1.prepare("UPDATE visitor_sessions SET lastSeenAt=?, userType=?, contributorId=?, activeSeconds=activeSeconds+? WHERE sessionId=?")
          .bind(nowIso, userType, contributorId, elapsedSeconds, sessionId).run();
      } else {
        await d1.prepare("INSERT INTO visitor_sessions (sessionId,userType,contributorId,firstSeenAt,lastSeenAt,activeSeconds) VALUES (?,?,?,?,?,0)")
          .bind(sessionId, userType, contributorId, nowIso, nowIso).run();
      }
      return jsonResponse({success:true});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // --- Super-Admin-only live stats for the dashboard's Live Status panel.
  // Replaces the hardcoded "Visitors: N/A". "Online now" is a presence
  // window (last 90s), not a total; "Today" counts distinct sessions seen
  // today; time-on-site figures are the real heartbeat-accumulated totals,
  // not estimated from page views. ---
  if(path==='/api/admin/live-stats' && request.method==='GET'){
    try{
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      if(!payload || payload.role!=='SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const cutoffIso = new Date(Date.now()-90*1000).toISOString();
      const onlineNowRow = await d1.prepare("SELECT COUNT(*) as n FROM visitor_sessions WHERE lastSeenAt>=?").bind(cutoffIso).first();
      const contributorsOnlineRow = await d1.prepare("SELECT COUNT(*) as n FROM visitor_sessions WHERE lastSeenAt>=? AND userType='contributor'").bind(cutoffIso).first();
      const todayRow = await d1.prepare("SELECT COUNT(DISTINCT sessionId) as n FROM visitor_sessions WHERE date(lastSeenAt)=date('now')").first();
      const totalRow = await d1.prepare("SELECT COUNT(*) as n, SUM(activeSeconds) as total FROM visitor_sessions").first();
      const totalUsers = (totalRow && totalRow.n) || 0;
      const totalTimeSeconds = (totalRow && totalRow.total) || 0;
      const avgTimeSeconds = totalUsers>0 ? Math.round(totalTimeSeconds/totalUsers) : 0;
      return jsonResponse({success:true, stats:{
        onlineNow: (onlineNowRow&&onlineNowRow.n)||0,
        contributorsOnline: (contributorsOnlineRow&&contributorsOnlineRow.n)||0,
        usersToday: (todayRow&&todayRow.n)||0,
        totalUsers,
        totalTimeSeconds,
        avgTimeSeconds
      }});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // --- A contributor's own submissions and stats. Filtered server-side by their own id only (no IDOR). ---
  if(path==='/api/contributor/my-submissions' && request.method==='GET'){
    try{
      const auth = await requireActiveContributor(request, env);
      if(auth.error) return auth.error;
      const { contributor, d1 } = auth;
      let res;
      try{
        res = await d1.prepare(
          "SELECT id,type,status,timestamp,summary,articleId,reviewReason FROM submissions WHERE userId=? AND userRole='CONTRIBUTOR' ORDER BY timestamp DESC"
        ).bind(contributor.id).all();
      }catch(e){
        // reviewReason column may not exist yet on an older DB - fall back without it
        res = await d1.prepare(
          "SELECT id,type,status,timestamp,summary,articleId FROM submissions WHERE userId=? AND userRole='CONTRIBUTOR' ORDER BY timestamp DESC"
        ).bind(contributor.id).all();
      }
      const rows = res.results || [];
      const stats = { total: rows.length, pending:0, approved:0, rejected:0 };
      rows.forEach(r=>{
        if(r.status==='pending' || r.status==='under_review') stats.pending++;
        else if(r.status==='approved') stats.approved++;
        else if(r.status==='rejected') stats.rejected++;
      });
      return jsonResponse({success:true, submissions:rows, stats});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // --- Suggestions: visitors (no auth) and contributors (auth) both feed the same table ---
  if(path==='/api/suggestions' && request.method==='POST'){
    try{
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const body = await request.json().catch(()=>({}));
      // Simple honeypot: a hidden form field real users never fill in.
      if(body.website) return jsonResponse({success:true}); // pretend success, drop silently
      const content = (body.suggestion||'').toString().trim();
      if(!content) return jsonResponse({success:false,error:'Suggestion text required'},400);
      if(content.length > 4000) return jsonResponse({success:false,error:'Suggestion too long'},400);
      const id = 'sug'+Date.now()+Math.random().toString(36).slice(2,6);
      await d1.prepare(
        "INSERT INTO suggestions (id,source,contributorId,name,email,category,content,sourceRef,status,timestamp) VALUES (?,?,?,?,?,?,?,?,?,?)"
      ).bind(id, 'visitor', null, (body.name||'').toString().slice(0,200), (body.email||'').toString().slice(0,200),
        (body.category||'general').toString().slice(0,100), content, (body.source||'').toString().slice(0,500), 'NEW', new Date().toISOString()).run();
      await logContributorAudit(d1, 'visitor', 'VISITOR', 'suggestion_created', id, '');
      return jsonResponse({success:true, message:'Thank you for your suggestion'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  if(path==='/api/contributor/suggest' && request.method==='POST'){
    try{
      const auth = await requireActiveContributor(request, env);
      if(auth.error) return auth.error;
      const { contributor, d1 } = auth;
      const body = await request.json().catch(()=>({}));
      const content = (body.content||'').toString().trim();
      if(!content) return jsonResponse({success:false,error:'Suggestion text required'},400);
      if(content.length > 4000) return jsonResponse({success:false,error:'Suggestion too long'},400);
      const id = 'sug'+Date.now()+Math.random().toString(36).slice(2,6);
      await d1.prepare(
        "INSERT INTO suggestions (id,source,contributorId,name,email,category,content,sourceRef,status,timestamp) VALUES (?,?,?,?,?,?,?,?,?,?)"
      ).bind(id, 'contributor', contributor.id, contributor.displayName, null,
        (body.category||'general').toString().slice(0,100), content, (body.source||'').toString().slice(0,500), 'NEW', new Date().toISOString()).run();
      await logContributorAudit(d1, contributor.id, 'CONTRIBUTOR', 'suggestion_created', id, '');
      return jsonResponse({success:true, message:'Suggestion submitted'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // --- Super Admin contributor management (all routes SUPER_ADMIN only) ---
  if(path==='/api/admin/contributors' && request.method==='GET'){
    try{
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      if(!payload || payload.role !== 'SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      await expireContributorStatuses(d1);
      const list = await d1.prepare(
        "SELECT id,displayName,country,stateRegion,joinedAt,status,contributionCount,lastActiveAt,statusSince,statusExpiresAt,statusPermanent FROM contributors ORDER BY joinedAt DESC"
      ).all();
      const totalC = await d1.prepare("SELECT COUNT(*) as n FROM contributors").first();
      const activeC = await d1.prepare("SELECT COUNT(*) as n FROM contributors WHERE status='ACTIVE'").first();
      const suspendedC = await d1.prepare("SELECT COUNT(*) as n FROM contributors WHERE status='SUSPENDED'").first();
      const blockedC = await d1.prepare("SELECT COUNT(*) as n FROM contributors WHERE status='BLOCKED'").first();
      const subTotal = await d1.prepare("SELECT COUNT(*) as n FROM submissions WHERE userRole='CONTRIBUTOR'").first();
      const subPending = await d1.prepare("SELECT COUNT(*) as n FROM submissions WHERE userRole='CONTRIBUTOR' AND status='pending'").first();
      const subApproved = await d1.prepare("SELECT COUNT(*) as n FROM submissions WHERE userRole='CONTRIBUTOR' AND status='approved'").first();
      const subRejected = await d1.prepare("SELECT COUNT(*) as n FROM submissions WHERE userRole='CONTRIBUTOR' AND status='rejected'").first();
      return jsonResponse({success:true,
        stats:{
          totalContributors: totalC.n, active: activeC.n, suspended: suspendedC.n, blocked: blockedC.n,
          totalSubmissions: subTotal.n, pending: subPending.n, approved: subApproved.n, rejected: subRejected.n
        },
        contributors: list.results || []
      });
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  if(path==='/api/admin/contributor-profile' && request.method==='GET'){
    try{
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      if(!payload || payload.role !== 'SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      const id = url.searchParams.get('id');
      if(!id) return jsonResponse({success:false,error:'id required'},400);
      await expireContributorStatuses(d1);
      const contributor = await d1.prepare("SELECT * FROM contributors WHERE id=?").bind(id).first();
      if(!contributor) return jsonResponse({success:false,error:'Not found'},404);
      const submissions = await d1.prepare("SELECT id,type,status,timestamp,summary FROM submissions WHERE userId=? ORDER BY timestamp DESC").bind(id).all();
      const suggestions = await d1.prepare("SELECT id,category,content,status,timestamp FROM suggestions WHERE contributorId=? ORDER BY timestamp DESC").bind(id).all();
      // NE MASTER IMPLEMENTATION PASS (correction pass): real, D1-sourced
      // contribution records across every content type that carries creator
      // attribution. Nothing here is invented - a type simply comes back
      // empty if this contributor has no rows in it (e.g. tribes/people/places
      // only carry attribution for records saved after the authorId/authorName
      // columns were added, so older rows correctly show no contributor here).
      let contributions = { articles:[], stories:[], dictionary:[], tribes:[], people:[], places:[], media:[] };
      try{ const r=await d1.prepare("SELECT id,title,state,updatedAt FROM articles WHERE authorId=? ORDER BY updatedAt DESC LIMIT 100").bind(id).all(); contributions.articles=r.results||[]; }catch(e){}
      try{ const r=await d1.prepare("SELECT id,title,state,updatedAt FROM stories WHERE authorId=? ORDER BY updatedAt DESC LIMIT 100").bind(id).all(); contributions.stories=r.results||[]; }catch(e){}
      try{ const r=await d1.prepare("SELECT id,word,meaning,dateAdded FROM dictionary WHERE contributor=? ORDER BY dateAdded DESC LIMIT 100").bind(id).all(); contributions.dictionary=r.results||[]; }catch(e){}
      try{ const r=await d1.prepare("SELECT id,name,state,updatedAt FROM tribes WHERE authorId=? ORDER BY updatedAt DESC LIMIT 100").bind(id).all(); contributions.tribes=r.results||[]; }catch(e){}
      try{ const r=await d1.prepare("SELECT id,name,state,updatedAt FROM people WHERE authorId=? ORDER BY updatedAt DESC LIMIT 100").bind(id).all(); contributions.people=r.results||[]; }catch(e){}
      try{ const r=await d1.prepare("SELECT id,name,state,updatedAt FROM places WHERE authorId=? ORDER BY updatedAt DESC LIMIT 100").bind(id).all(); contributions.places=r.results||[]; }catch(e){}
      try{ const r=await d1.prepare("SELECT id,title,category,updatedAt FROM media WHERE authorId=? ORDER BY updatedAt DESC LIMIT 100").bind(id).all(); contributions.media=r.results||[]; }catch(e){}
      const contributionTotals = Object.fromEntries(Object.entries(contributions).map(([k,v])=>[k,v.length]));
      // Status-change history for this contributor, read from the existing
      // audit log (contributor_audit_logs) - no new table/column added.
      // Counts every time an admin has ever set this contributor to
      // SUSPENDED or BLOCKED, so a past warning still shows even after
      // they've been set back to ACTIVE.
      let statusCounts = { suspended:0, blocked:0 };
      try{
        const suspendedRow = await d1.prepare(
          "SELECT COUNT(*) as n FROM contributor_audit_logs WHERE action='contributor_status_changed' AND affectedRecord=? AND summary='SUSPENDED'"
        ).bind(id).first();
        const blockedRow = await d1.prepare(
          "SELECT COUNT(*) as n FROM contributor_audit_logs WHERE action='contributor_status_changed' AND affectedRecord=? AND summary='BLOCKED'"
        ).bind(id).first();
        statusCounts = { suspended: (suspendedRow&&suspendedRow.n)||0, blocked: (blockedRow&&blockedRow.n)||0 };
      }catch(e){}
      return jsonResponse({success:true, contributor, submissions: submissions.results||[], suggestions: suggestions.results||[], contributions, contributionTotals, statusCounts });
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  if(path==='/api/admin/contributor-status' && request.method==='POST'){
    try{
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      if(!payload || payload.role !== 'SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      const body = await request.json().catch(()=>({}));
      const { contributorId, status, permanent } = body;
      if(!contributorId || !['ACTIVE','SUSPENDED','BLOCKED'].includes(status)) return jsonResponse({success:false,error:'contributorId and valid status required'},400);
      // Suspend = 10-day auto-expiry. Block = 30-day auto-expiry, unless
      // `permanent` is explicitly true, in which case it never auto-expires
      // and only a manual Unblock (status=ACTIVE) clears it. Setting ACTIVE
      // (manual Unsuspend/Unblock, or the auto-expiry sweep) always clears
      // all three restriction fields back to their unrestricted state.
      // The audit summary stays exactly 'SUSPENDED'/'BLOCKED'/'ACTIVE' - no
      // suffix for permanent - so the existing "Suspended X times / Blocked
      // X times" counters (which count on those exact summary values) keep
      // working unchanged and are not duplicated by this feature.
      const nowIso = new Date().toISOString();
      let statusSince = null, statusExpiresAt = null, statusPermanent = 0;
      if(status === 'SUSPENDED'){
        statusSince = nowIso;
        statusExpiresAt = new Date(Date.now() + 10*24*60*60*1000).toISOString();
      } else if(status === 'BLOCKED'){
        statusSince = nowIso;
        statusPermanent = permanent === true ? 1 : 0;
        statusExpiresAt = statusPermanent ? null : new Date(Date.now() + 30*24*60*60*1000).toISOString();
      }
      await d1.prepare(
        "UPDATE contributors SET status=?, statusSince=?, statusExpiresAt=?, statusPermanent=? WHERE id=?"
      ).bind(status, statusSince, statusExpiresAt, statusPermanent, contributorId).run();
      await logContributorAudit(d1, payload.username||'SUPER_ADMIN', 'SUPER_ADMIN', 'contributor_status_changed', contributorId, status);
      return jsonResponse({success:true, message:'Status updated'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  if(path==='/api/admin/suggestions' && request.method==='GET'){
    try{
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      if(!payload || payload.role !== 'SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      const res = await d1.prepare("SELECT * FROM suggestions ORDER BY timestamp DESC").all();
      const suggestions = res.results || [];
      const unreadCount = suggestions.filter(s=>s.status==='NEW').length;
      return jsonResponse({success:true, suggestions, unreadCount});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/admin/suggestions/read' && request.method==='POST'){
    try{
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      if(!payload || payload.role !== 'SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      const body = await request.json().catch(()=>({}));
      if(!body.id) return jsonResponse({success:false,error:'Suggestion id required'},400);
      await d1.prepare("UPDATE suggestions SET status='READ' WHERE id=?").bind(body.id).run();
      return jsonResponse({success:true, message:'Marked as read'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/admin/suggestions/delete' && request.method==='POST'){
    try{
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      if(!payload || payload.role !== 'SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      const body = await request.json().catch(()=>({}));
      if(!body.id) return jsonResponse({success:false,error:'Suggestion id required'},400);
      await d1.prepare("DELETE FROM suggestions WHERE id=?").bind(body.id).run();
      return jsonResponse({success:true, message:'Suggestion deleted'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // --- MILESTONE 1: Categories (additive; does not touch homepage rendering) ---
  // NE MASTER IMPLEMENTATION PASS: helper to compute real, D1-derived content
  // counts per category name. Counts are calculated from existing records
  // (articles.categories JSON array) rather than a new denormalized table,
  // per "do not add unnecessary denormalized tables unless needed."
  async function computeCategoryContentCounts(d1){
    const counts = {};
    try{
      const arts = await d1.prepare("SELECT categories FROM articles").all();
      for(const row of (arts.results||[])){
        let cats = [];
        try{ cats = JSON.parse(row.categories||'[]'); }catch{}
        if(!Array.isArray(cats)) continue;
        for(const c of cats){ if(!c) continue; counts[c] = (counts[c]||0)+1; }
      }
    }catch(e){}
    // Tribes & Communities and Tribal Dictionary map onto whole tables, not a
    // tag field - report those two directly from real row counts as well.
    try{
      const t = await d1.prepare("SELECT COUNT(*) as n FROM tribes").first();
      if(t) counts['Tribes & Communities'] = (counts['Tribes & Communities']||0) + t.n;
    }catch(e){}
    try{
      const w = await d1.prepare("SELECT COUNT(*) as n FROM dictionary").first();
      if(w) counts['Tribal Dictionary'] = (counts['Tribal Dictionary']||0) + w.n;
    }catch(e){}
    return counts;
  }
  if(path==='/api/d1/categories' && request.method==='GET'){
    try{
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const res = await d1.prepare("SELECT * FROM categories WHERE isHidden=0 AND (isActive IS NULL OR isActive=1) ORDER BY masterOrder ASC").all();
      const withCounts = url.searchParams.get('counts')==='1';
      let categories = res.results || [];
      if(withCounts){
        const counts = await computeCategoryContentCounts(d1);
        categories = categories.map(c=>({...c, contentCount: counts[c.name]||0}));
      }
      return jsonResponse({success:true, categories});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/admin/categories' && request.method==='GET'){
    try{
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      if(!payload || payload.role !== 'SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const res = await d1.prepare("SELECT * FROM categories ORDER BY masterOrder ASC").all();
      const counts = await computeCategoryContentCounts(d1);
      const categories = (res.results||[]).map(c=>({...c, contentCount: counts[c.name]||0}));
      return jsonResponse({success:true, categories});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/admin/categories/save' && request.method==='POST'){
    try{
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      if(!payload || payload.role !== 'SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const body = await request.json().catch(()=>({}));
      const c = body.category;
      if(!c || !c.name) return jsonResponse({success:false,error:'Category name required'},400);
      const id = c.id || ('cat'+Date.now()+Math.random().toString(36).slice(2,6));
      const existing = c.id ? await d1.prepare("SELECT id FROM categories WHERE id=?").bind(c.id).first() : null;
      // Duplicate-name guard only when creating a brand new category (not when editing an existing one).
      if(!existing){
        const dup = await d1.prepare("SELECT id FROM categories WHERE name=?").bind(c.name).first();
        if(dup) return jsonResponse({success:false,error:'A category with this name already exists'},409);
      }
      await d1.prepare(
        "INSERT OR REPLACE INTO categories (id,name,masterOrder,inQuickAccess,quickAccessLabel,quickAccessOrder,isHidden,description,isActive,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        id, c.name, c.masterOrder ?? null, c.inQuickAccess?1:0, c.quickAccessLabel||null, c.quickAccessOrder ?? null,
        c.isHidden?1:0, c.description||null, (c.isActive===false||c.isActive===0)?0:1,
        existing? (c.createdAt||new Date().toISOString()) : new Date().toISOString(), new Date().toISOString()
      ).run();
      return jsonResponse({success:true, id, message: existing?'Category updated':'Category created'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  // Safe deletion: only allowed when the category has zero associated content
  // (per real D1 counts), otherwise the caller is told to hide/deactivate
  // instead - per "do not permanently delete a category if doing so could
  // orphan existing content."
  if(path==='/api/admin/categories/delete' && request.method==='POST'){
    try{
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      if(!payload || payload.role !== 'SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const body = await request.json().catch(()=>({}));
      if(!body.id) return jsonResponse({success:false,error:'Category id required'},400);
      const cat = await d1.prepare("SELECT * FROM categories WHERE id=?").bind(body.id).first();
      if(!cat) return jsonResponse({success:false,error:'Category not found'},404);
      const counts = await computeCategoryContentCounts(d1);
      const n = counts[cat.name]||0;
      if(n > 0) return jsonResponse({success:false,error:`Cannot delete: ${n} content item(s) reference "${cat.name}". Hide or deactivate it instead.`},409);
      await d1.prepare("DELETE FROM categories WHERE id=?").bind(body.id).run();
      return jsonResponse({success:true,message:'Category deleted (had no associated content)'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/admin/categories/reorder' && request.method==='POST'){
    try{
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      if(!payload || payload.role !== 'SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const body = await request.json().catch(()=>({}));
      const updates = Array.isArray(body.updates) ? body.updates : [];
      if(updates.length===0) return jsonResponse({success:false,error:'No updates provided'},400);
      for(const u of updates){
        if(!u.id) continue;
        if(typeof u.masterOrder === 'number'){
          await d1.prepare("UPDATE categories SET masterOrder=?, updatedAt=? WHERE id=?").bind(u.masterOrder, new Date().toISOString(), u.id).run();
        }
        if(typeof u.quickAccessOrder === 'number'){
          await d1.prepare("UPDATE categories SET quickAccessOrder=?, updatedAt=? WHERE id=?").bind(u.quickAccessOrder, new Date().toISOString(), u.id).run();
        }
      }
      return jsonResponse({success:true, message:'Order updated', count: updates.length});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/admin/categories/seed' && request.method==='POST'){
    try{
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      if(!payload || payload.role !== 'SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);

      // Exact, verified source — 67 master categories, each with its confirmed order.
      // "Explore 8 States" deliberately excluded (not a real category).
      const masterList = ["History & Heritage","States & Districts","Tribes & Communities","Cities & Towns","Tourist Spots & Places","Nature & Wildlife","Culture & Traditions","Languages & Local Dialects","Tribal Dictionary","Food & Cuisine","Festivals & Celebrations","Traditional Clothing","Arts & Crafts","Music & Songs","Dance & Performing Arts","Villages & Communities","People of Northeast India","Stories & Oral Traditions","Historical Places","Mountains & Valleys","Rivers & Lakes","Forests & Biodiversity","Traditional Houses","Handloom & Weaving","Traditional Skills","Agriculture & Farming","Business & Local Economy","Community Photos","Videos & Media","Community Contributions","Religion & Spiritual Heritage","Churches & Christian Heritage","Religious Heritage","Indigenous Knowledge","Medicinal Plants","Traditional Medicine","Traditional Sports","Modern Sports","Martial Arts","Education & Institutions","Science & Innovation","Local Inventions","Railways & Transport","Roads & Travel","Airports & Aviation","Healthcare","Important Institutions","Monuments & Memorials","Historical Conflicts","Peace & Community History","Historical Leaders","Artists & Creators","Writers & Poets","Film & Cinema","Radio & Broadcasting","Local Media","Historical Documents","Proverbs & Sayings","Scripts & Writing Systems","Digital Northeast","Local Businesses","Markets & Handicrafts","Local Economy","Traditional Farming","Fishing & Aquaculture","Protected Areas","Birds"];
      if(masterList.length !== 67) return jsonResponse({success:false,error:'Seed source mismatch: expected 67 master categories, found '+masterList.length+'. Stopping without seeding.'},500);

      // Quick-access 17-box list: [name, label-if-different, quickAccessOrder]. "Explore 8 States" excluded.
      const quickAccess = [
        ["Cities & Towns", null, 1],
        ["Tourist Spots & Places", "Tourist Spot and Places", 2],
        ["Tribes & Communities", null, 3],
        ["Food & Cuisine", "Food", 4],
        ["Traditional Clothing", null, 5],
        ["Festivals & Celebrations", "Festival", 6],
        ["Arts & Crafts", "Arts & Craft", 7],
        ["Handloom & Weaving", "Handloom & Weavers", 8],
        ["Music & Songs", "Music and Songs", 9],
        ["Rivers & Lakes", "Rivers & Lake", 10],
        ["Modern Sports", null, 11],
        ["Science & Innovation", null, 12],
        ["Traditional Houses", "Tradition Houses", 13],
        ["Mountains & Valleys", "Mountain & Valley", 14],
        ["Northeast Fashion", null, 15],
        ["Northeast Beauties", null, 16]
      ];
      const quickAccessMap = {};
      quickAccess.forEach(([name,label,order])=>{ quickAccessMap[name] = {label, order}; });

      // Full genuine set = 67 master + the 2 not already in it (Northeast Fashion, Northeast Beauties)
      const fullNameList = [...masterList];
      ["Northeast Fashion","Northeast Beauties"].forEach(n=>{ if(!fullNameList.includes(n)) fullNameList.push(n); });
      if(fullNameList.length !== 69) return jsonResponse({success:false,error:'Seed source mismatch: expected 69 genuine categories total, computed '+fullNameList.length+'. Stopping without seeding.'},500);

      // Duplicate check within source itself
      const seen = {};
      const duplicatesInSource = [];
      fullNameList.forEach(n=>{ seen[n]=(seen[n]||0)+1; });
      Object.keys(seen).forEach(n=>{ if(seen[n]>1) duplicatesInSource.push(n); });

      let insertedCount = 0, skippedCount = 0;
      const now = new Date().toISOString();
      for(let i=0;i<fullNameList.length;i++){
        const name = fullNameList[i];
        const existing = await d1.prepare("SELECT id FROM categories WHERE name=?").bind(name).first();
        if(existing){ skippedCount++; continue; }
        const qa = quickAccessMap[name];
        const id = 'cat'+Date.now()+Math.random().toString(36).slice(2,6)+i;
        await d1.prepare(
          "INSERT INTO categories (id,name,masterOrder,inQuickAccess,quickAccessLabel,quickAccessOrder,isHidden,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?,?,?)"
        ).bind(
          id, name, i+1, qa?1:0, qa?(qa.label||null):null, qa?qa.order:null, 0, now, now
        ).run();
        insertedCount++;
      }
      const finalCount = await d1.prepare("SELECT COUNT(*) as c FROM categories").first();
      return jsonResponse({
        success:true,
        insertedCount, skippedCount,
        duplicatesInSource,
        finalDatabaseCount: finalCount ? finalCount.c : null,
        expectedGenuineCount: 69
      });
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  if(path==='/api/admin/audit-log' && request.method==='GET'){
    try{
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      if(!payload || payload.role !== 'SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      const res = await d1.prepare("SELECT * FROM contributor_audit_logs ORDER BY timestamp DESC LIMIT 200").all();
      return jsonResponse({success:true, logs: res.results || []});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // --- NE MASTER IMPLEMENTATION PASS: Global Search (SUPER_ADMIN, reads D1 only) ---
  if(path==='/api/admin/search' && request.method==='GET'){
    try{
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      if(!payload || payload.role !== 'SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const q = (url.searchParams.get('q')||'').trim();
      if(!q) return jsonResponse({success:true, results:[], query:''});
      const like = '%'+q+'%';
      const results = [];
      const push = (type, rows, mapFn) => { for(const r of (rows||[])) results.push({type, ...mapFn(r)}); };
      try{ const r=await d1.prepare("SELECT id,title,state,authorName FROM articles WHERE title LIKE ? OR intro LIKE ? LIMIT 15").bind(like,like).all(); push('article', r.results, x=>({id:x.id,label:x.title,sub:x.state,creator:x.authorName})); }catch(e){}
      try{ const r=await d1.prepare("SELECT id,title,state,authorName FROM stories WHERE title LIKE ? OR intro LIKE ? LIMIT 15").bind(like,like).all(); push('story', r.results, x=>({id:x.id,label:x.title,sub:x.state,creator:x.authorName})); }catch(e){}
      try{ const r=await d1.prepare("SELECT id,word,meaning,contributor FROM dictionary WHERE word LIKE ? OR meaning LIKE ? LIMIT 15").bind(like,like).all(); push('dictionary', r.results, x=>({id:x.id,label:x.word,sub:x.meaning,creator:x.contributor})); }catch(e){}
      try{ const r=await d1.prepare("SELECT id,name,state,authorName FROM tribes WHERE name LIKE ? LIMIT 15").bind(like).all(); push('tribe', r.results, x=>({id:x.id,label:x.name,sub:x.state,creator:x.authorName})); }catch(e){}
      try{ const r=await d1.prepare("SELECT id,name,state,authorName FROM people WHERE name LIKE ? LIMIT 15").bind(like).all(); push('person', r.results, x=>({id:x.id,label:x.name,sub:x.state,creator:x.authorName})); }catch(e){}
      try{ const r=await d1.prepare("SELECT id,name,state,authorName FROM places WHERE name LIKE ? LIMIT 15").bind(like).all(); push('place', r.results, x=>({id:x.id,label:x.name,sub:x.state,creator:x.authorName})); }catch(e){}
      try{ const r=await d1.prepare("SELECT id,title,category,authorName FROM media WHERE title LIKE ? LIMIT 15").bind(like).all(); push('photo', r.results, x=>({id:x.id,label:x.title,sub:x.category,creator:x.authorName})); }catch(e){}
      try{ const r=await d1.prepare("SELECT id,name,description FROM categories WHERE name LIKE ? LIMIT 15").bind(like).all(); push('category', r.results, x=>({id:x.id,label:x.name,sub:x.description||''})); }catch(e){}
      try{ const r=await d1.prepare("SELECT id,displayName,email,status FROM contributors WHERE displayName LIKE ? OR email LIKE ? LIMIT 15").bind(like,like).all(); push('contributor', r.results, x=>({id:x.id,label:x.displayName,sub:x.status,creator:null})); }catch(e){}
      return jsonResponse({success:true, results, query:q, count:results.length});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // --- NE MASTER IMPLEMENTATION PASS: Settings (D1-backed key/value store) ---
  // Public GET returns only the small set of settings the public site needs
  // (siteTitle, adsEnabled) so this never leaks admin-only data. Full admin
  // GET/SAVE requires SUPER_ADMIN, matching every other admin route here.
  const NE_PUBLIC_SETTING_KEYS = ['siteTitle','adsEnabled','publicHomeDesign'];
  if(path==='/api/d1/settings' && request.method==='GET'){
    try{
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},503);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const res = await d1.prepare("SELECT key,value FROM settings").all();
      const out = {};
      for(const row of (res.results||[])){
        if(NE_PUBLIC_SETTING_KEYS.includes(row.key)){
          try{ out[row.key] = JSON.parse(row.value); }catch{ out[row.key] = row.value; }
        }
      }
      return jsonResponse({success:true, settings: out});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/admin/settings' && request.method==='GET'){
    try{
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      if(!payload || payload.role !== 'SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const res = await d1.prepare("SELECT * FROM settings").all();
      const out = {};
      for(const row of (res.results||[])){
        try{ out[row.key] = JSON.parse(row.value); }catch{ out[row.key] = row.value; }
      }
      return jsonResponse({success:true, settings: out});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/admin/settings/save' && request.method==='POST'){
    try{
      const token = getTokenFromRequest(request);
      const payload = token ? await verifyJWT(token, getJwtSecret(env), env) : null;
      if(!payload || payload.role !== 'SUPER_ADMIN') return jsonResponse({success:false,error:'SUPER_ADMIN only'},403);
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},500);
      const d1 = env.NE_ENCYCLOPEDIA_D1;
      await initD1Tables(d1);
      const body = await request.json().catch(()=>({}));
      const updates = body.settings && typeof body.settings==='object' ? body.settings : null;
      if(!updates) return jsonResponse({success:false,error:'settings object required'},400);
      const now = new Date().toISOString();
      for(const key of Object.keys(updates)){
        await d1.prepare("INSERT OR REPLACE INTO settings (key,value,updatedAt,updatedBy) VALUES (?,?,?,?)")
          .bind(key, JSON.stringify(updates[key]), now, payload.username||'SUPER_ADMIN').run();
      }
      // Stage 2 v1 safety correction: whenever studioConfig is saved, derive a
      // narrow, public-safe projection (active design only — no notes, no
      // inactive designs, no customSections/globalFeatures) and store it
      // under its own settings key. This is the ONLY key exposed publicly
      // for homepage rendering; the full studioConfig stays admin-only.
      if(Object.prototype.hasOwnProperty.call(updates,'studioConfig')){
        let pub = null;
        try{
          const sc = updates.studioConfig;
          const hd = sc && sc.homepageDesigns;
          if(hd && Array.isArray(hd.designs) && hd.activeDesignId){
            const active = hd.designs.find((d)=>d && d.id===hd.activeDesignId);
            if(active && typeof active==='object'){
              const NE_SHAPES=['round','oval','rectangle','square','none']; // round 8: "none" = "No Box" (transparent background)
              const NE_SIZES=['smaller','standard','medium','large','custom'];
              const NE_ORIENTS=['vertical','horizontal','swipe'];
              const NE_FONT_SIZES=['small','standard','medium','large','custom'];
              const NE_SECTION_COLOR_KEYS=['indigo','deepIndigo','teal','saffron','deepOrange','purple','red','blue','yellow','green','orange','pink','brown','black','white','grey','cyan','custom'];
              // Round 9: Font Family -- same curated 21-entry allowlist as
              // the client's NE_FONT_FAMILIES (keys only; labels/CSS
              // font-family strings are looked up client-side, never
              // trusted from a saved value).
              // Round 12: 13 more curated fonts added client-side (see
              // NE_FONT_FAMILIES) -- mirrored here so a save actually keeps
              // them instead of being silently stripped by this allowlist.
              const NE_FONT_FAMILY_KEYS=['inter','fraunces','roboto','openSans','lato','poppins','montserrat','nunito','workSans','rubik','manrope','merriweather','playfairDisplay','lora','ptSerif','sourceSerif4','oswald','bebasNeue','raleway','jetbrainsMono','spaceMono','greatVibes','lobster','dancingScript','pacifico','parisienne','sacramento','allura','cookie','grandHotel','rochester','berkshireSwash','leckerliOne','questrial'];
              pub = {
                activeDesignId: hd.activeDesignId,
                sections: Array.isArray(active.sections) ? active.sections : [],
                categoryDisplayCount: (active.categoryDisplayCount==='all'||typeof active.categoryDisplayCount==='number') ? active.categoryDisplayCount : null,
                categoryShape: (typeof active.categoryShape==='string' && NE_SHAPES.includes(active.categoryShape)) ? active.categoryShape : null,
                categorySize: (typeof active.categorySize==='string' && NE_SIZES.includes(active.categorySize)) ? active.categorySize : null,
                categorySizeCustom: (active.categorySize==='custom' && active.categorySizeCustom && typeof active.categorySizeCustom==='object') ? {
                  height: typeof active.categorySizeCustom.height==='number' ? active.categorySizeCustom.height : null,
                  fontSize: typeof active.categorySizeCustom.fontSize==='number' ? active.categorySizeCustom.fontSize : null
                } : null,
                categoryOrientation: (typeof active.categoryOrientation==='string' && NE_ORIENTS.includes(active.categoryOrientation)) ? active.categoryOrientation : null,
                // Round 4: Super Admin category-selection system for Quick
                // Categories. Only an array of plain id strings is ever
                // carried into the public projection — never category
                // objects, names, or any other field — same narrowing
                // discipline as every other field derived here. Capped
                // defensively; real category counts are nowhere near this.
                categorySelectedIds: Array.isArray(active.categorySelectedIds)
                  ? active.categorySelectedIds.filter((x)=>typeof x==='string' && x.length>0 && x.length<=200).slice(0,2000)
                  : [],
                // Round 5: independent per-section Shape/Size/Orientation.
                // Round 6: extended to ALL 7 homepage sections (not just the
                // 3 category-tile ones), plus two new fields — Font Size and
                // Colour. Only the 7 known section keys, and only
                // shape/size/sizeCustom/orientation/fontSize/fontSizeCustom/
                // color/colorCustom, are ever carried through — same
                // narrowing discipline as the shared fields above, plus a
                // strict hex-format check for the custom colour so nothing
                // but a validated #rrggbb string can ever reach a style
                // attribute. A design saved before round 5 has no
                // sectionVisuals at all, so this is safely {} and every
                // section falls back to its own existing default appearance,
                // exactly as before.
                sectionVisuals: (()=>{
                  const rawSV = active.sectionVisuals && typeof active.sectionVisuals==='object' ? active.sectionVisuals : {};
                  const outSV = {};
                  // Round 13: 5 new "Title" keys added (headerLogo, heroTitle,
                  // featuredHeading, exploreByTopicHeading,
                  // allCategoriesHeading) -- same class of bug as the
                  // donateColor fix in Round 12: without adding these here,
                  // any Title Colour/Font Size/Font Style data saved under
                  // these keys would be silently stripped on every save.
                  // Round 14: 'footer' added the same way (Colour/Font
                  // Colour/Font Size/Font Family+Bold+Italic+Underline/
                  // Letter Spacing/Text Align). Every field below is
                  // validated the exact same way regardless of which key
                  // it's attached to.
                  ['hero','quickActions','dailyNews','quickCategories','featured','exploreByTopic','allCategories','headerLogo','heroTitle','featuredHeading','exploreByTopicHeading','allCategoriesHeading','footer'].forEach((key)=>{
                    const sv = rawSV[key];
                    if(!sv || typeof sv!=='object') return;
                    const clean = {};
                    if(typeof sv.shape==='string' && NE_SHAPES.includes(sv.shape)) clean.shape = sv.shape;
                    if(typeof sv.size==='string' && NE_SIZES.includes(sv.size)) clean.size = sv.size;
                    if(sv.size==='custom' && sv.sizeCustom && typeof sv.sizeCustom==='object'){
                      clean.sizeCustom = {
                        height: typeof sv.sizeCustom.height==='number' ? sv.sizeCustom.height : null,
                        fontSize: typeof sv.sizeCustom.fontSize==='number' ? sv.sizeCustom.fontSize : null
                      };
                    }
                    if(typeof sv.orientation==='string' && NE_ORIENTS.includes(sv.orientation)) clean.orientation = sv.orientation;
                    if(typeof sv.fontSize==='string' && NE_FONT_SIZES.includes(sv.fontSize)) clean.fontSize = sv.fontSize;
                    if(sv.fontSize==='custom' && sv.fontSizeCustom && typeof sv.fontSizeCustom==='object'){
                      clean.fontSizeCustom = {
                        fontSize: typeof sv.fontSizeCustom.fontSize==='number' ? sv.fontSizeCustom.fontSize : null
                      };
                    }
                    if(typeof sv.color==='string' && NE_SECTION_COLOR_KEYS.includes(sv.color)) clean.color = sv.color;
                    if(sv.color==='custom' && typeof sv.colorCustom==='string' && /^#[0-9a-fA-F]{6}$/.test(sv.colorCustom)) clean.colorCustom = sv.colorCustom;
                    // Round 8d: Font Colour -- independent from the background
                    // Colour above, same validated palette/hex allowlist.
                    if(typeof sv.fontColor==='string' && NE_SECTION_COLOR_KEYS.includes(sv.fontColor)) clean.fontColor = sv.fontColor;
                    if(sv.fontColor==='custom' && typeof sv.fontColorCustom==='string' && /^#[0-9a-fA-F]{6}$/.test(sv.fontColorCustom)) clean.fontColorCustom = sv.fontColorCustom;
                    // Round 12: Donate button colour -- only ever meaningful
                    // on the 'hero' key (the only Donate button site-wide),
                    // but validated the same way regardless of key so a
                    // stray value elsewhere is just as safely narrowed.
                    if(typeof sv.donateColor==='string' && NE_SECTION_COLOR_KEYS.includes(sv.donateColor)) clean.donateColor = sv.donateColor;
                    if(sv.donateColor==='custom' && typeof sv.donateColorCustom==='string' && /^#[0-9a-fA-F]{6}$/.test(sv.donateColorCustom)) clean.donateColorCustom = sv.donateColorCustom;
                    // Round 8: per-section Width % (1-100). Shrinks & centers
                    // the WHOLE section (every tile/row/box inside it
                    // together, via its existing order-style wrapper),
                    // independent of shape/size/colour.
                    if(typeof sv.widthPercent==='number' && sv.widthPercent>=1 && sv.widthPercent<=100) clean.widthPercent = sv.widthPercent;
                    // Round 9: Font Family + text styling (Bold/Italic/
                    // Underline/Letter Spacing/Text Align) + Columns, same
                    // narrowing discipline as every field above -- only a
                    // known key, the literal 'on', a number in a bounded
                    // range, or one of 3 alignment strings ever passes
                    // through.
                    if(typeof sv.fontFamily==='string' && NE_FONT_FAMILY_KEYS.includes(sv.fontFamily)) clean.fontFamily = sv.fontFamily;
                    if(sv.bold==='on') clean.bold = 'on';
                    if(sv.italic==='on') clean.italic = 'on';
                    if(sv.underline==='on') clean.underline = 'on';
                    if(typeof sv.letterSpacing==='number' && sv.letterSpacing>=-5 && sv.letterSpacing<=20) clean.letterSpacing = sv.letterSpacing;
                    if(typeof sv.textAlign==='string' && (sv.textAlign==='left'||sv.textAlign==='center'||sv.textAlign==='right')) clean.textAlign = sv.textAlign;
                    if(typeof sv.columns==='number' && Number.isInteger(sv.columns) && sv.columns>=1 && sv.columns<=6) clean.columns = sv.columns;
                    if(Object.keys(clean).length>0) outSV[key] = clean;
                  });
                  return outSV;
                })(),
                // Round 8: page-wide background colour -- a design-level
                // field (not per-section), reusing the same colour system
                // (18 named colours + validated custom hex) as every
                // per-section Colour control.
                pageBackgroundColor: (typeof active.pageBackgroundColor==='string' && NE_SECTION_COLOR_KEYS.includes(active.pageBackgroundColor)) ? active.pageBackgroundColor : null,
                pageBackgroundColorCustom: (active.pageBackgroundColor==='custom' && typeof active.pageBackgroundColorCustom==='string' && /^#[0-9a-fA-F]{6}$/.test(active.pageBackgroundColorCustom)) ? active.pageBackgroundColorCustom : null
              };
            }
          }
        }catch(err){ pub = null; }
        await d1.prepare("INSERT OR REPLACE INTO settings (key,value,updatedAt,updatedBy) VALUES (?,?,?,?)")
          .bind('publicHomeDesign', JSON.stringify(pub), now, payload.username||'SUPER_ADMIN').run();
      }
      return jsonResponse({success:true, message:'Settings saved to D1'});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }

  // ================= END NE CONTRIBUTOR V1 =================

  if(path==='/api/login' && request.method==='POST'){
    try{
      const body=await request.json().catch(()=>({}));
      const username=(body.username||'').toString().trim().toLowerCase();
      const password=(body.password||'').toString();
      if(!username || !password){
        return jsonResponse({success:false,error:'Username and password required'},400);
      }
      if(username!=='benjamin'){
        // Keep same error message to avoid user enumeration but still check KV
        // We only support benjamin for super admin as per requirement
      }
      const key='user_'+username;
      let userStr=null;
      try{ userStr=await env.NE_USERS_KV.get(key); }catch(e){ return jsonResponse({success:false,error:'KV binding error: '+e.message},500); }
      if(!userStr){
        // Do NOT recreate user - requirement 5
        return jsonResponse({success:false,error:'Invalid credentials'},401);
      }
      let user;
      try{ user=JSON.parse(userStr); }catch{ return jsonResponse({success:false,error:'Corrupted user record. Use /api/reset-benjamin with SETUP_TOKEN to recover.'},500); }
      const salt=getSalt(env);
      const computedHash=await pbkdf2Hash(password, salt);
      const storedHash=user.passwordHash || user.hash;
      if(!storedHash || computedHash!==storedHash){
        return jsonResponse({success:false,error:'Invalid credentials'},401);
      }
      // Generate fresh JWT using SAME env.JWT_SECRET as change-password
      const secret=getJwtSecret(env);
      if(!secret){
        return jsonResponse({success:false,error:'JWT secret not configured'},500);
      }
      const payload={
        username: user.username,
        role: user.role || 'SUPER_ADMIN',
        displayName: user.displayName || 'Ben Yanthan',
        tokenVersion: typeof user.tokenVersion==='number' ? user.tokenVersion : 0,
        iat: Math.floor(Date.now()/1000),
        exp: Math.floor(Date.now()/1000)+7*24*3600
      };
      const token=await signJWT(payload, secret);
      // Return JSON - NOT homepage HTML - requirement N
      return new Response(JSON.stringify({success:true, token, user:{username:payload.username, displayName:payload.displayName, role:payload.role}}),{
        headers:{
          'Content-Type':'application/json',
          'Access-Control-Allow-Origin':'*',
          'Set-Cookie': `ne_token=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7*24*3600}`,
          'Cache-Control':'no-store'
        }
      });
    }catch(e){
      return jsonResponse({success:false,error:'Login error: '+e.message},500);
    }
  }

  // --- CHANGE PASSWORD: verifies against same record + same PBKDF2 ---
  if(path==='/api/change-password' && request.method==='POST'){
    try{
      const token=getTokenFromRequest(request);
      if(!token){
        return jsonResponse({success:false,error:'Not authenticated - no token. Please login again.'},401);
      }
      const secret=getJwtSecret(env);
      const payload=await verifyJWT(token, secret, env);
      if(!payload){
        return jsonResponse({success:false,error:'Invalid or expired token. Please login again.'},401);
      }
      const body=await request.json().catch(()=>({}));
      const currentPassword=(body.currentPassword||'').toString();
      const newPassword=(body.newPassword||'').toString();
      if(!currentPassword || !newPassword){
        return jsonResponse({success:false,error:'Current and new password required'},400);
      }
      if(newPassword.length<8){
        return jsonResponse({success:false,error:'New password must be at least 8 characters'},400);
      }
      const key='user_'+payload.username.toLowerCase();
      const userStr=await env.NE_USERS_KV.get(key);
      if(!userStr){
        return jsonResponse({success:false,error:'User not found'},404);
      }
      const user=JSON.parse(userStr);
      const salt=getSalt(env);
      const curHashed=await pbkdf2Hash(currentPassword, salt);
      const storedHash=user.passwordHash || user.hash;
      if(curHashed!==storedHash){
        return jsonResponse({success:false,error:'Current password is incorrect'},400);
      }
      const newHashed=await pbkdf2Hash(newPassword, salt);
      user.passwordHash=newHashed;
      user.hash=newHashed;
      user.saltVersion='pbkdf2-100k-sha256';
      user.tokenVersion=(typeof user.tokenVersion==='number' ? user.tokenVersion+1 : 1);
      user.updatedAt=Date.now();
      await env.NE_USERS_KV.put(key, JSON.stringify(user));
      return jsonResponse({success:true,message:'Password changed successfully - old password no longer works. Please login again with new password.'});
    }catch(e){
      return jsonResponse({success:false,error:'Change password error: '+e.message},500);
    }
  }

  // All other routes -> static assets (index.html, setup.html etc unchanged)
    try{
    if(env && env.ASSETS && env.ASSETS.fetch){
      return await fetchAssetWithWrapperFallback(request, env);
    }
  }catch(e){}
  try{
    return await fetch(request);
  }catch(e){
    return new Response('Asset not found', {status:404, headers:{'Content-Type':'text/plain'}});
  }
 }
}
