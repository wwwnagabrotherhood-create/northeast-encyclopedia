
// V26 WRAPPER TOLERANCE - ASSETS ONLY, NOT FOR /api/*
// Handles mobile desktop-site uploads that create wrapper folders like MyFiles/1000174040
async function fetchAssetWithWrapperFallback(request, env) {
  try {
    let res = await env.ASSETS.fetch(request);
    if (res.status !== 404) return res;
  } catch(e) {}
  
  const url = new URL(request.url);
  const path = url.pathname;
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
  // If still not found and root, try original ASSETS again
  try {
    return await env.ASSETS.fetch(request);
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

// Verifies a Google Identity Services ID token entirely server-side against
// Google's published public keys. No client secret is needed for this flow -
// only the (public) Client ID, checked against the token's `aud` claim.
async function verifyGoogleIdToken(idToken, expectedClientId){
  try{
    if(!idToken || typeof idToken !== 'string') return null;
    const parts = idToken.split('.');
    if(parts.length !== 3) return null;
    const [h, p, s] = parts;

    const headerStr = b64urlDecode(h);
    const payloadStr = b64urlDecode(p);
    if(!headerStr || !payloadStr) return null;
    const header = JSON.parse(headerStr);
    const payload = JSON.parse(payloadStr);

    if(header.alg !== 'RS256') return null;

    // Basic claim checks before doing any network/crypto work
    if(!payload.exp || Date.now()/1000 > payload.exp) return null;
    if(payload.aud !== expectedClientId) return null;
    if(payload.iss !== 'accounts.google.com' && payload.iss !== 'https://accounts.google.com') return null;
    if(payload.email_verified === false) return null;
    if(!payload.sub) return null;

    // Fetch Google's current public keys and find the one matching this token's kid
    const jwksRes = await fetch('https://www.googleapis.com/oauth2/v3/certs');
    if(!jwksRes.ok) return null;
    const jwks = await jwksRes.json();
    const jwk = (jwks.keys||[]).find(k => k.kid === header.kid);
    if(!jwk) return null;

    const key = await crypto.subtle.importKey(
      'jwk', jwk, {name:'RSASSA-PKCS1-v1_5', hash:'SHA-256'}, false, ['verify']
    );
    const signedData = new TextEncoder().encode(h+'.'+p);
    const sigBytes = b64urlDecodeToBytes(s);
    const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sigBytes, signedData);
    if(!valid) return null;

    return payload; // contains sub, email, name, picture, email_verified, etc.
  }catch(e){ return null; }
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
ALTER TABLE submissions ADD COLUMN reviewReason TEXT;
`.split(';');
    for(let stmt of statements){
      stmt = stmt.trim();
      if(!stmt) continue;
      try{ await d1.exec(stmt); }catch(e){}
    }
    return true;
  }catch(e){ return false; }
}

async function d1GetAllData(env){
  if(!env.NE_ENCYCLOPEDIA_D1) return null;
  const d1 = env.NE_ENCYCLOPEDIA_D1;
  try{
    await initD1Tables(d1);
    const articles = await d1.prepare("SELECT * FROM articles ORDER BY updatedAt DESC").all();
    const tribes = await d1.prepare("SELECT * FROM tribes ORDER BY name ASC").all();
    const people = await d1.prepare("SELECT * FROM people ORDER BY name ASC").all();
    const places = await d1.prepare("SELECT * FROM places ORDER BY name ASC").all();
    const dict = await d1.prepare("SELECT * FROM dictionary ORDER BY word ASC").all();
    const stories = await d1.prepare("SELECT * FROM stories ORDER BY updatedAt DESC").all();
    const submissions = await d1.prepare("SELECT * FROM submissions WHERE status='pending' ORDER BY timestamp DESC").all();
    const revisions = await d1.prepare("SELECT * FROM revisions ORDER BY timestamp DESC LIMIT 100").all();
    return {
      articles: articles.results || [],
      tribes: tribes.results || [],
      people: people.results || [],
      places: places.results || [],
      dict: dict.results || [],
      stories: stories.results || [],
      submissions: submissions.results || [],
      revisions: revisions.results || []
    };
  }catch(e){ return {error: e.message}; }
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
      if(data && data.error) return jsonResponse({success:false,error:data.error},500);
      return jsonResponse({success:true,data});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
  }
  if(path==='/api/d1/articles' && request.method==='GET'){
    try{
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},503);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const result = await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT * FROM articles WHERE verified=1 ORDER BY updatedAt DESC").all();
      return jsonResponse({success:true,articles: result.results||[]});
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
      await env.NE_ENCYCLOPEDIA_D1.prepare(
        "INSERT OR REPLACE INTO articles (id,title,slug,state,intro,content,categories,tags,references_list,imageUrl,imageCaption,imageCredit,infobox,authorId,authorName,createdAt,updatedAt,verified,views,relatedIds) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        a.id, a.title, a.slug||a.title.toLowerCase().replace(/\s+/g,'-'), a.state||'', a.intro||'', a.content||'',
        JSON.stringify(a.categories||[]), JSON.stringify(a.tags||[]), JSON.stringify(a.references||a.references_list||[]),
        a.imageUrl||'', a.imageCaption||'', a.imageCredit||'', JSON.stringify(a.infobox||{}),
        a.authorId||payload.username, a.authorName||payload.displayName, a.createdAt||new Date().toISOString(), new Date().toISOString(),
        1, a.views||0, JSON.stringify(a.relatedIds||[])
      ).run();
      return jsonResponse({success:true,message:'Article saved to D1 online'});
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
      await env.NE_ENCYCLOPEDIA_D1.prepare(
        "INSERT OR REPLACE INTO dictionary (id,word,language,tribe,state,meaning,example,pronunciation,altSpelling,contributor,source,dateAdded) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        w.id, w.word, w.language||'', w.tribe||'', w.state||'', w.meaning, w.example||'', w.pronunciation||'', w.altSpelling||'',
        w.contributor||payload.username, w.source||payload.displayName, w.dateAdded||new Date().toISOString()
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
      await env.NE_ENCYCLOPEDIA_D1.prepare(
        "INSERT OR REPLACE INTO stories (id,title,state,intro,content,authorId,authorName,imageUrl,imageCaption,imageCredit,createdAt,updatedAt,verified) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        st.id, st.title, st.state||'', st.intro||'', st.content, st.authorId||payload.username, st.authorName||payload.displayName,
        st.imageUrl||'', st.imageCaption||'', st.imageCredit||'', st.createdAt||new Date().toISOString(), new Date().toISOString(), 1
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
  if(path==='/api/d1/media' && request.method==='GET'){
    try{
      if(!env.NE_ENCYCLOPEDIA_D1) return jsonResponse({success:false,error:'D1 not configured'},503);
      await initD1Tables(env.NE_ENCYCLOPEDIA_D1);
      const result = await env.NE_ENCYCLOPEDIA_D1.prepare("SELECT * FROM media WHERE verified=1 ORDER BY updatedAt DESC").all();
      return jsonResponse({success:true,media: result.results||[]});
    }catch(e){ return jsonResponse({success:false,error:e.message},500); }
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
      await env.NE_ENCYCLOPEDIA_D1.prepare(
        "INSERT OR REPLACE INTO articles (id,title,slug,state,intro,content,categories,tags,references_list,imageUrl,imageCaption,imageCredit,infobox,authorId,authorName,createdAt,updatedAt,verified,views,relatedIds) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(
        data.id||subResult.articleId||'a'+Date.now(), data.title||'Untitled', data.slug||(data.title||'').toLowerCase().replace(/\s+/g,'-'), data.state||'', data.intro||'', data.content||'',
        JSON.stringify(data.categories||[]), JSON.stringify(data.tags||[]), JSON.stringify(data.references||[]), data.imageUrl||'', data.imageCaption||'', data.imageCredit||'', JSON.stringify(data.infobox||{}),
        data.authorId||subResult.userId, data.authorName||subResult.username, data.createdAt||new Date().toISOString(), new Date().toISOString(), 1, data.views||0, JSON.stringify(data.relatedIds||[])
      ).run();
      await env.NE_ENCYCLOPEDIA_D1.prepare("UPDATE submissions SET status='approved' WHERE id=?").bind(subId).run();
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
      if(dump.articles) for(let a of dump.articles){ if(a.imageUrl && a.imageUrl.length > 1000000) continue; try{ await env.NE_ENCYCLOPEDIA_D1.prepare("INSERT OR REPLACE INTO articles (id,title,slug,state,intro,content,categories,tags,references_list,imageUrl,imageCaption,imageCredit,infobox,authorId,authorName,createdAt,updatedAt,verified,views,relatedIds) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(a.id,a.title,a.slug||'',a.state||'',a.intro||'',a.content||'',JSON.stringify(a.categories||[]),JSON.stringify(a.tags||[]),JSON.stringify(a.references||[]),a.imageUrl||'',a.imageCaption||'',a.imageCredit||'',JSON.stringify(a.infobox||{}),a.authorId||'',a.authorName||'',a.createdAt||new Date().toISOString(),a.updatedAt||new Date().toISOString(),1,a.views||0,JSON.stringify(a.relatedIds||[])).run(); count++; }catch{} }
      if(dump.tribes) for(let t of dump.tribes){ try{ await env.NE_ENCYCLOPEDIA_D1.prepare("INSERT OR REPLACE INTO tribes (id,name,altNames,state,district,language,history,culture,festivals,food,clothing,arts,population,references_list,imageUrl) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(t.id,t.name,JSON.stringify(t.altNames||[]),t.state||'',t.district||'',t.language||'',t.history||'',t.culture||'',t.festivals||'',t.food||'',t.clothing||'',t.arts||'',t.population||'',JSON.stringify(t.references||[]),t.imageUrl||'').run(); count++; }catch{} }
      if(dump.dict) for(let d of dump.dict){ try{ await env.NE_ENCYCLOPEDIA_D1.prepare("INSERT OR REPLACE INTO dictionary (id,word,language,tribe,state,meaning,example,pronunciation,altSpelling,contributor,source,dateAdded) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)").bind(d.id,d.word,d.language||'',d.tribe||'',d.state||'',d.meaning||'',d.example||'',d.pronunciation||'',d.altSpelling||'',d.contributor||'',d.source||'',d.dateAdded||new Date().toISOString()).run(); count++; }catch{} }
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
          "INSERT OR REPLACE INTO dictionary (id,word,language,tribe,state,meaning,example,pronunciation,altSpelling,contributor,source,dateAdded) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
        ).bind(
          wordId, w.word, w.language||'', w.tribe||'', w.state||'', w.meaning, w.example||'', w.pronunciation||'', w.altSpelling||'',
          contributor.id, w.source||contributor.displayName, w.dateAdded||new Date().toISOString()
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
          "INSERT OR REPLACE INTO stories (id,title,state,intro,content,authorId,authorName,imageUrl,imageCaption,imageCredit,createdAt,updatedAt,verified) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
        ).bind(
          storyId, st.title, st.state||'', st.intro||'', st.content, contributor.id, contributor.displayName,
          st.imageUrl||'', st.imageCaption||'', st.imageCredit||'', st.createdAt||new Date().toISOString(), new Date().toISOString(), 1
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
      const list = await d1.prepare(
        "SELECT id,displayName,country,stateRegion,joinedAt,status,contributionCount,lastActiveAt FROM contributors ORDER BY joinedAt DESC"
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
      const contributor = await d1.prepare("SELECT * FROM contributors WHERE id=?").bind(id).first();
      if(!contributor) return jsonResponse({success:false,error:'Not found'},404);
      const submissions = await d1.prepare("SELECT id,type,status,timestamp,summary FROM submissions WHERE userId=? ORDER BY timestamp DESC").bind(id).all();
      const suggestions = await d1.prepare("SELECT id,category,content,status,timestamp FROM suggestions WHERE contributorId=? ORDER BY timestamp DESC").bind(id).all();
      return jsonResponse({success:true, contributor, submissions: submissions.results||[], suggestions: suggestions.results||[] });
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
      const { contributorId, status } = body;
      if(!contributorId || !['ACTIVE','SUSPENDED','BLOCKED'].includes(status)) return jsonResponse({success:false,error:'contributorId and valid status required'},400);
      await d1.prepare("UPDATE contributors SET status=? WHERE id=?").bind(status, contributorId).run();
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
