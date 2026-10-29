// advisor-api worker — private CRM backend for the advisor portal.
// KV binding: LEADS
// Secret: ADVISOR_AUTH = "<salt_hex>:<sha256_hex(salt + ':' + password)>"
//
// Endpoints:
//   GET  /api/health                    -> {ok:true}            (public)
//   POST /api/lead        {lead fields} -> {ok:true}            (public, rate-limited)
//   POST /api/login       {password}    -> {ok:true, token}     (public, rate-limited)
//   GET  /api/leads                     -> {ok:true, leads:[]}  (auth)
//   PATCH /api/leads/:id  {stage,notes} -> {ok:true}            (auth)
//   DELETE /api/leads/:id               -> {ok:true}            (auth)
//   POST /api/market-leads {leads:[..]} -> {ok, added, skipped} (auth — daily market-radar ingest, URL-deduped)
//   GET  /api/market-leads              -> {ok:true, leads:[]}  (auth)
//   PATCH /api/market-leads/:id {status,notes} -> {ok:true}     (auth)
//   DELETE /api/market-leads/:id        -> {ok:true}            (auth)
//   GET  /api/radar-settings            -> {ok, enabled}        (auth — portal on/off switch for the daily scan)
//   PUT  /api/radar-settings {enabled}  -> {ok, enabled}        (auth)

const ALLOWED_ORIGINS = [
  'https://real-estate-platform-0aei.onrender.com',
  'https://muse.ai'
];
const INTENTS = ['buyer', 'seller', 'investor', 'renter'];
const STAGES = ['new', 'contacted', 'viewing', 'offer', 'closed', 'dropped'];
const MKINDS = ['buyer', 'seller', 'pair'];
const MSTATUSES = ['new', 'contacted', 'dismissed'];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CFG_KEYS = ['gcal', 'google', 'ingest', 'service', 'calls']; // admin-writable cfg: keys — config POST validates against it, config GET probes only these
const TOKEN_TTL = 86400; // 24h
const TS_HOSTS = ['real-estate-platform-0aei.onrender.com', 'muse.ai'];

function cors(origin) {
  const h = {
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin',
    'Cache-Control': 'no-store'
  };
  if (origin && ALLOWED_ORIGINS.indexOf(origin) !== -1) h['Access-Control-Allow-Origin'] = origin;
  else if (!origin) h['Access-Control-Allow-Origin'] = '*';
  return h;
}
function json(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: Object.assign({ 'Content-Type': 'application/json' }, cors(origin))
  });
}

// simple per-IP rate limiter (in-memory, best-effort)
const hits = new Map();
function limited(ip, max, windowMs) {
  const now = Date.now();
  if (hits.size > 5000) { for (const [hk, hv] of hits) if (now > hv.reset) hits.delete(hk); }
  const k = ip + ':' + max + ':' + windowMs;
  let r = hits.get(k);
  if (!r || now > r.reset) { r = { count: 0, reset: now + windowMs }; hits.set(k, r); }
  r.count++;
  return r.count > max;
}

// Expand an IPv6 address and keep its /64 prefix as the rate-limit key.
// The naive split(':').slice(0,4) broke on compressed forms: in
// 2001:db8:abcd::1 the '::' yields an empty element, so two addresses in
// the same /64 could land in different buckets (cycle 26, Claude M1).
function ipKey(ip) {
  if (ip.indexOf(':') === -1 || ip.indexOf('.') !== -1) return ip;
  const h = ip.split('::');
  const a = h[0] ? h[0].split(':') : [];
  const b = h.length > 1 && h[1] ? h[1].split(':') : [];
  const fill = h.length > 1 ? new Array(Math.max(0, 8 - a.length - b.length)).fill('0') : [];
  return a.concat(fill, b).slice(0, 4).map(function (x) { return parseInt(x || '0', 16).toString(16); }).join(':') + '::';
}

// ---- KV op reduction (free-tier write/list caps are the tight resource) ----
// 1) /api/track aggregates beacons in isolate memory and flushes the daily
//    stats doc to KV in batches (same 'stat:<day>' key and doc format),
//    instead of one KV read+write per pageview.
// 2) Admin list endpoints (portal tabs) are cached in-isolate for a few
//    seconds; any non-GET request clears the cache, so portal edits are
//    never hidden by it.
// 3) Visitor session + ban lookups are cached in-isolate briefly; purges and
//    ban changes evict/update their entries immediately.
const ADMIN_CACHE_TTL = 20000;
const GEN_CACHE_MAX_AGE = 600000; // cycle 23: bound gen-matched entries so a KV propagation skew cannot pin stale admin data indefinitely
const adminCache = new Map();
function adminCached(name, loader) {
  const now = Date.now();
  const hit = adminCache.get(name);
  if (hit && now - hit.t < ADMIN_CACHE_TTL) return hit.promise;
  const promise = Promise.resolve().then(loader);
  adminCache.set(name, { t: now, promise: promise });
  promise.catch(function () {
    const c = adminCache.get(name);
    if (c && c.promise === promise) adminCache.delete(name);
  });
  return promise;
}
// Generation-keyed cache for the expensive admin LIST builders (contacts,
// desk, leads, market leads, users, newsletter). A single 'admin:gen' key is
// bumped by every mutating request (see the router), and entries record the
// gen they were built under: while the gen is unchanged, repeat portal loads
// cost ONE small read instead of ~a dozen KV list calls. Same-isolate
// freshness is unchanged (the router still clears the whole cache on any
// write); the plain TTL applies only when the gen read itself fails.
let genMemo = { t: 0, v: null };
async function currentGen(env) {
  if (genMemo.v !== null && Date.now() - genMemo.t < 5000) return genMemo.v;
  try {
    const raw = await env.LEADS.get('admin:gen');
    const v = raw === null || raw === undefined ? '0' : String(raw);
    genMemo = { t: Date.now(), v: v };
    return v;
  } catch (e) { return null; }
}
async function adminCachedGen(env, name, loader) {
  const g = await currentGen(env);
  const hit = adminCache.get(name);
  if (hit && hit.gen !== undefined) {
    if (g !== null && hit.gen === g && Date.now() - hit.t < GEN_CACHE_MAX_AGE) return hit.promise;
    if (g === null && Date.now() - hit.t < ADMIN_CACHE_TTL) return hit.promise;
  }
  const promise = Promise.resolve().then(loader);
  adminCache.set(name, { t: Date.now(), gen: g === null ? '__unknown__' : g, promise: promise });
  promise.catch(function () {
    const c = adminCache.get(name);
    if (c && c.promise === promise) adminCache.delete(name);
  });
  return promise;
}
const SESS_CACHE_TTL = 60000;
const sessCache = new Map(); // 'usess:<token>' -> { t, email|null }
const BAN_CACHE_TTL = 60000;
const banCache = new Map(); // normalized email -> { t, banned }
const TRACK_FLUSH_EVENTS = 25;
const TRACK_FLUSH_MS = 60000;
let trackBuf = null; // { day, doc, events, firstTs, loading }
let trackFlushChain = Promise.resolve();
function flushTrack(env) {
  const buf = trackBuf;
  if (!buf || buf.events === 0) return trackFlushChain;
  if (buf.loadFailed) { buf.events = 0; buf.firstTs = 0; return trackFlushChain; } // day doc never loaded: drop this buffer rather than overwrite the stored stats (cycle 26, Claude M6)
  const key = 'stat:' + buf.day;
  const snapshot = JSON.stringify(buf.doc);
  buf.events = 0;
  buf.firstTs = 0;
  trackFlushChain = trackFlushChain.then(function () { return env.LEADS.put(key, snapshot); }).catch(function () {});
  return trackFlushChain;
}

function bumpC(map, key, cap) {
  if (!key || key === '__proto__' || key === 'constructor' || key === 'prototype') return;
  if (Object.prototype.hasOwnProperty.call(map, key)) { map[key]++; return; }
  if (Object.keys(map).length >= cap) return;
  map[key] = 1;
}
async function sha256hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function timingSafeEqual(a, b) {
  a = String(a == null ? '' : a);
  b = String(b == null ? '' : b);
  if (!a || !b) return false;
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
const PBKDF2_ITERS = 20000;
async function pbkdf2Hex(password, salt, iters) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: new TextEncoder().encode(salt), iterations: iters }, key, 256);
  return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function makePassHash(password) {
  const salt = randHex(16);
  return 'pbkdf2$' + PBKDF2_ITERS + '$' + salt + '$' + (await pbkdf2Hex(password, salt, PBKDF2_ITERS));
}
async function verifyUserPass(user, pass) {
  try {
    if (!user) return false;
    const ph = String(user.passHash || '');
    if (ph.indexOf('pbkdf2$') === 0) {
      const p = ph.split('$');
      const iters = Math.min(Math.max(parseInt(p[1], 10) || 1, 1), 100000);
      if (!p[2] || !p[3]) return false;
      const got = await pbkdf2Hex(pass, p[2], iters);
      return timingSafeEqual(got, p[3]);
    }
    // legacy single-round salted SHA-256 (upgraded on successful login)
    const hash = await sha256hex(String(user.salt || '') + ':' + pass);
    return timingSafeEqual(hash, ph);
  } catch (e) { return false; }
}
async function checkPassword(env, password) {
  const auth = env.ADVISOR_AUTH || '';
  if (auth.indexOf('pbkdf2$') === 0) {
    const p = auth.split('$');
    const iters = Math.min(Math.max(parseInt(p[1], 10) || 1, 1), 100000);
    if (!p[2] || !p[3]) return false;
    const got = await pbkdf2Hex(password, p[2], iters);
    return timingSafeEqual(got, p[3]);
  }
  const i = auth.indexOf(':');
  if (i < 0) return false;
  const salt = auth.slice(0, i);
  const want = auth.slice(i + 1);
  const got = await sha256hex(salt + ':' + password);
  return timingSafeEqual(got, want);
}
function randHex(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}
// Scoped machine credentials (cfg:ingest / cfg:service): long-lived tokens
// accepted ONLY on an allowlist of routes, for jobs that must not hold the
// full admin login (the radar ingest agent browses attacker-controlled
// pages; the weekly maintenance job needs a handful of read/maintenance
// routes). Anything outside the allowlist still needs a real admin session.
async function scopedAuthed(request, env, path, method) {
  const INGEST = (method === 'POST' && path === '/api/market-leads') || (method === 'GET' && path === '/api/radar-settings') || (method === 'GET' && path === '/api/market-leads') || (path === '/api/radar-seen' && (method === 'GET' || method === 'POST'));
  const SERVICE = (path === '/api/admin/maintenance' && (method === 'GET' || method === 'POST')) ||
    (method === 'POST' && path === '/api/admin/backup-stamp') ||
    (method === 'GET' && (path === '/api/leads' || path === '/api/admin/users' || path === '/api/admin/newsletter' || path === '/api/admin/viewings' || path === '/api/admin/mailq'));
  const scope = INGEST ? 'ingest' : (SERVICE ? 'service' : null);
  if (!scope) return false;
  const h = request.headers.get('Authorization') || '';
  const m = h.match(/^Bearer ([0-9a-f]{48})$/);
  if (!m) return false;
  const cfg = await env.LEADS.get('cfg:' + scope, { type: 'json' });
  if (!cfg || !cfg.token) return false;
  return timingSafeEqual(m[1], String(cfg.token));
}
async function authed(request, env) {
  const h = request.headers.get('Authorization') || '';
  const m = h.match(/^Bearer ([0-9a-f]{64})$/);
  if (!m) return false;
  const rawExp = await env.LEADS.get('tok:' + m[1]);
  if (!rawExp) return false;
  const exp = parseInt(rawExp, 10);
  if (!(exp > Date.now())) {
    await env.LEADS.delete('tok:' + m[1]).catch(() => {});
    return false;
  }
  return true;
}

// ---- visitor accounts, viewings, mail queue (features 1-3) ----
// Sample listing catalog (mirrors the site mock provider; the live DDF
// adapter replaces this after licensing). Matching fields only.
const CATALOG = [
  { mls: "R2991001", street: "2108-4981 Kingsway", city: "Burnaby", type: "condo", price: 689000, beds: 2, status: "active" },
  { mls: "R2991002", street: "45-1188 Inlet Street", city: "Coquitlam", type: "townhouse", price: 749000, beds: 3, status: "active" },
  { mls: "R2991003", street: "7421 18th Avenue", city: "Burnaby", type: "house", price: 1299000, beds: 4, status: "active" },
  { mls: "R2991004", street: "1506-833 Seymour Street", city: "Vancouver", type: "condo", price: 549000, beds: 1, status: "active" },
  { mls: "R2991005", street: "22-15500 102A Avenue", city: "Surrey", type: "townhouse", price: 899000, beds: 3, status: "pending" },
  { mls: "R2991006", street: "309-550 Kirkland Avenue", city: "Port Coquitlam", type: "condo", price: 425000, beds: 2, status: "active" }
];
function catalogByMls(mls) {
  return mergedCatalog().filter(function (c) { return c.mls === mls; })[0] || null;
}
function critNum(v) {
  if (v === null || v === undefined || v === '') return NaN;
  const n = Number(String(v).replace(/[^0-9.]/g, ''));
  return isFinite(n) && n > 0 ? n : NaN;
}
function matchSearch(criteria) {
  const c = criteria || {};
  const q = String(c.q || '').toLowerCase();
  const maxPrice = critNum(c.maxPrice);
  const minBeds = critNum(c.minBeds);
  const completionBy = critNum(c.completionBy);
  return mergedCatalog().filter(function (l) {
    if (l.status && l.status !== 'active') return false;
    if (c.city && String(l.city || '').toLowerCase() !== String(c.city).toLowerCase()) return false;
    if (c.type && String(l.type || '').toLowerCase() !== String(c.type).toLowerCase()) return false;
    if (isFinite(maxPrice) && l.price > maxPrice) return false;
    if (isFinite(minBeds) && l.beds < minBeds) return false;
    if (c.presale === 'only' && l.pt !== 'presale') return false;
    if (c.presale === 'no' && l.pt === 'presale') return false;
    if (isFinite(completionBy) && l.pt === 'presale') {
      const cyr = parseInt(String(l.completion || '').slice(0, 4), 10);
      if (!cyr || cyr > completionBy) return false;
    }
    if (q && (l.street + ' ' + l.city + ' ' + l.mls).toLowerCase().indexOf(q) === -1) return false;
    return true;
  }).map(function (l) { return l.mls; });
}
/* ================= portal-managed listings + site settings =================
   The Site Admin portal is the source of truth for the listings Erfan adds
   himself: records live in KV under listing:<mls> in the exact shape the
   site's LISTINGS array uses, uploaded photos under lphoto:<id> (data
   URLs), and site-wide settings under site:settings. The six built-in
   sample listings stay in code (CATALOG here, the baked array on the
   site); a KV record with the same mls OVERRIDES the sample everywhere,
   and a {_deleted:true} record removes it. mergedCatalog() above is what
   every consumer (booking, availability, saved-search matching, desk)
   reads. */
/* Full built-in sample records (mirror the site's baked LISTINGS array;
   used ONLY to prefill the portal editor so editing a sample never loses
   fields). Keep in step with the site source if the samples ever change. */
const SEED_LISTINGS = [
 {
  "mls": "R2991001",
  "price": 689000,
  "street": "2108-4981 Kingsway",
  "city": "Burnaby",
  "postal": "V5H 4M2",
  "type": "condo",
  "beds": 2,
  "baths": 2,
  "sqft": 872,
  "lot": null,
  "year": 2019,
  "parking": "underground",
  "stalls": 1,
  "strata": 412,
  "tax": 2410,
  "status": "active",
  "listed": "2026-10-08",
  "dom": 10,
  "photo": "photos/R2991001.webp",
  "features": [
   "balcony",
   "laundry",
   "gym",
   "concierge"
  ],
  "desc": {
   "en": "Bright 2-bed corner unit steps to Metrotown SkyTrain. Open plan, quartz counters, balcony with city views.",
   "fa": "واحد گوشه‌ای روشن دوخوابه، چند قدمی اسکای‌ترین متروتاون. نقشه‌ی باز، کانتر کوارتز و بالکن با چشم‌انداز شهر.",
   "hi": "मेट्रोटाउन स्काईट्रेन से कुछ कदम दूर उजला 2-बेड कॉर्नर यूनिट। ओपन प्लान, क्वार्ट्ज़ काउंटर, शहर के दृश्य वाली बालकनी।",
   "zh": "明亮的两卧转角单位,步行可达 Metrotown 天车站。开放式布局,石英台面,阳台享城市景观。"
  }
 },
 {
  "mls": "R2991002",
  "price": 749000,
  "street": "45-1188 Inlet Street",
  "city": "Coquitlam",
  "postal": "V3B 6A9",
  "type": "townhouse",
  "beds": 3,
  "baths": 2.5,
  "sqft": 1340,
  "lot": null,
  "year": 2016,
  "parking": "garage",
  "stalls": 2,
  "strata": 285,
  "tax": 3120,
  "status": "active",
  "listed": "2026-10-02",
  "dom": 16,
  "photo": "photos/R2991002.webp",
  "features": [
   "fenced_yard",
   "dbl_garage",
   "fireplace"
  ],
  "desc": {
   "en": "End-unit townhouse near Lafarge Lake. Double garage, fenced yard, top-floor primary retreat.",
   "fa": "تاون‌هاوس انتهایی نزدیک دریاچه‌ی لافارژ. گاراژ دوبل، حیاط محصور و اتاق‌خواب اصلی در طبقه‌ی بالا.",
   "hi": "लाफ़ार्ज झील के पास एंड-यूनिट टाउनहाउस। डबल गैरेज, बाड़ वाला आँगन, ऊपरी मंज़िल पर मुख्य बेडरूम।",
   "zh": "位于 Lafarge 湖附近的端户联排别墅。双车位车库、围栏庭院,顶层主卧套房。"
  }
 },
 {
  "mls": "R2991003",
  "price": 1299000,
  "street": "7421 18th Avenue",
  "city": "Burnaby",
  "postal": "V3N 1H3",
  "type": "house",
  "beds": 4,
  "baths": 3,
  "sqft": 2310,
  "lot": 6012,
  "year": 1988,
  "parking": "garage",
  "stalls": 2,
  "strata": null,
  "tax": 5260,
  "status": "active",
  "listed": "2026-09-28",
  "dom": 20,
  "photo": "photos/R2991003.webp",
  "features": [
   "reno_kitchen",
   "suite",
   "deck"
  ],
  "desc": {
   "en": "Updated family home on a quiet street. Renovated kitchen (2023), 1-bed suite potential (verify legality).",
   "fa": "خانه‌ی خانوادگی به‌روز در خیابانی آرام. آشپزخانه‌ی بازسازی‌شده (۲۰۲۳) و قابلیت سوئیت یک‌خوابه (قانونی‌بودن را بررسی کنید).",
   "hi": "शांत सड़क पर नवीनीकृत पारिवारिक घर। 2023 में नवीनीकृत रसोई, 1-बेड सूट की संभावना (वैधता जाँचें)।",
   "zh": "位于安静街道的翻新家庭住宅。厨房于 2023 年翻新,具备一卧套房潜力(请核实合法性)。"
  }
 },
 {
  "mls": "R2991004",
  "price": 549000,
  "street": "1506-833 Seymour Street",
  "city": "Vancouver",
  "postal": "V6B 0G4",
  "type": "condo",
  "beds": 1,
  "baths": 1,
  "sqft": 618,
  "lot": null,
  "year": 2011,
  "parking": "underground",
  "stalls": 1,
  "strata": 498,
  "tax": 2050,
  "status": "active",
  "listed": "2026-10-12",
  "dom": 6,
  "photo": "photos/R2991004.webp",
  "features": [
   "concierge",
   "rooftop",
   "bike_room"
  ],
  "desc": {
   "en": "Downtown 1-bed, 2 blocks to Granville SkyTrain. Floor-to-ceiling windows, 24hr concierge.",
   "fa": "یک‌خوابه در مرکز شهر، دو بلوک تا اسکای‌ترین گرنویل. پنجره‌های سرتاسری و پذیرش ۲۴ ساعته.",
   "hi": "डाउनटाउन 1-बेड, ग्रानविल स्काईट्रेन से 2 ब्लॉक। फ़र्श से छत तक खिड़कियाँ, 24 घंटे कंसीयर्ज।",
   "zh": "市中心一卧单位,距 Granville 天车站仅两个街区。落地窗,24 小时礼宾服务。"
  }
 },
 {
  "mls": "R2991005",
  "price": 899000,
  "street": "22-15500 102A Avenue",
  "city": "Surrey",
  "postal": "V3R 7B4",
  "type": "townhouse",
  "beds": 3,
  "baths": 2.5,
  "sqft": 1480,
  "lot": null,
  "year": 2021,
  "parking": "garage",
  "stalls": 2,
  "strata": 310,
  "tax": 3480,
  "status": "pending",
  "listed": "2026-09-20",
  "dom": 28,
  "photo": "photos/R2991005.webp",
  "features": [
   "ac",
   "ev",
   "playground"
  ],
  "desc": {
   "en": "Near-new townhouse in Guildford. Air conditioning, EV charging in the garage, steps to parks and schools.",
   "fa": "تاون‌هاوس تقریباً نوساز در گیلدفورد. کولر گازی، شارژر خودرو برقی در گاراژ و نزدیک پارک و مدرسه.",
   "hi": "गिल्डफ़ोर्ड में लगभग नया टाउनहाउस। एयर कंडीशनिंग, गैरेज में EV चार्जिंग, पार्क और स्कूल पास में।",
   "zh": "Guildford 近乎全新的联排别墅。配备空调、车库配备电动车充电,步行可达公园和学校。"
  }
 },
 {
  "mls": "R2991006",
  "price": 425000,
  "street": "309-550 Kirkland Avenue",
  "city": "Port Coquitlam",
  "postal": "V3B 1H2",
  "type": "condo",
  "beds": 2,
  "baths": 1,
  "sqft": 795,
  "lot": null,
  "year": 1994,
  "parking": "underground",
  "stalls": 1,
  "strata": 365,
  "tax": 1760,
  "status": "active",
  "listed": "2026-10-05",
  "dom": 13,
  "photo": "photos/R2991006.webp",
  "features": [
   "mt_view",
   "new_roof",
   "storage"
  ],
  "desc": {
   "en": "2-bed with mountain views. Newer roof (2022), well-managed strata, near West Coast Express.",
   "fa": "دوخوابه با چشم‌انداز کوهستان. سقف نسبتاً نوساز (۲۰۲۲)، مدیریت خوب ساختمان و نزدیک قطار West Coast Express.",
   "hi": "पहाड़ के दृश्य वाला 2-बेड। अपेक्षाकृत नई छत (2022), अच्छी तरह प्रबंधित स्ट्राटा, West Coast Express के पास।",
   "zh": "两卧单位,享山景。屋顶较新(2022年),物业管理良好,靠近西海岸快线。"
  }
 }
];
let customListings = [];
let customSlim = [];
let deletedSeedMls = [];
let customCatalogAt = 0;
let catalogRefreshing = null;
async function refreshCustomCatalog(env, force) {
  if (!force && customCatalogAt > 0 && Date.now() - customCatalogAt < 120000) return;
  if (!force && catalogRefreshing) return catalogRefreshing;
  catalogRefreshing = (async function () {
    try {
      await doRefreshCustomCatalog(env);
    } catch (e) {
      console.error('catalog refresh failed', e && e.message);
      customCatalogAt = Date.now() - 90000;
    } finally {
      catalogRefreshing = null;
    }
  })();
  return catalogRefreshing;
}
async function buildCatalogSnap(env) {
  const full = [], deleted = [];
  const seeds = {};
  CATALOG.forEach(function (c) { seeds[c.mls] = 1; });
  let cursor = undefined;
  do {
    const page = await kvList(env, { prefix: 'listing:', limit: 200, cursor: cursor });
    for (const k of page.keys) {
      const rec = await env.LEADS.get(k.name, { type: 'json' });
      if (!rec || !rec.mls) continue;
      if (rec._deleted) { if (seeds[rec.mls]) deleted.push(rec.mls); continue; }
      full.push(rec);
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  try { await env.LEADS.put('catalog:snap', JSON.stringify({ listings: full, deleted: deleted, at: Date.now() })); } catch (e) {}
  return { full: full, deleted: deleted };
}
async function updateCatalogSnap(env, rec, removedMls, tombstone) {
  const snap = await env.LEADS.get('catalog:snap', { type: 'json' });
  if (!snap || !Array.isArray(snap.listings)) { await buildCatalogSnap(env); return; }
  let listings = snap.listings, deleted = Array.isArray(snap.deleted) ? snap.deleted : [];
  if (rec) {
    listings = listings.filter(function (r) { return r.mls !== rec.mls; }).concat([rec]);
    deleted = deleted.filter(function (m) { return m !== rec.mls; });
  }
  if (removedMls) {
    listings = listings.filter(function (r) { return r.mls !== removedMls; });
    if (tombstone && deleted.indexOf(removedMls) === -1) deleted.push(removedMls);
  }
  try { await env.LEADS.put('catalog:snap', JSON.stringify({ listings: listings, deleted: deleted, at: Date.now() })); } catch (e) {}
}
async function doRefreshCustomCatalog(env) {
  const snap = await env.LEADS.get('catalog:snap', { type: 'json' });
  if (snap && Array.isArray(snap.listings)) {
    customListings = snap.listings;
    customSlim = snap.listings.map(slimOf);
    deletedSeedMls = Array.isArray(snap.deleted) ? snap.deleted : [];
    customCatalogAt = Date.now();
    return;
  }
  const built = await buildCatalogSnap(env);
  customListings = built.full;
  customSlim = built.full.map(slimOf);
  deletedSeedMls = built.deleted;
  customCatalogAt = Date.now();
}
function mergedCatalog() {
  const over = {}, del = {};
  customSlim.forEach(function (c) { over[c.mls] = 1; });
  deletedSeedMls.forEach(function (m) { del[m] = 1; });
  return CATALOG.filter(function (c) { return !over[c.mls] && !del[c.mls]; }).concat(customSlim);
}
function slimOf(rec) { return { mls: rec.mls, street: rec.street, city: rec.city, type: rec.type, price: rec.price, beds: rec.beds, status: rec.status || 'active', pt: rec.pt || 'resale', completion: rec.completion || '' }; }
function upsertLocalListing(rec) {
  customListings = customListings.filter(function (r) { return r.mls !== rec.mls; }).concat([rec]);
  customSlim = customSlim.filter(function (r) { return r.mls !== rec.mls; }).concat([slimOf(rec)]);
  deletedSeedMls = deletedSeedMls.filter(function (m) { return m !== rec.mls; });
  customCatalogAt = Date.now();
}
function removeLocalListing(mls, tombstone) {
  customListings = customListings.filter(function (r) { return r.mls !== mls; });
  customSlim = customSlim.filter(function (r) { return r.mls !== mls; });
  if (tombstone && deletedSeedMls.indexOf(mls) === -1) deletedSeedMls.push(mls);
  customCatalogAt = Date.now();
}
const LISTING_TYPES = ['condo', 'townhouse', 'house', 'duplex', 'apartment', 'land'];
function cleanHttpsUrl(v, max) {
  const s = String(v == null ? '' : v).trim();
  if (!s) return '';
  if (s.length > max || /[\s"'<>`\\]/.test(s)) return null;
  let u;
  try { u = new URL(s); } catch (e) { return null; }
  return (u.protocol === 'https:' && !u.username && !u.password) ? u.href : null;
}
function cleanListing(input) {
  const d = (input && typeof input === 'object') ? input : {};
  const cs = function (v, max) { return String(v == null ? '' : v).replace(/[\u0000-\u001f<>]/g, ' ').trim().slice(0, max); };
  const num = function (v, min, max) { if (v === '' || v == null) return null; const n = Number(v); if (!isFinite(n) || n < min || n > max) return undefined; return n; };
  if (String(d.mls == null ? '' : d.mls).trim().length > 24) return { error: 'mls' };
  const mls = cs(d.mls, 24).toUpperCase();
  if (!/^[A-Z0-9-]{3,24}$/.test(mls)) return { error: 'mls' };
  const street = cs(d.street, 120), city = cs(d.city, 60);
  if (!street || !city) return { error: 'address' };
  const price = num(d.price, 1000, 999999999);
  if (price === undefined || price === null) return { error: 'price' };
  if (LISTING_TYPES.indexOf(String(d.type || '')) === -1) return { error: 'type' };
  const beds = num(d.beds, 0, 30);
  if (beds === undefined || beds === null) return { error: 'beds' };
  const baths = num(d.baths, 0, 30);
  if (baths === undefined) return { error: 'baths' };
  const status = ['active', 'pending', 'sold'].indexOf(String(d.status || '')) !== -1 ? String(d.status) : 'active';
  let listed = cs(d.listed, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(listed) || isNaN(Date.parse(listed)) || new Date(Date.parse(listed + 'T00:00:00Z')).toISOString().slice(0, 10) !== listed) listed = new Date().toISOString().slice(0, 10);
  const descIn = (d.desc && typeof d.desc === 'object') ? d.desc : {};
  if (d.photo && String(d.photo).length > 600) return { error: 'photo' };
  let photo = cs(d.photo, 600);
  if (photo && photo !== 'upload') {
    photo = cleanHttpsUrl(photo, 600);
    if (photo === null) return { error: 'photo' };
  }
  return { rec: {
    mls: mls, price: Math.round(price), street: street, city: city, postal: cs(d.postal, 10),
    type: String(d.type), beds: beds, baths: baths == null ? 0 : baths,
    sqft: num(d.sqft, 0, 1000000), lot: num(d.lot, 0, 10000000),
    year: num(d.year, 1800, 2100), parking: cs(d.parking, 40), stalls: num(d.stalls, 0, 50),
    strata: num(d.strata, 0, 100000), tax: num(d.tax, 0, 1000000),
    status: status, listed: listed,
    pt: d.pt === 'presale' ? 'presale' : 'resale',
    project: cs(d.project, 80), developer: cs(d.developer, 80), completion: cs(d.completion, 20),
    depositPct: num(d.depositPct, 0, 100), depositStruct: cs(d.depositStruct, 60),
    assignment: (d.assignment === true || d.assignment === 'yes' || d.assignment === 1),
    originalPrice: (function () { const op = num(d.originalPrice, 1000, 999999999); return (op === undefined || op === null) ? null : Math.round(op); })(),
    dom: Math.max(0, Math.floor((Date.now() - Date.parse(listed)) / 86400000) || 0),
    photo: photo,
    features: Array.isArray(d.features) ? d.features.map(function (f) { return cs(f, 30); }).filter(Boolean).slice(0, 14) : [],
    desc: { en: cs(descIn.en, 2000), fa: cs(descIn.fa, 2000), hi: cs(descIn.hi, 2000), zh: cs(descIn.zh, 2000) },
    _custom: true, updated_at: new Date().toISOString()
  } };
}
function validPhotoData(s) {
  if (typeof s !== 'string' || s.length > 2800000) return false;
  const m = s.match(/^data:image\/(webp|jpeg|png);base64,([A-Za-z0-9+/]+={0,2})$/);
  if (!m || m[2].length % 4 !== 0) return false;
  let h = '';
  try { h = atob(m[2].slice(0, 24)); } catch (e) { return false; }
  if (m[1] === 'png') return h.charCodeAt(0) === 0x89 && h.substr(1, 3) === 'PNG';
  if (m[1] === 'jpeg') return h.charCodeAt(0) === 0xff && h.charCodeAt(1) === 0xd8 && h.charCodeAt(2) === 0xff;
  return h.substr(0, 4) === 'RIFF' && h.substr(8, 4) === 'WEBP';
}
function publicListing(rec, base) {
  const out = Object.assign({}, rec);
  delete out._custom;
  const ver = Date.parse(out.updated_at) || 0;
  delete out.updated_at;
  out.dom = Math.max(0, Math.floor((Date.now() - Date.parse(out.listed)) / 86400000) || 0);
  if (out.photo === 'upload') out.photo = base + '/api/lphoto/' + encodeURIComponent(out.mls) + (ver ? '?v=' + ver : '');
  return out;
}
async function getSiteSettings(env) {
  return (await env.LEADS.get('site:settings', { type: 'json' })) || {};
}
function cleanSettings(input) {
  const d = (input && typeof input === 'object') ? input : {};
  const cs = function (v, max) { return String(v == null ? '' : v).replace(/[\u0000-\u001f<>]/g, ' ').trim().slice(0, max); };
  const langObj = function (o, max) {
    const s = (o && typeof o === 'object') ? o : {};
    return { en: cs(s.en, max), fa: cs(s.fa, max), hi: cs(s.hi, max), zh: cs(s.zh, max) };
  };
  const out = {};
  out.brand = cs(d.brand, 60);
  out.email = cs(d.email, 80);
  if (out.email && !EMAIL_RE.test(out.email)) return { error: 'email' };
  out.phone = cs(d.phone, 30);
  if (out.phone && !/^[0-9+()\-.\s]{7,30}$/.test(out.phone)) return { error: 'phone' };
  if (out.email && !/^[^\s@"'<>]+@[^\s@"'<>]+\.[^\s@"'<>]+$/.test(out.email)) return { error: 'email' };
  const rate = Number(d.rate);
  out.rate = (isFinite(rate) && rate >= 0.5 && rate <= 15) ? rate : null;
  if (d.rate !== undefined && d.rate !== '' && d.rate !== null && out.rate === null) return { error: 'rate' };
  const sl = (d.slots && typeof d.slots === 'object') ? d.slots : {};
  const hm = function (v, fb) { const s = cs(v, 5); if (!s) return fb; return /^([01]\d|2[0-3]):[0-5]\d$/.test(s) ? s : null; };
  const step = parseInt(sl.step, 10);
  const sStart = hm(sl.start, '08:00'), sEnd = hm(sl.end, '19:00');
  if (!sStart || !sEnd || !(step >= 5 && step <= 120)) return { error: 'slots' };
  const mins = function (s) { return +s.slice(0, 2) * 60 + +s.slice(3); };
  if (mins(sEnd) - mins(sStart) < step) return { error: 'slots' };
  out.slots = { start: sStart, end: sEnd, step: step };
  if (!out.brand) return { error: 'brand' };
  const hero = (d.hero && typeof d.hero === 'object') ? d.hero : {};
  out.hero = { title: langObj(hero.title, 160), sub: langObj(hero.sub, 300) };
  out.announcement = langObj(d.announcement, 240);
  if (d.heroPhoto && String(d.heroPhoto).length > 600) return { error: 'heroPhoto' };
  let heroPhoto = cs(d.heroPhoto, 600);
  if (heroPhoto && heroPhoto !== 'upload') {
    heroPhoto = cleanHttpsUrl(heroPhoto, 600);
    if (heroPhoto === null) return { error: 'heroPhoto' };
  }
  out.heroPhoto = heroPhoto;
  return { settings: out };
}
function publicSettings(s, base) {
  const out = Object.assign({}, s);
  if (out.heroPhoto === 'upload') out.heroPhoto = base + '/api/lphoto/__hero' + (s.updated_at ? '?v=' + (Date.parse(s.updated_at) || '') : '');
  return out;
}

async function queueMail(env, item) {
  const id = Date.now().toString(36) + '-' + randHex(6);
  const rec = Object.assign({}, item, { id: id, created_at: new Date().toISOString(), sent: false });
  await env.LEADS.put('mailq:' + id, JSON.stringify(rec));
  await idxAdd(env, 'mailq', id);
  return id;
}
async function userAuth(request, env) {
  const h = request.headers.get('Authorization') || '';
  const m = h.match(/^Bearer (u_[0-9a-f]{32})$/);
  if (!m) return null;
  const key = 'usess:' + m[1];
  const c = sessCache.get(key);
  if (c && Date.now() - c.t < SESS_CACHE_TTL && (!c.exp || Date.now() <= c.exp)) {
    if (c.email && (await isBanned(env, c.email))) return null;
    return c.email;
  }
  const raw = await env.LEADS.get(key);
  let email = null;
  let exp = 0;
  if (raw) {
    let s = null;
    try { s = JSON.parse(raw); } catch (e) {}
    if (s && Date.now() <= s.exp) { email = s.email; exp = s.exp; }
  }
  if (sessCache.size > 5000) { let nEv = 0; for (const kk of sessCache.keys()) { sessCache.delete(kk); if (++nEv >= 1000) break; } }
  sessCache.set(key, { t: Date.now(), email: email, exp: exp });
  if (email && (await isBanned(env, email))) return null;
  return email;
}
async function userSaved(env, email) {
  return (await env.LEADS.get('usaved:' + email, { type: 'json' })) || [];
}
async function userSearches(env, email) {
  return (await env.LEADS.get('usearch:' + email, { type: 'json' })) || [];
}

// ---- bans (admin-managed, by email; gmail-normalized so dots/+tags can't dodge) ----
const PLUS_TAG_DOMAINS = ['outlook.com', 'hotmail.com', 'live.com', 'icloud.com', 'me.com', 'mac.com', 'proton.me', 'protonmail.com', 'pm.me', 'fastmail.com'];
function normEmail(email) {
  const e = String(email || '').normalize('NFKC').replace(/[\u00AD\u061C\u200B-\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]/g, '').trim().toLowerCase();
  if (e.length > 254) return e;
  const at = e.lastIndexOf('@');
  if (at < 1) return e;
  let local = e.slice(0, at);
  let dom = e.slice(at + 1).replace(/\.+$/, '');
  if (dom === 'googlemail.com') dom = 'gmail.com';
  if (dom === 'gmail.com') local = local.split('+')[0].replace(/\./g, '');
  else if (PLUS_TAG_DOMAINS.indexOf(dom) !== -1) local = local.split('+')[0];
  if (!local) return e;
  return local + '@' + dom;
}
async function isBanned(env, email) {
  if (!email) return false;
  const ne = normEmail(email);
  const c = banCache.get(ne);
  if (c && Date.now() - c.t < BAN_CACHE_TTL) return c.banned;
  if (ne.length > 200) return false;
  const banned = (await env.LEADS.get('ban:' + ne)) !== null;
  if (banCache.size > 5000) { let nEv = 0; for (const kk of banCache.keys()) { banCache.delete(kk); if (++nEv >= 1000) break; } }
  banCache.set(ne, { t: Date.now(), banned: banned });
  return banned;
}
async function purgeUserSessions(env, email) {
  const target = normEmail(email);
  let cursor;
  do {
    const page = await kvList(env, { prefix: 'usess:', limit: 1000, cursor: cursor });
    await Promise.all(page.keys.map(async function (k) {
      let s = null;
      try { s = await env.LEADS.get(k.name, { type: 'json' }); } catch (e) { s = null; }
      if (s && normEmail(s.email) === target) { sessCache.delete(k.name); await env.LEADS.delete(k.name); }
    }));
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
}

// ---- unified contacts (the realtor desk): users + leads + viewings merged by email ----
function contactTags(c) {
  const tags = [];
  const text = (c.leads || []).map(function (l) { return (l.message || '') + ' ' + (l.intent || ''); }).join(' ').toLowerCase();
  if (/\burgent\b|\basap\b|فوری|عجله/.test(text)) tags.push('urgent');
  if (/\b(invest|investor|investing|investment|roi|rent|rental|renting)\b|سرمایه|اجاره/.test(text)) tags.push('investor');
  if (/\bfirst[\s-]?time\b|اولین|بار اول/.test(text)) tags.push('first-time buyer');
  if ((c.leads || []).some(function (l) { return l.intent === 'seller'; })) tags.push('seller');
  if ((c.leads || []).some(function (l) { return l.intent === 'buyer'; })) tags.push('buyer');
  if ((c.viewings || []).some(function (v) { return v.status !== 'cancelled'; })) tags.push('booked viewing');
  return tags;
}
// ---- per-listing viewing availability (set by Erfan in the portal) ----
// KV avail:<mls> = { dates: [{ date: 'YYYY-MM-DD', times: ['10:00', ...] }] }
async function getAvail(env, mls) {
  try { const a = await env.LEADS.get('avail:' + mls, { type: 'json' }); return (a && Array.isArray(a.dates)) ? a : null; } catch (e) { return null; }
}
async function bookedSlotSet(env, mls) {
  const set = {};
  try {
    const vidx = (await env.LEADS.get('vidx', { type: 'json' })) || [];
    for (const id of vidx.slice(0, 200)) {
      // vidx is newest-first (unshift on write), so the cap covers the most
      // recent bookings; one corrupt record must not abort the whole scan.
      try {
        const raw = await env.LEADS.get('viewing:' + id);
        if (!raw) continue;
        const v = JSON.parse(raw);
        if (v.listingId === mls && (v.status === 'new' || v.status === 'confirmed')) set[v.date + '|' + v.time] = true;
      } catch (e) {}
    }
  } catch (e) {}
  return set;
}
// Public view of a listing's availability: future dates only, booked slots removed.
// Returns null when the owner set no availability (all standard slots open).
async function publicAvail(env, mls) {
  return adminCached('avail:' + mls, function () { return publicAvailFresh(env, mls); });
}
function validLang(l) { const v = String(l || '').toLowerCase(); return ['en', 'fa', 'hi', 'zh'].indexOf(v) >= 0 ? v : 'en'; }
// Real-calendar date + 24h "HH:MM" time, not in the past (America/Vancouver),
// at most ~120 days out. Cycle 24: the old lower bound compared the DATE at
// UTC midnight minus 2 days, so a direct API call could book a slot earlier
// today (or yesterday); the time of day is compared now too.
function validSlot(date, time) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) return false;
  const t = Date.parse(date + 'T00:00:00Z');
  if (isNaN(t) || new Date(t).toISOString().slice(0, 10) !== date) return false;
  const nowD = new Date();
  const today = nowD.toLocaleDateString('en-CA', { timeZone: 'America/Vancouver' });
  const nowTime = nowD.toLocaleTimeString('en-CA', { timeZone: 'America/Vancouver', hourCycle: 'h23', hour: '2-digit', minute: '2-digit' });
  if (date < today || (date === today && time <= nowTime)) return false;
  return t <= Date.now() + 120 * 86400000;
}
// With no per-listing availability set, the confirmed site rules apply
// server-side too (cycle 24): the settings grid (default 08:00-19:00 every
// 30 min, end inclusive, matching the client) and Sundays off.
async function slotOnGrid(env, date, time) {
  const dow = new Date(Date.parse(date + 'T12:00:00Z')).getUTCDay();
  if (dow === 0) return false;
  const st = await getSiteSettings(env);
  const sl = (st && st.slots && st.slots.start) ? st.slots : { start: '08:00', end: '19:00', step: 30 };
  const mins = function (s) { return +String(s).slice(0, 2) * 60 + +String(s).slice(3); };
  const t = mins(time), a = mins(sl.start), b = mins(sl.end), step = (sl.step >= 5 && sl.step <= 120) ? sl.step : 30;
  return t >= a && t <= b && (t - a) % step === 0;
}
// An email counts as verified when the account came via Google, was verified
// through the emailed link, or predates the flag (verified field absent on an
// EXISTING record). A missing or corrupt record fails closed (cycle 24):
// sessions are only minted for existing users, so no record = account gone.
async function emailVerified(env, email) {
  const raw = await env.LEADS.get('user:' + email);
  if (!raw) return false;
  let u = null; try { u = JSON.parse(raw); } catch (e) {}
  if (!u) return false;
  return u.viaGoogle === true || u.verified !== false;
}
// Per-slot claim for viewings (KV has no CAS: this narrows the double-book
// race to a same-millisecond window; read-back keeps the loser out).
async function claimSlot(env, mls, date, time, vid) {
  const k = 'slot:' + mls + ':' + date + 'T' + time;
  const cur = await env.LEADS.get(k);
  if (cur && cur !== vid) {
    const r = await env.LEADS.get('viewing:' + cur, { type: 'json' });
    // Only a live viewing blocks the slot (same predicate as bookedSlotSet):
    // cancelled/done claims are stale and can be taken over. (An admin cancel
    // via PATCH never released the claim; this read is what frees it.)
    if (r && (r.status === 'new' || r.status === 'confirmed')) return false;
  }
  try { await env.LEADS.put(k, vid, { expirationTtl: 120 * 86400 }); } catch (e) { return false; }
  return (await env.LEADS.get(k)) === vid;
}
async function releaseSlot(env, mls, date, time, vid) {
  if (!mls || !date || !time) return;
  const k = 'slot:' + mls + ':' + date + 'T' + time;
  const cur = await env.LEADS.get(k);
  if (cur === vid) await env.LEADS.delete(k);
}
// Ingested (attacker-influenced) text: strip control + bidi-override chars so
// scraped listings can't smuggle invisible or direction-flipping content
// into the portal, then cap.
const CTRL_RE = /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u200b\u200e\u200f\u2028\u2029\u202a-\u202e\u2060\u2066-\u2069\ufeff]/g;
function cleanText(v, n) { return String(v == null ? '' : v).replace(CTRL_RE, ' ').trim().slice(0, n); }
// Ingested URL: parse it, http(s) only, no embedded credentials, no quotes
// or angle brackets; drop the fragment and tracking parameters so the
// dedupe hash is stable across re-posts of the same listing.
function safeUrl(raw, max) {
  try {
    const u = new URL(String(raw || '').trim());
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return '';
    if (u.username || u.password) return '';
    u.hash = '';
    for (const k of Array.from(u.searchParams.keys())) { if (/^(utm_|fbclid|gclid|mc_)/i.test(k)) u.searchParams.delete(k); }
    u.searchParams.sort();
    const h = u.href;
    return (h.length <= max && !/['"<>`]/.test(h)) ? h : '';
  } catch (e) { return ''; }
}
async function publicAvailFresh(env, mls) {
  const a = await getAvail(env, mls);
  if (!a || !a.dates.length) return null;
  const nowD = new Date();
  const today = nowD.toLocaleDateString('en-CA', { timeZone: 'America/Vancouver' });
  const nowTime = nowD.toLocaleTimeString('en-CA', { timeZone: 'America/Vancouver', hourCycle: 'h23', hour: '2-digit', minute: '2-digit' });
  const booked = await bookedSlotSet(env, mls);
  const dates = a.dates
    .filter(function (d) { return d && typeof d.date === 'string' && d.date >= today; })
    .map(function (d) { return { date: d.date, times: (d.times || []).filter(function (t) { return !booked[d.date + '|' + t] && (d.date !== today || t > nowTime); }) }; })
    .filter(function (d) { return d.times.length > 0; })
    .sort(function (x, y) { return x.date < y.date ? -1 : (x.date > y.date ? 1 : 0); });
  return dates;
}
// ---- per-user activity log (powers the contact timeline in the portal) ----
// KV uact:<normEmail> = [{ ts, kind, label }] newest first, cap 60.
async function pushActivity(env, email, kind, label) {
  try {
    if (!email) return;
    const key = 'uact:' + normEmail(email);
    const arr = (await env.LEADS.get(key, { type: 'json' })) || [];
    arr.unshift({ ts: new Date().toISOString(), kind: String(kind || '').slice(0, 32), label: String(label || '').slice(0, 160) });
    await env.LEADS.put(key, JSON.stringify(arr.slice(0, 60)));
  } catch (e) {}
}
async function allTasks(env) {
  const ids = await idxGet(env, 'tasks', 'task:', 300);
  const out = [];
  for (const id of ids) {
    try { const t = await env.LEADS.get('task:' + id, { type: 'json' }); if (t) out.push(t); } catch (e) {}
  }
  return out;
}

// ---- business calls (plumbing built Oct 2026; the dedicated number itself
// activates with the domain in Dec 2026 — config lives in KV cfg:calls =
// { provider, number, forwardTo, secret, twilioAccountSid, twilioAuthToken },
// written through the admin config endpoint; until then every route below is
// inert). One normalized storeCall() serves every provider: generic ingest
// (secret header) today, Twilio webhooks below, a VoIP.ms CDR adapter later.
function normPhone(v) {
  let d = String(v || '').replace(/[^0-9+]/g, '');
  if (d.startsWith('+')) d = '+' + d.slice(1).replace(/\+/g, '');
  const digits = d.replace(/\D/g, '');
  if (digits.length === 10) return '+1' + digits;
  if (digits.length === 11 && digits.charAt(0) === '1') return '+' + digits;
  return d.startsWith('+') ? d : (digits ? '+' + digits : '');
}
function phoneLast10(v) { return String(v || '').replace(/\D/g, '').slice(-10); }
async function getCallsCfg(env) { return (await env.LEADS.get('cfg:calls', { type: 'json' })) || null; }
async function matchPhoneEmail(env, phone) {
  const last = phoneLast10(phone);
  if (last.length < 10) return null;
  const uids = await idxGet(env, 'users', 'user:');
  for (const em of uids) {
    const u = await env.LEADS.get('user:' + em, { type: 'json' });
    if (u && u.email && phoneLast10(u.profile && u.profile.phone) === last) return { email: u.email, name: u.name || '' };
  }
  const lids = await idxGet(env, 'leads', 'lead:');
  for (const lid of lids) {
    const l = await env.LEADS.get('lead:' + lid, { type: 'json' });
    if (l && l.email && phoneLast10(l.phone) === last) return { email: l.email, name: l.name || '' };
  }
  return null;
}
async function storeCall(env, rec) {
  const prov = String(rec.provider || 'generic').slice(0, 20);
  const pcid = String(rec.providerCallId || '').slice(0, 80);
  if (!pcid) return { ok: false, error: 'providerCallId' };
  const id = 'call_' + (await sha256hex(prov + ':' + pcid)).slice(0, 20);
  const existing = await env.LEADS.get('call:' + id, { type: 'json' });
  const now = new Date().toISOString();
  const merged = Object.assign({}, existing || {}, {
    id: id, provider: prov, providerCallId: pcid,
    direction: rec.direction === 'out' ? 'out' : 'in',
    from: normPhone(rec.from), to: normPhone(rec.to),
    startedAt: String(rec.startedAt || (existing && existing.startedAt) || now).slice(0, 40),
    durationSec: Math.max(0, Math.min(86400, parseInt(rec.durationSec, 10) || 0)),
    status: ['completed', 'missed', 'voicemail', 'busy', 'failed', 'no-answer'].indexOf(rec.status) !== -1 ? rec.status : 'completed',
    recordingUrl: String(rec.recordingUrl || (existing && existing.recordingUrl) || '').slice(0, 600),
    transcript: String(rec.transcript || (existing && existing.transcript) || '').slice(0, 4000),
    created_at: (existing && existing.created_at) || now,
    updated_at: now
  });
  const isNew = !existing;
  if (isNew) {
    const other = merged.direction === 'in' ? merged.from : merged.to;
    const who = await matchPhoneEmail(env, other);
    if (who) { merged.matchedEmail = who.email; merged.matchedName = who.name || ''; }
  }
  await env.LEADS.put('call:' + id, JSON.stringify(merged));
  if (isNew) {
    await idxAdd(env, 'calls', id);
    if (merged.matchedEmail) {
      await pushActivity(env, merged.matchedEmail, 'call', (merged.direction === 'in' ? '📞 Incoming call' : '📞 Outgoing call') + ' · ' + merged.durationSec + 's · ' + merged.status);
    }
  }
  return { ok: true, id: id, created: isNew };
}
function escapeXml(s) { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
async function twilioSigOk(env, cfg, request, params) {
  if (!cfg || !cfg.twilioAuthToken) return false;
  const sig = request.headers.get('X-Twilio-Signature') || '';
  if (!sig) return false;
  const u = new URL(request.url);
  let data = 'https://' + u.host + u.pathname + u.search;
  const keys = Object.keys(params).sort();
  for (const k of keys) data += k + params[k];
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(cfg.twilioAuthToken), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const b64 = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(mac))));
  return timingSafeEqual(b64, sig);
}
async function readFormParams(request) {
  const params = {};
  try { const fd = await request.formData(); for (const e of fd.entries()) params[e[0]] = String(e[1]); } catch (e) {}
  return params;
}


// ---- business SMS (same plug-in pattern as calls) ------------------------
// Inbound texts are stored, matched to a CRM person, and (when configured) a
// copy is forwarded to Erfan's personal cell. His reply to that forwarded SMS
// arrives at the business number FROM his own number — the webhook detects
// it and relays it to the client from the business number, so he can run
// whole conversations from his phone's Messages app without the portal.
async function storeSms(env, rec) {
  const prov = String(rec.provider || 'generic').slice(0, 20);
  const pmid = String(rec.providerMsgId || '').slice(0, 80);
  if (!pmid) return { ok: false, error: 'providerMsgId' };
  const id = 'sms_' + (await sha256hex(prov + ':' + pmid)).slice(0, 20);
  const existing = await env.LEADS.get('sms:' + id, { type: 'json' });
  if (existing) return { ok: true, id: id, created: false };
  const now = new Date().toISOString();
  const atParsed = Date.parse(rec.at || '');
  const msg = {
    id: id, provider: prov, providerMsgId: pmid,
    direction: rec.direction === 'out' ? 'out' : 'in',
    from: normPhone(rec.from), to: normPhone(rec.to),
    body: String(rec.body || '').slice(0, 3200),
    media: Array.isArray(rec.media) ? rec.media.slice(0, 6).map(function (m) { return String(m).slice(0, 600); }) : [],
    at: isNaN(atParsed) ? now : new Date(atParsed).toISOString(),
    read: rec.direction === 'out' ? true : false,
    created_at: now
  };
  const other = msg.direction === 'in' ? msg.from : msg.to;
  const who = await matchPhoneEmail(env, other);
  if (who) { msg.matchedEmail = who.email; msg.matchedName = who.name || ''; }
  await env.LEADS.put('sms:' + id, JSON.stringify(msg));
  await idxAdd(env, 'sms', id);
  if (msg.matchedEmail) {
    await pushActivity(env, msg.matchedEmail, 'sms', (msg.direction === 'in' ? '💬 Text from client: ' : '💬 Text to client: ') + msg.body.slice(0, 120));
  }
  return { ok: true, id: id, created: true, msg: msg };
}
async function sendSms(env, cfg, to, body) {
  // Sends FROM the business number via the configured provider. Returns true
  // only when the provider accepted the message.
  try {
    if (!cfg || !cfg.number) return false;
    if (cfg.provider === 'twilio') {
      if (!cfg.twilioAccountSid || !cfg.twilioAuthToken) return false;
      const form = new URLSearchParams({ From: cfg.number, To: to, Body: String(body || '').slice(0, 1600) });
      const r = await fetch('https://api.twilio.com/2010-04-01/Accounts/' + encodeURIComponent(cfg.twilioAccountSid) + '/Messages.json', {
        method: 'POST', signal: AbortSignal.timeout(8000),
        headers: { Authorization: 'Basic ' + btoa(cfg.twilioAccountSid + ':' + cfg.twilioAuthToken), 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form.toString()
      });
      if (!r.ok) return false;
      const j = await r.json().catch(function () { return null; });
      return (j && j.sid) ? j.sid : true;
    }
    if (cfg.provider === 'voipms') {
      if (!cfg.voipmsUser || !cfg.voipmsPass) return false;
      const q = new URLSearchParams({ api_username: cfg.voipmsUser, api_password: cfg.voipmsPass, method: 'sendSMS', did: String(cfg.number).replace(/\D/g, ''), destination: String(to).replace(/\D/g, ''), message: String(body || '').slice(0, 1600) });
      const r = await fetch('https://voip.ms/api/v1/rest.php?' + q.toString(), { signal: AbortSignal.timeout(8000) });
      if (!r.ok) return false;
      const j = await r.json().catch(function () { return null; });
      return !!(j && j.status === 'success');
    }
  } catch (e) {}
  return false;
}
async function forwardSmsToOwner(env, cfg, msg) {
  // Copy of an inbound client text to Erfan's personal cell + remember which
  // client his next reply belongs to (24h relay window, latest texter wins;
  // with several simultaneous threads the portal thread stays unambiguous).
  if (!cfg || !cfg.forwardTo || cfg.smsForward === false) return;
  const label = msg.matchedName || msg.from;
  const sid = await sendSms(env, cfg, cfg.forwardTo, '💬 ' + label + ': ' + msg.body);
  if (sid) {
    try { await env.LEADS.put('smsrelay', JSON.stringify({ client: msg.from, at: Date.now() }), { expirationTtl: 24 * 3600 }); } catch (e) {}
  }
}

// ---- KV list-usage counter ------------------------------------------------
// The free plan caps list operations at 1,000/day (that is the budget that
// ran out on 2026-10-22). The worker counts its own app-traffic list calls
// (coalesced KV flush every 20) so maintenance can warn BEFORE the wall.
let listOpsToday = -1, listOpsDay = '', listOpsDirty = 0;
function vancouverDay() { try { return new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Vancouver', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date()); } catch (e) { return new Date().toISOString().slice(0, 10); } }
// KV daily quotas reset at midnight UTC, so the list-usage counter is keyed
// to the UTC day (cycle 25) — a Vancouver-day key lagged the real quota
// window by 7-8h and under-reported exactly when the warning mattered.
function utcDay() { return new Date().toISOString().slice(0, 10); }
async function countListOp(env) {
  const day = utcDay();
  if (listOpsDay !== day) { listOpsDay = day; listOpsToday = -1; listOpsDirty = 0; }
  if (listOpsToday < 0) {
    try { const u = await env.LEADS.get('usage:lists:' + day, { type: 'json' }); listOpsToday = (u && typeof u.count === 'number') ? u.count : 0; } catch (e) { listOpsToday = 0; }
  }
  listOpsToday++; listOpsDirty++;
  if (listOpsDirty >= 20) {
    listOpsDirty = 0;
    try { await env.LEADS.put('usage:lists:' + day, JSON.stringify({ count: listOpsToday, at: new Date().toISOString() }), { expirationTtl: 7 * 86400 }); } catch (e) {}
  }
}
async function kvList(env, opts) { await countListOp(env); return env.LEADS.list(opts); }
// ---- automatic whole-site backup (Cloudflare cron trigger) ----
// Erfan's rule (2026-10-23): from 2026-12-01 the worker backs ITSELF up
// nightly with zero human or agent involvement — a full dump of the LEADS
// namespace into backup:full:<day>, newest 30 kept, every run appended to
// backup:log (rendered on the portal Maintenance page) and backup:last
// refreshed. Excluded by design: the backups themselves (recursion), live
// login sessions and one-time codes (tok:/usess:/gcode: — they expire on
// their own and must never be archived), the volatile list-usage counter,
// scratch spaces (pano:/trash:), and EVERY key carrying a TTL (slot claims,
// SMS relay state, maintenance locks — a restore must never resurrect
// them). EVERYTHING else is in:
// leads, users, CRM deep data (cmeta:, task:), listings, site settings,
// configs (cfg:), availability, viewings, calls/SMS, mail queue, radar.
const BACKUP_START_DAY = '2026-12-01';
const BACKUP_KEEP = 30;
const BACKUP_SKIP_PREFIX = ['backup:full:', 'backup:log', 'backup:last', 'tok:', 'usess:', 'usage:lists:', 'pano:', 'trash:', 'gstate:', 'gcode:', 'maint:lock'];
async function runFullBackup(env, source) {
  const day = vancouverDay();
  if (day < BACKUP_START_DAY) return { skipped: 'before_start', day: day };
  const at = new Date().toISOString();
  try {
    const names = [];
    let cursor;
    do {
      const page = await kvList(env, { limit: 1000, cursor: cursor });
      for (const k of page.keys) {
        if (k.expiration) continue; // TTL keys must not be archived (see header)
        if (!BACKUP_SKIP_PREFIX.some(function (p) { return k.name.indexOf(p) === 0; })) names.push(k.name);
      }
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
    const kv = {};
    let kvChars = 0;
    for (let i = 0; i < names.length; i += 10) {
      const batch = names.slice(i, i + 10);
      const vals = await Promise.all(batch.map(function (n) { return env.LEADS.get(n); }));
      for (let j = 0; j < batch.length; j++) if (vals[j] !== null) { kv[batch[j]] = vals[j]; kvChars += vals[j].length; }
      // Abort during the load, before memory/CPU cliffs, not after stringify.
      if (kvChars > 12000000) throw new Error('backup too large: >' + kvChars + ' chars (aborted during load)');
    }
    const dump = { taken_at: at, day: day, source: source || 'cron', count: Object.keys(kv).length, kv: kv };
    const body = JSON.stringify(dump);
    const bodyBytes = new TextEncoder().encode(body).length;
    if (bodyBytes > 24000000) throw new Error('backup too large: ' + bodyBytes + ' bytes');
    await env.LEADS.put('backup:full:' + day, body);
    const back = await env.LEADS.get('backup:full:' + day);
    if (back !== body) throw new Error('backup verify failed after write');
    const bnames = [];
    let c2;
    do {
      const page = await kvList(env, { prefix: 'backup:full:', limit: 1000, cursor: c2 });
      for (const k of page.keys) bnames.push(k.name);
      c2 = page.list_complete ? undefined : page.cursor;
    } while (c2);
    const dated = bnames.filter(function (n) { return /^backup:full:\d{4}-\d{2}-\d{2}$/.test(n); });
    dated.sort().reverse();
    for (const old of dated.slice(BACKUP_KEEP)) await env.LEADS.delete(old);
    const stamp = { at: at, keys: dump.count, bytes: bodyBytes, note: source === 'cron' ? 'auto (worker cron)' : String(source || 'cron').slice(0, 40) };
    await env.LEADS.put('backup:last', JSON.stringify(stamp));
    const log = (await env.LEADS.get('backup:log', { type: 'json' })) || [];
    log.unshift({ day: day, at: at, ok: true, keys: dump.count, bytes: bodyBytes, source: stamp.note });
    await env.LEADS.put('backup:log', JSON.stringify(log.slice(0, 40)));
    return { ok: true, day: day, keys: dump.count, bytes: bodyBytes };
  } catch (e) {
    try {
      const log2 = (await env.LEADS.get('backup:log', { type: 'json' })) || [];
      log2.unshift({ day: day, at: at, ok: false, error: String((e && e.message) || e).slice(0, 160), source: source || 'cron' });
      await env.LEADS.put('backup:log', JSON.stringify(log2.slice(0, 40)));
    } catch (e2) {}
    return { ok: false, day: day, error: String((e && e.message) || e) };
  }
}


// ---- KV index keys -------------------------------------------------------
// List operations are the scarcest free-plan resource (1,000/day vs 100,000
// reads/day), so hot paths never enumerate by prefix. Each collection keeps
// ONE index key holding its member ids, maintained at write time; readers do
// 1 get for the index + 1 get per item. idxGet self-heals: a missing index is
// rebuilt with a single (rare) list and stored. Readers tolerate index
// entries whose item was deleted (they filter nulls).
async function idxGet(env, name, prefix, cap) {
  const raw = await env.LEADS.get('idx:' + name, { type: 'json' });
  if (Array.isArray(raw)) return raw.slice();
  const keys = await listAllKeys(env, prefix, cap || 5000);
  const ids = keys.map(function (k) { return String(k.name || k).slice(prefix.length); });
  try { await env.LEADS.put('idx:' + name, JSON.stringify(ids)); } catch (e) {}
  return ids;
}
async function idxAdd(env, name, id) {
  try {
    const raw = await env.LEADS.get('idx:' + name, { type: 'json' });
    if (!Array.isArray(raw)) return; // not built yet: idxGet builds from live keys, and the item is already written
    if (raw.indexOf(id) === -1) { raw.push(id); await env.LEADS.put('idx:' + name, JSON.stringify(raw)); }
  } catch (e) {}
}
async function idxRemove(env, name, id) {
  try {
    const raw = await env.LEADS.get('idx:' + name, { type: 'json' });
    if (!Array.isArray(raw)) return;
    const next = raw.filter(function (x) { return x !== id; });
    if (next.length !== raw.length) await env.LEADS.put('idx:' + name, JSON.stringify(next));
  } catch (e) {}
}
async function listAllKeys(env, prefix, cap) {
  const keys = [];
  let cursor;
  do {
    const page = await kvList(env, { prefix: prefix, limit: 1000, cursor: cursor });
    for (const k of page.keys) { keys.push(k); if (cap && keys.length >= cap) return keys; }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return keys;
}
async function buildContacts(env) {
  return adminCachedGen(env, 'contacts', function () { return buildContactsFresh(env); });
}

/* ================= site speed (maintenance gauge) ================= */
async function speedCheck(env) {
  const out = { at: new Date().toISOString() };
  const s0 = Date.now();
  try { await env.LEADS.get('site:settings'); out.kvOk = true; } catch (e) { out.kvOk = false; }
  out.kvMs = Date.now() - s0;
  async function fetchTimed(url) {
    const st = Date.now();
    try { const r = await fetch(url, { method: 'GET', signal: AbortSignal.timeout(8000) }); const txt = await r.text(); return { ms: Date.now() - st, bytes: new TextEncoder().encode(txt).length, status: r.status }; }
    catch (e) { return { ms: null, bytes: 0, status: 0 }; }
  }
  const both = await Promise.all([fetchTimed('https://real-estate-platform-0aei.onrender.com/'), fetchTimed('https://real-estate-platform-0aei.onrender.com/listings.html')]);
  const home = both[0], lst = both[1];
  out.homeMs = home.ms; out.homeKB = Math.round(home.bytes / 1024); out.homeStatus = home.status;
  out.listMs = lst.ms; out.listKB = Math.round(lst.bytes / 1024); out.listStatus = lst.status;
  let score = 100;
  if (out.kvOk === false) score -= 25;
  if (out.kvMs > 800) score -= 25; else if (out.kvMs > 300) score -= 10;
  if (home.status >= 400) score -= 60;
  if (lst.ms === null) score -= 15; else if (lst.status >= 400) score -= 15;
  if (home.ms === null) score -= 50;
  else if (home.ms > 2500) score -= 40; else if (home.ms > 1500) score -= 25; else if (home.ms > 900) score -= 10;
  if (lst.ms !== null) { if (lst.ms > 2500) score -= 15; else if (lst.ms > 1500) score -= 8; }
  if (out.homeKB > 450) score -= 12; else if (out.homeKB > 350) score -= 5;
  out.score = Math.max(0, Math.min(100, score));
  out.band = out.score >= 85 ? 'excellent' : out.score >= 65 ? 'good' : out.score >= 40 ? 'poor' : 'terrible';
  return out;
}

/* ================= CRM meta + AI ================= */
async function getCMeta(env, nk) { return (await env.LEADS.get('cmeta:' + nk, { type: 'json' })) || {}; }
async function saveCMeta(env, nk, meta) {
  await env.LEADS.put('cmeta:' + nk, JSON.stringify(meta));
  adminCache.delete('contacts'); adminCache.delete('desk'); adminCache.delete('crmmatches'); adminCache.delete('crmanalytics');
}
function parseBudget(text) {
  const s = String(text || '').replace(/,/g, '');
  function inRange(v) { return v >= 50000 && v <= 50000000 ? Math.round(v) : 0; }
  // Unit amounts ("900k", "1.2m", "$2 million"): take the LARGEST in-range
  // value — in a range like "800k-1.2m" the ceiling is the budget — and skip
  // a match used as a distance ("2 m from transit").
  let best = 0;
  const um = /(\d+(?:\.\d+)?)\s*(k|mm|m|million|thousand)\b/gi;
  let m;
  while ((m = um.exec(s)) !== null) {
    if (/^\s*from\b/i.test(s.slice(um.lastIndex))) continue;
    let v = parseFloat(m[1]);
    const u = m[2].toLowerCase();
    v *= (u === 'k' || u === 'thousand') ? 1000 : 1000000;
    const r = inRange(v);
    if (r > best) best = r;
  }
  if (best) return best;
  // Bare amounts: 5+ digits NOT glued to a letter — an MLS id like R2812345
  // is not a budget.
  const bare = s.match(/(?:^|[^A-Za-z0-9])(\d{5,}(?:\.\d+)?)(?![A-Za-z0-9])/);
  if (bare) { const r2 = inRange(parseFloat(bare[1])); if (r2) return r2; }
  return 0;
}
function todayVancouver() { try { return new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Vancouver', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date()); } catch (e) { return new Date().toISOString().slice(0, 10); } }
async function aiInternal(env, pathName, payload) {
  if (!/^\/[a-z0-9\/_-]+$/i.test(pathName)) return { ok: false, error: 'ai_path' };
  const bc = await env.LEADS.get('cfg:brief', { type: 'json' });
  if (!bc || !bc.secret) return { ok: false, error: 'ai_not_configured' };
  try {
    const ctl = new AbortController();
    const tm = setTimeout(function () { ctl.abort(); }, 30000);
    const fetcher = (env.AICHAT && typeof env.AICHAT.fetch === 'function') ? env.AICHAT.fetch.bind(env.AICHAT) : fetch;
    const r = await fetcher('https://ai-chat.erfanbillion.workers.dev' + pathName, {
      method: 'POST', signal: ctl.signal, redirect: 'error',
      headers: { 'Content-Type': 'application/json', Origin: 'https://real-estate-platform-0aei.onrender.com', 'X-Brief-Secret': String(bc.secret) },
      body: JSON.stringify(payload)
    });
    const j = await r.json().catch(function () { return null; });
    clearTimeout(tm);
    if (!r.ok || !j || !j.ok) return { ok: false, error: 'ai_unavailable' };
    return j;
  } catch (e) { return { ok: false, error: 'ai_unavailable' }; }
}
function crmBriefPayload(c) {
  return {
    name: c.name || '', lang: c.lang || 'en', tier: c.tier, score: c.score, stage: c.personStage,
    searches: (c.searches || []).slice(0, 10).map(function (s) { return { name: s.name || '', criteria: s.criteria || {} }; }),
    savedHomes: (c.savedHomes || []).map(function (h) { return { title: h.title, price: h.priceNow }; }),
    viewings: (c.viewings || []).slice(0, 10).map(function (v) { return { date: v.date, time: v.time, listing: v.listingId, status: v.status }; }),
    leads: (c.leads || []).slice(0, 10).map(function (l) { return { intent: l.intent || '', stage: l.stage, message: String(l.message || '').slice(0, 300), at: l.created_at }; }),
    recentActivity: (c.activity || []).slice(0, 10).map(function (a) { return { kind: a.kind, label: a.label || '', at: a.ts }; }),
    nextAction: c.nextAction ? c.nextAction.text : '', opportunities: c.opportunities || [],
    extracted: c.brief || null
  };
}
async function buildContactsFresh(env) {
  const byKey = Object.create(null);
  function entry(email) {
    const key = normEmail(email);
    if (!key || key.indexOf('@') < 1) return null;
    if (!byKey[key]) byKey[key] = { email: email, name: '', isUser: false, lang: '', phone: '', created_at: '', lastLogin: '', profile: null, savedCount: 0, searchCount: 0, leads: [], viewings: [], searches: [], logged: [], tasks: [], lastActivity: '', savedHomes: [] };
    return byKey[key];
  }
  const ulist = { keys: (await idxGet(env, 'users', 'user:', 5000)).map(function (id) { return { name: 'user:' + id }; }) };
  for (const k of ulist.keys) {
    const u = await env.LEADS.get(k.name, { type: 'json' });
    if (!u || !u.email) continue;
    const e = entry(u.email);
    if (!e) continue;
    e.isUser = true; e.name = u.name || e.name; e.lang = u.lang || e.lang; e.profile = u.profile || e.profile;
    if (!e.created_at || (u.created_at && u.created_at < e.created_at)) e.created_at = u.created_at || e.created_at;
    e.lastLogin = [e.lastLogin, u.lastLogin || ''].sort().pop();
    if (u.profile && u.profile.phone) e.phone = u.profile.phone;
    const svList = await userSaved(env, u.email);
    const svPrices = (await env.LEADS.get('usavep:' + u.email, { type: 'json' })) || {};
    for (const m of svList) if (!e.savedHomes.some(function (h) { return h.mls === m; })) e.savedHomes.push({ mls: m, priceThen: (typeof svPrices[m] === 'number' ? svPrices[m] : null), priceNow: null });
    e.savedCount = e.savedHomes.length;
    e.searches = e.searches.concat(await userSearches(env, u.email));
    e.searchCount = e.searches.length;
    e.lastActivity = [e.lastActivity, u.lastLogin || '', u.created_at || ''].sort().pop();
  }
  const llist = { keys: (await idxGet(env, 'leads', 'lead:', 5000)).map(function (id) { return { name: 'lead:' + id }; }) };
  for (const k of llist.keys) {
    const l = await env.LEADS.get(k.name, { type: 'json' });
    if (!l || !l.email) continue;
    const e = entry(l.email);
    if (!e) continue;
    e.leads.push({ id: l.id, created_at: l.created_at, intent: l.intent, stage: l.stage, message: l.message || '', source: l.source || '' });
    if (!e.name) e.name = l.name || '';
    if (l.phone && !e.phone) e.phone = l.phone;
    e.lastActivity = [e.lastActivity, l.created_at || ''].sort().pop();
  }
  const vidx = (await env.LEADS.get('vidx', { type: 'json' })) || [];
  for (const id of vidx.slice(0, 200)) {
    const v = await env.LEADS.get('viewing:' + id, { type: 'json' });
    if (!v || !v.email) continue;
    const e = entry(v.email);
    if (!e) continue;
    e.viewings.push({ id: v.id, date: v.date, time: v.time, listingId: v.listingId, status: v.status, created_at: v.created_at });
    if (!e.name) e.name = v.name || '';
    if (v.phone && !e.phone) e.phone = v.phone;
    e.lastActivity = [e.lastActivity, v.created_at || ''].sort().pop();
  }
  // Preload activity logs + tasks (async) before the sync scoring pass
  const taskList = await allTasks(env);
  const tasksByEmail = Object.create(null);
  for (const t of taskList) { const te = normEmail(t.email || ''); if (!te) continue; (tasksByEmail[te] = tasksByEmail[te] || []).push(t); }
  for (const key of Object.keys(byKey)) {
    byKey[key].logged = (await env.LEADS.get('uact:' + key, { type: 'json' })) || [];
    byKey[key].tasks = (tasksByEmail[key] || []).slice().sort(function (a, b) { return String(a.due).localeCompare(String(b.due)); });
  }
  // CRM joins: ban records + per-person meta (tags/notes/stage/AI brief fields)
  const banSet = Object.create(null);
  for (const bid of await idxGet(env, 'bans', 'ban:')) { const b = await env.LEADS.get('ban:' + bid, { type: 'json' }); if (b) banSet[bid] = b; }
  const metaByKey = Object.create(null);
  for (const key of Object.keys(byKey)) metaByKey[key] = (await env.LEADS.get('cmeta:' + key, { type: 'json' })) || null;
  // Duplicate merge: a person merged into another folds all their data in.
  function finalTarget(key) {
    const seen = Object.create(null); let cur = key;
    for (let i = 0; i < 10; i++) {
      const m = metaByKey[cur];
      if (!m || !m.mergedInto || m.mergedInto === cur || seen[cur]) return null;
      seen[cur] = 1; cur = m.mergedInto;
      if (!byKey[cur]) return null;
      const nm = metaByKey[cur];
      if (!nm || !nm.mergedInto) return cur;
    }
    return null;
  }
  // Resolve every merge target BEFORE folding anything (cycle 25): with
  // A→B→C, folding B into C first deleted B, and finalTarget(A) then found
  // no B and silently left A unmerged — insertion order decided the result.
  const targetOf = Object.create(null);
  for (const key of Object.keys(byKey)) {
    const meta0 = metaByKey[key];
    if (!meta0 || !meta0.mergedInto) continue;
    const ft0 = finalTarget(key);
    if (ft0 && ft0 !== key) targetOf[key] = ft0;
  }
  for (const key of Object.keys(targetOf)) {
    const ft = targetOf[key];
    const e = byKey[key], target = byKey[ft];
    target.isUser = target.isUser || e.isUser;
    if (!target.name) target.name = e.name;
    if (!target.phone) target.phone = e.phone;
    if (!target.lang) target.lang = e.lang;
    target.leads = target.leads.concat(e.leads);
    target.viewings = target.viewings.concat(e.viewings);
    target.searches = target.searches.concat(e.searches);
    target.logged = target.logged.concat(e.logged);
    target.tasks = target.tasks.concat(e.tasks).sort(function (a, b) { return String(a.due).localeCompare(String(b.due)); });
    for (const h of e.savedHomes) if (!target.savedHomes.some(function (x) { return x.mls === h.mls; })) target.savedHomes.push(h);
    target.savedCount = target.savedHomes.length;
    target.searchCount = target.searches.length;
    target.lastActivity = [target.lastActivity, e.lastActivity].sort().pop();
    if (!target.created_at || (e.created_at && e.created_at < target.created_at)) target.created_at = e.created_at;
    // Suppression survives a merge: a DNC flag or ban recorded on the
    // merged-away person keeps protecting the surviving contact.
    if (metaByKey[key] && metaByKey[key].dnc) metaByKey[ft] = Object.assign({}, metaByKey[ft] || {}, { dnc: true });
    if (banSet[key]) banSet[ft] = banSet[key];
    target.mergedEmails = (target.mergedEmails || []).concat([e.email]);
    delete byKey[key];
  }
  const now = Date.now();
  const todayStr = todayVancouver();
  const out = Object.values(byKey).map(function (e) {
    let score = 0;
    const scoreParts = [];
    function addPts(label, pts) { score += pts; scoreParts.push({ label: label, pts: pts }); }
    if (e.isUser) addPts('Has an account', 10);
    if (e.phone) addPts('Phone on file', 20);
    if (e.savedCount > 0) addPts('Saved homes', 15);
    if (e.searchCount > 0) addPts('Saved searches', 10);
    if (e.leads.length > 0) addPts('Sent a lead', 10);
    if (e.viewings.some(function (v) { return v.status !== 'cancelled'; })) addPts('Booked a viewing', 25);
    if (e.viewings.some(function (v) { return v.status === 'done'; })) addPts('Viewing completed', 10);
    score = Math.min(100, score);
    let followUp = null;
    const openLead = e.leads.filter(function (l) { return l.stage === 'new'; }).sort(function (a, b) { return String(a.created_at).localeCompare(String(b.created_at)); })[0];
    const openViewing = e.viewings.filter(function (v) { return v.status === 'new'; }).sort(function (a, b) { return String(a.created_at).localeCompare(String(b.created_at)); })[0];
    const cands = [openLead ? { t: openLead.created_at, k: 'lead' } : null, openViewing ? { t: openViewing.created_at, k: 'viewing' } : null]
      .filter(function (x) { return x && !isNaN(Date.parse(x.t)); })
      .sort(function (a, b) { return Date.parse(a.t) - Date.parse(b.t); });
    if (cands.length) {
      const hrs = Math.floor((now - Date.parse(cands[0].t)) / 3600000);
      if (hrs >= 24) followUp = { since: cands[0].t, hours: hrs, kind: cands[0].k };
    }
    e.leads.sort(function (a, b) { return String(b.created_at).localeCompare(String(a.created_at)); });
    e.viewings.sort(function (a, b) { return String(b.date + ' ' + b.time).localeCompare(String(a.date + ' ' + a.time)); });
    const acts = [];
    if (e.isUser && e.created_at) acts.push({ ts: e.created_at, kind: 'registered', label: '' });
    for (const l of e.leads) acts.push({ ts: l.created_at, kind: 'lead', label: ((l.intent || '') + (l.source ? ' · ' + l.source : '')).slice(0, 160) });
    for (const v of e.viewings) acts.push({ ts: v.created_at, kind: 'viewing', label: (v.date + ' ' + v.time + ' · ' + (v.listingId || '') + ' · ' + v.status).slice(0, 160) });
    for (const s of (e.searches || [])) if (s.created_at) acts.push({ ts: s.created_at, kind: 'search', label: s.name || '' });
    for (const a of (e.logged || [])) acts.push(a);
    acts.sort(function (a, b) { return String(b.ts).localeCompare(String(a.ts)); });
    // ---- CRM enrichment ----
    const nk = normEmail(e.email);
    const meta = metaByKey[nk] || null;
    const homes = e.savedHomes.map(function (h) {
      const cat = catalogByMls(h.mls);
      return { mls: h.mls, priceThen: h.priceThen, priceNow: cat ? cat.price : null, title: cat ? (cat.street + ', ' + cat.city) : h.mls };
    });
    const opportunities = [];
    for (const h of homes) if (h.priceThen && h.priceNow && h.priceThen > h.priceNow) opportunities.push({ kind: 'price_drop', mls: h.mls, title: h.title, was: h.priceThen, now: h.priceNow });
    const savedSet = Object.create(null); homes.forEach(function (h) { savedSet[h.mls] = 1; });
    for (const s of (e.searches || [])) {
      const fresh = matchSearch(s.criteria || {}).filter(function (m) { return (s.notified || []).indexOf(m) === -1 && !savedSet[m]; });
      if (fresh.length) opportunities.push({ kind: 'new_match', mls: fresh[0], count: fresh.length, searchName: s.name || '' });
    }
    // behavioural prediction (transparent heuristic over the activity trail)
    const tsList = acts.map(function (a) { return Date.parse(a.ts || ''); }).filter(function (t) { return !isNaN(t); });
    const daysSince = tsList.length ? Math.floor((now - Math.max.apply(null, tsList)) / 86400000) : 999;
    const ev30 = tsList.filter(function (t) { return now - t < 30 * 86400000; }).length;
    const evPrev = tsList.filter(function (t) { return now - t >= 30 * 86400000 && now - t < 60 * 86400000; }).length;
    const trend = ev30 > evPrev + 1 ? 'rising' : (ev30 === 0 && evPrev >= 2 ? 'cooling' : 'steady');
    const upcomingV = e.viewings.some(function (v) { return v.status !== 'cancelled' && v.status !== 'done' && v.date >= todayStr; });
    let predict = Math.round(score * 0.6 + Math.min(ev30, 10) * 3 + (upcomingV ? 12 : 0) + (score >= 60 ? 8 : 0) - (daysSince > 21 ? 15 : daysSince > 10 ? 7 : 0));
    predict = Math.max(2, Math.min(97, predict));
    const coldRisk = score >= 30 && daysSince >= 10 && daysSince !== 999 && (evPrev >= 2 || score >= 60);
    // person stage: furthest lead stage, overridable in meta
    const stageRank = { new: 0, contacted: 1, viewing: 2, offer: 3, closed: 4, dropped: -1 };
    let stageAuto = 'new';
    for (const l of e.leads) if ((stageRank[l.stage] !== undefined ? stageRank[l.stage] : -1) > (stageRank[stageAuto] !== undefined ? stageRank[stageAuto] : -1)) stageAuto = l.stage;
    if (stageAuto === 'new' && e.leads.length && e.leads.every(function (l) { return l.stage === 'dropped'; })) stageAuto = 'dropped';
    const personStage = (meta && meta.stage) || stageAuto;
    // next best action (first matching rule wins)
    let nextAction = null;
    const overdueTask = (e.tasks || []).filter(function (t) { return !t.done && t.due < todayStr; })[0];
    const doneRecent = e.viewings.filter(function (v) { return v.status === 'done'; }).sort(function (a, b) { return String(b.date).localeCompare(String(a.date)); })[0];
    if (banSet[nk]) nextAction = { kind: 'banned', text: 'Banned address — no outreach' };
    else if (meta && meta.dnc) nextAction = { kind: 'dnc', text: 'Do not contact — marked DNC' };
    else if (followUp) nextAction = { kind: 'call', text: 'Follow up now — ' + followUp.kind + ' waiting ' + followUp.hours + 'h' };
    else if (overdueTask) nextAction = { kind: 'task', text: 'Overdue task: ' + overdueTask.text };
    else if (upcomingV) { const uv = e.viewings.filter(function (v) { return v.status !== 'cancelled' && v.status !== 'done'; }).sort(function (a, b) { return String(a.date + a.time).localeCompare(String(b.date + b.time)); })[0]; nextAction = { kind: 'prepare', text: 'Prepare for the viewing on ' + (uv ? uv.date + ' ' + uv.time : '') }; }
    else if (doneRecent && (now - Date.parse(doneRecent.date)) >= 0 && (now - Date.parse(doneRecent.date)) < 7 * 86400000) nextAction = { kind: 'feedback', text: 'Ask for feedback on the ' + doneRecent.date + ' viewing' };
    else if (opportunities.length) nextAction = { kind: 'opportunity', text: opportunities[0].kind === 'price_drop' ? 'Tell them: a saved home dropped in price' : 'Send them the new matching listing' };
    else if (coldRisk) nextAction = { kind: 'reengage', text: 'Re-engage — this contact is going cold' };
    else if (e.savedCount >= 3 && !e.viewings.length) nextAction = { kind: 'invite', text: 'Invite them to book a viewing' };
    return Object.assign({}, e, { score: score, scoreParts: scoreParts, tier: score >= 60 ? 'hot' : (score >= 30 ? 'warm' : 'cold'), tags: contactTags(e), followUp: (banSet[nk] || (meta && meta.dnc)) ? null : followUp, activity: acts.slice(0, 25), openTasks: (e.tasks || []).filter(function (t) { return !t.done; }),
      savedHomes: homes, banned: !!banSet[nk], banReason: banSet[nk] ? (banSet[nk].reason || '') : '', customTags: (meta && meta.tags) || [], notes: (meta && meta.notes) || [], personStage: personStage, stageAuto: stageAuto,
      brief: (meta && meta.brief) || null, dnc: !!(meta && meta.dnc), mergedEmails: e.mergedEmails || [], opportunities: (banSet[nk] || (meta && meta.dnc)) ? [] : opportunities,
      predict: predict, trend: trend, coldRisk: coldRisk, daysSinceActivity: daysSince === 999 ? null : daysSince, nextAction: nextAction });
  });
  // duplicate candidates: same phone, or same name on different emails
  const byPhone = Object.create(null), byName = Object.create(null);
  for (const c of out) {
    const ph = phoneLast10(c.phone || ''); if (ph.length >= 10) (byPhone[ph] = byPhone[ph] || []).push(c);
    const nm = String(c.name || '').trim().toLowerCase();
    if (nm.length >= 4) (byName[nm] = byName[nm] || []).push(c);
  }
  for (const c of out) {
    const dups = Object.create(null);
    const ph2 = phoneLast10(c.phone || ''); if (ph2.length >= 10) for (const o of (byPhone[ph2] || [])) if (o !== c) dups[normEmail(o.email)] = o.email;
    const nm = String(c.name || '').trim().toLowerCase();
    if (nm.length >= 4) for (const o of (byName[nm] || [])) if (o !== c) dups[normEmail(o.email)] = o.email;
    c.dupWith = Object.values(dups);
  }
  out.sort(function (a, b) { return (b.score - a.score) || String(b.lastActivity).localeCompare(String(a.lastActivity)); });
  return out;
}

// ---- Google Calendar service-account bridge (viewing invites) ----
function pemToDer(pem) {
  const b64 = String(pem).replace(/-----BEGIN PRIVATE KEY-----/, '').replace(/-----END PRIVATE KEY-----/, '').replace(/\s+/g, '');
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function b64urlOf(bytes) {
  const arr = new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
let gTokCache = { email: '', tok: null, exp: 0 };
let gTokErr = '';
async function gcalAccessToken(sa) {
  const now = Math.floor(Date.now() / 1000);
  if (gTokCache.tok && gTokCache.email === sa.client_email && now < gTokCache.exp - 300) return gTokCache.tok;
  const enc = new TextEncoder();
  const head = b64urlOf(enc.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const claim = b64urlOf(enc.encode(JSON.stringify({ iss: sa.client_email, scope: 'https://www.googleapis.com/auth/calendar.events', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 })));
  const key = await crypto.subtle.importKey('pkcs8', pemToDer(sa.private_key), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(head + '.' + claim));
  const jwt = head + '.' + claim + '.' + b64urlOf(sig);
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + jwt, signal: AbortSignal.timeout(8000) });
  const j = await r.json().catch(function () { return null; });
  if (j && j.access_token) { gTokCache = { email: sa.client_email, tok: j.access_token, exp: now + (j.expires_in || 3600) }; gTokErr = ''; return j.access_token; }
  gTokErr = String((j && (j.error_description || j.error)) || 'no_token').slice(0, 150);
  return null;
}
function plus30(date, time) {
  let pr = date.split('-').map(Number); let y = pr[0], mo = pr[1], dd = pr[2];
  pr = time.split(':').map(Number); let hh = pr[0], mm = pr[1] + 30;
  if (mm >= 60) { mm -= 60; hh += 1; }
  if (hh >= 24) { hh -= 24; const dt = new Date(Date.UTC(y, mo - 1, dd + 1)); y = dt.getUTCFullYear(); mo = dt.getUTCMonth() + 1; dd = dt.getUTCDate(); }
  const p = function (n) { return String(n).padStart(2, '0'); };
  return y + '-' + p(mo) + '-' + p(dd) + 'T' + p(hh) + ':' + p(mm) + ':00';
}
async function gcalCtx(env) {
  const sa = await env.LEADS.get('cfg:gcal', { type: 'json' });
  if (!sa || !sa.client_email || !sa.private_key) return null;
  const tok = await gcalAccessToken(sa);
  if (!tok) return null;
  return { sa: sa, tok: tok, calId: encodeURIComponent(sa.calendarId || 'primary') };
}
async function gcalDeleteEvent(env, eventId) {
  try {
    const g = await gcalCtx(env);
    if (!g || !eventId) return false;
    const r = await fetch('https://www.googleapis.com/calendar/v3/calendars/' + g.calId + '/events/' + encodeURIComponent(eventId) + '?sendUpdates=all', { method: 'DELETE', headers: { 'Authorization': 'Bearer ' + g.tok }, signal: AbortSignal.timeout(8000) });
    return r.ok || r.status === 404 || r.status === 410;
  } catch (e) { return false; }
}
async function gcalPatchEventTimes(env, eventId, date, time) {
  try {
    const g = await gcalCtx(env);
    if (!g || !eventId) return false;
    const r = await fetch('https://www.googleapis.com/calendar/v3/calendars/' + g.calId + '/events/' + encodeURIComponent(eventId) + '?sendUpdates=all', { method: 'PATCH', headers: { 'Authorization': 'Bearer ' + g.tok, 'Content-Type': 'application/json' }, body: JSON.stringify({ start: { dateTime: date + 'T' + time + ':00', timeZone: 'America/Vancouver' }, end: { dateTime: plus30(date, time), timeZone: 'America/Vancouver' } }), signal: AbortSignal.timeout(8000) });
    return r.ok;
  } catch (e) { return false; }
}
async function gcalStamp(env, ok, eventId, error) {
  try {
    const rec = ok ? { ok: true, at: new Date().toISOString(), eventId: eventId || null } : { ok: false, at: new Date().toISOString(), error: String(error || 'unknown error').slice(0, 200) };
    await env.LEADS.put('gcal:last', JSON.stringify(rec));
  } catch (e) {}
}
async function gcalCreateViewing(env, sa, b) {
  // Google forbids service accounts from inviting attendees on their OWN
  // calendar (403 forbiddenForServiceAccounts, no DWD on consumer Gmail).
  // Preferred setup: cfg:gcal carries calendarId = one of Erfan's calendars
  // shared with the SA as writer — events land directly in his calendar.
  // Fallbacks keep the event landing somewhere and record the failure at
  // KV key gcalerr for diagnosis (readable via /api/admin/config?key=gcalerr).
  try {
    const tok = await gcalAccessToken(sa);
    if (!tok) { await env.LEADS.put('gcalerr', JSON.stringify({ at: new Date().toISOString(), step: 'token', error: gTokErr })); await gcalStamp(env, false, null, gTokErr || 'token'); return; }
    const L = b.listing;
    const addr = L ? (L.street + ', ' + L.city) : 'the booked home';
    const ev = {
      summary: 'Showing \u2014 ' + addr + (L ? ' (MLS ' + L.mls + ')' : ''),
      id: b.eventId || undefined,
      location: L ? (L.street + ', ' + L.city + ', BC') : '',
      description: 'Booked via the website.\nVisitor: ' + String(b.name || '').replace(/[\r\n<>]+/g, ' ') + ' <' + String(b.email || '').replace(/[\r\n<>]+/g, ' ') + '>\nPhone: ' + String(b.phone || '-').replace(/[\r\n<>]+/g, ' ') + '\nViewing ID: ' + b.id + '\nManage in the Site Admin portal, Viewings tab.',
      start: { dateTime: b.date + 'T' + b.time + ':00', timeZone: 'America/Vancouver' },
      end: { dateTime: plus30(b.date, b.time), timeZone: 'America/Vancouver' },
      attendees: sa.calendarId ? [{ email: b.email }] : [{ email: b.email }, { email: 'erfanbcrealestate@gmail.com' }]
    };
    const calId = encodeURIComponent(sa.calendarId || 'primary');
    let r = await fetch('https://www.googleapis.com/calendar/v3/calendars/' + calId + '/events?sendUpdates=all', { method: 'POST', headers: { 'Authorization': 'Bearer ' + tok, 'Content-Type': 'application/json' }, body: JSON.stringify(ev), signal: AbortSignal.timeout(8000) });
    if (r.status === 409 && b.eventId) { await gcalStamp(env, true, b.eventId); return b.eventId; } // deterministic id already created (retry)
    if (r.ok) { const j = await r.json().catch(function () { return null; }); await gcalStamp(env, true, (j && j.id) || b.eventId || null); return j && j.id ? j.id : null; }
    if (!r.ok) {
      const body1 = (await r.text().catch(function () { return ''; })).slice(0, 300);
      const status1 = r.status;
      if (r.status === 403 || r.status === 400) {
        const ev2 = Object.assign({}, ev); delete ev2.attendees;
        r = await fetch('https://www.googleapis.com/calendar/v3/calendars/' + calId + '/events?sendUpdates=none', { method: 'POST', headers: { 'Authorization': 'Bearer ' + tok, 'Content-Type': 'application/json' }, body: JSON.stringify(ev2), signal: AbortSignal.timeout(8000) });
        if (r.ok) { await env.LEADS.put('gcalerr', JSON.stringify({ at: new Date().toISOString(), step: 'insert-no-attendees', note: 'attendees forbidden; event created without them', first: body1 })); const j2 = await r.json().catch(function () { return null; }); await gcalStamp(env, true, (j2 && j2.id) || b.eventId || null); return j2 && j2.id ? j2.id : null; }
      }
      await env.LEADS.put('gcalerr', JSON.stringify({ at: new Date().toISOString(), step: 'insert', status: r.status, firstStatus: status1, body: body1 }));
      await gcalStamp(env, false, null, 'insert ' + r.status + ': ' + body1.slice(0, 150));
    }
    return null;
  } catch (e) {
    try { await env.LEADS.put('gcalerr', JSON.stringify({ at: new Date().toISOString(), step: 'exception', message: String(e && e.message || e).slice(0, 200) })); } catch (e2) {}
    await gcalStamp(env, false, null, String(e && e.message || e).slice(0, 200));
    return null;
  }
}

async function turnstileOk(env, token, ip) {
  if (!token) return false;
  const tok = String(token).slice(0, 2048);
  if (env.TURNSTILE_SECRET_KEY) {
    try {
      const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'secret=' + encodeURIComponent(env.TURNSTILE_SECRET_KEY) + '&response=' + encodeURIComponent(tok) + (ip ? '&remoteip=' + encodeURIComponent(ip) : ''),
        signal: AbortSignal.timeout(8000)
      });
      const j = await r.json();
      return !!(j && j.success && (!j.hostname || TS_HOSTS.indexOf(j.hostname) !== -1));
    } catch (e) { return false; }
  }
  if (env.NEWSLETTER) {
    // No own secret configured: verify through the newsletter worker, which
    // already holds the Turnstile secret (service binding, not public fetch).
    try {
      const icfg = await env.LEADS.get('cfg:internal', { type: 'json' }).catch(() => null);
      const iHeaders = { 'Content-Type': 'application/json' };
      if (icfg && icfg.secret) iHeaders['X-Internal-Secret'] = String(icfg.secret);
      const r = await env.NEWSLETTER.fetch('https://newsletter.internal/internal/verify', {
        method: 'POST',
        headers: iHeaders,
        body: JSON.stringify({ token: tok }),
        signal: AbortSignal.timeout(8000)
      });
      const j = await r.json();
      return !!(j && j.success);
    } catch (e) { return false; }
  }
  return false; // fail closed: no verification path configured (a config slip must not silently disable the captcha)
}

async function handleRequest(request, env, ctx) {
    const origin = request.headers.get('Origin');
    const url = new URL(request.url);
    const path = url.pathname;
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors(origin) });
    if (origin && !ALLOWED_ORIGINS.includes(origin)) {
      return new Response(JSON.stringify({ ok: false, error: 'forbidden' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
    }
    if (request.method === 'POST' || request.method === 'PATCH' || request.method === 'PUT') {
      const cl = parseInt(request.headers.get('Content-Length') || '0', 10);
      const capLimit = (path.indexOf('/api/admin/listings') === 0 || path === '/api/admin/settings') ? 3145728 : 32768;
      if (cl > capLimit) return json({ ok: false, error: 'too_large' }, 413, origin); // a missing Content-Length is NOT rejected: several legitimate clients don't expose one
    }
    if ((request.method === 'POST' || request.method === 'PATCH' || request.method === 'PUT') && !request.headers.get('Content-Length')) {
      // Cycle 26 (Claude M2): chunked bodies used to bypass the cap entirely
      // and request.json() buffered them whole. Count the clone's bytes up
      // front and reject past the same cap; the original body stays unread.
      const cap2 = (path.indexOf('/api/admin/listings') === 0 || path === '/api/admin/settings') ? 3145728 : 32768;
      try {
        const reader = request.clone().body.getReader();
        let n = 0;
        for (;;) {
          const r = await reader.read();
          if (r.done) break;
          n += r.value.byteLength;
          if (n > cap2) { try { await reader.cancel(); } catch (e) {} return json({ ok: false, error: 'too_large' }, 413, origin); }
        }
      } catch (e) {}
    }
    let ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    ip = ipKey(ip); // aggregate IPv6 by /64 so one network can't rotate addresses past the rate limits
    // Admin-cache generation bump: handled by the fetch wrapper in the
    // default export below, AFTER the response is known (cycle 26, H1).
    if (path.indexOf('/api/') === 0 && path !== '/api/track') { try { await refreshCustomCatalog(env, false); } catch (e) {} }
    try {
      // ---- public: health ----
      if (path === '/api/health') {
        return json({ ok: true }, 200, origin);
      }

      // ---- public: submit a lead (site contact form) ----
      if (path === '/api/lead' && request.method === 'POST') {
        if (limited(ip, 5, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        if (String(d.hp || '') !== '') return json({ ok: true }, 200, origin); // honeypot: silently drop bots
        if (!(await turnstileOk(env, d.turnstileToken, ip))) return json({ ok: false, error: 'captcha' }, 400, origin);
        const name = String(d.name || '').trim().slice(0, 120);
        if (/[\r\n<>]|https?:|www\./i.test(name)) return json({ ok: false, error: 'validation' }, 400, origin);
        const intent = String(d.intent || '').trim().toLowerCase();
        const city = String(d.city || '').trim().slice(0, 80);
        const budget = String(d.budget || '').trim().slice(0, 40);
        const email = String(d.email || '').trim().toLowerCase().slice(0, 160);
        const phone = String(d.phone || '').trim().slice(0, 40);
        const message = String(d.message || '').trim().slice(0, 2000);
        const source = String(d.source || 'site-form').trim().slice(0, 40);
        if (!name || !INTENTS.includes(intent)) return json({ ok: false, error: 'validation' }, 400, origin);
        if (email && !EMAIL_RE.test(email)) return json({ ok: false, error: 'validation' }, 400, origin);
        if (!email && !phone) return json({ ok: false, error: 'validation' }, 400, origin);
        if (phone && !/^[+\d][\d\s().-]{6,39}$/.test(phone)) return json({ ok: false, error: 'validation' }, 400, origin);
        if (email && (await isBanned(env, email))) return json({ ok: true }, 200, origin); // banned: silently drop
        const id = Date.now().toString(36) + '-' + randHex(6);
        const lead = {
          id: id, created_at: new Date().toISOString(),
          name: name, intent: intent, city: city, budget: budget,
          email: email, phone: phone, message: message,
          stage: 'new', notes: '', source: source
        };
        await env.LEADS.put('lead:' + id, JSON.stringify(lead));
        await idxAdd(env, 'leads', id);
        if (email) {
          await queueMail(env, { kind: 'followup', to: email, lang: validLang(d.lang), name: name, ref: id });
        }
        return json({ ok: true }, 200, origin);
      }

      // ---- public: lightweight site-traffic beacon (aggregates only, no raw logs) ----
      if (path === '/api/track' && request.method === 'POST') {
        if (limited(ip, 600, 3600000)) return json({ ok: true }, 200, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const day = new Date().toLocaleDateString('en-CA', { timeZone: 'America/Vancouver' });
        // Aggregate into the in-isolate buffer; flushed to KV in batches by
        // flushTrack (same 'stat:<day>' key and doc shape as before).
        if (!trackBuf || trackBuf.day !== day) {
          if (trackBuf && trackBuf.events > 0) { const p0 = flushTrack(env); if (ctx && ctx.waitUntil) ctx.waitUntil(p0); }
          const fresh = { day: day, doc: null, events: 0, firstTs: 0, loading: null, uvCount: 0 };
          fresh.loading = env.LEADS.get('stat:' + day, { type: 'json' })
            .then(function (dd) { fresh.doc = dd || { pv: {}, ev: {}, li: {}, lang: {}, ref: {}, uv: {} }; fresh.uvCount = Object.keys(fresh.doc.uv || {}).length; })
            .catch(function () { fresh.doc = { pv: {}, ev: {}, li: {}, lang: {}, ref: {}, uv: {} }; fresh.loadFailed = true; });
          trackBuf = fresh;
        }
        if (!trackBuf.doc) await trackBuf.loading;
        const doc = trackBuf.doc;
        const type = String(d.type || 'pageview').slice(0, 30);
        const page = String(d.page || '').slice(0, 80);
        if (type === 'pageview' && page) bumpC(doc.pv, page, 300);
        if (type === 'event') {
          const ev = String(d.event || '').slice(0, 40);
          if (ev) {
            bumpC(doc.ev, ev, 100);
            if (ev === 'listing_view' && d.listingId) {
              const lid = String(d.listingId).slice(0, 40);
              bumpC(doc.li, lid, 100);
            }
          }
        }
        const lang = String(d.lang || '').slice(0, 5);
        if (lang) bumpC(doc.lang, lang, 20);
        const ref = String(d.ref || '').slice(0, 80);
        if (type === 'pageview' && ref) bumpC(doc.ref, ref, 200);
        const ua = request.headers.get('User-Agent') || '';
        const uh = (await sha256hex(ip + '|' + ua + '|' + day)).slice(0, 16);
        if (!Object.prototype.hasOwnProperty.call(doc.uv, uh) && (trackBuf.uvCount || 0) < 5000) { doc.uv[uh] = 1; trackBuf.uvCount = (trackBuf.uvCount || 0) + 1; }
        trackBuf.events++;
        if (!trackBuf.firstTs) trackBuf.firstTs = Date.now();
        if (trackBuf.events >= TRACK_FLUSH_EVENTS || Date.now() - trackBuf.firstTs >= TRACK_FLUSH_MS) {
          const p = flushTrack(env);
          if (ctx && ctx.waitUntil) ctx.waitUntil(p);
        }
        return json({ ok: true }, 200, origin);
      }

      // ---- newsletter subscribers (public subscribe; mirrored from the site form) ----
      if (path === '/api/newsletter/subscribe' && request.method === 'POST') {
        if (limited('nl:' + ip, 10, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const nname = String(d.name || '').trim().slice(0, 120);
        const nemail = String(d.email || '').trim().toLowerCase().slice(0, 160);
        const nlang = ['en', 'fa', 'hi', 'zh'].includes(String(d.lang || '').toLowerCase()) ? String(d.lang).toLowerCase() : 'en';
        if (!EMAIL_RE.test(nemail)) return json({ ok: false, error: 'validation' }, 400, origin);
        if (await isBanned(env, nemail)) return json({ ok: true }, 200, origin); // banned: silently accept, store nothing
        const existing = await env.LEADS.get('nlsub:' + nemail);
        if (!existing) {
          await env.LEADS.put('nlsub:' + nemail, JSON.stringify({ name: nname, email: nemail, lang: nlang, created_at: new Date().toISOString() }));
          await idxAdd(env, 'nlsubs', nemail);
        }
        return json({ ok: true }, 200, origin);
      }

      // ---- Google sign-in (public) ----
      if (path === '/api/user/google/start' && request.method === 'GET') {
        // Top-level navigation: errors return to the site as #gerror, never raw JSON.
        const gfail = () => Response.redirect('https://real-estate-platform-0aei.onrender.com/listings.html#gerror=auth', 302);
        if (limited(ip, 30, 3600000)) return gfail();
        const cfg = await env.LEADS.get('cfg:google', { type: 'json' });
        if (!cfg || !cfg.clientId) return gfail();
        const gch = String(url.searchParams.get('c') || '');
        if (!/^[0-9a-f]{64}$/.test(gch)) return gfail();
        const state = randHex(24);
        await env.LEADS.put('gstate:' + state, JSON.stringify({ at: Date.now(), c: gch }), { expirationTtl: 1800 });
        const ru = 'https://advisor-api.erfanbillion.workers.dev/api/user/google/callback';
        const gu = 'https://accounts.google.com/o/oauth2/v2/auth?client_id=' + encodeURIComponent(cfg.clientId) + '&redirect_uri=' + encodeURIComponent(ru) + '&response_type=code&scope=' + encodeURIComponent('openid email profile') + '&state=' + state + '&prompt=select_account';
        const gresp = Response.redirect(gu, 302);
        const gh = new Headers(gresp.headers);
        gh.set('Set-Cookie', 'gst=' + state + '; Max-Age=1800; Path=/api/user/google; HttpOnly; Secure; SameSite=Lax');
        return new Response(null, { status: 302, headers: gh });
      }
      if (path === '/api/user/google/callback' && request.method === 'GET') {
        const SITE = 'https://real-estate-platform-0aei.onrender.com/listings.html';
        const fail = (e) => { const fh = new Headers(); fh.set('Location', SITE + '#gerror=' + e); fh.set('Set-Cookie', 'gst=; Max-Age=0; Path=/api/user/google; HttpOnly; Secure; SameSite=Lax'); fh.set('Cache-Control', 'no-store'); return new Response(null, { status: 302, headers: fh }); };
        const cfg = await env.LEADS.get('cfg:google', { type: 'json' });
        if (!cfg || !cfg.clientId || !cfg.clientSecret) return fail('auth');
        const code = url.searchParams.get('code') || ''; const state = url.searchParams.get('state') || '';
        if (!code || !state) return fail('auth');
        const gstMatch = /(?:^|; )gst=([0-9a-f]{48})/.exec(request.headers.get('Cookie') || '');
        if (!gstMatch || gstMatch[1] !== state) return fail('auth');
        const sraw = await env.LEADS.get('gstate:' + state);
        if (!sraw) return fail('auth');
        await env.LEADS.delete('gstate:' + state);
        let gch2 = '';
        try { gch2 = String(JSON.parse(sraw).c || ''); } catch (e) {}
        if (!/^[0-9a-f]{64}$/.test(gch2)) return fail('auth');
        const ru = 'https://advisor-api.erfanbillion.workers.dev/api/user/google/callback';
        const tres = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ code: code, client_id: cfg.clientId, client_secret: cfg.clientSecret, redirect_uri: ru, grant_type: 'authorization_code' }), signal: AbortSignal.timeout(8000) });
        const tj = await tres.json().catch(() => ({}));
        if (!tj.id_token) return fail('auth');
        const vres = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(tj.id_token), { signal: AbortSignal.timeout(8000) });
        const vj = await vres.json().catch(() => ({}));
        if (vj.aud !== cfg.clientId || String(vj.email_verified) !== 'true' || !vj.email) return fail('auth');
        const email = String(vj.email).toLowerCase();
        if (await isBanned(env, email)) return fail('banned');
        let user = null;
        const raw = await env.LEADS.get('user:' + email);
        if (raw) { try { user = JSON.parse(raw); } catch (e) {} }
        let uDirty = false;
        if (!user) {
          const loc = String(vj.locale || '').slice(0, 2);
          user = { name: String(vj.name || email.split('@')[0]).slice(0, 120), email: email, salt: '', passHash: 'google', lang: ['en', 'fa', 'hi', 'zh'].indexOf(loc) >= 0 ? loc : 'en', created_at: new Date().toISOString(), viaGoogle: true };
          uDirty = true;
        } else if (!user.viaGoogle) {
          // Google sign-in proves ownership of this email: retire any password
          // credentials registered before the owner arrived (pre-hijack guard)
          // and end that password's live sessions.
          user.salt = ''; user.passHash = 'google'; user.viaGoogle = true;
          await purgeUserSessions(env, email);
          uDirty = true;
        }
        const prevLogin = user.lastLogin ? new Date(user.lastLogin).getTime() : 0;
        user.lastLogin = new Date().toISOString();
        if (uDirty || Date.now() - prevLogin > 86400000) await env.LEADS.put('user:' + email, JSON.stringify(user));
        if (uDirty) await idxAdd(env, 'users', email);
        // Cycle 22 (closes cycle-19 H1): the session token never travels in a
        // URL again (fixation + browser-history/log leakage). The browser
        // gets a single-use code (2-minute TTL, bound to the PKCE-style
        // challenge from /start) and exchanges it at the endpoint below; the
        // session is minted only at exchange time, and only the exchange
        // response body ever carries the token.
        const gcode = randHex(24);
        await env.LEADS.put('gcode:' + gcode, JSON.stringify({ email: email, c: gch2 }), { expirationTtl: 120 });
        const sh = new Headers();
        sh.set('Location', SITE + '#gcode=' + gcode);
        sh.set('Set-Cookie', 'gst=; Max-Age=0; Path=/api/user/google; HttpOnly; Secure; SameSite=Lax');
        sh.set('Cache-Control', 'no-store');
        return new Response(null, { status: 302, headers: sh });
      }
      if (path === '/api/user/google/exchange' && request.method === 'POST') {
        if (limited('gx:' + ip, 60, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        let gd = null;
        try { gd = await request.json(); } catch (e) {}
        const gcodeIn = String((gd || {}).code || '');
        const gverIn = String((gd || {}).verifier || '');
        if (!/^[0-9a-f]{48}$/.test(gcodeIn) || !/^[0-9a-f]{64}$/.test(gverIn)) return json({ ok: false, error: 'code' }, 400, origin);
        const graw = await env.LEADS.get('gcode:' + gcodeIn);
        if (!graw) return json({ ok: false, error: 'code' }, 401, origin);
        await env.LEADS.delete('gcode:' + gcodeIn); // single-use: burn regardless of outcome
        let grec = null;
        try { grec = JSON.parse(graw); } catch (e) {}
        const gEmail = String((grec || {}).email || '');
        const gChal = String((grec || {}).c || '');
        if (!gEmail || !/^[0-9a-f]{64}$/.test(gChal)) return json({ ok: false, error: 'code' }, 401, origin);
        const gGot = await sha256hex(gverIn);
        if (!timingSafeEqual(gGot, gChal)) return json({ ok: false, error: 'code' }, 401, origin);
        if (await isBanned(env, gEmail)) return json({ ok: false, error: 'banned' }, 403, origin);
        if (!(await env.LEADS.get('user:' + gEmail))) return json({ ok: false, error: 'code' }, 401, origin);
        const gtok = 'u_' + randHex(16);
        await env.LEADS.put('usess:' + gtok, JSON.stringify({ email: gEmail, exp: Date.now() + 30 * 86400000 }), { expirationTtl: 30 * 86400 });
        const grr = json({ ok: true, token: gtok }, 200, origin);
        grr.headers.set('Cache-Control', 'no-store');
        return grr;
      }
      // ---- visitor accounts (public) ----
      if (path === '/api/user/register' && request.method === 'POST') {
        if (limited('rg:' + ip, 10, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        if (!(await turnstileOk(env, d.turnstileToken, ip))) return json({ ok: false, error: 'captcha' }, 400, origin);
        const name = String(d.name || '').trim().slice(0, 120);
        const email = String(d.email || '').trim().toLowerCase().slice(0, 160);
        const pass = String(d.password || '').slice(0, 256);
        const ulang = validLang(d.lang);
        if (!name || !EMAIL_RE.test(email) || pass.length < 8) return json({ ok: false, error: 'validation' }, 400, origin);
        if (await isBanned(env, email)) return json({ ok: false, error: 'banned' }, 403, origin);
        const exists = await env.LEADS.get('user:' + email);
        if (exists) return json({ ok: false, error: 'exists' }, 409, origin);
        const user = { name: name, email: email, salt: '', passHash: await makePassHash(pass), lang: ulang, created_at: new Date().toISOString(), verified: false };
        await env.LEADS.put('user:' + email, JSON.stringify(user));
        await idxAdd(env, 'users', email);
        const vt = randHex(16);
        await env.LEADS.put('uverify:' + vt, email, { expirationTtl: 7 * 86400 });
        await queueMail(env, { kind: 'verify', to: email, lang: ulang, name: name, token: vt });
        const token = 'u_' + randHex(16);
        await env.LEADS.put('usess:' + token, JSON.stringify({ email: email, exp: Date.now() + 30 * 86400000 }), { expirationTtl: 30 * 86400 });
        return json({ ok: true, token: token, user: { name: name, email: email, lang: ulang } }, 200, origin);
      }
      if (path === '/api/user/verify' && request.method === 'GET') {
        const vt = String(url.searchParams.get('t') || '');
        const vem = /^[0-9a-f]{32}$/.test(vt) ? await env.LEADS.get('uverify:' + vt) : null;
        if (vem) {
          // token intentionally NOT deleted on use: mail scanners prefetch GET links and would burn it before the real click; verification is idempotent and the token dies on its own TTL (cycle 26)
          const raw = await env.LEADS.get('user:' + vem);
          if (raw) { try { const uu = JSON.parse(raw); uu.verified = true; await env.LEADS.put('user:' + vem, JSON.stringify(uu)); } catch (e) {} }
          return Response.redirect('https://real-estate-platform-0aei.onrender.com/listings.html#verified=1', 302);
        }
        return Response.redirect('https://real-estate-platform-0aei.onrender.com/listings.html#verified=0', 302);
      }
      if (path === '/api/user/login' && request.method === 'POST') {
        if (limited(ip, 20, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const email = String(d.email || '').trim().toLowerCase().slice(0, 160);
        const pass = String(d.password || '').slice(0, 256);
        if (await isBanned(env, email)) { await makePassHash(pass); return json({ ok: false, error: 'credentials' }, 401, origin); } // no per-attempt purge (purgeUserSessions lists usess: — a list-quota lever for strangers); the ban-time purge + userAuth's ban check already close live sessions, and the dummy hash keeps timing flat
        const lfK = 'lf:' + email;
        const lf = parseInt((await env.LEADS.get(lfK)) || '0', 10);
        if (lf >= 10) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        const raw = await env.LEADS.get('user:' + email);
        if (!raw) { await makePassHash(pass); return json({ ok: false, error: 'credentials' }, 401, origin); }
        let user = null;
        try { user = JSON.parse(raw); } catch (e) {}
        if (!user) { await makePassHash(pass); return json({ ok: false, error: 'credentials' }, 401, origin); }
        if (user.viaGoogle || user.passHash === 'google') { await makePassHash(pass); return json({ ok: false, error: 'credentials' }, 401, origin); } // Google-only account: there is no password credential to check (explicit guard, cycle 26)
        if (!(await verifyUserPass(user, pass))) {
          await env.LEADS.put(lfK, String(lf + 1), { expirationTtl: 900 });
          return json({ ok: false, error: 'credentials' }, 401, origin);
        }
        await env.LEADS.delete(lfK);
        const hashUpgraded = String(user.passHash || '').indexOf('pbkdf2$') !== 0;
        if (hashUpgraded) {
          user.passHash = await makePassHash(pass); user.salt = '';
        }
        const loginStale = !user.lastLogin || (Date.now() - new Date(user.lastLogin).getTime() > 86400000);
        user.lastLogin = new Date().toISOString();
        if (hashUpgraded || loginStale) await env.LEADS.put('user:' + email, JSON.stringify(user)); // write only on hash upgrade or a >24h-stale lastLogin (cycle 26: fewer writes, narrower verify race)
        const token = 'u_' + randHex(16);
        await env.LEADS.put('usess:' + token, JSON.stringify({ email: email, exp: Date.now() + 30 * 86400000 }), { expirationTtl: 30 * 86400 });
        return json({ ok: true, token: token, user: { name: user.name, email: user.email, lang: user.lang } }, 200, origin);
      }
      if (path === '/api/user/me' && request.method === 'GET') {
        if (limited(ip, 120, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        const email = await userAuth(request, env);
        if (!email) return json({ ok: false, error: 'auth' }, 401, origin);
        const raw = await env.LEADS.get('user:' + email);
        let user = { name: '', email: email, lang: 'en' };
        if (raw) { try { user = JSON.parse(raw); } catch (e) {} }
        const savedList = await userSaved(env, email);
        const savePrices = (await env.LEADS.get('usavep:' + email, { type: 'json' })) || {};
        const drops = [];
        savedList.forEach(function (mls) {
          const cur = catalogByMls(mls);
          const was = savePrices[mls];
          if (cur && typeof was === 'number' && cur.price < was) drops.push({ mls: mls, was: was, now: cur.price });
        });
        const recent = (await env.LEADS.get('urecent:' + email, { type: 'json' })) || [];
        return json({ ok: true, user: { name: user.name, email: user.email, lang: user.lang }, profile: user.profile || {}, saved: savedList, savedPrices: savePrices, priceDrops: drops, recent: recent, searches: await userSearches(env, email) }, 200, origin);
      }
      if (path === '/api/user/save' && request.method === 'POST') {
        if (limited('sv:' + ip, 60, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        const email = await userAuth(request, env);
        if (!email) return json({ ok: false, error: 'auth' }, 401, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        const mls = String((d || {}).mls || '').slice(0, 40);
        const saved = await userSaved(env, email);
        const i = saved.indexOf(mls);
        if (i === -1 && !catalogByMls(mls)) return json({ ok: false, error: 'validation' }, 400, origin); // catalog check only when ADDING: a delisted home must remain unsaveable (cycle 26, Claude M5)
        const savePrices = (await env.LEADS.get('usavep:' + email, { type: 'json' })) || {};
        if (i !== -1) { saved.splice(i, 1); delete savePrices[mls]; }
        else if (saved.length >= 100) return json({ ok: false, error: 'limit' }, 400, origin);
        else { saved.push(mls); const homeS = catalogByMls(mls); if (homeS) savePrices[mls] = homeS.price; }
        await env.LEADS.put('usaved:' + email, JSON.stringify(saved.slice(0, 100)));
        await env.LEADS.put('usavep:' + email, JSON.stringify(savePrices));
        await pushActivity(env, email, i !== -1 ? 'unsave' : 'save', mls);
        return json({ ok: true, saved: saved }, 200, origin);
      }
      if (path === '/api/user/searches' && request.method === 'POST') {
        if (limited('us:' + ip, 30, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        const email = await userAuth(request, env);
        if (!email) return json({ ok: false, error: 'auth' }, 401, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const c = d.criteria || {};
        const criteria = {
          q: String(c.q || '').slice(0, 80), city: String(c.city || '').slice(0, 40),
          type: String(c.type || '').slice(0, 20), maxPrice: String(c.maxPrice || '').slice(0, 12),
          minBeds: String(c.minBeds || '').slice(0, 4),
          presale: (c.presale === 'only' || c.presale === 'no') ? c.presale : '',
          completionBy: String(c.completionBy || '').replace(/[^0-9]/g, '').slice(0, 4)
        };
        const searches = await userSearches(env, email);
        const rec = {
          id: 's_' + randHex(6), name: String(d.name || 'Search').slice(0, 80),
          criteria: criteria, notify: !!d.notify, notified: [], created_at: new Date().toISOString()
        };
        if (searches.length >= 20) return json({ ok: false, error: 'limit' }, 400, origin);
        const matches = matchSearch(criteria);
        rec.notified = matches;
        searches.unshift(rec);
        await env.LEADS.put('usearch:' + email, JSON.stringify(searches.slice(0, 20)));
        await pushActivity(env, email, 'search', rec.name);
        if (rec.notify && matches.length && (await emailVerified(env, email))) {
          const ulang = validLang(d.lang);
          const raw = await env.LEADS.get('user:' + email);
          let uname = '';
          if (raw) { try { uname = JSON.parse(raw).name || ''; } catch (e) {} }
          await queueMail(env, { kind: 'alert', to: email, lang: ulang, name: uname, searchId: rec.id, searchName: rec.name, listings: matches.slice(0, 20).map(function (m) { const l = catalogByMls(m); return { mls: l.mls, street: l.street, city: l.city, price: l.price }; }) });
        }
        return json({ ok: true, search: rec, matches: matches }, 200, origin);
      }
      const usm = path.match(/^\/api\/user\/searches\/([A-Za-z0-9_-]+)$/);
      if (usm && request.method === 'DELETE') {
        const email = await userAuth(request, env);
        if (!email) return json({ ok: false, error: 'auth' }, 401, origin);
        const searches = (await userSearches(env, email)).filter(function (s) { return s.id !== usm[1]; });
        await env.LEADS.put('usearch:' + email, JSON.stringify(searches));
        return json({ ok: true }, 200, origin);
      }

      // ---- visitor account v2: profile (all fields optional), recent, my viewings ----
      if (path === '/api/user/profile' && request.method === 'POST') {
        if (limited('pf:' + ip, 30, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        const email = await userAuth(request, env);
        if (!email) return json({ ok: false, error: 'auth' }, 401, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const raw = await env.LEADS.get('user:' + email);
        if (!raw) return json({ ok: false, error: 'auth' }, 401, origin);
        const user = JSON.parse(raw);
        const p = user.profile || {};
        if (d.name != null && String(d.name).trim()) user.name = String(d.name).trim().slice(0, 120);
        if (d.phone != null) { const ph = String(d.phone).trim().slice(0, 40); if (ph && !/^[+\d][\d\s().-]{6,39}$/.test(ph)) return json({ ok: false, error: 'validation' }, 400, origin); p.phone = ph; }
        if (d.budget != null) p.budget = String(d.budget).trim().slice(0, 40);
        if (d.intent != null) p.intent = ['buy', 'sell', 'rent', 'invest', ''].includes(String(d.intent)) ? String(d.intent) : p.intent || '';
        if (d.areas != null && Array.isArray(d.areas)) p.areas = d.areas.slice(0, 8).map(function (a) { return String(a).slice(0, 40); });
        if (d.contactPref != null) p.contactPref = ['email', 'phone', 'either', ''].includes(String(d.contactPref)) ? String(d.contactPref) : p.contactPref || '';
        if (d.lang != null && ['en', 'fa', 'hi', 'zh'].includes(String(d.lang))) user.lang = String(d.lang);
        user.profile = p;
        await env.LEADS.put('user:' + email, JSON.stringify(user));
        return json({ ok: true, user: { name: user.name, email: user.email, lang: user.lang }, profile: p }, 200, origin);
      }
      if (path === '/api/user/recent' && request.method === 'POST') {
        if (limited('rc:' + ip, 60, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        const email = await userAuth(request, env);
        if (!email) return json({ ok: false, error: 'auth' }, 401, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        const mls = String((d || {}).mls || '').slice(0, 40);
        if (!catalogByMls(mls)) return json({ ok: false, error: 'validation' }, 400, origin);
        const curRecent = (await env.LEADS.get('urecent:' + email, { type: 'json' })) || [];
        if (curRecent[0] === mls) return json({ ok: true, recent: curRecent }, 200, origin); // no change: skip both writes (cycle 27, Claude L13)
        let recent = [mls].concat(curRecent.filter(function (m) { return m !== mls; })).slice(0, 12);
        await env.LEADS.put('urecent:' + email, JSON.stringify(recent));
        await pushActivity(env, email, 'view', mls);
        return json({ ok: true, recent: recent }, 200, origin);
      }
      if (path === '/api/user/viewings' && request.method === 'GET') {
        if (limited('uv:' + ip, 60, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        const email = await userAuth(request, env);
        if (!email) return json({ ok: false, error: 'auth' }, 401, origin);
        if (!(await emailVerified(env, email))) return json({ ok: false, error: 'unverified' }, 403, origin);
        let vids = (await env.LEADS.get('uvw:' + email, { type: 'json' })) || null;
        if (!vids) {
          // one-time self-healing migration from the legacy vu: marker keys
          const vuList = await kvList(env, { prefix: 'vu:' + email + ':', limit: 100 });
          vids = vuList.keys.map(function (k) { return k.name.split(':').pop(); });
          if (vids.length) { try { await env.LEADS.put('uvw:' + email, JSON.stringify(vids.slice(0, 50))); } catch (e) {} }
        }
        const vrecs = await Promise.all(vids.slice(0, 50).map(function (id) { return env.LEADS.get('viewing:' + id, { type: 'json' }); }));
        const mine = [];
        vrecs.forEach(function (v) {
          if (v && v.email === email) { const home = v.listingId ? catalogByMls(v.listingId) : null; mine.push(Object.assign({}, v, { listing: home ? { mls: home.mls, street: home.street, city: home.city, price: home.price } : null })); }
        });
        mine.sort(function (a, b) { return String(b.date + ' ' + b.time).localeCompare(String(a.date + ' ' + a.time)); });
        return json({ ok: true, viewings: mine }, 200, origin);
      }
      const uvm = path.match(/^\/api\/user\/viewings\/([A-Za-z0-9_-]+)\/(cancel|reschedule)$/);
      if (uvm && request.method === 'POST') {
        if (limited(ip, 20, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        const email = await userAuth(request, env);
        if (!email) return json({ ok: false, error: 'auth' }, 401, origin);
        if (!(await emailVerified(env, email))) return json({ ok: false, error: 'unverified' }, 403, origin);
        const rec = await env.LEADS.get('viewing:' + uvm[1], { type: 'json' });
        if (!rec || rec.email !== email) return json({ ok: false, error: 'not_found' }, 404, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const geid = rec.gcalEventId || ('v' + String(rec.id || '').slice(3));
        if (rec.status !== 'new' && rec.status !== 'confirmed') return json({ ok: false, error: 'state' }, 409, origin); // done/cancelled viewings are final (cycle 27, Claude L12)
        if (uvm[2] === 'cancel') {
          rec.status = 'cancelled';
          await env.LEADS.put('viewing:' + uvm[1], JSON.stringify(rec));
          await releaseSlot(env, rec.listingId, rec.date, rec.time, rec.id);
          if (ctx && ctx.waitUntil) ctx.waitUntil(gcalDeleteEvent(env, geid));
          return json({ ok: true }, 200, origin);
        }
        const ndate = String(d.date || '').slice(0, 10);
        const ntime = String(d.time || '').slice(0, 8);
        if (!validSlot(ndate, ntime)) return json({ ok: false, error: 'validation' }, 400, origin);
        const pub2 = rec.listingId ? await publicAvail(env, rec.listingId) : null;
        if (pub2) {
          const okSlot2 = pub2.some(function (dd) { return dd.date === ndate && dd.times.indexOf(ntime) >= 0; });
          if (!okSlot2) return json({ ok: false, error: 'slot_unavailable' }, 409, origin);
        } else if (!(await slotOnGrid(env, ndate, ntime))) {
          return json({ ok: false, error: 'slot_unavailable' }, 409, origin); // grid + Sunday rule now cover listing-less viewings too (cycle 27, Claude M5 — booking already enforced them)
        }
        const h0 = rec.listingId ? catalogByMls(rec.listingId) : null;
        if (h0 && h0.status && h0.status !== 'active') return json({ ok: false, error: 'listing_inactive' }, 400, origin);
        if (rec.listingId && !(ndate === rec.date && ntime === rec.time) && !(await claimSlot(env, rec.listingId, ndate, ntime, rec.id))) return json({ ok: false, error: 'slot_unavailable' }, 409, origin);
        if ((rec.rs || 0) >= 3) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        rec.rs = (rec.rs || 0) + 1;
        const odate = rec.date, otime = rec.time;
        rec.date = ndate; rec.time = ntime; rec.status = 'new';
        await env.LEADS.put('viewing:' + uvm[1], JSON.stringify(rec));
        if (rec.listingId && !(ndate === odate && ntime === otime)) await releaseSlot(env, rec.listingId, odate, otime, rec.id);
        if (ctx && ctx.waitUntil) ctx.waitUntil(gcalPatchEventTimes(env, geid, ndate, ntime));
        const home2 = rec.listingId ? catalogByMls(rec.listingId) : null;
        await queueMail(env, { kind: 'viewing', to: email, lang: rec.lang || 'en', name: rec.name, ref: rec.id, date: ndate, time: ntime, listing: home2 ? { mls: home2.mls, street: home2.street, city: home2.city } : null });
        return json({ ok: true }, 200, origin);
      }

      // ---- viewings (public booking) ----
      // Public: a listing's owner-set viewing availability (null = all slots open)
      // ---- public: portal-managed listings + site settings ----
      if (path === '/api/listings' && request.method === 'GET') {
        const base = 'https://' + url.host;
        return json({ ok: true, listings: customListings.map(function (r) { return publicListing(r, base); }), deleted: deletedSeedMls }, 200, origin);
      }
      if (path === '/api/settings' && request.method === 'GET') {
        const base = 'https://' + url.host;
        return json({ ok: true, settings: publicSettings(await getSiteSettings(env), base) }, 200, origin);
      }
      if (path.indexOf('/api/lphoto/') === 0 && request.method === 'GET') {
        let lid = '';
        try { lid = decodeURIComponent(path.slice('/api/lphoto/'.length)); } catch (e) {}
        if (!/^[A-Za-z0-9_-]{1,40}$/.test(lid)) return json({ ok: false, error: 'not_found' }, 404, origin);
        const dataUrl = await env.LEADS.get('lphoto:' + lid);
        const m = dataUrl && dataUrl.match(/^data:(image\/(?:webp|jpeg|png));base64,([A-Za-z0-9+/=]+)$/);
        if (!m) return json({ ok: false, error: 'not_found' }, 404, origin);
        let bin;
        try { const bs = atob(m[2]); bin = new Uint8Array(bs.length); for (let i = 0; i < bs.length; i++) bin[i] = bs.charCodeAt(i); }
        catch (e) { return json({ ok: false, error: 'not_found' }, 404, origin); }
        return new Response(bin, { headers: { 'Content-Type': m[1], 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; sandbox", 'Cache-Control': 'public, max-age=86400', 'Access-Control-Allow-Origin': '*' } });
      }

      if (path.indexOf('/api/availability/') === 0 && request.method === 'GET') {
        if (limited('av:' + ip, 120, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        let mls = '';
        try { mls = decodeURIComponent(path.slice('/api/availability/'.length)).slice(0, 40); } catch (e) { return json({ ok: false, error: 'not_found' }, 404, origin); }
        if (!catalogByMls(mls)) return json({ ok: false, error: 'not_found' }, 404, origin);
        const dates = await publicAvail(env, mls);
        return json({ ok: true, mls: mls, restricted: !!dates, dates: dates || [] }, 200, origin);
      }
      if (path === '/api/viewing' && request.method === 'POST') {
        if (limited('vw:' + ip, 10, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        if (limited('vwd:' + ip, 15, 86400000)) return json({ ok: false, error: 'rate_limit' }, 429, origin); // daily IP ceiling against slot squatting (cycle 27, Claude M7c)
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        if (!(await turnstileOk(env, d.turnstileToken, ip))) return json({ ok: false, error: 'captcha' }, 400, origin);
        const name = String(d.name || '').trim().slice(0, 120);
        if (/[\r\n<>]|https?:|www\./i.test(name)) return json({ ok: false, error: 'validation' }, 400, origin); // names flow into outbound mail + calendar invites (cycle 27, Claude M7d)
        const email = String(d.email || '').trim().toLowerCase().slice(0, 160);
        const phone = String(d.phone || '').trim().slice(0, 40);
        const listingId = String(d.listingId || '').slice(0, 40);
        const date = String(d.date || '').slice(0, 10);
        const time = String(d.time || '').slice(0, 8);
        const vlang = validLang(d.lang);
        if (!name || !EMAIL_RE.test(email) || !validSlot(date, time)) return json({ ok: false, error: 'validation' }, 400, origin);
        if (await isBanned(env, email)) return json({ ok: false, error: 'banned' }, 403, origin);
        // Per-email daily cap: a booking spams a calendar invite + mail at the
        // given address, so cap how often one address can be targeted.
        const vcK = 'vc:' + normEmail(email) + ':' + new Date().toISOString().slice(0, 10); // canonical key: +tag/dot variants share one cap (cycle 27, Claude M7a)
        const vcN = parseInt((await env.LEADS.get(vcK)) || '0', 10);
        if (vcN >= 3) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        const home = listingId ? catalogByMls(listingId) : null;
        if (listingId && !home) return json({ ok: false, error: 'validation' }, 400, origin);
        if (home && home.status && home.status !== 'active') return json({ ok: false, error: 'listing_inactive' }, 400, origin);
        const lid = home ? home.mls : '';
        // Owner-set availability: when set for this listing, only those slots
        // can be booked; otherwise the site grid + Sundays-off rule applies.
        const pub = home ? await publicAvail(env, lid) : null;
        if (pub) {
          const okSlot = pub.some(function (d) { return d.date === date && d.times.indexOf(time) >= 0; });
          if (!okSlot) return json({ ok: false, error: 'slot_unavailable' }, 409, origin);
        } else if (!(await slotOnGrid(env, date, time))) {
          return json({ ok: false, error: 'slot_unavailable' }, 409, origin);
        }
        const vid = 'vw_' + randHex(6);
        const rec = { id: vid, created_at: new Date().toISOString(), name: name, email: email, phone: phone, listingId: lid, date: date, time: time, lang: vlang, status: 'new', gcalEventId: 'v' + vid.slice(3) };
        // The viewing record is written BEFORE the slot claim (cycle 24): a
        // claim whose record doesn't exist yet reads as "free" to a rival
        // claimer, which let two claims pass in the gap.
        await env.LEADS.put('viewing:' + vid, JSON.stringify(rec));
        if (home && !(await claimSlot(env, lid, date, time, vid))) {
          await env.LEADS.delete('viewing:' + vid);
          return json({ ok: false, error: 'slot_unavailable' }, 409, origin);
        }
        // Post-claim bookkeeping is best-effort (cycle 27, Claude M8 + M6): the
        // slot is already the visitor's — a KV failure here must not 500 them
        // or orphan the claim. The per-user viewing index (uvw:) is written
        // here too, replacing the vu: marker keys that cost a list per read.
        try {
          await env.LEADS.put(vcK, String(vcN + 1), { expirationTtl: 172800 });
          const uvw = (await env.LEADS.get('uvw:' + email, { type: 'json' })) || [];
          uvw.unshift(vid);
          await env.LEADS.put('uvw:' + email, JSON.stringify(uvw.slice(0, 50)));
          const vidx = (await env.LEADS.get('vidx', { type: 'json' })) || [];
          vidx.unshift(vid);
          await env.LEADS.put('vidx', JSON.stringify(vidx.slice(0, 1000)));
          const leadId = Date.now().toString(36) + '-' + randHex(6);
          const lead = {
            id: leadId, created_at: new Date().toISOString(), name: name, intent: 'buyer',
            city: home ? home.city : '', budget: '', email: email, phone: phone,
            message: 'Viewing requested: ' + date + ' ' + time + (home ? ' — ' + home.street + ' (' + home.mls + ')' : ''),
            stage: 'viewing', notes: '', source: 'viewing'
          };
          await env.LEADS.put('lead:' + leadId, JSON.stringify(lead));
          await idxAdd(env, 'leads', leadId);
          await queueMail(env, { kind: 'viewing', to: email, lang: vlang, name: name, ref: vid, date: date, time: time, listing: home ? { mls: home.mls, street: home.street, city: home.city } : null });
          await pushActivity(env, email, 'viewing', date + ' ' + time + (listingId ? ' · ' + listingId : ''));
        } catch (e) { console.error(e); }
        // Google Calendar invites: if a service account is configured
        // (KV cfg:gcal = the SA JSON), create the calendar event and email
        // the invites (visitor + Erfan's business inbox) the moment a
        // viewing is booked. Runs via waitUntil; failures never affect
        // the booking itself.
        try {
          const sa = await env.LEADS.get('cfg:gcal', { type: 'json' });
          if (sa && sa.client_email && sa.private_key && ctx && ctx.waitUntil) {
            ctx.waitUntil(gcalCreateViewing(env, sa, { id: vid, eventId: rec.gcalEventId, name: name, email: email, phone: phone, date: date, time: time, listing: home ? { mls: home.mls, street: home.street, city: home.city } : null }));
          }
        } catch (e) {}
        return json({ ok: true, id: vid }, 200, origin);
      }

      // ---- public: login ----
      if (path === '/api/login' && request.method === 'POST') {
        if (limited('lg:' + ip, 10, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        const pw = d && typeof d.password === 'string' ? d.password : '';
        if (!(await turnstileOk(env, d && d.turnstileToken, ip))) return json({ ok: false, error: 'captcha' }, 400, origin);
        if (!pw || !(await checkPassword(env, pw))) {
          return json({ ok: false, error: 'invalid' }, 401, origin);
        }
        const token = randHex(32);
        await env.LEADS.put('tok:' + token, String(Date.now() + TOKEN_TTL * 1000), { expirationTtl: TOKEN_TTL });
        return json({ ok: true, token: token }, 200, origin);
      }


      // ---- business calls: provider webhooks + generic ingest (own auth) ----
      if (path === '/api/calls/ingest' && request.method === 'POST') {
        if (limited('ingest:' + ip, 600, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        const ccfg = await getCallsCfg(env);
        if (!ccfg || !ccfg.secret) return json({ ok: false, error: 'not_configured' }, 503, origin);
        const sec = request.headers.get('X-Call-Secret') || '';
        if (!sec || !timingSafeEqual(sec, String(ccfg.secret))) return json({ ok: false, error: 'unauthorized' }, 401, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        if (!d || typeof d !== 'object') return json({ ok: false, error: 'validation' }, 400, origin);
        const rr = await storeCall(env, Object.assign({}, d, { provider: d.provider || ccfg.provider || 'generic' }));
        return json(rr, rr.ok ? 200 : 400, origin);
      }
      if (path === '/api/calls/twilio/voice' && request.method === 'POST') {
        const ccfg = await getCallsCfg(env);
        const xmlHead = { 'Content-Type': 'text/xml; charset=utf-8' };
        const unavailable = '<?xml version="1.0" encoding="UTF-8"?><Response><Say voice="alice">Sorry, this number is not in service yet. Please try again later.</Say><Hangup/></Response>';
        if (!ccfg || !ccfg.forwardTo || !ccfg.number) return new Response(unavailable, { status: 200, headers: xmlHead });
        const params = await readFormParams(request);
        // Twilio routes verify UNCONDITIONALLY (cycle 27, Claude H1): gating on
        // ccfg.provider left the route open whenever provider was unset/mistyped.
        if (!ccfg.twilioAuthToken || !(await twilioSigOk(env, ccfg, request, params))) return new Response(unavailable, { status: 200, headers: xmlHead });
        const base = 'https://' + new URL(request.url).host;
        if (normPhone(params.From) === normPhone(ccfg.forwardTo)) {
          const gather = '<?xml version="1.0" encoding="UTF-8"?><Response><Gather action="' + base + '/api/calls/twilio/voice/outbound" method="POST" finishOnKey="#" timeout="30"><Say voice="alice">Enter the number you want to call, then press pound.</Say></Gather></Response>';
          return new Response(gather, { status: 200, headers: xmlHead });
        }
        const xml = '<?xml version="1.0" encoding="UTF-8"?><Response>' +
          '<Say voice="alice">Please hold while we connect you. This call may be recorded.</Say>' +
          '<Dial record="record-from-answer-dual" action="' + base + '/api/calls/twilio/status" method="POST">' +
          '<Number>' + escapeXml(ccfg.forwardTo) + '</Number></Dial></Response>'; // no statusCallback here: the Dial action already posts the completed event — both together double-stored every forwarded call (cycle 27, Claude M10)
        return new Response(xml, { status: 200, headers: xmlHead });
      }
      if (path === '/api/calls/twilio/status' && request.method === 'POST') {
        const ccfg = await getCallsCfg(env);
        if (!ccfg) return new Response('not configured', { status: 503 });
        const params = await readFormParams(request);
        if (!ccfg.twilioAuthToken || !(await twilioSigOk(env, ccfg, request, params))) return new Response('forbidden', { status: 403 });
        if (limited('callst:' + String(params.From || ''), 60, 3600000)) return new Response('<?xml version="1.0" encoding="UTF-8"?><Response></Response>', { status: 200, headers: { 'Content-Type': 'text/xml; charset=utf-8' } });
        const rawStatus = String(params.DialCallStatus || params.CallStatus || '').toLowerCase();
        const statusMap = { completed: 'completed', busy: 'busy', 'no-answer': 'no-answer', failed: 'failed', canceled: 'missed' };
        const rec = {
          provider: 'twilio', providerCallId: params.CallSid || params.DialCallSid || '',
          direction: (url.searchParams.get('dir') === 'out' || String(params.Direction || 'inbound').indexOf('outbound') === 0) ? 'out' : 'in',
          from: params.From || '', to: params.To || '',
          durationSec: parseInt(params.DialCallDuration || params.CallDuration || '0', 10) || 0,
          status: statusMap[rawStatus] || 'completed',
          recordingUrl: (params.RecordingUrl && String(params.RecordingUrl).indexOf('https://api.twilio.com/') === 0) ? params.RecordingUrl + '.mp3' : '' // host-validated (cycle 27, Claude L17)
        };
        if (rec.providerCallId) await storeCall(env, rec);
        return new Response('<?xml version="1.0" encoding="UTF-8"?><Response></Response>', { status: 200, headers: { 'Content-Type': 'text/xml; charset=utf-8' } });
      }


      if (path === '/api/calls/twilio/voice/outbound' && request.method === 'POST') {
        const ccfg = await getCallsCfg(env);
        const xmlHead = { 'Content-Type': 'text/xml; charset=utf-8' };
        const unavailable = '<?xml version="1.0" encoding="UTF-8"?><Response><Say voice="alice">Sorry, this number is not in service yet.</Say><Hangup/></Response>';
        if (!ccfg || !ccfg.number || !ccfg.forwardTo) return new Response(unavailable, { status: 200, headers: xmlHead });
        const params = await readFormParams(request);
        if (!ccfg.twilioAuthToken || !(await twilioSigOk(env, ccfg, request, params))) return new Response(unavailable, { status: 200, headers: xmlHead });
        if (normPhone(params.From) !== normPhone(ccfg.forwardTo)) return new Response(unavailable, { status: 200, headers: xmlHead });
        const rawDigits = String(params.Digits || '').replace(/[^0-9]/g, '');
        if (!/^1?[2-9]\d{9}$/.test(rawDigits)) return new Response('<?xml version="1.0" encoding="UTF-8"?><Response><Say voice="alice">That number looks incomplete. Please call back and try again.</Say><Hangup/></Response>', { status: 200, headers: xmlHead }); // NANP only (cycle 27, Claude H2): no premium/international destinations
        const target = normPhone(rawDigits);
        const base = 'https://' + new URL(request.url).host;
        const xml = '<?xml version="1.0" encoding="UTF-8"?><Response><Dial callerId="' + escapeXml(ccfg.number) + '" record="record-from-answer-dual" action="' + base + '/api/calls/twilio/status?dir=out" method="POST"><Number>' + escapeXml(target) + '</Number></Dial></Response>';
        return new Response(xml, { status: 200, headers: xmlHead });
      }
      if (path === '/api/calls/twilio/sms' && request.method === 'POST') {
        const ccfg = await getCallsCfg(env);
        if (!ccfg || !ccfg.number) return new Response('not configured', { status: 503 });
        const params = await readFormParams(request);
        if (!ccfg.twilioAuthToken || !(await twilioSigOk(env, ccfg, request, params))) return new Response('forbidden', { status: 403 });
        const empty = new Response('<?xml version="1.0" encoding="UTF-8"?><Response></Response>', { status: 200, headers: { 'Content-Type': 'text/xml; charset=utf-8' } });
        const fromN = normPhone(params.From || '');
        if (ccfg.forwardTo && fromN === normPhone(ccfg.forwardTo)) {
          const relay = (await env.LEADS.get('smsrelay', { type: 'json' })) || null;
          if (relay && relay.client && params.Body) {
            // Claim the relay record BEFORE sending (cycle 27, Claude M9): a
            // Twilio webhook retry must not text the client twice.
            const pre = await storeSms(env, { provider: 'twilio', providerMsgId: 'relay-' + (params.MessageSid || params.SmsSid || ''), direction: 'out', from: ccfg.number, to: relay.client, body: String(params.Body || '') });
            if (pre.ok && pre.created) await sendSms(env, ccfg, relay.client, params.Body);
          }
          return empty;
        }
        if (limited('smsin:' + fromN, 20, 3600000)) return empty; // inbound flood guard (cycle 27, Claude M11)
        const media = [];
        for (let i = 0; i < 6; i++) { if (params['MediaUrl' + i] && String(params['MediaUrl' + i]).indexOf('https://api.twilio.com/') === 0) media.push(params['MediaUrl' + i]); }
        const stored = await storeSms(env, { provider: 'twilio', providerMsgId: params.MessageSid || params.SmsSid || '', direction: 'in', from: params.From || '', to: params.To || ccfg.number, body: String(params.Body || ''), media: media });
        if (stored.ok && stored.msg) await forwardSmsToOwner(env, ccfg, stored.msg);
        return empty;
      }
      if (path === '/api/sms/ingest' && request.method === 'POST') {
        if (limited('ingest:' + ip, 600, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        const ccfg = await getCallsCfg(env);
        if (!ccfg || !ccfg.secret) return json({ ok: false, error: 'not_configured' }, 503, origin);
        const sec = request.headers.get('X-Call-Secret') || '';
        if (!sec || !timingSafeEqual(sec, String(ccfg.secret))) return json({ ok: false, error: 'unauthorized' }, 401, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        if (!d || typeof d !== 'object') return json({ ok: false, error: 'validation' }, 400, origin);
        const stored = await storeSms(env, Object.assign({}, d, { provider: d.provider || ccfg.provider || 'generic' }));
        if (stored.ok && stored.created && stored.msg && stored.msg.direction === 'in') await forwardSmsToOwner(env, ccfg, stored.msg);
        return json({ ok: stored.ok, id: stored.id, created: stored.created }, stored.ok ? 200 : 400, origin);
      }

      // ---- auth required below ----
      if (!(await authed(request, env)) && !(await scopedAuthed(request, env, path, request.method))) {
        return json({ ok: false, error: 'unauthorized' }, 401, origin);
      }

      if (path === '/api/leads' && request.method === 'GET') {
        const leads = await adminCachedGen(env, 'leads', async function () {
          const leadIds = await idxGet(env, 'leads', 'lead:');
          const out = (await Promise.all(
            leadIds.map(function (id) { return env.LEADS.get('lead:' + id, { type: 'json' }); })
          )).filter(Boolean);
          out.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
          return out;
        });
        return json({ ok: true, leads: leads }, 200, origin);
      }

      const m = path.match(/^\/api\/leads\/([A-Za-z0-9-]+)$/);
      if (m) {
        const key = 'lead:' + m[1];
        if (request.method === 'PATCH') {
          const lead = await env.LEADS.get(key, { type: 'json' });
          if (!lead) return json({ ok: false, error: 'not_found' }, 404, origin);
          let d = null;
          try { d = await request.json(); } catch (e) {}
          d = d || {};
          if (d.stage !== undefined) {
            const st = String(d.stage).toLowerCase();
            if (!STAGES.includes(st)) return json({ ok: false, error: 'validation' }, 400, origin);
            lead.stage = st;
          }
          if (d.notes != null) lead.notes = String(d.notes).slice(0, 2000);
          await env.LEADS.put(key, JSON.stringify(lead));
          return json({ ok: true, lead: lead }, 200, origin);
        }
        if (request.method === 'DELETE') {
          await env.LEADS.delete(key);
          await idxRemove(env, 'leads', m[1]);
          return json({ ok: true }, 200, origin);
        }
      }

      // ---- market radar leads (daily agent ingest + portal review) ----
      if (path === '/api/market-leads' && request.method === 'POST') {
        let d = null;
        try { d = await request.json(); } catch (e) {}
        if (!d || !Array.isArray(d.leads)) return json({ ok: false, error: 'validation' }, 400, origin); // a malformed batch must fail loudly, not report ok with 0 added (cycle 28, Claude M4)
        const items = d.leads.slice(0, 60);
        let added = 0, skipped = 0;
        const seenBatch = new Set();
        for (const it of items) {
          if (!it || typeof it !== 'object') { skipped++; continue; }
          const url = safeUrl(it.url, 600);
          if (!url) { skipped++; continue; }
          const urlKey = 'murl:' + (await sha256hex(url));
          if (seenBatch.has(urlKey)) { skipped++; continue; }
          seenBatch.add(urlKey);
          if (await env.LEADS.get(urlKey)) { skipped++; continue; }
          const kind = MKINDS.includes(String(it.kind || '').toLowerCase()) ? String(it.kind).toLowerCase() : 'buyer';
          const conf = Math.max(0, Math.min(100, parseInt(it.confidence, 10) || 0));
          const cleanMatch = function (m) {
            if (!m || typeof m !== 'object') return null;
            return {
              title: cleanText(m.title, 200),
              url: safeUrl(m.url, 600),
              price: cleanText(m.price, 60),
              note: cleanText(m.note, 400)
            };
          };
          let matches = Array.isArray(it.matches) ? it.matches.map(cleanMatch).filter(Boolean).slice(0, 3) : [];
          const match = cleanMatch(it.match) || matches[0] || null;
          if (!matches.length && match) matches = [match];
          const matchScore = Math.max(0, Math.min(100, parseInt(it.matchScore, 10) || 0));
          const pclass = String(it.propertyClass || '').toLowerCase() === 'commercial' ? 'commercial' : 'residential';
          const belowPct = Math.max(0, Math.min(60, parseInt(it.belowMarketPct, 10) || 0));
          const priceNum = (typeof it.priceNum === 'number' && isFinite(it.priceNum) && it.priceNum > 0) ? Math.round(it.priceNum) : null;
          const id = Date.now().toString(36) + '-' + randHex(6);
          const nowS = Math.floor(Date.now() / 1000);
          const lead = {
            id: id, created_at: new Date().toISOString(),
            kind: kind,
            title: cleanText(it.title, 200),
            area: cleanText(it.area, 80),
            price: cleanText(it.price, 60),
            source: cleanText(it.source, 40),
            url: url,
            posted_at: cleanText(it.posted_at, 60),
            summary: cleanText(it.summary, 1200),
            match: match,
            matches: matches,
            matchScore: matchScore,
            propertyClass: pclass,
            belowMarketPct: belowPct,
            marketNote: cleanText(it.marketNote, 300),
            priceNum: priceNum,
            confidence: conf,
            risk: cleanText(it.risk, 300),
            presale: (it.presale && typeof it.presale === 'object') ? {
              project: cleanText(it.presale.project, 80), developer: cleanText(it.presale.developer, 80),
              completion: cleanText(it.presale.completion, 20),
              originalPrice: (typeof it.presale.originalPrice === 'number' && isFinite(it.presale.originalPrice) && it.presale.originalPrice > 0) ? Math.round(it.presale.originalPrice) : null,
              depositPaid: cleanText(it.presale.depositPaid, 60), assignmentFee: cleanText(it.presale.assignmentFee, 60)
            } : null,
            flags: Array.isArray(it.flags) ? it.flags.map(function (f) { return cleanText(f, 120); }).filter(Boolean).slice(0, 6) : [],
            status: 'new', notes: ''
          };
          await env.LEADS.put('mlead:' + id, JSON.stringify(lead), { expiration: nowS + 60 * 86400 });
          await env.LEADS.put(urlKey, id, { expiration: nowS + 61 * 86400 });
          added++;
        }
        return json({ ok: true, added: added, skipped: skipped, dropped: Math.max(0, d.leads.length - 60) }, 200, origin);
      }

      if (path === '/api/market-leads' && request.method === 'GET') {
        const mleads = await adminCachedGen(env, 'mleads', async function () {
          const mkeys = await listAllKeys(env, 'mlead:', 2000); // paginated (was a single 1000-key page: beyond it the NEWEST leads silently vanished — cycle 28, Claude H2)
          const out = (await Promise.all(
            mkeys.map(k => env.LEADS.get(k.name, { type: 'json' }))
          )).filter(Boolean);
          out.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
          return out;
        });
        return json({ ok: true, leads: mleads }, 200, origin);
      }

      // ---- market radar: seen registry (posts the scan already reviewed;
      // lets later runs skip re-reviewing them and spot price drops) ----
      if (path === '/api/radar-seen' && request.method === 'GET') {
        const keys = await listAllKeys(env, 'seen:', 2000);
        const vals = await Promise.all(keys.map(k => env.LEADS.get(k.name, { type: 'json' })));
        const seen = vals.filter(Boolean).sort(function (a, b) { return String(b.at || '').localeCompare(String(a.at || '')); }).slice(0, 2000);
        return json({ ok: true, seen: seen }, 200, origin);
      }
      if (path === '/api/radar-seen' && request.method === 'POST') {
        let d = null;
        try { d = await request.json(); } catch (e) {}
        if (!d || !Array.isArray(d.items)) return json({ ok: false, error: 'validation' }, 400, origin);
        const items = d.items.slice(0, 100);
        let saved = 0;
        const nowS2 = Math.floor(Date.now() / 1000);
        for (const it of items) {
          if (!it || typeof it !== 'object') continue;
          const u = safeUrl(it.url, 600);
          if (!u) continue;
          const pn = (typeof it.priceNum === 'number' && isFinite(it.priceNum) && it.priceNum > 0) ? Math.round(it.priceNum) : null;
          const seenKey = 'seen:' + (await sha256hex(u));
          let keepPn = pn;
          if (keepPn === null) { const prev = await env.LEADS.get(seenKey, { type: 'json' }); if (prev && typeof prev.priceNum === 'number') keepPn = prev.priceNum; } // an unparsed re-post must not erase the price baseline (cycle 28, Claude M10)
          await env.LEADS.put(seenKey, JSON.stringify({ url: u, priceNum: keepPn, at: new Date().toISOString() }), { expiration: nowS2 + 61 * 86400 });
          saved++;
        }
        return json({ ok: true, saved: saved, dropped: Math.max(0, d.items.length - 100) }, 200, origin);
      }

      const mm = path.match(/^\/api\/market-leads\/([A-Za-z0-9-]+)$/);
      if (mm) {
        const key = 'mlead:' + mm[1];
        if (request.method === 'PATCH') {
          const lead = await env.LEADS.get(key, { type: 'json' });
          if (!lead) return json({ ok: false, error: 'not_found' }, 404, origin);
          let d = null, dBad = false;
          try { d = await request.json(); } catch (e) { dBad = true; }
          if (dBad || !d || typeof d !== 'object') return json({ ok: false, error: 'validation' }, 400, origin);
          if (d.status !== undefined) {
            const st = String(d.status).toLowerCase();
            if (!MSTATUSES.includes(st)) return json({ ok: false, error: 'validation' }, 400, origin);
            lead.status = st;
          }
          if (d.notes != null) lead.notes = String(d.notes).slice(0, 2000);
          const expT = Math.max(Math.floor((Date.parse(lead.created_at || '') || Date.now()) / 1000) + 60 * 86400, Math.floor(Date.now() / 1000) + 120); // never under KV's 60-second minimum TTL (cycle 28, Claude L1)
          await env.LEADS.put(key, JSON.stringify(lead), { expiration: expT });
          return json({ ok: true, lead: lead }, 200, origin);
        }
        if (request.method === 'DELETE') {
          // The murl: marker stays as a tombstone (until its TTL) so a lead
          // the owner rejected is not re-ingested by the next daily run.
          await env.LEADS.delete(key);
          return json({ ok: true }, 200, origin);
        }
      }

      // ---- admin: aggregated site-traffic stats ----
      if (path === '/api/admin/stats' && request.method === 'GET') {
        const days = Math.max(1, Math.min(31, parseInt(url.searchParams.get('days') || '14', 10) || 14));
        const series = [];
        const tot = { pv: {}, ev: {}, li: {}, lang: {}, ref: {}, views: 0, uniques: 0 };
        for (let i = days - 1; i >= 0; i--) {
          const dk = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
          const doc = await env.LEADS.get('stat:' + dk, { type: 'json' });
          let views = 0, uniques = 0;
          if (doc) {
            Object.values(doc.pv || {}).forEach(v => { if (typeof v === 'number') views += v; });
            uniques = Object.keys(doc.uv || {}).length;
            ['pv', 'ev', 'li', 'lang', 'ref'].forEach(k => {
              Object.entries(doc[k] || {}).forEach(([kk, vv]) => { if (typeof vv !== 'number' || kk === '__proto__' || kk === 'constructor' || kk === 'prototype') return; tot[k][kk] = (tot[k][kk] || 0) + vv; });
            });
          }
          series.push({ day: dk, views: views, uniques: uniques });
          tot.views += views; tot.uniques += uniques;
        }
        const today = series[series.length - 1] || { views: 0, uniques: 0 };
        return json({ ok: true, days: days, series: series, totals: tot, today: today }, 200, origin);
      }

      // ---- admin: newsletter subscribers (grouped by language) ----
      if (path === '/api/admin/newsletter' && request.method === 'GET') {
        const data = await adminCachedGen(env, 'newsletter', async function () {
          const subs = [];
          for (const nid of await idxGet(env, 'nlsubs', 'nlsub:')) {
            const raw = await env.LEADS.get('nlsub:' + nid);
            if (!raw) continue;
            try { const s = JSON.parse(raw); subs.push({ name: s.name || '', email: s.email || '', lang: s.lang || 'en', created_at: s.created_at || '' }); } catch (e) {}
          }
          subs.sort(function (a, b) { return String(b.created_at).localeCompare(String(a.created_at)); });
          const byLang = { en: 0, fa: 0, hi: 0, zh: 0 };
          subs.forEach(function (s) { if (Object.prototype.hasOwnProperty.call(byLang, s.lang)) byLang[s.lang]++; });
          return { subscribers: subs, byLang: byLang, count: subs.length };
        });
        return json({ ok: true, subscribers: data.subscribers, byLang: data.byLang, count: data.count }, 200, origin);
      }
      if (path === '/api/admin/newsletter' && request.method === 'DELETE') {
        const em = String(url.searchParams.get('email') || '').trim().toLowerCase();
        if (!em || em.length > 160) return json({ ok: false, error: 'validation' }, 400, origin);
        await env.LEADS.delete('nlsub:' + em);
        await idxRemove(env, 'nlsubs', em);
        return json({ ok: true }, 200, origin);
      }

      // ---- admin: portal-managed listings + site settings ----
      if (path === '/api/admin/listings' && request.method === 'GET') {
        if (!(await authed(request, env))) return json({ ok: false, error: 'unauthorized' }, 401, origin);
        await refreshCustomCatalog(env, true);
        return json({ ok: true, listings: customListings, deletedSeeds: deletedSeedMls, seeds: SEED_LISTINGS }, 200, origin);
      }
      if (path === '/api/admin/listings' && request.method === 'POST') {
        if (!(await authed(request, env))) return json({ ok: false, error: 'unauthorized' }, 401, origin);
        let body = null;
        try { body = await request.json(); } catch (e) {}
        if (!body || typeof body !== 'object') return json({ ok: false, error: 'validation' }, 400, origin);
        const cl = cleanListing(body.listing);
        if (cl.error) return json({ ok: false, error: 'validation', field: cl.error }, 400, origin);
        const rec = cl.rec;
        const isNew = !customListings.some(function (r) { return r.mls === rec.mls; });
        if (isNew && customListings.length >= 300) return json({ ok: false, error: 'too_many' }, 400, origin);
        if (body.photoData !== undefined) {
          if (body.photoData === '') {
            await env.LEADS.delete('lphoto:' + rec.mls);
            if (rec.photo === 'upload') rec.photo = '';
          } else if (validPhotoData(body.photoData)) {
            await env.LEADS.put('lphoto:' + rec.mls, body.photoData);
            rec.photo = 'upload';
          } else {
            return json({ ok: false, error: 'validation', field: 'photoData' }, 400, origin);
          }
        }
        if (rec.photo === 'upload' && !(await env.LEADS.get('lphoto:' + rec.mls))) {
          return json({ ok: false, error: 'validation', field: 'photo_missing' }, 400, origin);
        }
        await env.LEADS.put('listing:' + rec.mls, JSON.stringify(rec));
        upsertLocalListing(rec);
        await updateCatalogSnap(env, rec);
        return json({ ok: true, listing: rec }, 200, origin);
      }
      const ldel = path.match(/^\/api\/admin\/listings\/(.+)$/);
      if (ldel && request.method === 'DELETE') {
        if (!(await authed(request, env))) return json({ ok: false, error: 'unauthorized' }, 401, origin);
        let mls = '';
        try { mls = decodeURIComponent(ldel[1]).toUpperCase(); } catch (e) { return json({ ok: false, error: 'validation' }, 400, origin); } // validate the FULL id before deleting: truncating first mapped over-long ids onto other listings (cycle 28, Claude M6)
        if (!/^[A-Z0-9-]{3,24}$/.test(mls)) return json({ ok: false, error: 'validation' }, 400, origin);
        const tomb = url.searchParams.get('tombstone') === '1';
        if (tomb && !CATALOG.some(function (c) { return c.mls === mls; })) return json({ ok: false, error: 'validation', field: 'tombstone_non_seed' }, 400, origin);
        if (tomb) {
          await env.LEADS.put('listing:' + mls, JSON.stringify({ mls: mls, _deleted: true, updated_at: new Date().toISOString() }));
        } else {
          await env.LEADS.delete('listing:' + mls);
        }
        await env.LEADS.delete('lphoto:' + mls);
        await env.LEADS.delete('avail:' + mls); // availability must not resurface if the mls is re-created (cycle 28, Claude L8)
        removeLocalListing(mls, tomb);
        await updateCatalogSnap(env, null, mls, tomb);
        return json({ ok: true }, 200, origin);
      }
      if (path === '/api/admin/settings' && request.method === 'GET') {
        if (!(await authed(request, env))) return json({ ok: false, error: 'unauthorized' }, 401, origin);
        return json({ ok: true, settings: await getSiteSettings(env) }, 200, origin);
      }
      if (path === '/api/admin/settings' && request.method === 'POST') {
        if (!(await authed(request, env))) return json({ ok: false, error: 'unauthorized' }, 401, origin);
        let body = null;
        try { body = await request.json(); } catch (e) {}
        if (!body || typeof body !== 'object') return json({ ok: false, error: 'validation' }, 400, origin);
        const cs2 = cleanSettings(body.settings);
        if (cs2.error) return json({ ok: false, error: 'validation', field: cs2.error }, 400, origin);
        const st = cs2.settings;
        if (body.heroPhotoData !== undefined) {
          if (body.heroPhotoData === '') {
            await env.LEADS.delete('lphoto:__hero');
            if (st.heroPhoto === 'upload') st.heroPhoto = '';
          } else if (validPhotoData(body.heroPhotoData)) {
            await env.LEADS.put('lphoto:__hero', body.heroPhotoData);
            st.heroPhoto = 'upload';
          } else {
            return json({ ok: false, error: 'validation', field: 'heroPhotoData' }, 400, origin);
          }
        }
        if (st.heroPhoto === 'upload' && !(await env.LEADS.get('lphoto:__hero'))) {
          return json({ ok: false, error: 'validation', field: 'heroPhoto_missing' }, 400, origin);
        }
        st.updated_at = new Date().toISOString();
        await env.LEADS.put('site:settings', JSON.stringify(st));
        return json({ ok: true, settings: st }, 200, origin);
      }

      // ---- admin: per-listing viewing availability ----
      if (path === '/api/admin/availability' && request.method === 'GET') {
        await refreshCustomCatalog(env, true);
        const out = await Promise.all(mergedCatalog().map(async function (c) {
          const a = await getAvail(env, c.mls);
          return { mls: c.mls, street: c.street, city: c.city, price: c.price, dates: a ? a.dates : [] };
        }));
        return json({ ok: true, listings: out }, 200, origin);
      }
      const avm = path.match(/^\/api\/admin\/availability\/(.+)$/);
      if (avm && (request.method === 'POST' || request.method === 'DELETE')) {
        let mlsRaw = '';
        try { mlsRaw = decodeURIComponent(avm[1]).slice(0, 40); } catch (e) { return json({ ok: false, error: 'validation' }, 400, origin); }
        const catA = catalogByMls(mlsRaw);
        if (!catA) return json({ ok: false, error: 'not_found' }, 404, origin);
        const mls = catA.mls;
        if (request.method === 'DELETE') { await env.LEADS.delete('avail:' + mls); return json({ ok: true }, 200, origin); }
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        if (d.dates !== undefined && !Array.isArray(d.dates)) return json({ ok: false, error: 'validation', field: 'dates' }, 400, origin);
        const rowsIn = Array.isArray(d.dates) ? d.dates.length : 0;
        const today = new Date().toLocaleDateString('en-CA', { timeZone: 'America/Vancouver' });
        const horizon = new Date(Date.now() + 365 * 86400000).toISOString().slice(0, 10);
        const clean = [];
        const seenD = {};
        for (const row of (Array.isArray(d.dates) ? d.dates : []).slice(0, 60)) {
          const dt = String((row && row.date) || '').slice(0, 10);
          const dOk = /^\d{4}-\d{2}-\d{2}$/.test(dt) && !isNaN(Date.parse(dt + 'T00:00:00Z')) && new Date(Date.parse(dt + 'T00:00:00Z')).toISOString().slice(0, 10) === dt;
          if (!dOk || dt < today || dt > horizon || seenD[dt]) continue;
          const times = [];
          for (const t of (Array.isArray(row.times) ? row.times : []).slice(0, 12)) {
            const ts = String(t).slice(0, 5);
            if (/^([01]\d|2[0-3]):[0-5]\d$/.test(ts) && times.indexOf(ts) < 0) times.push(ts);
          }
          if (!times.length) continue;
          times.sort();
          seenD[dt] = true;
          clean.push({ date: dt, times: times });
        }
        clean.sort(function (x, y) { return x.date < y.date ? -1 : 1; });
        if (!clean.length) { if (rowsIn > 0) return json({ ok: false, error: 'validation', field: 'dates', rejected: rowsIn }, 400, origin); await env.LEADS.delete('avail:' + mls); return json({ ok: true, dates: [] }, 200, origin); } // non-empty-but-all-invalid must not silently wipe availability (cycle 28, Claude M5)
        await env.LEADS.put('avail:' + mls, JSON.stringify({ dates: clean }));
        return json({ ok: true, dates: clean }, 200, origin);
      }

      // ---- admin: tasks & reminders ----
      if (path === '/api/admin/tasks' && request.method === 'GET') {
        const all = await allTasks(env);
        all.sort(function (a, b) { return String(a.due).localeCompare(String(b.due)); });
        return json({ ok: true, tasks: all }, 200, origin);
      }
      if (path === '/api/admin/tasks' && request.method === 'POST') {
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const em = normEmail(String(d.email || ''));
        const text = cleanText(d.text, 200);
        const due = String(d.due || '').slice(0, 10);
        if (!em || !text || !/^\d{4}-\d{2}-\d{2}$/.test(due) || isNaN(Date.parse(due + 'T00:00:00Z')) || new Date(Date.parse(due + 'T00:00:00Z')).toISOString().slice(0, 10) !== due) return json({ ok: false, error: 'validation' }, 400, origin);
        const t = { id: 'tk_' + randHex(6), email: em, text: text, due: due, done: false, created_at: new Date().toISOString() };
        await env.LEADS.put('task:' + t.id, JSON.stringify(t));
        await idxAdd(env, 'tasks', t.id);
        adminCache.delete('contacts'); // post-write: a contacts build started before this write must not re-serve stale data
        return json({ ok: true, task: t }, 200, origin);
      }
      const tkm = path.match(/^\/api\/admin\/tasks\/(tk_[A-Za-z0-9_-]+)$/);
      if (tkm && (request.method === 'PATCH' || request.method === 'DELETE')) {
        const t = await env.LEADS.get('task:' + tkm[1], { type: 'json' });
        if (!t) return json({ ok: false, error: 'not_found' }, 404, origin);
        if (request.method === 'DELETE') {
          await env.LEADS.delete('task:' + tkm[1]);
          await idxRemove(env, 'tasks', tkm[1]);
          adminCache.delete('contacts');
          return json({ ok: true }, 200, origin);
        }
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        if (d.done !== undefined) t.done = d.done === true;
        if (d.text !== undefined) { const tx = cleanText(d.text, 200); if (!tx) return json({ ok: false, error: 'validation' }, 400, origin); t.text = tx; }
        if (d.due !== undefined) { const du = String(d.due).slice(0, 10); if (!/^\d{4}-\d{2}-\d{2}$/.test(du) || isNaN(Date.parse(du + 'T00:00:00Z')) || new Date(Date.parse(du + 'T00:00:00Z')).toISOString().slice(0, 10) !== du) return json({ ok: false, error: 'validation' }, 400, origin); t.due = du; }
        await env.LEADS.put('task:' + tkm[1], JSON.stringify(t));
        adminCache.delete('contacts');
        return json({ ok: true, task: t }, 200, origin);
      }

      // ---- admin: CRM ----
      if (path === '/api/admin/crm/merge' && request.method === 'POST') {
        let d = null; try { d = await request.json(); } catch (e) {}
        const from = normEmail(String((d || {}).from || ''));
        const to = normEmail(String((d || {}).to || ''));
        if (!from || !to || from === to || from.indexOf('@') < 1 || to.indexOf('@') < 1) return json({ ok: false, error: 'validation' }, 400, origin);
        let chainCur = to; let isCycle = false;
        for (let ci = 0; ci < 10; ci++) { const cm = await getCMeta(env, chainCur); if (!cm.mergedInto) break; if (cm.mergedInto === from) { isCycle = true; break; } chainCur = cm.mergedInto; }
        if (isCycle) return json({ ok: false, error: 'merge_cycle' }, 400, origin);
        const endMeta = await getCMeta(env, chainCur);
        if (endMeta.mergedInto === from) return json({ ok: false, error: 'merge_cycle' }, 400, origin);
        if (endMeta.mergedInto) return json({ ok: false, error: 'merge_chain_too_long' }, 400, origin);
        const canonicalTo = chainCur; // merge into the END of the chain, not a dead middle record (cycle 29, Claude M1)
        const meta = await getCMeta(env, from);
        if (meta.mergedInto && meta.mergedInto !== canonicalTo) return json({ ok: false, error: 'already_merged' }, 409, origin);
        const tMeta = await getCMeta(env, canonicalTo);
        let tChanged = false;
        if (meta.dnc && !tMeta.dnc) { tMeta.dnc = true; tChanged = true; }
        if (meta.stage && !tMeta.stage) { tMeta.stage = meta.stage; tChanged = true; }
        const tagUnion = Array.from(new Set([].concat(tMeta.tags || [], meta.tags || []))).slice(0, 12);
        if (JSON.stringify(tagUnion) !== JSON.stringify(tMeta.tags || [])) { tMeta.tags = tagUnion; tChanged = true; }
        if ((meta.notes || []).length) { const haveIds = Object.create(null); (tMeta.notes || []).forEach(function (n) { haveIds[n.id] = 1; }); const extra = meta.notes.filter(function (n) { return !haveIds[n.id]; }); if (extra.length) { tMeta.notes = (tMeta.notes || []).concat(extra).slice(0, 100); tChanged = true; } }
        if (tChanged) await saveCMeta(env, canonicalTo, tMeta);
        for (const t of await allTasks(env)) if (normEmail(t.email || '') === from) { t.email = canonicalTo; await env.LEADS.put('task:' + t.id, JSON.stringify(t)); }
        meta.mergedInto = canonicalTo;
        await saveCMeta(env, from, meta); // mergedInto written LAST: a failure above leaves the merge retryable instead of hiding `from` behind an incomplete target
        await pushActivity(env, canonicalTo, 'note', 'Merged duplicate contact ' + from + ' into this profile');
        await env.LEADS.put('audit:' + Date.now() + ':' + randHex(6), JSON.stringify({ action: 'crm_merge', target: canonicalTo, from: from, ip: ip, at: new Date().toISOString() }), { expirationTtl: 730 * 86400 });
        adminCache.delete('contacts'); adminCache.delete('desk');
        return json({ ok: true }, 200, origin);
      }
      if (path === '/api/admin/crm/matches' && request.method === 'GET') {
        const pairs = await adminCachedGen(env, 'crmmatches', async function () {
          const contacts = await buildContacts(env);
          const out = [];
          for (const c of contacts) {
            if (c.banned) continue;
            const savedSet = Object.create(null);
            (c.savedHomes || []).forEach(function (h) { savedSet[h.mls] = 1; });
            for (const s of (c.searches || [])) {
              const crit = s.criteria || {};
              for (const mls of matchSearch(crit)) {
                if (savedSet[mls]) continue;
                const l = catalogByMls(mls); if (!l) continue;
                let fit = 40;
                if (crit.maxPrice) { const mp = parseInt(String(crit.maxPrice).replace(/[^0-9]/g, ''), 10); if (mp > 0) fit += Math.round(Math.max(0, Math.min(1, (mp - l.price) / mp)) * 25); }
                else fit += 12;
                if (crit.minBeds && l.beds >= parseInt(crit.minBeds, 10)) fit += 15;
                if (crit.q && (l.street + ' ' + l.city).toLowerCase().indexOf(String(crit.q).toLowerCase()) !== -1) fit += 10;
                if (l.listed && (Date.now() - Date.parse(l.listed)) < 30 * 86400000) fit += 10;
                out.push({ email: c.email, name: c.name || c.email, mls: mls, title: l.street + ', ' + l.city, price: l.price, fit: Math.min(100, fit), searchName: s.name || '' });
              }
            }
          }
          out.sort(function (a, b) { return b.fit - a.fit; });
          return out.slice(0, 60);
        });
        return json({ ok: true, matches: pairs }, 200, origin);
      }
      if (path === '/api/admin/crm/analytics' && request.method === 'GET') {
        const data = await adminCachedGen(env, 'crmanalytics', async function () {
          const leads = [];
          for (const lid of await idxGet(env, 'leads', 'lead:')) { const l = await env.LEADS.get('lead:' + lid, { type: 'json' }); if (l) leads.push(l); }
          const stages = { new: 0, contacted: 0, viewing: 0, offer: 0, closed: 0, dropped: 0 };
          let leads7d = 0; const wk = Date.now() - 7 * 86400000;
          for (const l of leads) { if (stages[l.stage] !== undefined) stages[l.stage]++; if (Date.parse(l.created_at || '') > wk) leads7d++; }
          const prob = { new: 0.05, contacted: 0.15, viewing: 0.35, offer: 0.65, closed: 1, dropped: 0 };
          const contacts = await buildContacts(env);
          const byEmail = Object.create(null);
          contacts.forEach(function (c) { byEmail[normEmail(c.email)] = c; });
          let pipeline = 0, expected = 0, pricedDeals = 0;
          for (const l of leads) {
            if (l.stage === 'dropped') continue;
            let val = 0;
            const mm = String(l.message || '').match(/\(([A-Za-z]\d{7,})\)/);
            if (mm) { const cat = catalogByMls(mm[1]); if (cat) val = cat.price; }
            if (!val) val = parseBudget(l.budget);
            if (!val) { const c = byEmail[normEmail(l.email || '')]; if (c && (c.savedHomes || []).length) val = Math.max.apply(null, c.savedHomes.map(function (h) { return h.priceNow || 0; })); }
            if (val > 0) { pricedDeals++; pipeline += val; expected += val * (prob[l.stage] !== undefined ? prob[l.stage] : 0.05); }
          }
          const order = ['new', 'contacted', 'viewing', 'offer', 'closed'];
          let bottleneck = null, worst = Infinity;
          const reached = order.map(function (_, i) { return order.slice(i).reduce(function (s2, st) { return s2 + (stages[st] || 0); }, 0); });
          for (let i = 0; i < order.length - 1; i++) { if (reached[i] > 0) { const r = reached[i + 1] / reached[i]; if (r < worst) { worst = r; bottleneck = order[i] + ' → ' + order[i + 1]; } } }
          const tasks = await allTasks(env);
          const todayStr = todayVancouver();
          return { stages: stages, totalLeads: leads.length, leads7d: leads7d, pipeline: Math.round(pipeline), expected: Math.round(expected), commission: Math.round(expected * 0.025), pricedDeals: pricedDeals, bottleneck: bottleneck,
            tasksOverdue: tasks.filter(function (t) { return !t.done && t.due < todayStr; }).length,
            tasksDueToday: tasks.filter(function (t) { return !t.done && t.due === todayStr; }).length,
            coldRiskCount: contacts.filter(function (c) { return c.coldRisk; }).length,
            hotCount: contacts.filter(function (c) { return c.tier === 'hot'; }).length, people: contacts.length };
        });
        return json({ ok: true, analytics: data }, 200, origin);
      }
      if (path === '/api/admin/mailq' && request.method === 'POST') {
        let d = null; try { d = await request.json(); } catch (e) {}
        const to = normEmail(String((d || {}).to || ''));
        const subject = String((d || {}).subject || '').replace(/[\r\n]+/g, ' ').slice(0, 200);
        const body = String((d || {}).body || '').slice(0, 4000);
        if (!to || to.indexOf('@') < 1 || !subject || !body) return json({ ok: false, error: 'validation' }, 400, origin);
        const banRec = await env.LEADS.get('ban:' + to, { type: 'json' });
        const toMeta = await getCMeta(env, to);
        if (banRec || (toMeta && toMeta.dnc)) return json({ ok: false, error: 'suppressed' }, 403, origin);
        const mid = await queueMail(env, { kind: 'manual', to: to, lang: validLang((d || {}).lang), name: String((d || {}).name || '').replace(/[\r\n]+/g, ' ').slice(0, 80), subject: subject, body: body });
        return json({ ok: true, id: mid }, 200, origin);
      }
      const crmNoteDel = path.match(/^\/api\/admin\/crm\/([^/]+)\/notes\/([A-Za-z0-9-]+)$/);
      if (crmNoteDel && request.method === 'DELETE') {
        let nk = ''; try { nk = normEmail(decodeURIComponent(crmNoteDel[1])); } catch (e) { return json({ ok: false, error: 'validation' }, 400, origin); }
        if (!nk || nk.indexOf('@') < 1) return json({ ok: false, error: 'validation' }, 400, origin);
        const meta = await getCMeta(env, nk);
        meta.notes = (meta.notes || []).filter(function (n) { return n.id !== crmNoteDel[2]; });
        await saveCMeta(env, nk, meta);
        return json({ ok: true }, 200, origin);
      }
      const crmSub = path.match(/^\/api\/admin\/crm\/([^/]+)\/(notes|logcall|ai-brief|ai-extract)$/);
      if (crmSub) {
        let nk = ''; try { nk = normEmail(decodeURIComponent(crmSub[1])); } catch (e) { return json({ ok: false, error: 'validation' }, 400, origin); }
        const sub = crmSub[2];
        let d = null; try { d = await request.json(); } catch (e) {}
        d = d || {};
        if (sub === 'notes' && request.method === 'POST') {
          const text = String(d.text || '').trim().slice(0, 2000);
          if (!nk || nk.indexOf('@') < 1 || !text) return json({ ok: false, error: 'validation' }, 400, origin);
          const meta = await getCMeta(env, nk);
          const note = { id: 'nt' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), text: text, kind: d.kind === 'call' ? 'call' : 'note', at: new Date().toISOString() };
          meta.notes = [note].concat(meta.notes || []).slice(0, 100);
          await saveCMeta(env, nk, meta);
          await pushActivity(env, nk, 'note', text.slice(0, 120));
          return json({ ok: true, note: note }, 200, origin);
        }
        if (sub === 'logcall' && request.method === 'POST') {
          const text = String(d.text || '').trim().slice(0, 2000);
          if (!nk || nk.indexOf('@') < 1) return json({ ok: false, error: 'validation' }, 400, origin);
          const meta = await getCMeta(env, nk);
          const note = { id: 'nt' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), text: text || 'Call logged', kind: 'call', at: new Date().toISOString() };
          meta.notes = [note].concat(meta.notes || []).slice(0, 100);
          await saveCMeta(env, nk, meta);
          await pushActivity(env, nk, 'call', (text || 'Call').slice(0, 120));
          let task = null;
          const days = Math.max(0, Math.min(60, parseInt(d.followUpDays, 10) || 0));
          if (days > 0) {
            task = { id: 'tk' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7), email: nk, text: 'Follow up call with ' + (String(d.name || '').slice(0, 80) || nk), due: new Date(Date.parse(todayVancouver() + 'T00:00:00Z') + days * 86400000).toISOString().slice(0, 10), done: false, created_at: new Date().toISOString() };
            await env.LEADS.put('task:' + task.id, JSON.stringify(task));
            await idxAdd(env, 'tasks', task.id); // allTasks reads the index: without this the task is invisible until the nightly reindex (found in cycle-29 vetting)
            adminCache.delete('contacts'); adminCache.delete('desk');
          }
          return json({ ok: true, note: note, task: task }, 200, origin);
        }
        if (sub === 'ai-brief' && request.method === 'POST') {
          const contacts = await buildContacts(env);
          const c = contacts.filter(function (x) { return normEmail(x.email) === nk; })[0];
          if (!c) return json({ ok: false, error: 'not_found' }, 404, origin);
          const aimode = ['brief', 'draft', 'meeting'].indexOf(d.mode) !== -1 ? d.mode : 'brief';
          if (aimode === 'draft' && (c.banned || c.dnc)) return json({ ok: false, error: 'suppressed' }, 403, origin);
          const outAi = await aiInternal(env, '/api/internal/brief', { contact: crmBriefPayload(c), mode: aimode });
          if (!outAi.ok) return json(outAi, 502, origin);
          return json(outAi, 200, origin);
        }
        if (sub === 'ai-extract' && request.method === 'POST') {
          const text = String(d.text || '').trim().slice(0, 3000);
          if (!nk || nk.indexOf('@') < 1 || !text) return json({ ok: false, error: 'validation' }, 400, origin);
          const contacts = await buildContacts(env);
          const c = contacts.filter(function (x) { return normEmail(x.email) === nk; })[0];
          const outAi = await aiInternal(env, '/api/internal/extract', { text: text, contact: c ? crmBriefPayload(c) : { email: nk } });
          if (!outAi.ok) return json(outAi, 502, origin);
          const ex = outAi.extracted || {};
          const exSum = typeof ex.summary === 'string' ? ex.summary : ''; // LLM output is untrusted-typed: a non-string summary must not throw or stringify as [object Object] (cycle 29, Claude M4)
          const meta = await getCMeta(env, nk);
          const prev = meta.brief || {};
          const S = function (x) { return x === null || x === undefined ? '' : String(x).slice(0, 200); };
          meta.brief = { budget: S(ex.budget) || prev.budget || '', areas: S(ex.areas) || prev.areas || '', timeline: S(ex.timeline) || prev.timeline || '',
            preApproved: (ex.preApproved !== null && ex.preApproved !== undefined) ? !!ex.preApproved : prev.preApproved,
            mustHaves: S(ex.mustHaves) || prev.mustHaves || '', objections: S(ex.objections) || prev.objections || '', updated_at: new Date().toISOString() };
          const note = { id: 'nt' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), text: ((exSum ? exSum + ' — ' : '') + text).slice(0, 2000), kind: 'note', at: new Date().toISOString() };
          meta.notes = [note].concat(meta.notes || []).slice(0, 100);
          await saveCMeta(env, nk, meta);
          await pushActivity(env, nk, 'note', (exSum || text).slice(0, 120));
          let created = 0;
          for (const t of (Array.isArray(ex.tasks) ? ex.tasks : []).slice(0, 3)) {
            const ttext = String((t || {}).text || '').slice(0, 200);
            if (!ttext) continue;
            const diRaw = parseInt((t || {}).dueInDays, 10);
            const diDays = Number.isFinite(diRaw) ? Math.max(0, Math.min(90, diRaw)) : 2;
            const tt = { id: 'tk' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7) + created, email: nk, text: ttext, due: new Date(Date.parse(todayVancouver() + 'T00:00:00Z') + diDays * 86400000).toISOString().slice(0, 10), done: false, created_at: new Date().toISOString() };
            await env.LEADS.put('task:' + tt.id, JSON.stringify(tt));
            await idxAdd(env, 'tasks', tt.id);
            created++;
          }
          if (created) { adminCache.delete('contacts'); adminCache.delete('desk'); }
          return json({ ok: true, extracted: ex, note: note, tasksCreated: created, suggestedStage: ['new', 'contacted', 'viewing', 'offer', 'closed', 'dropped'].indexOf(ex.suggestedStage) !== -1 ? ex.suggestedStage : '' }, 200, origin);
        }
      }
      const crmOne = path.match(/^\/api\/admin\/crm\/([^/]+)$/);
      if (crmOne && request.method === 'PATCH') {
        let nk = ''; try { nk = normEmail(decodeURIComponent(crmOne[1])); } catch (e) { return json({ ok: false, error: 'validation' }, 400, origin); }
        if (!nk || nk.indexOf('@') < 1) return json({ ok: false, error: 'validation' }, 400, origin);
        let d = null; try { d = await request.json(); } catch (e) {}
        const meta = await getCMeta(env, nk);
        if (d && Array.isArray(d.tags)) meta.tags = d.tags.map(function (t) { return cleanText(t, 30); }).filter(Boolean).slice(0, 12);
        if (d && d.stage !== undefined) { if (['new', 'contacted', 'viewing', 'offer', 'closed', 'dropped', ''].indexOf(d.stage) === -1) return json({ ok: false, error: 'validation' }, 400, origin); meta.stage = d.stage; }
        if (d && d.dnc !== undefined) { const nd = !!d.dnc; if (nd !== !!meta.dnc) { meta.dnc = nd; await env.LEADS.put('audit:' + Date.now() + ':' + randHex(6), JSON.stringify({ action: 'crm_dnc', target: nk, dnc: nd, ip: ip, at: new Date().toISOString() }), { expirationTtl: 730 * 86400 }); } }
        await saveCMeta(env, nk, meta);
        return json({ ok: true, meta: { tags: meta.tags || [], stage: meta.stage || '', dnc: !!meta.dnc } }, 200, origin);
      }

      // ---- admin: viewings ----
      if (path === '/api/admin/viewings' && request.method === 'GET') {
        const vidx = (await env.LEADS.get('vidx', { type: 'json' })) || [];
        const out = [];
        for (const id of vidx.slice(0, 100)) {
          const raw = await env.LEADS.get('viewing:' + id);
          if (raw) { try { out.push(JSON.parse(raw)); } catch (e) {} }
        }
        return json({ ok: true, viewings: out }, 200, origin);
      }
      const vwm = path.match(/^\/api\/admin\/viewings\/([A-Za-z0-9_-]+)$/);
      if (vwm && request.method === 'PATCH') {
        let d = null;
        try { d = await request.json(); } catch (e) {}
        const raw = await env.LEADS.get('viewing:' + vwm[1]);
        if (!raw) return json({ ok: false, error: 'not_found' }, 404, origin);
        let rec = null;
        try { rec = JSON.parse(raw); } catch (e) {}
        if (!rec) return json({ ok: false, error: 'corrupt' }, 500, origin);
        const st = String((d || {}).status || '').toLowerCase();
        if (!['new', 'confirmed', 'done', 'cancelled'].includes(st)) return json({ ok: false, error: 'validation' }, 400, origin);
        if (rec.status === 'cancelled' && st !== 'cancelled') return json({ ok: false, error: 'conflict' }, 409, origin);
        rec.status = st;
        // Keep the calendar in sync with the desk: cancelling removes the
        // event; confirming queues the visitor a confirmation email (once).
        let cancelEv = '';
        if (st === 'cancelled' && rec.gcalEventId) cancelEv = rec.gcalEventId; // the id stays on the record: if the calendar delete fails, re-cancelling retries it (cycle 29, Claude M5)
        let mailConfirm = false;
        if (st === 'confirmed' && !rec.confirmMailAt) { rec.confirmMailAt = new Date().toISOString(); mailConfirm = true; }
        await env.LEADS.put('viewing:' + vwm[1], JSON.stringify(rec)); // record first, side effects second: a failed put must not leave a queued confirmation behind
        if (mailConfirm) {
          const home3 = rec.listingId ? catalogByMls(rec.listingId) : null;
          await queueMail(env, { kind: 'viewing', to: rec.email, lang: rec.lang || 'en', name: rec.name, ref: rec.id, date: rec.date, time: rec.time, confirmed: true, listing: home3 ? { mls: home3.mls, street: home3.street, city: home3.city } : null });
        }
        if (cancelEv && ctx && ctx.waitUntil) ctx.waitUntil(Promise.resolve(gcalDeleteEvent(env, cancelEv)).catch(function () {}));
        return json({ ok: true }, 200, origin);
      }

      // ---- admin: registered visitors (summary) + delete / ban by email ----
      if (path === '/api/admin/users' && request.method === 'GET') {
        const data = await adminCachedGen(env, 'users', async function () {
        const userIds = await idxGet(env, 'users', 'user:', 5000);
        const banSet = Object.create(null);
        for (const bid of await idxGet(env, 'bans', 'ban:')) { const bv = await env.LEADS.get('ban:' + bid, { type: 'json' }); if (bv) banSet[bid] = bv; }
        const out = [];
        for (const uid of userIds) {
          const raw = await env.LEADS.get('user:' + uid);
          if (!raw) continue;
          let u = null;
          try { u = JSON.parse(raw); } catch (e) {}
          if (!u) continue;
          const saved = await userSaved(env, u.email);
          const searches = await userSearches(env, u.email);
          const ban = banSet[normEmail(u.email)];
          out.push({ name: u.name, email: u.email, lang: u.lang, created_at: u.created_at, lastLogin: u.lastLogin || '', phone: (u.profile && u.profile.phone) || '', intent: (u.profile && u.profile.intent) || '', savedCount: saved.length, searchCount: searches.length, banned: !!ban, banReason: ban ? (ban.reason || '') : '' });
        }
        out.sort(function (a, b) { return String(b.created_at).localeCompare(String(a.created_at)); });
        const banList = Object.keys(banSet).map(function (nk) { return { email: banSet[nk].email || nk, normalized: nk, reason: banSet[nk].reason || '', at: banSet[nk].at || '' }; });
        return { users: out, count: out.length, bans: banList };
        });
        return json({ ok: true, users: data.users, count: data.count, bans: data.bans }, 200, origin);
      }
      const aum = path.match(/^\/api\/admin\/users\/(.+)$/);
      if (aum && (request.method === 'DELETE' || request.method === 'POST')) {
        let target = '';
        try { target = decodeURIComponent(aum[1]).trim().toLowerCase(); } catch (e) { return json({ ok: false, error: 'validation' }, 400, origin); }
        if (!EMAIL_RE.test(target)) return json({ ok: false, error: 'validation' }, 400, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        if (request.method === 'DELETE') {
          // Delete the account + everything the account owns. Leads, viewings
          // and newsletter records stay: they are the business's own records.
          // NOTE: user-owned keys use the raw email, but uact:/tasks are keyed
          // by the NORMALIZED email — cascade with targetN for those.
          // Sessions are purged FIRST (a live session could recreate saved
          // data mid-cascade) and again at the end; the user record goes last.
          const targetN = normEmail(target);
          await purgeUserSessions(env, target);
          await env.LEADS.delete('usaved:' + target);
          await env.LEADS.delete('usavep:' + target);
          await env.LEADS.delete('usearch:' + target);
          await env.LEADS.delete('urecent:' + target);
          await env.LEADS.delete('uvw:' + target); // the cycle-27 viewing index must not resurrect for a future re-registration
          await env.LEADS.delete('uact:' + targetN);
          for (const tt2 of await allTasks(env)) {
            if (tt2 && tt2.email === targetN) await env.LEADS.delete('task:' + tt2.id);
          }
          await env.LEADS.delete('user:' + target);
          await idxRemove(env, 'users', target);
          await purgeUserSessions(env, target);
          await env.LEADS.put('audit:' + Date.now() + ':' + randHex(6), JSON.stringify({ action: 'user_delete', target: target, ip: ip, at: new Date().toISOString() }), { expirationTtl: 730 * 86400 });
          return json({ ok: true }, 200, origin);
        }
        if (d.action === 'ban') {
          await env.LEADS.put('ban:' + normEmail(target), JSON.stringify({ email: target, reason: String(d.reason || '').slice(0, 200), at: new Date().toISOString() }));
          await idxAdd(env, 'bans', normEmail(target));
          banCache.set(normEmail(target), { t: Date.now(), banned: true });
          await purgeUserSessions(env, target);
          await env.LEADS.put('audit:' + Date.now() + ':' + randHex(6), JSON.stringify({ action: 'user_ban', target: target, ip: ip, at: new Date().toISOString() }), { expirationTtl: 730 * 86400 });
          return json({ ok: true }, 200, origin);
        }
        if (d.action === 'unban') {
          await env.LEADS.delete('ban:' + normEmail(target));
          await idxRemove(env, 'bans', normEmail(target));
          banCache.set(normEmail(target), { t: Date.now(), banned: false });
          await env.LEADS.put('audit:' + Date.now() + ':' + randHex(6), JSON.stringify({ action: 'user_unban', target: target, ip: ip, at: new Date().toISOString() }), { expirationTtl: 730 * 86400 });
          return json({ ok: true }, 200, origin);
        }
        return json({ ok: false, error: 'validation' }, 400, origin);
      }

      // ---- admin: unified contacts + desk overview ----
      if (path === '/api/admin/contacts' && request.method === 'GET') {
        const contacts = await buildContacts(env);
        return json({ ok: true, contacts: contacts, count: contacts.length }, 200, origin);
      }
      if (path === '/api/admin/desk' && request.method === 'GET') {
        const data = await adminCachedGen(env, 'desk', async function () {
        const todayStr = todayVancouver();
        const vidx2 = (await env.LEADS.get('vidx', { type: 'json' })) || [];
        const allV = [];
        for (const id of vidx2.slice(0, 200)) { const v = await env.LEADS.get('viewing:' + id, { type: 'json' }); if (v) allV.push(v); }
        const upcoming = allV.filter(function (v) { return v.date >= todayStr && (v.status === 'new' || v.status === 'confirmed'); })
          .sort(function (a, b) { return String(a.date + ' ' + a.time).localeCompare(String(b.date + ' ' + b.time)); }).slice(0, 10)
          .map(function (v) { const h = v.listingId ? catalogByMls(v.listingId) : null; return { id: v.id, date: v.date, time: v.time, name: v.name, email: v.email, status: v.status, listing: h ? (h.street + ', ' + h.city) : v.listingId }; });
        const dayAgo = Date.now() - 86400000;
        let newLeads24h = 0;
        for (const lid of await idxGet(env, 'leads', 'lead:')) { const l = await env.LEADS.get('lead:' + lid, { type: 'json' }); if (l && new Date(l.created_at).getTime() > dayAgo) newLeads24h++; }
        const contacts2 = await buildContacts(env);
        const followUps = contacts2.filter(function (c) { return c.followUp; });
        let mailUnsent = 0;
        for (const mid of await idxGet(env, 'mailq', 'mailq:')) { const mm = await env.LEADS.get('mailq:' + mid, { type: 'json' }); if (mm && !mm.sent) mailUnsent++; }
        const ulist2 = { keys: await idxGet(env, 'users', 'user:', 5000) };
        const nameByKey = Object.create(null);
        for (const c of contacts2) nameByKey[normEmail(c.email)] = c.name || c.email;
        const tasksDueAll = (await allTasks(env)).filter(function (t) { return !t.done && t.due <= todayStr; })
          .sort(function (a, b) { return String(a.due).localeCompare(String(b.due)); });
        const tasksDue = tasksDueAll.slice(0, 8)
          .map(function (t) { return { id: t.id, email: t.email, name: nameByKey[t.email] || t.email, text: t.text, due: t.due, overdue: t.due < todayStr }; });
        return { today: todayStr, upcomingViewings: upcoming, viewingsToday: allV.filter(function (v) { return v.date === todayStr && (v.status === 'new' || v.status === 'confirmed'); }).length, newLeads24h: newLeads24h, followUps: followUps.slice(0, 5).map(function (c) { return { email: c.email, name: c.name, hours: c.followUp.hours, kind: c.followUp.kind, score: c.score }; }), followUpCount: followUps.length, hotCount: contacts2.filter(function (c) { return c.tier === 'hot'; }).length, usersTotal: ulist2.keys.length, mailUnsent: mailUnsent, tasksDue: tasksDue, tasksDueCount: tasksDueAll.length };
        });
        return json(Object.assign({ ok: true }, data), 200, origin);
      }

      // ---- admin: outgoing mail queue (drained by the mailer cron once a sender is configured) ----
      if (path === '/api/admin/mailq' && request.method === 'GET') {
        const mkeys = (await idxGet(env, 'mailq', 'mailq:')).map(function (id) { return 'mailq:' + id; }).sort().reverse().slice(0, 100);
        const out = [];
        for (const key of mkeys) {
          const raw = await env.LEADS.get(key);
          if (!raw) continue;
          try { const rec = JSON.parse(raw); if (rec) { delete rec.token; out.push(rec); } } catch (e) {} // token stripped for every kind, not just verify (cycle 29, Claude H1)
        }
        return json({ ok: true, mail: out }, 200, origin);
      }
      const mqm = path.match(/^\/api\/admin\/mailq\/([A-Za-z0-9-]+)$/);
      if (mqm && request.method === 'PATCH') {
        const raw = await env.LEADS.get('mailq:' + mqm[1]);
        if (!raw) return json({ ok: false, error: 'not_found' }, 404, origin);
        let rec = null;
        try { rec = JSON.parse(raw); } catch (e) {}
        if (!rec) return json({ ok: false, error: 'corrupt' }, 500, origin);
        if (!rec.sent) {
          rec.sent = true;
          rec.sent_at = new Date().toISOString();
          await env.LEADS.put('mailq:' + mqm[1], JSON.stringify(rec), { expirationTtl: 90 * 86400 }); // sent records age out instead of accumulating forever (cycle 29, Claude L7)
        }
        return json({ ok: true }, 200, origin);
      }

      // ---- admin: config values in KV (e.g. cfg:gcal bridge) ----
      if (path === '/api/admin/config' && request.method === 'POST') {
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        // Only the known bridge/credential keys may be written, as non-null
        // objects of bounded size — an arbitrary cfg: write could otherwise
        // plant values other code paths trust.
        const key = String(d.key || '');
        if (CFG_KEYS.indexOf(key) === -1 || d.value === null || typeof d.value !== 'object' || Array.isArray(d.value) || JSON.stringify(d.value).length > 8192) return json({ ok: false, error: 'validation' }, 400, origin);
        await env.LEADS.put('cfg:' + key, JSON.stringify(d.value));
        await env.LEADS.put('audit:' + Date.now() + ':' + randHex(6), JSON.stringify({ action: 'config_set', target: key, ip: ip, at: new Date().toISOString() }), { expirationTtl: 730 * 86400 });
        return json({ ok: true }, 200, origin);
      }
      if (path === '/api/admin/config' && request.method === 'GET') {
        const key = String(url.searchParams.get('key') || '').slice(0, 40);
        if (key === 'gcalerr') { const gv = await env.LEADS.get('gcalerr', { type: 'json' }); const safe = gv ? { at: gv.at || '', step: gv.step || '', status: gv.status || 0, note: String(gv.note || gv.error || gv.message || '').replace(/Bearer\s+\S+/gi, 'Bearer [redacted]').replace(/([?&](?:key|token|access_token|secret|api_key)=)[^&\s]+/gi, '$1[redacted]').slice(0, 200) } : null; return json({ ok: true, value: safe }, 200, origin); }
        if (!key) return json({ ok: false, error: 'validation' }, 400, origin);
        if (CFG_KEYS.indexOf(key) === -1) return json({ ok: true, value: null }, 200, origin); // existence probes only for the known keys (cycle 29, Claude L13)
        const has = (await env.LEADS.get('cfg:' + key)) !== null;
        return json({ ok: true, value: has ? { configured: true } : null }, 200, origin);
      }



      // ---- admin: site AI usage (proxied from the ai-chat worker) ----
      if (path === '/api/admin/ai-usage' && request.method === 'GET') {
        const ai = await aiInternal(env, '/api/internal/usage', {});
        if (!ai || !ai.ok) return json({ ok: false, error: (ai && ai.error) || 'ai_unavailable' }, 200, origin);
        return json(ai, 200, origin);
      }

      // ---- admin: KV backup stamp (the weekly backup job reports success here) ----
      if (path === '/api/admin/backup-stamp' && request.method === 'POST') {
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const stamp = { at: new Date().toISOString(), keys: Math.min(5000000, Math.max(0, parseInt(d.keys, 10) || 0)), bytes: Math.min(1099511627776, Math.max(0, parseInt(d.bytes, 10) || 0)), note: String(d.note || '').slice(0, 120) };
        await env.LEADS.put('backup:last', JSON.stringify(stamp));
        return json({ ok: true, stamp: stamp }, 200, origin);
      }

      // ---- admin: business SMS threads ----
      if (path === '/api/admin/sms' && request.method === 'GET') {
        const ccfg = await getCallsCfg(env);
        const emailF = normEmail(url.searchParams.get('email') || '');
        const phoneF = phoneLast10(url.searchParams.get('phone') || '');
        const limit = Math.min(300, Math.max(1, parseInt(url.searchParams.get('limit') || '200', 10) || 200));
        const sids = await idxGet(env, 'sms', 'sms:');
        let msgs = [];
        for (const sid2 of sids) { const m2 = await env.LEADS.get('sms:' + sid2, { type: 'json' }); if (m2) msgs.push(m2); }
        msgs.sort(function (a, b) { return String(b.at).localeCompare(String(a.at)); });
        let unread = 0;
        for (const m3 of msgs) if (m3.direction === 'in' && !m3.read) unread++;
        if (emailF) msgs = msgs.filter(function (m4) { return m4.matchedEmail && normEmail(m4.matchedEmail) === emailF; });
        if (phoneF) msgs = msgs.filter(function (m5) { return phoneLast10(m5.from) === phoneF || phoneLast10(m5.to) === phoneF; });
        return json({ ok: true, configured: !!(ccfg && ccfg.number), number: (ccfg && ccfg.number) || '', unread: unread, messages: msgs.slice(0, limit) }, 200, origin);
      }
      if (path === '/api/admin/sms/send' && request.method === 'POST') {
        const ccfg = await getCallsCfg(env);
        if (!ccfg || !ccfg.number) return json({ ok: false, error: 'not_configured' }, 503, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const to = normPhone(d.to || '');
        const body = String(d.body || '').trim().slice(0, 1600);
        if (phoneLast10(to).length < 10 || !body) return json({ ok: false, error: 'validation' }, 400, origin);
        const sid = await sendSms(env, ccfg, to, body);
        if (!sid) return json({ ok: false, error: 'send_failed' }, 502, origin);
        let storedId = '', storeWarn = false;
        try { const stored = await storeSms(env, { provider: ccfg.provider || 'generic', providerMsgId: typeof sid === 'string' ? sid : 'portal-' + randHex(8), direction: 'out', from: ccfg.number, to: to, body: body }); storedId = stored.id; } catch (e) { storeWarn = true; } // the text is already sent: a store failure must not read as a send failure (a portal retry would double-text) — cycle 30, Claude Low
        return json({ ok: true, id: storedId, warning: storeWarn ? 'sent_but_unstored' : undefined }, 200, origin);
      }
      if (path === '/api/admin/sms/read' && request.method === 'POST') {
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const target = phoneLast10(d.phone || '');
        if (target.length < 10) return json({ ok: false, error: 'validation' }, 400, origin);
        const sids = await idxGet(env, 'sms', 'sms:');
        let marked = 0;
        for (const sid2 of sids) {
          const m2 = await env.LEADS.get('sms:' + sid2, { type: 'json' });
          if (m2 && m2.direction === 'in' && !m2.read && phoneLast10(m2.from) === target) {
            m2.read = true;
            await env.LEADS.put('sms:' + sid2, JSON.stringify(m2));
            marked++;
          }
        }
        return json({ ok: true, marked: marked }, 200, origin);
      }

      // ---- admin: business call log ----
      if (path === '/api/admin/calls' && request.method === 'GET') {
        const ccfg = await getCallsCfg(env);
        const emailF = normEmail(url.searchParams.get('email') || '');
        const phoneF = phoneLast10(url.searchParams.get('phone') || '');
        const limit = Math.min(200, Math.max(1, parseInt(url.searchParams.get('limit') || '100', 10) || 100));
        const cids = await idxGet(env, 'calls', 'call:');
        let calls = [];
        for (const cid of cids) { const c = await env.LEADS.get('call:' + cid, { type: 'json' }); if (c) calls.push(c); }
        calls.sort(function (a, b) { return String(b.startedAt).localeCompare(String(a.startedAt)); });
        if (emailF) calls = calls.filter(function (c) { return c.matchedEmail && normEmail(c.matchedEmail) === emailF; });
        if (phoneF) calls = calls.filter(function (c) { return phoneLast10(c.from) === phoneF || phoneLast10(c.to) === phoneF; });
        return json({ ok: true, configured: !!(ccfg && ccfg.number), number: (ccfg && ccfg.number) || '', provider: (ccfg && ccfg.provider) || '', calls: calls.slice(0, limit) }, 200, origin);
      }
      const callLeadM = path.match(/^\/api\/admin\/calls\/([A-Za-z0-9_-]+)\/lead$/);
      if (callLeadM && request.method === 'POST') {
        const call = await env.LEADS.get('call:' + callLeadM[1], { type: 'json' });
        if (!call) return json({ ok: false, error: 'not_found' }, 404, origin);
        if (call.leadId) return json({ ok: true, leadId: call.leadId, already: true }, 200, origin);
        const other = call.direction === 'in' ? call.from : call.to;
        const last10 = phoneLast10(other);
        if (last10.length !== 10) return json({ ok: false, error: 'no_caller_number' }, 400, origin); // withheld/anonymous callers get no junk lead (cycle 30, Claude Low)
        const leadId = 'ld_call_' + callLeadM[1]; // deterministic: a retry or double-click reuses this lead instead of duplicating it
        const lead = { id: leadId, created_at: new Date().toISOString(), name: '📞 Caller ···' + last10.slice(-4), intent: 'buyer', city: '', budget: '', email: 'caller-' + last10 + '@calls.local', phone: other, message: 'Call ' + String(call.startedAt || '').slice(0, 16).replace('T', ' ') + ' · ' + (call.durationSec || 0) + 's · ' + call.status, stage: 'new', notes: '', source: 'call' };
        await env.LEADS.put('lead:' + leadId, JSON.stringify(lead));
        await idxAdd(env, 'leads', leadId);
        call.leadId = leadId;
        await env.LEADS.put('call:' + callLeadM[1], JSON.stringify(call));
        return json({ ok: true, leadId: leadId }, 200, origin);
      }
      const callRecM = path.match(/^\/api\/admin\/calls\/([A-Za-z0-9_-]+)\/recording$/);
      if (callRecM && request.method === 'GET') {
        const call = await env.LEADS.get('call:' + callRecM[1], { type: 'json' });
        if (!call || !call.recordingUrl) return json({ ok: false, error: 'no_recording' }, 404, origin);
        const ccfg = await getCallsCfg(env);
        const rheaders = {};
        let cu;
        try { cu = new URL(call.recordingUrl); } catch (e) { return json({ ok: false, error: 'bad_url' }, 400, origin); }
        if (ccfg && ccfg.provider === 'twilio' && ccfg.twilioAccountSid && ccfg.twilioAuthToken && /(^|\.)twilio\.com$/.test(cu.hostname)) {
          rheaders.Authorization = 'Basic ' + btoa(ccfg.twilioAccountSid + ':' + ccfg.twilioAuthToken);
        }
        if (cu.protocol !== 'https:') return json({ ok: false, error: 'bad_url' }, 400, origin); // never proxy plain-http or non-web schemes (cycle 30, Claude M6)
        const up = await fetch(call.recordingUrl, { headers: rheaders });
        if (!up.ok) return json({ ok: false, error: 'fetch_failed', status: up.status }, 502, origin);
        const upCt = up.headers.get('Content-Type') || '';
        const safeCt = /^audio\//i.test(upCt) ? upCt : 'audio/mpeg'; // only audio types are ever served from this origin, whatever the upstream claims
        return new Response(up.body, { status: 200, headers: Object.assign({ 'Content-Type': safeCt, 'Cache-Control': 'private, max-age=300', 'X-Content-Type-Options': 'nosniff' }, cors(origin)) });
      }

      // ---- admin: site maintenance (checks + safe repairs, portal Maintenance tab) ----
      if (path === '/api/admin/maintenance' && request.method === 'GET') {
        const last = await env.LEADS.get('maint:last', { type: 'json' });
        const log = (await env.LEADS.get('maint:log', { type: 'json' })) || [];
        const speedLog = (await env.LEADS.get('speed:log', { type: 'json' })) || [];
        const backup = (await env.LEADS.get('backup:last', { type: 'json' })) || null;
        const backups = (await env.LEADS.get('backup:log', { type: 'json' })) || [];
        return json({ ok: true, last: last, log: log, speedLog: speedLog, backup: backup, backups: backups }, 200, origin);
      }
      if (path === '/api/admin/maintenance' && request.method === 'POST') {
        if ((await env.LEADS.get('maint:lock')) !== null) return json({ ok: false, error: 'busy' }, 429, origin);
        await env.LEADS.put('maint:lock', '1', { expirationTtl: 240 });
        try {
          const started = new Date().toISOString();
          const checks = [], repairs = [], issues = [];
          function check(name, ok, detail) { checks.push({ name: name, ok: !!ok, detail: String(detail || '') }); if (!ok) issues.push(name + ' — ' + detail); }
          async function listAll(prefix) { const out = []; let cursor = undefined; do { const res = await env.LEADS.list({ prefix: prefix, limit: 500, cursor: cursor }); for (const k of res.keys) out.push(k.name); cursor = res.list_complete ? undefined : res.cursor; } while (cursor); return out; }
          // Nightly reindex: rebuild the KV index keys + the catalog snapshot
          // from ground truth, so any out-of-band KV edit (dashboard fix or
          // restore) self-heals within a day instead of staying invisible.
          try {
            const IDX_DEFS = [['leads', 'lead:'], ['users', 'user:'], ['tasks', 'task:'], ['bans', 'ban:'], ['mailq', 'mailq:'], ['nlsubs', 'nlsub:'], ['calls', 'call:'], ['sms', 'sms:']];
            for (const [nm, pfx] of IDX_DEFS) {
              const names = await listAll(pfx);
              if (!names.length) { const oldIdx = (await env.LEADS.get('idx:' + nm, { type: 'json' })) || []; if (oldIdx.length) { repairs.push('Reindex kept the old ' + nm + ' index — the ground-truth list came back empty'); continue; } } // a transient empty list must not wipe a good index (cycle 30, Claude M4)
              await env.LEADS.put('idx:' + nm, JSON.stringify(names.map(function (n) { return n.slice(pfx.length); })));
            }
            await buildCatalogSnap(env);
          } catch (e) {}
          const SITE = 'https://real-estate-platform-0aei.onrender.com';
          const PAGES = ['', 'listings.html', 'mortgage-calculator.html', 'buy-vs-rent.html', 'affordability.html', 'investor-analysis.html', 'ai-assistant.html', 'seller-tools.html', 'first-time-buyers.html', 'knowledge-centre.html', 'contact.html', 'listing-R2991001.html', 'listing-R2991002.html', 'listing-R2991003.html', 'listing-R2991004.html', 'listing-R2991005.html', 'listing-R2991006.html', 'area-burnaby-metrotown.html', 'area-coquitlam-coquitlam-centre.html', 'area-surrey-surrey-city-centre.html', 'area-vancouver-downtown.html', 'area-richmond.html', 'area-port-coquitlam.html'];
          for (const p of PAGES) {
            const label = p || 'index.html';
            try {
              const r = await fetch(SITE + '/' + p, { headers: { 'User-Agent': 'ErfanMaint/1.0' } });
              const buf = await r.arrayBuffer();
              const bytes = buf.byteLength;
              const head = new TextDecoder().decode(buf.slice(0, 60000));
              const hasTitle = /<title>[^<]{5,}<\/title>/.test(head);
              const hasDesc = head.indexOf('name="description"') !== -1;
              const hasCanon = head.indexOf('rel="canonical"') !== -1;
              const h1 = (head.match(/<h1[\s>]/g) || []).length;
              check('page ' + label, r.status === 200 && hasTitle && hasDesc && hasCanon && h1 >= 1 && bytes <= 450000,
                'status ' + r.status + ', ' + Math.round(bytes / 1024) + 'KB' + (hasTitle ? '' : ', title MISSING') + (hasDesc ? '' : ', description MISSING') + (hasCanon ? '' : ', canonical MISSING') + ', h1 x' + h1 + (bytes > 450000 ? ', OVERWEIGHT' : ''));
            } catch (e) { check('page ' + label, false, 'fetch failed'); }
          }
          const ASSETS = ['photos/R2991001.jpg', 'photos/R2991001.webp', 'photos/hero.webp', 'vendor/pannellum.js', 'robots.txt', 'sitemap.xml', 'fonts.css', 'fonts/vazirmatn-400.woff2'];
          for (const a of ASSETS) {
            try { const r = await fetch(SITE + '/' + a, { headers: { 'User-Agent': 'ErfanMaint/1.0' } }); try { await r.arrayBuffer(); } catch (e) {} check('asset ' + a, r.status === 200, 'status ' + r.status); }
            catch (e) { check('asset ' + a, false, 'fetch failed'); }
          }
          // service-to-service calls MUST use service bindings: public fetch between *.workers.dev workers is blocked at the edge (error 1042)
          const sellerFetch = (env.SELLER && env.SELLER.fetch) ? function (u, o) { return env.SELLER.fetch(u, o); } : fetch;
          const newsFetch = (env.NEWSLETTER && env.NEWSLETTER.fetch) ? function (u, o) { return env.NEWSLETTER.fetch(u, o); } : fetch;
          try { let r = await sellerFetch('https://seller-api.erfanbillion.workers.dev/api/tour/R2991001'); if (r.status !== 200) { await new Promise(function (res) { setTimeout(res, 2500); }); r = await sellerFetch('https://seller-api.erfanbillion.workers.dev/api/tour/R2991001'); } check('tour service', r.status === 200, 'status ' + r.status); } catch (e) { check('tour service', false, 'unreachable'); }
          try { const r = await newsFetch('https://newsletter-signup.erfanbillion.workers.dev', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); check('newsletter service', r.status < 500, 'status ' + r.status); } catch (e) { check('newsletter service', false, 'unreachable'); }
          // repairs: expired admin tokens + visitor sessions
          let purged = 0;
          for (const k of (await listAll('tok:')).slice(0, 300)) { const exp = parseInt((await env.LEADS.get(k)) || '0', 10); if (!exp || Date.now() > exp) { await env.LEADS.delete(k); purged++; } }
          if (purged) repairs.push('Purged ' + purged + ' expired admin tokens');
          let sessPurged = 0;
          for (const k of (await listAll('usess:')).slice(0, 300)) { let exp = 0; try { exp = (JSON.parse((await env.LEADS.get(k)) || '{}')).exp || 0; } catch (e) {} if (!exp || Date.now() > exp) { await env.LEADS.delete(k); sessPurged++; } }
          if (sessPurged) repairs.push('Purged ' + sessPurged + ' expired visitor sessions');
          // mail queue: count unsent directly from the records (queueMail no
          // longer maintains an index key — records are the source of truth).
          let unsent = 0, mailOldest = null;
          for (const k of await listAll('mailq:')) { const raw = await env.LEADS.get(k); if (raw) { try { const mr = JSON.parse(raw); if (!mr.sent) { unsent++; if (mr.created_at && (!mailOldest || mr.created_at < mailOldest)) mailOldest = mr.created_at; } } catch (e) {} } }
          // repairs: orphan visitor data (saved/searches without a user record).
          // KV lists are eventually consistent, so a just-registered user's data
          // can look orphaned: re-check the user key directly before deleting,
          // keep a 30-day trash copy, and cap deletions per run.
          const userKeys = await listAll('user:');
          const userSet = Object.create(null); userKeys.forEach(function (k) { userSet[k.slice(5)] = 1; });
          let orphans = 0;
          for (const pref of ['usaved:', 'usavep:', 'usearch:', 'urecent:']) {
            for (const k of await listAll(pref)) {
              if (orphans >= 25) break;
              const em = k.slice(pref.length);
              if (userSet[em]) continue;
              if ((await env.LEADS.get('user:' + em)) !== null) continue;
              const val = await env.LEADS.get(k);
              if (val) await env.LEADS.put('trash:' + k, val, { expirationTtl: 30 * 86400 });
              await env.LEADS.delete(k);
              orphans++;
            }
          }
          if (orphans) repairs.push('Removed ' + orphans + ' orphan visitor records (30-day trash copies kept)');
          // counts
          const vidx = (await env.LEADS.get('vidx', { type: 'json' })) || [];
          let viewPending = 0;
          for (const id of vidx.slice(0, 100)) { const raw = await env.LEADS.get('viewing:' + id); if (raw) { try { if ((JSON.parse(raw).status || 'new') === 'new') viewPending++; } catch (e) {} } }
          const counts = {
            users: userKeys.length,
            leads: (await listAll('lead:')).length,
            marketLeads: (await listAll('mlead:')).length,
            subscribers: (await listAll('nlsub:')).length,
            viewingsPending: viewPending,
            mailUnsent: unsent, mailOldest: mailOldest
          };
          // ---- speed measurement + cache refresh (portal speed gauge) ----
          let speed = null;
          try { speed = await speedCheck(env); } catch (e) { check('Site speed', false, 'speed check threw'); } // an unguarded throw here used to skip the whole tail (cycle 30, Claude M1)
          if (speed) {
            check('Site speed', speed.band === 'excellent' || speed.band === 'good', 'score ' + speed.score + '/100 (' + speed.band + ') · home ' + (speed.homeMs === null ? 'unreachable' : speed.homeMs + 'ms') + ' · ' + speed.homeKB + ' KB · KV ' + speed.kvMs + 'ms');
            try {
              const slog = (await env.LEADS.get('speed:log', { type: 'json' })) || [];
              slog.unshift({ at: speed.at, score: speed.score, band: speed.band });
              await env.LEADS.put('speed:log', JSON.stringify(slog.slice(0, 14)));
            } catch (e) {}
          }
          try {
            adminCache.clear();
            await refreshCustomCatalog(env, true);
            await buildContacts(env);
            repairs.push('Worker caches cleared and rebuilt warm (admin lists + listing catalog)');
          } catch (e) { check('Cache rebuild', false, String((e && e.message) || e).slice(0, 120)); }
          let listUsage = 0;
          try { const u2 = await env.LEADS.get('usage:lists:' + utcDay(), { type: 'json' }); if (u2 && typeof u2.count === 'number') listUsage = u2.count; } catch (e) {}
          if (listUsage >= 700) issues.push('KV list usage high — ' + listUsage + '/1000 today');
          // Auto-backup freshness (cycle 25): runFullBackup can be killed by
          // platform limits BEFORE it can write its own failure log, so this
          // nightly check is the alarm — from the Dec 1 start, the newest
          // backup:log entry must be ok and less than 36h old.
          try {
            if (vancouverDay() >= BACKUP_START_DAY) {
              const blog = (await env.LEADS.get('backup:log', { type: 'json' })) || [];
              const newestB = blog[0];
              const ageH = newestB ? (Date.now() - Date.parse(newestB.at)) / 3600000 : Infinity;
              check('Auto-backup freshness', !!(newestB && newestB.ok && ageH < 36), newestB ? ('last entry ' + newestB.day + ', ' + Math.round(ageH) + 'h ago, ok=' + !!newestB.ok) : 'no auto-backup has ever run');
            }
          } catch (e) {}
          let aiUsageSnap = null;
          try {
            const aiU = await aiInternal(env, '/api/internal/usage', {});
            if (aiU && aiU.ok) {
              aiUsageSnap = aiU;
              if (aiU.chat && aiU.chat.left <= 70) issues.push('AI chat budget low — ' + aiU.chat.left + ' of ' + aiU.chat.budget + ' chats left today');
              if (aiU.search && aiU.search.left <= 15) issues.push('AI search budget low — ' + aiU.search.left + ' of ' + aiU.search.budget + ' searches left today');
              if (aiU.lastChat && aiU.lastChat.isLastBackup) issues.push('AI chat is answering on its LAST backup provider (' + aiU.lastChat.provider + ')');
            }
          } catch (e) {}
          // ---- calendar bridge status (last viewing -> Google Calendar attempt) ----
          let gcalLast = null;
          try { gcalLast = await env.LEADS.get('gcal:last', { type: 'json' }); } catch (e) { gcalLast = null; }
          if (!gcalLast) check('Calendar bridge', true, 'no calendar event recorded yet');
          else if (gcalLast.ok) check('Calendar bridge', true, 'last event OK at ' + (gcalLast.at || '') + (gcalLast.eventId ? ' · ' + gcalLast.eventId : ''));
          else check('Calendar bridge', false, 'last attempt failed at ' + (gcalLast.at || '') + ' — ' + String(gcalLast.error || 'unknown error').slice(0, 160));
          // ---- nightly canary: end-to-end lead + chat probes (after existing checks) ----
          const canaryAt = new Date().toISOString();
          let canaryLeadId = null, canaryLeadOk = false;
          try {
            canaryLeadId = Date.now().toString(36) + '-' + randHex(6);
            const clead = { id: canaryLeadId, created_at: new Date().toISOString(), name: '🧪 Canary', intent: 'buyer', city: '', budget: '', email: 'canary@maintenance.local', phone: '', message: 'Nightly canary — auto-generated, auto-deleted.', stage: 'new', notes: '', source: 'canary' };
            await env.LEADS.put('lead:' + canaryLeadId, JSON.stringify(clead), { expirationTtl: 3600 }); // if the invocation dies before the delete below, the canary self-expires within the hour (cycle 30, Claude M2)
            await idxAdd(env, 'leads', canaryLeadId);
            const back = await env.LEADS.get('lead:' + canaryLeadId, { type: 'json' });
            canaryLeadOk = !!(back && back.id === canaryLeadId && back.source === 'canary' && back.email === 'canary@maintenance.local');
          } catch (e) { canaryLeadOk = false; }
          if (canaryLeadId) {
            let deleted = false;
            try {
              await env.LEADS.delete('lead:' + canaryLeadId);
              await idxRemove(env, 'leads', canaryLeadId);
              const still = await env.LEADS.get('lead:' + canaryLeadId);
              deleted = still === null || still === undefined;
            } catch (e) { deleted = false; }
            try { adminCache.delete('leads'); adminCache.delete('contacts'); adminCache.delete('desk'); } catch (e) {}
            if (!deleted) issues.push('Canary — leftover canary lead ' + canaryLeadId + ' could not be deleted');
          }
          if (!canaryLeadOk) issues.push('Canary — lead pipeline failed');
          let canaryChatOk = false;
          try {
            const fetcher = (env.AICHAT && typeof env.AICHAT.fetch === 'function') ? env.AICHAT.fetch.bind(env.AICHAT) : fetch;
            const ctl = new AbortController();
            const tm = setTimeout(function () { ctl.abort(); }, 25000);
            try {
              const cr = await fetcher('https://ai-chat.erfanbillion.workers.dev/', { method: 'POST', signal: ctl.signal, headers: { 'Content-Type': 'application/json', Origin: 'https://real-estate-platform-0aei.onrender.com' }, body: JSON.stringify({ message: 'Reply with the single word: ok', lang: 'en', history: [] }) });
              const cj = await cr.json().catch(function () { return null; });
              canaryChatOk = !!(cr.ok && cj && typeof cj.reply === 'string' && cj.reply.trim().length > 0);
            } finally { clearTimeout(tm); }
          } catch (e) { canaryChatOk = false; }
          if (!canaryChatOk) issues.push('Canary — site chat did not answer');
          const canary = { leadOk: canaryLeadOk, chatOk: canaryChatOk, at: canaryAt };
          const backupLog = (await env.LEADS.get('backup:log', { type: 'json' })) || [];
          if (vancouverDay() > BACKUP_START_DAY) { const lastOkB = backupLog.filter(function (b) { return b.ok; })[0]; if (!lastOkB || !(Date.now() - Date.parse(lastOkB.at) <= 36 * 3600000)) issues.push('Auto backup — no successful backup in the last 36h'); } // NaN-safe: an unparseable timestamp fails CLOSED, matching the freshness check (cycle 30, Claude Low)
          const report = { ts: started, finished: new Date().toISOString(), checks: checks, repairs: repairs, issues: issues, counts: counts, speed: speed, usage: { listsToday: listUsage }, ai: aiUsageSnap, gcal: gcalLast, canary: canary, backups: backupLog.slice(0, 30) };
          await env.LEADS.put('maint:last', JSON.stringify(report));
          const log = (await env.LEADS.get('maint:log', { type: 'json' })) || [];
          log.unshift({ ts: started, issues: issues.length, repairs: repairs.length, checksOk: checks.filter(function (c) { return c.ok; }).length, checksTotal: checks.length });
          await env.LEADS.put('maint:log', JSON.stringify(log.slice(0, 20)));
          return json({ ok: true, report: report }, 200, origin);
        } finally { await env.LEADS.delete('maint:lock').catch(function () {}); } // the lock releases even when a check throws mid-run (cycle 30, Claude M1)
      }

      // ---- admin: saved-search alert digest (new matches since last notify) ----
      if (path === '/api/admin/alert-digest' && request.method === 'GET') {
        const skeys = (await idxGet(env, 'users', 'user:')).map(function (em) { return { name: 'usearch:' + em }; });
        const out = [];
        for (const k of skeys) {
          const email = k.name.slice('usearch:'.length);
          if (await isBanned(env, email)) continue;
          const searches = await userSearches(env, email);
          for (const s of searches) {
            if (!s.notify) continue;
            const now = matchSearch(s.criteria);
            const fresh = now.filter(function (m) { return (s.notified || []).indexOf(m) === -1; });
            if (fresh.length) out.push({ email: email, searchId: s.id, searchName: s.name, fresh: fresh });
          }
        }
        return json({ ok: true, digests: out }, 200, origin);
      }
      if (path === '/api/admin/alert-sent' && request.method === 'POST') {
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const email = String(d.email || '').trim().toLowerCase();
        if (!EMAIL_RE.test(email)) return json({ ok: false, error: 'validation' }, 400, origin);
        const searches = await userSearches(env, email);
        const s = searches.filter(function (x) { return x.id === d.searchId; })[0];
        if (!s) return json({ ok: false, error: 'not_found' }, 404, origin);
        const add = (Array.isArray(d.listings) ? d.listings : []).filter(function (x) { return typeof x === 'string' && x.length <= 32; }).slice(0, 100);
        s.notified = Array.from(new Set((s.notified || []).concat(add))).slice(-500);
        await env.LEADS.put('usearch:' + email, JSON.stringify(searches));
        return json({ ok: true }, 200, origin);
      }

      // ---- market radar on/off switch (portal toggle; the daily scan checks this first) ----
      if (path === '/api/radar-settings' && request.method === 'GET') {
        const s = await env.LEADS.get('radar:settings', { type: 'json' });
        return json({ ok: true, enabled: !!(s && s.enabled === true) }, 200, origin);
      }
      if (path === '/api/radar-settings' && request.method === 'PUT') {
        let d = null;
        try { d = await request.json(); } catch (e) {}
        if (!d || typeof d.enabled !== 'boolean') return json({ ok: false, error: 'validation' }, 400, origin); // malformed input must not silently switch the radar OFF (cycle 30, Claude Low)
        const enabled = d.enabled;
        await env.LEADS.put('radar:settings', JSON.stringify({ enabled: enabled, updated_at: new Date().toISOString() }));
        return json({ ok: true, enabled: enabled }, 200, origin);
      }

      return json({ ok: false, error: 'not_found' }, 404, origin);
    } catch (e) {
      console.error(e);
      return json({ ok: false, error: 'server' }, 500, origin);
    }
}

export default {
  async fetch(request, env, ctx) {
    let resp;
    try { resp = await handleRequest(request, env, ctx); } catch (e) { console.error(e); resp = new Response(JSON.stringify({ ok: false, error: 'server' }), { status: 500, headers: { 'Content-Type': 'application/json' } }); } // a preamble throw must not surface as a raw platform error (cycle 30, Claude M8)
    // Cycle 26 (Claude H1): this bump used to run pre-routing on EVERY
    // non-GET request, so an unauthenticated junk POST burned a KV write and
    // cold-cleared every admin cache. It now fires only after a mutating
    // request actually succeeded (status < 400, /api/track excluded as before;
    // cycle 30: 5xx bumps too — a write may have landed before the failure).
    try {
      const m = request.method;
      const p = new URL(request.url).pathname;
      if (m !== 'GET' && m !== 'OPTIONS' && m !== 'HEAD' && p !== '/api/track' && (resp.status < 400 || resp.status >= 500)) {
        adminCache.clear();
        genMemo = { t: 0, v: null };
        if (ctx && ctx.waitUntil) { try { ctx.waitUntil(env.LEADS.put('admin:gen', String(Date.now())).catch(function () {})); } catch (e) {} }
      }
    } catch (e) {}
    return resp;
  },
  async scheduled(event, env, ctx) { ctx.waitUntil(runFullBackup(env, 'cron').catch(async function (e) { try { console.error(e); const bl = (await env.LEADS.get('backup:log', { type: 'json' })) || []; bl.unshift({ at: new Date().toISOString(), day: vancouverDay(), ok: false, via: 'cron-catch', error: String((e && e.message) || e).slice(0, 160) }); await env.LEADS.put('backup:log', JSON.stringify(bl.slice(0, 40))); } catch (e2) {} })); } // a rejected backup must still leave a failure entry the freshness alarm can see (cycle 30, Claude M7)
};
