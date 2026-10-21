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
  'https://muse.ai',
  'null'
];
const INTENTS = ['buyer', 'seller', 'investor', 'renter'];
const STAGES = ['new', 'contacted', 'viewing', 'offer', 'closed', 'dropped'];
const MKINDS = ['buyer', 'seller', 'pair'];
const MSTATUSES = ['new', 'contacted', 'dismissed'];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const TOKEN_TTL = 86400; // 24h

function cors(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  };
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
  const k = ip + ':' + max + ':' + windowMs;
  let r = hits.get(k);
  if (!r || now > r.reset) { r = { count: 0, reset: now + windowMs }; hits.set(k, r); }
  r.count++;
  return r.count > max;
}

async function sha256hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function checkPassword(env, password) {
  const auth = env.ADVISOR_AUTH || '';
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
async function authed(request, env) {
  const h = request.headers.get('Authorization') || '';
  const m = h.match(/^Bearer ([0-9a-f]{64})$/);
  if (!m) return false;
  const exp = await env.LEADS.get('tok:' + m[1]);
  if (!exp) return false;
  if (Date.now() > parseInt(exp, 10)) {
    await env.LEADS.delete('tok:' + m[1]).catch(() => {});
    return false;
  }
  return true;
}

// ---- visitor accounts, viewings, mail queue (features 1-3) ----
// Sample listing catalog (mirrors the site mock provider; the live DDF
// adapter replaces this after licensing). Matching fields only.
const CATALOG = [
  { mls: "R2991001", street: "2108-4981 Kingsway", city: "Burnaby", type: "condo", price: 689000, beds: 2 },
  { mls: "R2991002", street: "45-1188 Inlet Street", city: "Coquitlam", type: "townhouse", price: 749000, beds: 3 },
  { mls: "R2991003", street: "7421 18th Avenue", city: "Burnaby", type: "house", price: 1299000, beds: 4 },
  { mls: "R2991004", street: "1506-833 Seymour Street", city: "Vancouver", type: "condo", price: 549000, beds: 1 },
  { mls: "R2991005", street: "22-15500 102A Avenue", city: "Surrey", type: "townhouse", price: 899000, beds: 3 },
  { mls: "R2991006", street: "309-550 Kirkland Avenue", city: "Port Coquitlam", type: "condo", price: 425000, beds: 2 }
];
function catalogByMls(mls) {
  return CATALOG.filter(function (c) { return c.mls === mls; })[0] || null;
}
function matchSearch(criteria) {
  const c = criteria || {};
  const q = String(c.q || '').toLowerCase();
  return CATALOG.filter(function (l) {
    if (c.city && l.city !== c.city) return false;
    if (c.type && l.type !== c.type) return false;
    if (c.maxPrice && l.price > parseInt(c.maxPrice, 10)) return false;
    if (c.minBeds && l.beds < parseInt(c.minBeds, 10)) return false;
    if (q && (l.street + ' ' + l.city + ' ' + l.mls).toLowerCase().indexOf(q) === -1) return false;
    return true;
  }).map(function (l) { return l.mls; });
}
async function queueMail(env, item) {
  const id = Date.now().toString(36) + '-' + randHex(6);
  const rec = Object.assign({ id: id, created_at: new Date().toISOString(), sent: false }, item);
  await env.LEADS.put('mailq:' + id, JSON.stringify(rec));
  const idx = (await env.LEADS.get('mailqidx', { type: 'json' })) || [];
  idx.unshift(id);
  await env.LEADS.put('mailqidx', JSON.stringify(idx.slice(0, 300)));
  return id;
}
async function userAuth(request, env) {
  const h = request.headers.get('Authorization') || '';
  const m = h.match(/^Bearer (u_[0-9a-f]{32})$/);
  if (!m) return null;
  const raw = await env.LEADS.get('usess:' + m[1]);
  if (!raw) return null;
  let s = null;
  try { s = JSON.parse(raw); } catch (e) {}
  if (!s || Date.now() > s.exp) return null;
  return s.email;
}
async function userSaved(env, email) {
  return (await env.LEADS.get('usaved:' + email, { type: 'json' })) || [];
}
async function userSearches(env, email) {
  return (await env.LEADS.get('usearch:' + email, { type: 'json' })) || [];
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const url = new URL(request.url);
    const path = url.pathname;
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors(origin) });
    if (origin && !ALLOWED_ORIGINS.includes(origin)) {
      return new Response(JSON.stringify({ ok: false, error: 'forbidden' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
    }
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
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
        const name = String(d.name || '').trim().slice(0, 120);
        const intent = String(d.intent || '').trim().toLowerCase();
        const city = String(d.city || '').trim().slice(0, 80);
        const budget = String(d.budget || '').trim().slice(0, 40);
        const email = String(d.email || '').trim().slice(0, 160);
        const phone = String(d.phone || '').trim().slice(0, 40);
        const message = String(d.message || '').trim().slice(0, 2000);
        const source = String(d.source || 'site-form').trim().slice(0, 40);
        if (!name || !INTENTS.includes(intent)) return json({ ok: false, error: 'validation' }, 400, origin);
        if (email && !EMAIL_RE.test(email)) return json({ ok: false, error: 'validation' }, 400, origin);
        const id = Date.now().toString(36) + '-' + randHex(6);
        const lead = {
          id: id, created_at: new Date().toISOString(),
          name: name, intent: intent, city: city, budget: budget,
          email: email, phone: phone, message: message,
          stage: 'new', notes: '', source: source
        };
        await env.LEADS.put('lead:' + id, JSON.stringify(lead));
        if (email) {
          await queueMail(env, { kind: 'followup', to: email, lang: String(d.lang || 'en').slice(0, 5), name: name, ref: id });
        }
        return json({ ok: true }, 200, origin);
      }

      // ---- public: lightweight site-traffic beacon (aggregates only, no raw logs) ----
      if (path === '/api/track' && request.method === 'POST') {
        if (limited(ip, 600, 3600000)) return json({ ok: true }, 200, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const day = new Date().toISOString().slice(0, 10);
        const key = 'stat:' + day;
        const doc = (await env.LEADS.get(key, { type: 'json' })) || { pv: {}, ev: {}, li: {}, lang: {}, ref: {}, uv: {} };
        const type = String(d.type || 'pageview').slice(0, 30);
        const page = String(d.page || '').slice(0, 80);
        if (type === 'pageview' && page) doc.pv[page] = (doc.pv[page] || 0) + 1;
        if (type === 'event') {
          const ev = String(d.event || '').slice(0, 40);
          if (ev) {
            doc.ev[ev] = (doc.ev[ev] || 0) + 1;
            if (ev === 'listing_view' && d.listingId) {
              const lid = String(d.listingId).slice(0, 40);
              doc.li[lid] = (doc.li[lid] || 0) + 1;
            }
          }
        }
        const lang = String(d.lang || '').slice(0, 5);
        if (lang) doc.lang[lang] = (doc.lang[lang] || 0) + 1;
        const ref = String(d.ref || '').slice(0, 80);
        if (type === 'pageview' && ref) doc.ref[ref] = (doc.ref[ref] || 0) + 1;
        const ua = request.headers.get('User-Agent') || '';
        const uh = (await sha256hex(ip + '|' + ua + '|' + day)).slice(0, 16);
        if (Object.keys(doc.uv).length < 5000) doc.uv[uh] = 1;
        await env.LEADS.put(key, JSON.stringify(doc));
        return json({ ok: true }, 200, origin);
      }

      // ---- newsletter subscribers (public subscribe; mirrored from the site form) ----
      if (path === '/api/newsletter/subscribe' && request.method === 'POST') {
        if (limited(ip, 10, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const nname = String(d.name || '').trim().slice(0, 120);
        const nemail = String(d.email || '').trim().toLowerCase().slice(0, 160);
        const nlang = ['en', 'fa', 'hi', 'zh'].includes(String(d.lang || '').toLowerCase()) ? String(d.lang).toLowerCase() : 'en';
        if (!EMAIL_RE.test(nemail)) return json({ ok: false, error: 'validation' }, 400, origin);
        const existing = await env.LEADS.get('nlsub:' + nemail);
        if (!existing) {
          await env.LEADS.put('nlsub:' + nemail, JSON.stringify({ name: nname, email: nemail, lang: nlang, created_at: new Date().toISOString() }));
        }
        return json({ ok: true }, 200, origin);
      }

      // ---- visitor accounts (public) ----
      if (path === '/api/user/register' && request.method === 'POST') {
        if (limited(ip, 10, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const name = String(d.name || '').trim().slice(0, 120);
        const email = String(d.email || '').trim().toLowerCase().slice(0, 160);
        const pass = String(d.password || '');
        const ulang = String(d.lang || 'en').slice(0, 5);
        if (!name || !EMAIL_RE.test(email) || pass.length < 6) return json({ ok: false, error: 'validation' }, 400, origin);
        const exists = await env.LEADS.get('user:' + email);
        if (exists) return json({ ok: false, error: 'exists' }, 409, origin);
        const salt = randHex(8);
        const user = { name: name, email: email, salt: salt, passHash: await sha256hex(salt + ':' + pass), lang: ulang, created_at: new Date().toISOString() };
        await env.LEADS.put('user:' + email, JSON.stringify(user));
        const token = 'u_' + randHex(16);
        await env.LEADS.put('usess:' + token, JSON.stringify({ email: email, exp: Date.now() + 30 * 86400000 }));
        return json({ ok: true, token: token, user: { name: name, email: email, lang: ulang } }, 200, origin);
      }
      if (path === '/api/user/login' && request.method === 'POST') {
        if (limited(ip, 20, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const email = String(d.email || '').trim().toLowerCase().slice(0, 160);
        const pass = String(d.password || '');
        const raw = await env.LEADS.get('user:' + email);
        if (!raw) return json({ ok: false, error: 'credentials' }, 401, origin);
        const user = JSON.parse(raw);
        const hash = await sha256hex(user.salt + ':' + pass);
        if (!timingSafeEqual(hash, user.passHash)) return json({ ok: false, error: 'credentials' }, 401, origin);
        const token = 'u_' + randHex(16);
        await env.LEADS.put('usess:' + token, JSON.stringify({ email: email, exp: Date.now() + 30 * 86400000 }));
        return json({ ok: true, token: token, user: { name: user.name, email: user.email, lang: user.lang } }, 200, origin);
      }
      if (path === '/api/user/me' && request.method === 'GET') {
        const email = await userAuth(request, env);
        if (!email) return json({ ok: false, error: 'auth' }, 401, origin);
        const raw = await env.LEADS.get('user:' + email);
        const user = raw ? JSON.parse(raw) : { name: '', email: email, lang: 'en' };
        return json({ ok: true, user: { name: user.name, email: user.email, lang: user.lang }, saved: await userSaved(env, email), searches: await userSearches(env, email) }, 200, origin);
      }
      if (path === '/api/user/save' && request.method === 'POST') {
        const email = await userAuth(request, env);
        if (!email) return json({ ok: false, error: 'auth' }, 401, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        const mls = String((d || {}).mls || '').slice(0, 40);
        if (!catalogByMls(mls)) return json({ ok: false, error: 'validation' }, 400, origin);
        const saved = await userSaved(env, email);
        const i = saved.indexOf(mls);
        if (i !== -1) saved.splice(i, 1); else saved.push(mls);
        await env.LEADS.put('usaved:' + email, JSON.stringify(saved.slice(0, 100)));
        return json({ ok: true, saved: saved }, 200, origin);
      }
      if (path === '/api/user/searches' && request.method === 'POST') {
        const email = await userAuth(request, env);
        if (!email) return json({ ok: false, error: 'auth' }, 401, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const c = d.criteria || {};
        const criteria = {
          q: String(c.q || '').slice(0, 80), city: String(c.city || '').slice(0, 40),
          type: String(c.type || '').slice(0, 20), maxPrice: String(c.maxPrice || '').slice(0, 12),
          minBeds: String(c.minBeds || '').slice(0, 4)
        };
        const searches = await userSearches(env, email);
        const rec = {
          id: 's_' + randHex(6), name: String(d.name || 'Search').slice(0, 80),
          criteria: criteria, notify: !!d.notify, notified: [], created_at: new Date().toISOString()
        };
        const matches = matchSearch(criteria);
        rec.notified = matches;
        searches.unshift(rec);
        await env.LEADS.put('usearch:' + email, JSON.stringify(searches.slice(0, 20)));
        if (rec.notify && matches.length) {
          const ulang = String(d.lang || 'en').slice(0, 5);
          const raw = await env.LEADS.get('user:' + email);
          const uname = raw ? JSON.parse(raw).name : '';
          await queueMail(env, { kind: 'alert', to: email, lang: ulang, name: uname, searchId: rec.id, searchName: rec.name, listings: matches.map(function (m) { const l = catalogByMls(m); return { mls: l.mls, street: l.street, city: l.city, price: l.price }; }) });
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

      // ---- viewings (public booking) ----
      if (path === '/api/viewing' && request.method === 'POST') {
        if (limited(ip, 10, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        d = d || {};
        const name = String(d.name || '').trim().slice(0, 120);
        const email = String(d.email || '').trim().slice(0, 160);
        const phone = String(d.phone || '').trim().slice(0, 40);
        const listingId = String(d.listingId || '').slice(0, 40);
        const date = String(d.date || '').slice(0, 10);
        const time = String(d.time || '').slice(0, 8);
        const vlang = String(d.lang || 'en').slice(0, 5);
        if (!name || !EMAIL_RE.test(email) || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !time) return json({ ok: false, error: 'validation' }, 400, origin);
        const home = listingId ? catalogByMls(listingId) : null;
        const vid = 'vw_' + randHex(6);
        const rec = { id: vid, created_at: new Date().toISOString(), name: name, email: email, phone: phone, listingId: listingId, date: date, time: time, lang: vlang, status: 'new' };
        await env.LEADS.put('viewing:' + vid, JSON.stringify(rec));
        const vidx = (await env.LEADS.get('vidx', { type: 'json' })) || [];
        vidx.unshift(vid);
        await env.LEADS.put('vidx', JSON.stringify(vidx.slice(0, 200)));
        const lid = Date.now().toString(36) + '-' + randHex(6);
        const lead = {
          id: lid, created_at: new Date().toISOString(), name: name, intent: 'buyer',
          city: home ? home.city : '', budget: '', email: email, phone: phone,
          message: 'Viewing requested: ' + date + ' ' + time + (home ? ' — ' + home.street + ' (' + home.mls + ')' : ''),
          stage: 'viewing', notes: '', source: 'viewing'
        };
        await env.LEADS.put('lead:' + lid, JSON.stringify(lead));
        await queueMail(env, { kind: 'viewing', to: email, lang: vlang, name: name, ref: vid, date: date, time: time, listing: home ? { mls: home.mls, street: home.street, city: home.city } : null });
        return json({ ok: true, id: vid }, 200, origin);
      }

      // ---- public: login ----
      if (path === '/api/login' && request.method === 'POST') {
        if (limited(ip, 10, 3600000)) return json({ ok: false, error: 'rate_limit' }, 429, origin);
        let d = null;
        try { d = await request.json(); } catch (e) {}
        const pw = d && typeof d.password === 'string' ? d.password : '';
        if (!pw || !(await checkPassword(env, pw))) {
          return json({ ok: false, error: 'invalid' }, 401, origin);
        }
        const token = randHex(32);
        await env.LEADS.put('tok:' + token, String(Date.now() + TOKEN_TTL * 1000), { expirationTtl: TOKEN_TTL });
        return json({ ok: true, token: token }, 200, origin);
      }

      // ---- auth required below ----
      if (!(await authed(request, env))) {
        return json({ ok: false, error: 'unauthorized' }, 401, origin);
      }

      if (path === '/api/leads' && request.method === 'GET') {
        const list = await env.LEADS.list({ prefix: 'lead:', limit: 1000 });
        const leads = (await Promise.all(
          list.keys.map(k => env.LEADS.get(k.name, { type: 'json' }))
        )).filter(Boolean);
        leads.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
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
          if (d.notes !== undefined) lead.notes = String(d.notes).slice(0, 2000);
          await env.LEADS.put(key, JSON.stringify(lead));
          return json({ ok: true, lead: lead }, 200, origin);
        }
        if (request.method === 'DELETE') {
          await env.LEADS.delete(key);
          return json({ ok: true }, 200, origin);
        }
      }

      // ---- market radar leads (daily agent ingest + portal review) ----
      if (path === '/api/market-leads' && request.method === 'POST') {
        let d = null;
        try { d = await request.json(); } catch (e) {}
        const items = d && Array.isArray(d.leads) ? d.leads.slice(0, 60) : [];
        let added = 0, skipped = 0;
        for (const it of items) {
          const url = String((it && it.url) || '').trim().slice(0, 600);
          if (!/^https?:\/\//.test(url)) { skipped++; continue; }
          const urlKey = 'murl:' + (await sha256hex(url.toLowerCase()));
          if (await env.LEADS.get(urlKey)) { skipped++; continue; }
          const kind = MKINDS.includes(String(it.kind || '').toLowerCase()) ? String(it.kind).toLowerCase() : 'buyer';
          const conf = Math.max(0, Math.min(100, parseInt(it.confidence, 10) || 0));
          const match = it.match && typeof it.match === 'object' ? {
            title: String(it.match.title || '').slice(0, 200),
            url: String(it.match.url || '').slice(0, 600),
            price: String(it.match.price || '').slice(0, 60),
            note: String(it.match.note || '').slice(0, 400)
          } : null;
          const id = Date.now().toString(36) + '-' + randHex(6);
          const lead = {
            id: id, created_at: new Date().toISOString(),
            kind: kind,
            title: String(it.title || '').trim().slice(0, 200),
            area: String(it.area || '').trim().slice(0, 80),
            price: String(it.price || '').trim().slice(0, 60),
            source: String(it.source || '').trim().slice(0, 40),
            url: url,
            posted_at: String(it.posted_at || '').trim().slice(0, 60),
            summary: String(it.summary || '').trim().slice(0, 1200),
            match: match,
            confidence: conf,
            risk: String(it.risk || '').trim().slice(0, 300),
            status: 'new', notes: ''
          };
          await env.LEADS.put('mlead:' + id, JSON.stringify(lead));
          await env.LEADS.put(urlKey, id);
          added++;
        }
        return json({ ok: true, added: added, skipped: skipped }, 200, origin);
      }

      if (path === '/api/market-leads' && request.method === 'GET') {
        const list = await env.LEADS.list({ prefix: 'mlead:', limit: 1000 });
        const mleads = (await Promise.all(
          list.keys.map(k => env.LEADS.get(k.name, { type: 'json' }))
        )).filter(Boolean);
        mleads.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
        return json({ ok: true, leads: mleads }, 200, origin);
      }

      const mm = path.match(/^\/api\/market-leads\/([A-Za-z0-9-]+)$/);
      if (mm) {
        const key = 'mlead:' + mm[1];
        if (request.method === 'PATCH') {
          const lead = await env.LEADS.get(key, { type: 'json' });
          if (!lead) return json({ ok: false, error: 'not_found' }, 404, origin);
          let d = null;
          try { d = await request.json(); } catch (e) {}
          d = d || {};
          if (d.status !== undefined) {
            const st = String(d.status).toLowerCase();
            if (!MSTATUSES.includes(st)) return json({ ok: false, error: 'validation' }, 400, origin);
            lead.status = st;
          }
          if (d.notes !== undefined) lead.notes = String(d.notes).slice(0, 2000);
          await env.LEADS.put(key, JSON.stringify(lead));
          return json({ ok: true, lead: lead }, 200, origin);
        }
        if (request.method === 'DELETE') {
          const lead = await env.LEADS.get(key, { type: 'json' });
          if (lead && lead.url) {
            await env.LEADS.delete('murl:' + (await sha256hex(String(lead.url).toLowerCase())));
          }
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
            Object.values(doc.pv || {}).forEach(v => { views += v; });
            uniques = Object.keys(doc.uv || {}).length;
            ['pv', 'ev', 'li', 'lang', 'ref'].forEach(k => {
              Object.entries(doc[k] || {}).forEach(([kk, vv]) => { tot[k][kk] = (tot[k][kk] || 0) + vv; });
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
        const list = await env.LEADS.list({ prefix: 'nlsub:', limit: 1000 });
        const subs = [];
        for (const k of list.keys) {
          const raw = await env.LEADS.get(k.name);
          if (raw) subs.push(JSON.parse(raw));
        }
        subs.sort(function (a, b) { return String(b.created_at).localeCompare(String(a.created_at)); });
        const byLang = { en: 0, fa: 0, hi: 0, zh: 0 };
        subs.forEach(function (s) { if (byLang[s.lang] != null) byLang[s.lang]++; });
        return json({ ok: true, subscribers: subs, byLang: byLang, count: subs.length }, 200, origin);
      }
      if (path === '/api/admin/newsletter' && request.method === 'DELETE') {
        const em = String(url.searchParams.get('email') || '').trim().toLowerCase();
        if (!em) return json({ ok: false, error: 'validation' }, 400, origin);
        await env.LEADS.delete('nlsub:' + em);
        return json({ ok: true }, 200, origin);
      }

      // ---- admin: viewings ----
      if (path === '/api/admin/viewings' && request.method === 'GET') {
        const vidx = (await env.LEADS.get('vidx', { type: 'json' })) || [];
        const out = [];
        for (const id of vidx.slice(0, 100)) {
          const raw = await env.LEADS.get('viewing:' + id);
          if (raw) out.push(JSON.parse(raw));
        }
        return json({ ok: true, viewings: out }, 200, origin);
      }
      const vwm = path.match(/^\/api\/admin\/viewings\/([A-Za-z0-9_-]+)$/);
      if (vwm && request.method === 'PATCH') {
        let d = null;
        try { d = await request.json(); } catch (e) {}
        const raw = await env.LEADS.get('viewing:' + vwm[1]);
        if (!raw) return json({ ok: false, error: 'not_found' }, 404, origin);
        const rec = JSON.parse(raw);
        const st = String((d || {}).status || '').toLowerCase();
        if (['new', 'confirmed', 'done', 'cancelled'].includes(st)) rec.status = st;
        await env.LEADS.put('viewing:' + vwm[1], JSON.stringify(rec));
        return json({ ok: true }, 200, origin);
      }

      // ---- admin: registered visitors (summary) ----
      if (path === '/api/admin/users' && request.method === 'GET') {
        const list = await env.LEADS.list({ prefix: 'user:', limit: 200 });
        const out = [];
        for (const k of list.keys) {
          const raw = await env.LEADS.get(k.name);
          if (!raw) continue;
          const u = JSON.parse(raw);
          const saved = await userSaved(env, u.email);
          const searches = await userSearches(env, u.email);
          out.push({ name: u.name, email: u.email, lang: u.lang, created_at: u.created_at, savedCount: saved.length, searchCount: searches.length });
        }
        out.sort(function (a, b) { return String(b.created_at).localeCompare(String(a.created_at)); });
        return json({ ok: true, users: out, count: out.length }, 200, origin);
      }

      // ---- admin: outgoing mail queue (drained by the mailer cron once a sender is configured) ----
      if (path === '/api/admin/mailq' && request.method === 'GET') {
        const idx = (await env.LEADS.get('mailqidx', { type: 'json' })) || [];
        const out = [];
        for (const id of idx.slice(0, 100)) {
          const raw = await env.LEADS.get('mailq:' + id);
          if (raw) out.push(JSON.parse(raw));
        }
        return json({ ok: true, mail: out }, 200, origin);
      }
      const mqm = path.match(/^\/api\/admin\/mailq\/([A-Za-z0-9-]+)$/);
      if (mqm && request.method === 'PATCH') {
        const raw = await env.LEADS.get('mailq:' + mqm[1]);
        if (!raw) return json({ ok: false, error: 'not_found' }, 404, origin);
        const rec = JSON.parse(raw);
        rec.sent = true;
        rec.sent_at = new Date().toISOString();
        await env.LEADS.put('mailq:' + mqm[1], JSON.stringify(rec));
        return json({ ok: true }, 200, origin);
      }

      // ---- admin: saved-search alert digest (new matches since last notify) ----
      if (path === '/api/admin/alert-digest' && request.method === 'GET') {
        const list = await env.LEADS.list({ prefix: 'usearch:', limit: 200 });
        const out = [];
        for (const k of list.keys) {
          const email = k.name.slice('usearch:'.length);
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
        const email = String(d.email || '').toLowerCase();
        const searches = await userSearches(env, email);
        const s = searches.filter(function (x) { return x.id === d.searchId; })[0];
        if (!s) return json({ ok: false, error: 'not_found' }, 404, origin);
        const add = Array.isArray(d.listings) ? d.listings : [];
        s.notified = Array.from(new Set((s.notified || []).concat(add)));
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
        const enabled = !!(d && d.enabled === true);
        await env.LEADS.put('radar:settings', JSON.stringify({ enabled: enabled, updated_at: new Date().toISOString() }));
        return json({ ok: true, enabled: enabled }, 200, origin);
      }

      return json({ ok: false, error: 'not_found' }, 404, origin);
    } catch (e) {
      return json({ ok: false, error: 'server' }, 500, origin);
    }
  }
};
