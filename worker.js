// advisor-api worker — private CRM backend for the advisor portal.
// KV binding: LEADS
// Secret: ADVISOR_AUTH = "<salt_hex>:<sha256_hex(salt + ':' + password)>"

const ALLOWED_ORIGINS = [
  'https://real-estate-platform-0aei.onrender.com',
  'https://muse.ai',
  'null'
];
const INTENTS = ['buyer', 'seller', 'investor', 'renter'];
const STAGES = ['new', 'contacted', 'viewing', 'offer', 'closed', 'dropped'];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const TOKEN_TTL = 86400;

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
      if (path === '/api/health') {
        return json({ ok: true }, 200, origin);
      }
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
        return json({ ok: true }, 200, origin);
      }
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
      return json({ ok: false, error: 'not_found' }, 404, origin);
    } catch (e) {
      return json({ ok: false, error: 'server' }, 500, origin);
    }
  }
};
