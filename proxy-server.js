// FunnelHunter API Proxy + Stripe Webhook Handler
// Environment variables (set in Railway):
//   ANTHROPIC_API_KEY       = sk-ant-...
//   SUPABASE_URL            = https://yourproject.supabase.co
//   SUPABASE_ANON_KEY       = eyJ... (public)
//   SUPABASE_SERVICE_KEY    = eyJ... (admin - never expose publicly)
//   STRIPE_WEBHOOK_SECRET   = whsec_...

const https  = require('https');
const http   = require('http');
const crypto = require('crypto');

const PORT           = process.env.PORT || 3001;
const ANTHROPIC_KEY  = process.env.ANTHROPIC_API_KEY     || '';
const SUPABASE_URL   = process.env.SUPABASE_URL          || '';
const SUPABASE_ANON  = process.env.SUPABASE_ANON_KEY     || '';
const SUPABASE_SVC   = process.env.SUPABASE_SERVICE_KEY  || '';
const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';

if (!ANTHROPIC_KEY)  console.warn('WARNING: ANTHROPIC_API_KEY not set');
if (!SUPABASE_URL)   console.warn('WARNING: SUPABASE_URL not set');
if (!SUPABASE_SVC)   console.warn('WARNING: SUPABASE_SERVICE_KEY not set');
if (!WEBHOOK_SECRET) console.warn('WARNING: STRIPE_WEBHOOK_SECRET not set');

// ── Supabase REST helper (uses service key for admin access) ──
function sbRequest(method, path, body, useServiceKey = false) {
  return new Promise((resolve, reject) => {
    const key     = useServiceKey ? SUPABASE_SVC : SUPABASE_ANON;
    const url     = new URL(SUPABASE_URL + path);
    const payload = body ? JSON.stringify(body) : null;
    const options = {
      hostname: url.hostname,
      path:     url.pathname + url.search,
      method,
      headers: {
        'apikey':        key,
        'Authorization': 'Bearer ' + key,
        'Content-Type':  'application/json',
        'Prefer':        'return=minimal',
      }
    };
    if (payload) options.headers['Content-Length'] = Buffer.byteLength(payload);
    const req = https.request(options, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(data ? JSON.parse(data) : {}); }
        catch { resolve({}); }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// ── Get user ID from email using admin API ─────────────
async function getUserIdByEmail(email) {
  try {
    const resp = await sbRequest('GET',
      `/auth/v1/admin/users?email=${encodeURIComponent(email)}`,
      null, true);
    return resp?.users?.[0]?.id || null;
  } catch(e) {
    console.error('getUserIdByEmail error:', e.message);
    return null;
  }
}

// ── Upgrade or downgrade user plan in Supabase ─────────
async function setPlan(email, plan) {
  const userId = await getUserIdByEmail(email);
  if (!userId) {
    console.warn('No user found for email:', email);
    return;
  }
  try {
    await sbRequest('PATCH',
      `/rest/v1/profiles?id=eq.${userId}`,
      { plan, searches_used: 0, updated_at: new Date().toISOString() },
      true
    );
    console.log(`✓ Set ${email} → plan: ${plan}`);
  } catch(e) {
    console.error('setPlan error:', e.message);
  }
}

// ── Map Stripe price amount to plan name ───────────────
function planFromAmount(unitAmount) {
  if (unitAmount >= 24700) return 'agency';  // $247
  if (unitAmount >= 9700)  return 'pro';     // $97
  if (unitAmount >= 3700)  return 'basic';   // $37
  return 'trial';                             // $1 or anything lower
}

// ── Stripe webhook signature verification ─────────────
function verifyStripe(rawBody, sigHeader, secret) {
  try {
    const parts     = sigHeader.split(',');
    const timestamp = parts.find(p => p.startsWith('t=')).slice(2);
    const sig       = parts.find(p => p.startsWith('v1=')).slice(3);
    const expected  = crypto
      .createHmac('sha256', secret)
      .update(`${timestamp}.${rawBody}`)
      .digest('hex');
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  } catch { return false; }
}

// ── Main server ────────────────────────────────────────
http.createServer((req, res) => {

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers',
    'Content-Type, Authorization, anthropic-version, anthropic-dangerous-direct-browser-access, stripe-signature');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', anthropic: !!ANTHROPIC_KEY, supabase: !!SUPABASE_SVC }));
    return;
  }

  // Collect raw body (needed for Stripe signature verification)
  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', async () => {
    const rawBody = Buffer.concat(chunks);
    const bodyStr = rawBody.toString();

    // ── Stripe Webhook ────────────────────────────────
    if (req.method === 'POST' && req.url === '/webhook') {
      const sig = req.headers['stripe-signature'];
      if (!sig || !WEBHOOK_SECRET) {
        res.writeHead(400); res.end('Missing signature'); return;
      }
      if (!verifyStripe(bodyStr, sig, WEBHOOK_SECRET)) {
        res.writeHead(400); res.end('Invalid signature'); return;
      }

      let event;
      try { event = JSON.parse(bodyStr); }
      catch { res.writeHead(400); res.end('Bad JSON'); return; }

      console.log('Webhook:', event.type);
      const obj = event.data?.object;

      if (event.type === 'customer.subscription.created' ||
          event.type === 'customer.subscription.updated') {
        const email  = obj?.customer_email || obj?.metadata?.email;
        const status = obj?.status;
        const amount = obj?.items?.data?.[0]?.price?.unit_amount || 0;
        if (email) {
          if (status === 'active' || status === 'trialing') {
            await setPlan(email, planFromAmount(amount));
          } else if (status === 'canceled' || status === 'unpaid') {
            await setPlan(email, 'free');
          }
        }
      }

      if (event.type === 'customer.subscription.deleted') {
        const email = obj?.customer_email || obj?.metadata?.email;
        if (email) await setPlan(email, 'free');
      }

      res.writeHead(200); res.end('ok');
      return;
    }

    // ── Claude API Proxy ──────────────────────────────
    if (req.method !== 'POST' || req.url !== '/api/claude') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' })); return;
    }

    const key = process.env.ANTHROPIC_API_KEY || ANTHROPIC_KEY;
    if (!key) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'API key not configured.' })); return;
    }

    let payload;
    try { payload = JSON.parse(bodyStr); }
    catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' })); return;
    }

    payload.model      = 'claude-sonnet-4-5';
    payload.max_tokens = Math.min(payload.max_tokens || 1000, 4000);

    const outBody = JSON.stringify(payload);
    const isStream = payload.stream === true;

    const proxyReq = https.request({
      hostname: 'api.anthropic.com',
      path:     '/v1/messages',
      method:   'POST',
      headers: {
        'Content-Type':      'application/json',
        'Content-Length':    Buffer.byteLength(outBody),
        'x-api-key':         key,
        'anthropic-version': '2023-06-01',
      }
    }, proxyRes => {
      res.writeHead(proxyRes.statusCode, {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': isStream ? 'text/event-stream' : 'application/json',
        ...(isStream ? { 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' } : {})
      });
      proxyRes.pipe(res);
    });

    proxyReq.on('error', err => {
      console.error('Proxy error:', err.message);
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });

    proxyReq.write(outBody);
    proxyReq.end();
  });

}).listen(PORT, () => console.log('FunnelHunter proxy on port ' + PORT));
