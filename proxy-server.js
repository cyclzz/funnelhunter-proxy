// FunnelHunter API Proxy + Stripe Webhook Handler
// Deploy to Railway — set these environment variables:
//   ANTHROPIC_API_KEY  = sk-ant-...
//   SUPABASE_URL       = https://yourproject.supabase.co
//   SUPABASE_ANON_KEY  = eyJ...
//   STRIPE_WEBHOOK_SECRET = whsec_...

const https  = require('https');
const http   = require('http');
const crypto = require('crypto');

const PORT             = process.env.PORT || 3001;
const ANTHROPIC_KEY    = process.env.ANTHROPIC_API_KEY    || '';
const SUPABASE_URL     = process.env.SUPABASE_URL         || '';
const SUPABASE_KEY     = process.env.SUPABASE_ANON_KEY    || '';
const WEBHOOK_SECRET   = process.env.STRIPE_WEBHOOK_SECRET || '';

if (!ANTHROPIC_KEY)  console.warn('WARNING: ANTHROPIC_API_KEY not set');
if (!SUPABASE_URL)   console.warn('WARNING: SUPABASE_URL not set');
if (!SUPABASE_KEY)   console.warn('WARNING: SUPABASE_ANON_KEY not set');
if (!WEBHOOK_SECRET) console.warn('WARNING: STRIPE_WEBHOOK_SECRET not set');

// ── Supabase REST helper ───────────────────────────────
function supabaseRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const url     = new URL(SUPABASE_URL + path);
    const payload = body ? JSON.stringify(body) : null;
    const options = {
      hostname: url.hostname,
      path:     url.pathname + url.search,
      method,
      headers: {
        'apikey':        SUPABASE_KEY,
        'Authorization': 'Bearer ' + SUPABASE_KEY,
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

// ── Upgrade user plan in Supabase by email ─────────────
async function upgradePlan(email, plan, searchLimit) {
  try {
    // Find user by email in auth.users via Supabase admin endpoint
    const users = await supabaseRequest('GET',
      `/rest/v1/profiles?select=id&id=eq.${email}`, null);

    // Use email to find the auth user ID
    const authResp = await supabaseRequest('GET',
      `/auth/v1/admin/users?email=${encodeURIComponent(email)}`, null);

    const userId = authResp?.users?.[0]?.id;
    if (!userId) {
      console.log('No user found for email:', email);
      return;
    }

    await supabaseRequest('PATCH',
      `/rest/v1/profiles?id=eq.${userId}`,
      { plan, searches_used: 0, updated_at: new Date().toISOString() }
    );

    console.log(`✓ Upgraded ${email} to ${plan}`);
  } catch(e) {
    console.error('Plan upgrade error:', e.message);
  }
}

// ── Stripe webhook signature verification ─────────────
function verifyStripeSignature(payload, sigHeader, secret) {
  const parts     = sigHeader.split(',');
  const timestamp = parts.find(p => p.startsWith('t=')).slice(2);
  const sig       = parts.find(p => p.startsWith('v1=')).slice(3);
  const signed    = `${timestamp}.${payload}`;
  const expected  = crypto.createHmac('sha256', secret).update(signed).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}

// ── Main server ────────────────────────────────────────
const server = http.createServer((req, res) => {

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, anthropic-version, anthropic-dangerous-direct-browser-access, stripe-signature');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // Health check
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', keyLoaded: !!ANTHROPIC_KEY }));
    return;
  }

  // Read body for all POST requests
  let body = Buffer.alloc(0);
  req.on('data', chunk => { body = Buffer.concat([body, chunk]); });
  req.on('end', async () => {
    const bodyStr = body.toString();

    // ── Stripe Webhook ──────────────────────────────────
    if (req.method === 'POST' && req.url === '/webhook') {
      const sig = req.headers['stripe-signature'];

      if (!sig || !WEBHOOK_SECRET) {
        res.writeHead(400); res.end('Missing signature');
        return;
      }

      let valid = false;
      try { valid = verifyStripeSignature(bodyStr, sig, WEBHOOK_SECRET); }
      catch(e) { console.error('Signature error:', e.message); }

      if (!valid) {
        res.writeHead(400); res.end('Invalid signature');
        return;
      }

      let event;
      try { event = JSON.parse(bodyStr); }
      catch { res.writeHead(400); res.end('Invalid JSON'); return; }

      console.log('Stripe event:', event.type);

      // Handle subscription events
      const obj = event.data?.object;

      if (event.type === 'customer.subscription.created' ||
          event.type === 'customer.subscription.updated') {
        const status = obj?.status;
        const email  = obj?.customer_email || obj?.metadata?.email;

        // Determine plan from price amount
        const amount = obj?.items?.data?.[0]?.price?.unit_amount || 0;
        let plan = 'basic';
        if (amount >= 24700) plan = 'agency';
        else if (amount >= 9700) plan = 'pro';
        else if (amount >= 3700) plan = 'basic';
        else if (amount <= 100) plan = 'trial'; // $1

        if (email && (status === 'active' || status === 'trialing')) {
          await upgradePlan(email, plan);
        }

        if (status === 'canceled' || status === 'unpaid') {
          await upgradePlan(email, 'free');
        }
      }

      if (event.type === 'customer.subscription.deleted') {
        const email = obj?.customer_email || obj?.metadata?.email;
        if (email) await upgradePlan(email, 'free');
      }

      if (event.type === 'invoice.payment_succeeded') {
        console.log('Payment succeeded for:', obj?.customer_email);
        // Subscription events handle plan upgrade, this is just for logging
      }

      res.writeHead(200); res.end('ok');
      return;
    }

    // ── Claude API Proxy ────────────────────────────────
    if (req.method !== 'POST' || req.url !== '/api/claude') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
      return;
    }

    const currentKey = process.env.ANTHROPIC_API_KEY || ANTHROPIC_KEY;
    if (!currentKey) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'API key not configured.' }));
      return;
    }

    let payload;
    try { payload = JSON.parse(bodyStr); }
    catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
      return;
    }

    payload.model      = 'claude-sonnet-4-5';
    payload.max_tokens = Math.min(payload.max_tokens || 1000, 4000);

    const outBody = JSON.stringify(payload);
    const isStream = payload.stream === true;

    const options = {
      hostname: 'api.anthropic.com',
      path:     '/v1/messages',
      method:   'POST',
      headers: {
        'Content-Type':      'application/json',
        'Content-Length':    Buffer.byteLength(outBody),
        'x-api-key':         currentKey,
        'anthropic-version': '2023-06-01',
      }
    };

    const proxyReq = https.request(options, proxyRes => {
      const headers = {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': isStream ? 'text/event-stream' : 'application/json',
      };
      if (isStream) { headers['Cache-Control'] = 'no-cache'; headers['Connection'] = 'keep-alive'; }
      res.writeHead(proxyRes.statusCode, headers);
      proxyRes.pipe(res);
    });

    proxyReq.on('error', err => {
      console.error('Proxy error:', err.message);
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Upstream error: ' + err.message }));
      }
    });

    proxyReq.write(outBody);
    proxyReq.end();
  });
});

server.listen(PORT, () => {
  console.log('FunnelHunter proxy running on port ' + PORT);
});
