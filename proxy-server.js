// FunnelHunter API Proxy + Stripe Webhook Handler
// Environment variables (set in Railway):
//   ANTHROPIC_API_KEY       = sk-ant-...
//   SUPABASE_URL            = https://yourproject.supabase.co
//   SUPABASE_ANON_KEY       = eyJ...
//   SUPABASE_SERVICE_KEY    = eyJ... (admin)
//   STRIPE_WEBHOOK_SECRET   = whsec_...
//   STRIPE_SECRET_KEY       = sk_live_... (needed to fetch customer email)

const https  = require('https');
const http   = require('http');
const crypto = require('crypto');

const PORT           = process.env.PORT || 3001;
const ANTHROPIC_KEY  = process.env.ANTHROPIC_API_KEY     || '';
const SUPABASE_URL   = process.env.SUPABASE_URL          || '';
const SUPABASE_SVC   = process.env.SUPABASE_SERVICE_KEY  || '';
const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const STRIPE_KEY     = process.env.STRIPE_SECRET_KEY     || '';

console.log('Proxy starting...');
console.log('Anthropic:', !!ANTHROPIC_KEY, '| Supabase:', !!SUPABASE_SVC, '| Webhook:', !!WEBHOOK_SECRET, '| Stripe:', !!STRIPE_KEY);

// ── Fetch customer email from Stripe ───────────────────
function getStripeCustomer(customerId) {
  return new Promise((resolve) => {
    if (!STRIPE_KEY || !customerId) { resolve(null); return; }
    const opts = {
      hostname: 'api.stripe.com',
      path: '/v1/customers/' + customerId,
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + STRIPE_KEY }
    };
    const req = https.request(opts, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve(JSON.parse(d)); }
        catch { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.end();
  });
}

// ── Supabase REST helper ───────────────────────────────
function sbReq(method, path, body) {
  return new Promise((resolve, reject) => {
    const url     = new URL(SUPABASE_URL + path);
    const payload = body ? JSON.stringify(body) : null;
    const opts    = {
      hostname: url.hostname,
      path:     url.pathname + url.search,
      method,
      headers: {
        'apikey':        SUPABASE_SVC,
        'Authorization': 'Bearer ' + SUPABASE_SVC,
        'Content-Type':  'application/json',
        'Prefer':        'return=minimal',
      }
    };
    if (payload) opts.headers['Content-Length'] = Buffer.byteLength(payload);
    const req = https.request(opts, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: d ? JSON.parse(d) : {} }); }
        catch { resolve({ status: res.statusCode, body: d }); }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// ── Find user ID by email ──────────────────────────────
async function getUserIdByEmail(email) {
  try {
    const r = await sbReq('GET', `/auth/v1/admin/users?email=${encodeURIComponent(email)}`);
    console.log('User lookup for', email, '- status:', r.status, '- found:', r.body?.users?.length || 0);
    return r.body?.users?.[0]?.id || null;
  } catch(e) {
    console.error('getUserIdByEmail error:', e.message);
    return null;
  }
}

// ── Create Supabase user if they don't exist ───────────
async function createUserIfNeeded(email, plan) {
  // Check if user exists
  const existingId = await getUserIdByEmail(email);
  if (existingId) {
    console.log('User exists, upgrading plan:', email);
    return existingId;
  }

  // Create new user with temporary password
  const tempPassword = 'FH-' + Math.random().toString(36).slice(2, 10).toUpperCase() + '!';
  console.log('Creating new Supabase user for:', email);

  try {
    const r = await sbReq('POST', '/auth/v1/admin/users', {
      email,
      password: tempPassword,
      email_confirm: true,
      user_metadata: { plan, created_via: 'stripe_webhook' }
    });
    console.log('User creation status:', r.status, 'id:', r.body?.id);

    if (r.body?.id) {
      // Create profile row
      await sbReq('POST', '/rest/v1/profiles', {
        id: r.body.id,
        plan,
        searches_used: 0,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
      console.log('✓ Profile created for', email);

      // Send password reset email so they can set their own password
      await sbReq('POST', '/auth/v1/admin/generate_link', {
        type: 'recovery',
        email,
        options: { redirect_to: 'https://funnelhunter.netlify.app' }
      });
      console.log('✓ Password setup email sent to', email);
    }
    return r.body?.id || null;
  } catch(e) {
    console.error('createUserIfNeeded error:', e.message);
    return null;
  }
}

// ── Set user plan (creates user if needed) ─────────────
async function setPlan(email, plan) {
  console.log(`setPlan: ${email} -> ${plan}`);

  // Create user if they don't exist (new CF purchase)
  const userId = await createUserIfNeeded(email, plan);
  if (!userId) { console.warn('Could not find or create user:', email); return; }

  const r = await sbReq('PATCH',
    `/rest/v1/profiles?id=eq.${userId}`,
    { plan, searches_used: 0, updated_at: new Date().toISOString() }
  );
  console.log('Plan updated - status:', r.status);
}

// ── Map amount to plan ─────────────────────────────────
function planFromAmount(cents) {
  if (cents >= 24700) return 'agency';
  if (cents >= 9700)  return 'pro';
  if (cents >= 3700)  return 'basic';
  return 'trial';
}

// ── Verify Stripe signature ────────────────────────────
function verifyStripe(rawBody, sig, secret) {
  try {
    const ts  = sig.split(',').find(p => p.startsWith('t=')).slice(2);
    const v1  = sig.split(',').find(p => p.startsWith('v1=')).slice(3);
    const exp = crypto.createHmac('sha256', secret)
                      .update(ts + '.' + rawBody).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(v1), Buffer.from(exp));
  } catch(e) {
    console.error('verifyStripe error:', e.message);
    return false;
  }
}

// ── Handle Stripe event ────────────────────────────────
async function handleStripeEvent(event) {
  const obj    = event.data?.object;
  const type   = event.type;
  console.log('Handling event:', type);

  if (type === 'customer.subscription.created' ||
      type === 'customer.subscription.updated') {
    const status   = obj?.status;
    const custId   = obj?.customer;
    const amount   = obj?.items?.data?.[0]?.price?.unit_amount || 0;

    // Get email — try subscription first, then fetch from Stripe
    let email = obj?.customer_email || obj?.metadata?.email;
    if (!email && custId) {
      console.log('Fetching customer from Stripe:', custId);
      const cust = await getStripeCustomer(custId);
      email = cust?.email;
      console.log('Customer email from Stripe:', email);
    }

    if (!email) { console.warn('No email found for subscription event'); return; }

    if (status === 'active' || status === 'trialing') {
      await setPlan(email, planFromAmount(amount));
    } else if (status === 'canceled' || status === 'unpaid') {
      await setPlan(email, 'free');
    } else {
      console.log('Unhandled status:', status);
    }
  }

  if (type === 'customer.subscription.deleted') {
    const custId = obj?.customer;
    let email = obj?.customer_email || obj?.metadata?.email;
    if (!email && custId) {
      const cust = await getStripeCustomer(custId);
      email = cust?.email;
    }
    if (email) await setPlan(email, 'free');
  }

  if (type === 'invoice.payment_succeeded') {
    console.log('Payment succeeded - subscription events handle the plan upgrade');
  }

  // checkout.session.completed — backup to ensure user exists on first payment
  if (type === 'checkout.session.completed') {
    const email  = obj?.customer_email || obj?.customer_details?.email;
    const custId = obj?.customer;
    let finalEmail = email;
    if (!finalEmail && custId) {
      const cust = await getStripeCustomer(custId);
      finalEmail = cust?.email;
    }
    if (finalEmail) {
      console.log('Checkout completed for:', finalEmail);
      await createUserIfNeeded(finalEmail, 'trial');
    }
  }
}

// ── Main server ────────────────────────────────────────
const ALLOWED_ORIGINS = [
  'https://funnelhunter.netlify.app',
  'https://dcstone.myclickfunnels.com',
];

http.createServer((req, res) => {
  const origin = req.headers.origin || '';
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  const cors = {
    'Access-Control-Allow-Origin':  allowedOrigin,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, anthropic-version, stripe-signature',
  };

  if (req.method === 'OPTIONS') { res.writeHead(204, cors); res.end(); return; }

  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, anthropic: !!ANTHROPIC_KEY, supabase: !!SUPABASE_SVC, stripe: !!STRIPE_KEY }));
    return;
  }

  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', async () => {
    const buf     = Buffer.concat(chunks);
    const bodyStr = buf.toString('utf8');

    // ── Stripe Webhook ──────────────────────────────
    if (req.method === 'POST' && req.url === '/webhook') {
      const sig = req.headers['stripe-signature'] || '';
      if (!sig || !WEBHOOK_SECRET) {
        console.error('Missing sig or secret');
        res.writeHead(400, cors); res.end('Missing signature'); return;
      }
      if (!verifyStripe(bodyStr, sig, WEBHOOK_SECRET)) {
        console.error('Invalid signature');
        res.writeHead(400, cors); res.end('Invalid signature'); return;
      }
      let event;
      try { event = JSON.parse(bodyStr); }
      catch { res.writeHead(400, cors); res.end('Bad JSON'); return; }

      // Respond to Stripe immediately, then process async
      res.writeHead(200, cors); res.end('ok');
      handleStripeEvent(event).catch(e => console.error('Event handler error:', e.message));
      return;
    }

    // ── Claude Proxy ────────────────────────────────
    if (req.method !== 'POST' || req.url !== '/api/claude') {
      res.writeHead(404, { ...cors, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' })); return;
    }

    const key = process.env.ANTHROPIC_API_KEY || ANTHROPIC_KEY;
    if (!key) {
      res.writeHead(503, { ...cors, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'API key not configured.' })); return;
    }

    let payload;
    try { payload = JSON.parse(bodyStr); }
    catch {
      res.writeHead(400, { ...cors, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' })); return;
    }

    payload.model      = 'claude-sonnet-4-5';
    payload.max_tokens = Math.min(payload.max_tokens || 1000, 4000);

    const out      = JSON.stringify(payload);
    const isStream = payload.stream === true;

    const proxyReq = https.request({
      hostname: 'api.anthropic.com',
      path:     '/v1/messages',
      method:   'POST',
      headers: {
        'Content-Type':      'application/json',
        'Content-Length':    Buffer.byteLength(out),
        'x-api-key':         key,
        'anthropic-version': '2023-06-01',
      }
    }, proxyRes => {
      res.writeHead(proxyRes.statusCode, {
        ...cors,
        'Content-Type': isStream ? 'text/event-stream' : 'application/json',
        ...(isStream ? { 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' } : {})
      });
      proxyRes.pipe(res);
    });

    proxyReq.on('error', err => {
      console.error('Claude proxy error:', err.message);
      if (!res.headersSent) {
        res.writeHead(502, { ...cors, 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });

    proxyReq.write(out);
    proxyReq.end();
  });

}).listen(PORT, () => console.log('FunnelHunter proxy on port ' + PORT));
