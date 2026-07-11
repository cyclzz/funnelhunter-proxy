// FunnelHunter API Proxy + Stripe Webhook Handler + Admin API
// Environment variables (set in Railway):
//   ANTHROPIC_API_KEY       = sk-ant-...
//   SUPABASE_URL            = https://yourproject.supabase.co
//   SUPABASE_ANON_KEY       = eyJ...
//   SUPABASE_SERVICE_KEY    = eyJ... (admin)
//   STRIPE_WEBHOOK_SECRET   = whsec_...
//   STRIPE_SECRET_KEY       = sk_live_... (needed to fetch customer email)
//   ADMIN_EMAIL             = dconnorstone@gmail.com  (only this account can use /admin/* routes)

const https  = require('https');
const http   = require('http');
const crypto = require('crypto');

const PORT           = process.env.PORT || 3001;
const ANTHROPIC_KEY  = process.env.ANTHROPIC_API_KEY     || '';
const SUPABASE_URL   = process.env.SUPABASE_URL          || '';
const SUPABASE_ANON  = process.env.SUPABASE_ANON_KEY     || '';
const SUPABASE_SVC   = process.env.SUPABASE_SERVICE_KEY  || '';
const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const STRIPE_KEY     = process.env.STRIPE_SECRET_KEY     || '';
const ADMIN_EMAIL    = (process.env.ADMIN_EMAIL || '').toLowerCase();

console.log('Proxy starting...');
console.log('Anthropic:', !!ANTHROPIC_KEY, '| Supabase:', !!SUPABASE_SVC, '| Webhook:', !!WEBHOOK_SECRET, '| Stripe:', !!STRIPE_KEY, '| Admin:', !!ADMIN_EMAIL);

const PLAN_PRICES = { free: 0, trial: 0, basic: 37, pro: 97, agency: 247 };

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
function sbReq(method, path, body, useKey) {
  return new Promise((resolve, reject) => {
    const url     = new URL(SUPABASE_URL + path);
    const payload = body ? JSON.stringify(body) : null;
    const key     = useKey || SUPABASE_SVC;
    const opts    = {
      hostname: url.hostname,
      path:     url.pathname + url.search,
      method,
      headers: {
        'apikey':        key,
        'Authorization': 'Bearer ' + key,
        'Content-Type':  'application/json',
        'Prefer':        'return=representation',
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

// ── Resolve the caller's identity from a Supabase access token ────
// Used to gate /admin/* routes. Never trust a client-supplied email or
// flag — always resolve identity server-side from the token itself.
function resolveUserFromToken(token) {
  return new Promise((resolve) => {
    if (!token) { resolve(null); return; }
    const url = new URL(SUPABASE_URL + '/auth/v1/user');
    const opts = {
      hostname: url.hostname,
      path: url.pathname,
      method: 'GET',
      headers: {
        'apikey': SUPABASE_ANON || SUPABASE_SVC,
        'Authorization': 'Bearer ' + token,
      }
    };
    const req = https.request(opts, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(d);
          resolve(res.statusCode === 200 ? parsed : null);
        } catch { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.end();
  });
}

// ── Admin gate — returns the admin user object, or null if unauthorized ──
async function requireAdmin(req) {
  if (!ADMIN_EMAIL) { console.warn('ADMIN_EMAIL not set — admin routes disabled.'); return null; }
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return null;
  const user = await resolveUserFromToken(token);
  if (!user?.email || user.email.toLowerCase() !== ADMIN_EMAIL) return null;
  return user;
}

// ── Log a plan transition for analytics (signups, conversion, churn) ──
async function logPlanEvent(userId, oldPlan, newPlan) {
  try {
    await sbReq('POST', '/rest/v1/plan_events', { user_id: userId, old_plan: oldPlan, new_plan: newPlan });
  } catch(e) {
    console.error('logPlanEvent error:', e.message);
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
      await logPlanEvent(r.body.id, null, plan);

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

  // Fetch current plan first so we can log the transition accurately.
  let oldPlan = null;
  try {
    const cur = await sbReq('GET', `/rest/v1/profiles?id=eq.${userId}&select=plan`);
    oldPlan = cur.body?.[0]?.plan || null;
  } catch(e) { console.warn('Could not read old plan:', e.message); }

  const r = await sbReq('PATCH',
    `/rest/v1/profiles?id=eq.${userId}`,
    { plan, searches_used: 0, audits_used: 0, pitches_used: 0, updated_at: new Date().toISOString() }
  );
  console.log('Plan updated - status:', r.status);

  if (oldPlan !== plan) await logPlanEvent(userId, oldPlan, plan);
}

// ── Map amount to plan ─────────────────────────────────
// NOTE: Only used for non-trialing subscriptions. Trial subscriptions are
// identified by status (see handleStripeEvent), not amount, because the
// Trial plan's recurring rate ($97/mo after the $1 intro period) is
// identical to the Pro plan's rate. Relying on amount alone would upgrade
// every $1 trial signup to 'pro' from the very first webhook event.
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

    if (status === 'trialing') {
      // Trial and Pro share the same $97/mo recurring price, so amount
      // can't distinguish them. Status is the only reliable signal while
      // the subscription is still in its trial period.
      await setPlan(email, 'trial');
    } else if (status === 'active') {
      await setPlan(email, planFromAmount(amount));
    } else if (status === 'past_due') {
      // Card declined but Stripe is still retrying (grace period, by design).
      // Access stays as-is — no plan change. Logged for support visibility.
      console.log(`Payment past_due for ${email} — Stripe is retrying, access unchanged.`);
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

  // invoice.payment_succeeded — resets usage counters on renewal.
  // billing_reason tells us WHY the invoice was created:
  //   'subscription_create' = first payment (counters already 0, no-op)
  //   'subscription_cycle'  = monthly renewal — this is what resets usage
  //   'subscription_update' = plan change (setPlan already resets counters)
  if (type === 'invoice.payment_succeeded') {
    const billingReason = obj?.billing_reason;
    const custId = obj?.customer;
    let email = obj?.customer_email;
    if (!email && custId) {
      const cust = await getStripeCustomer(custId);
      email = cust?.email;
    }
    console.log(`Payment succeeded for ${email || custId} (billing_reason=${billingReason})`);

    if (email && billingReason === 'subscription_cycle') {
      const userId = await getUserIdByEmail(email);
      if (userId) {
        await sbReq('PATCH', `/rest/v1/profiles?id=eq.${userId}`,
          { searches_used: 0, audits_used: 0, pitches_used: 0, updated_at: new Date().toISOString() });
        console.log(`✓ Usage counters reset for ${email} (new billing cycle)`);
      } else {
        console.warn('Renewal payment succeeded but no matching user found for', email);
      }
    }
  }

  // invoice.payment_failed — card declined. Per business decision, access
  // stays live during Stripe's automatic retry window (past_due status),
  // so this handler only logs for support visibility. No plan change here;
  // if Stripe exhausts retries, customer.subscription.updated will fire
  // with status 'canceled' or 'unpaid' and setPlan(email, 'free') runs then.
  if (type === 'invoice.payment_failed') {
    const custId = obj?.customer;
    let email = obj?.customer_email;
    if (!email && custId) {
      const cust = await getStripeCustomer(custId);
      email = cust?.email;
    }
    console.warn(`⚠ Payment FAILED for ${email || custId} — Stripe will retry automatically. Access unchanged.`);
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

// ══════════════════════════════════════════════════════
// ADMIN API — all routes require requireAdmin() to pass
// ══════════════════════════════════════════════════════

// GET /admin/users?search=foo — merges auth.users (email) with profiles
async function adminListUsers(search) {
  const authRes = await sbReq('GET', '/auth/v1/admin/users?per_page=1000&page=1');
  const authUsers = authRes.body?.users || [];

  const profRes = await sbReq('GET', '/rest/v1/profiles?select=*');
  const profiles = profRes.body || [];
  const profileById = Object.fromEntries(profiles.map(p => [p.id, p]));

  let merged = authUsers.map(u => {
    const p = profileById[u.id] || {};
    return {
      id: u.id,
      email: u.email,
      created_at: u.created_at,
      last_sign_in_at: u.last_sign_in_at,
      first_name: p.first_name || null,
      plan: p.plan || 'free',
      searches_used: p.searches_used || 0,
      audits_used: p.audits_used || 0,
      pitches_used: p.pitches_used || 0,
    };
  });

  if (search) {
    const q = search.toLowerCase();
    merged = merged.filter(u =>
      (u.email || '').toLowerCase().includes(q) ||
      (u.first_name || '').toLowerCase().includes(q)
    );
  }

  merged.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  return merged;
}

// GET /admin/overview — aggregate stats for the dashboard
async function adminOverview() {
  const profRes = await sbReq('GET', '/rest/v1/profiles?select=id,plan,created_at');
  const profiles = profRes.body || [];

  const eventsRes = await sbReq('GET', '/rest/v1/plan_events?select=*&order=created_at.asc');
  const events = eventsRes.body || [];

  const byPlan = {};
  let mrr = 0;
  for (const p of profiles) {
    byPlan[p.plan] = (byPlan[p.plan] || 0) + 1;
    mrr += PLAN_PRICES[p.plan] || 0;
  }

  // Signups per day, last 30 days (based on profile creation date)
  const days = [];
  const now = new Date();
  for (let i = 29; i >= 0; i--) {
    const d = new Date(now); d.setDate(d.getDate() - i);
    days.push(d.toISOString().slice(0, 10));
  }
  const signupsByDay = Object.fromEntries(days.map(d => [d, 0]));
  for (const p of profiles) {
    const day = (p.created_at || '').slice(0, 10);
    if (day in signupsByDay) signupsByDay[day]++;
  }

  // Trial -> paid conversion: users who ever hit 'trial', vs those who
  // later also hit a paid plan.
  const paidPlans = ['basic', 'pro', 'agency'];
  const trialUserIds = new Set(events.filter(e => e.new_plan === 'trial').map(e => e.user_id));
  const convertedUserIds = new Set(
    events.filter(e => paidPlans.includes(e.new_plan) && trialUserIds.has(e.user_id)).map(e => e.user_id)
  );
  const conversionRate = trialUserIds.size ? (convertedUserIds.size / trialUserIds.size) : 0;

  // Churn in last 30 days: transitions TO 'free' FROM a paid plan
  const cutoff = new Date(now); cutoff.setDate(cutoff.getDate() - 30);
  const churnEvents = events.filter(e =>
    e.new_plan === 'free' && paidPlans.includes(e.old_plan) && new Date(e.created_at) >= cutoff
  );

  return {
    total_users: profiles.length,
    by_plan: byPlan,
    mrr_estimate: mrr,
    signups_last_30_days: days.map(d => ({ date: d, count: signupsByDay[d] })),
    trial_to_paid: {
      trial_users: trialUserIds.size,
      converted_users: convertedUserIds.size,
      conversion_rate: conversionRate,
    },
    churn_last_30_days: churnEvents.length,
  };
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

  const parsedUrl = new URL(req.url, 'http://internal');
  const pathname  = parsedUrl.pathname;

  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', async () => {
    const buf     = Buffer.concat(chunks);
    const bodyStr = buf.toString('utf8');

    // ── Admin API ─────────────────────────────────
    if (pathname.startsWith('/admin/')) {
      const admin = await requireAdmin(req);
      if (!admin) {
        res.writeHead(403, { ...cors, 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not authorized' }));
        return;
      }

      try {
        if (req.method === 'GET' && pathname === '/admin/overview') {
          const data = await adminOverview();
          res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
          res.end(JSON.stringify(data));
          return;
        }

        if (req.method === 'GET' && pathname === '/admin/users') {
          const data = await adminListUsers(parsedUrl.searchParams.get('search') || '');
          res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
          res.end(JSON.stringify(data));
          return;
        }

        const planMatch = pathname.match(/^\/admin\/users\/([0-9a-fA-F-]+)\/plan$/);
        if (req.method === 'POST' && planMatch) {
          const userId = planMatch[1];
          let payload;
          try { payload = JSON.parse(bodyStr); } catch { payload = {}; }
          const newPlan = payload.plan;
          if (!['free', 'trial', 'basic', 'pro', 'agency'].includes(newPlan)) {
            res.writeHead(400, { ...cors, 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid plan' }));
            return;
          }
          const cur = await sbReq('GET', `/rest/v1/profiles?id=eq.${userId}&select=plan`);
          const oldPlan = cur.body?.[0]?.plan || null;
          const update = { plan: newPlan, updated_at: new Date().toISOString() };
          if (payload.resetUsage) {
            update.searches_used = 0; update.audits_used = 0; update.pitches_used = 0;
          }
          await sbReq('PATCH', `/rest/v1/profiles?id=eq.${userId}`, update);
          if (oldPlan !== newPlan) await logPlanEvent(userId, oldPlan, newPlan);
          console.log(`Admin ${admin.email} set ${userId} plan: ${oldPlan} -> ${newPlan}`);
          res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
          return;
        }

        const resetMatch = pathname.match(/^\/admin\/users\/([0-9a-fA-F-]+)\/reset-usage$/);
        if (req.method === 'POST' && resetMatch) {
          const userId = resetMatch[1];
          await sbReq('PATCH', `/rest/v1/profiles?id=eq.${userId}`,
            { searches_used: 0, audits_used: 0, pitches_used: 0, updated_at: new Date().toISOString() });
          console.log(`Admin ${admin.email} reset usage for ${userId}`);
          res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
          return;
        }

        res.writeHead(404, { ...cors, 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
      } catch(e) {
        console.error('Admin route error:', e.message);
        res.writeHead(500, { ...cors, 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }

    // ── Stripe Webhook ──────────────────────────────
    if (req.method === 'POST' && pathname === '/webhook') {
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
    if (req.method !== 'POST' || pathname !== '/api/claude') {
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
