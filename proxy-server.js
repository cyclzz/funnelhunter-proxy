// FunnelHunter API Proxy — with Supabase auth verification
//
// Environment variables needed (set in Railway):
//   ANTHROPIC_API_KEY  = sk-ant-...
//   SUPABASE_URL       = https://yourproject.supabase.co
//   SUPABASE_ANON_KEY  = eyJ...  (the anon/public key, NOT service_role)
//
// Deploy to Railway: railway.app

const https = require('https');
const http  = require('http');

const PORT          = process.env.PORT || 3001;
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
const SUPABASE_URL  = process.env.SUPABASE_URL;
const SUPABASE_KEY  = process.env.SUPABASE_ANON_KEY;

if (!ANTHROPIC_KEY) { console.error('Missing ANTHROPIC_API_KEY'); process.exit(1); }
if (!SUPABASE_URL)  { console.error('Missing SUPABASE_URL');  process.exit(1); }
if (!SUPABASE_KEY)  { console.error('Missing SUPABASE_ANON_KEY'); process.exit(1); }

// ── Verify a Supabase JWT and return the user ──────────────────
async function getUser(token) {
  return new Promise((resolve, reject) => {
    const url = new URL('/auth/v1/user', SUPABASE_URL);
    const options = {
      hostname: url.hostname,
      path:     url.pathname,
      method:   'GET',
      headers: {
        'apikey':        SUPABASE_KEY,
        'Authorization': 'Bearer ' + token,
      }
    };
    const req = https.request(options, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const user = JSON.parse(data);
          if (user.id) resolve(user);
          else reject(new Error('Invalid token'));
        } catch { reject(new Error('Auth parse error')); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

// ── Main server ────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  if (req.method !== 'POST' || req.url !== '/api/claude') {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
    return;
  }

  // ── 1. Verify user is logged in ──
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '').trim();

  if (!token) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not authenticated. Please sign in.' }));
    return;
  }

  let user;
  try {
    user = await getUser(token);
  } catch (err) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Session expired. Please sign in again.' }));
    return;
  }

  // ── 2. Read and validate request body ──
  let body = '';
  req.on('data', chunk => body += chunk);
  await new Promise(r => req.on('end', r));

  let payload;
  try { payload = JSON.parse(body); }
  catch {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Invalid request' }));
    return;
  }

  // Force safe settings — user can't override the model or exceed token limits
  payload.model      = 'claude-sonnet-4-20250514';
  payload.max_tokens = Math.min(payload.max_tokens || 1000, 4000);

  const bodyStr = JSON.stringify(payload);
  const isStream = payload.stream === true;

  console.log(`[${new Date().toISOString()}] user=${user.email} stream=${isStream} tokens=${payload.max_tokens}`);

  // ── 3. Forward to Anthropic ──
  const options = {
    hostname: 'api.anthropic.com',
    path:     '/v1/messages',
    method:   'POST',
    headers: {
      'Content-Type':      'application/json',
      'Content-Length':    Buffer.byteLength(bodyStr),
      'x-api-key':         ANTHROPIC_KEY,
      'anthropic-version': '2023-06-01',
    }
  };

  const proxyReq = https.request(options, proxyRes => {
    const headers = {
      'Access-Control-Allow-Origin': '*',
      'Content-Type': isStream ? 'text/event-stream' : 'application/json',
    };
    if (isStream) {
      headers['Cache-Control'] = 'no-cache';
      headers['Connection']    = 'keep-alive';
    }
    res.writeHead(proxyRes.statusCode, headers);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', err => {
    console.error('Proxy error:', err.message);
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Service error. Please try again.' }));
    }
  });

  proxyReq.write(bodyStr);
  proxyReq.end();
});

server.listen(PORT, () => {
  console.log(`FunnelHunter proxy → port ${PORT}`);
  console.log(`Anthropic key: ${ANTHROPIC_KEY.slice(0,16)}...`);
  console.log(`Supabase: ${SUPABASE_URL}`);
});
