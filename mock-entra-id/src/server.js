'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { URLSearchParams } = require('url');

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const TENANT_ID = process.env.TENANT_ID || 'mock-tenant-id';
const KEY_ID = 'mock-signing-key-1';

// ── Keys ────────────────────────────────────────────────────
const CERTS_DIR = path.join(__dirname, 'certs');

function ensureKeys() {
  if (!fs.existsSync(path.join(CERTS_DIR, 'private.pem'))) {
    fs.mkdirSync(CERTS_DIR, { recursive: true });
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    fs.writeFileSync(path.join(CERTS_DIR, 'private.pem'), privateKey);
    fs.writeFileSync(path.join(CERTS_DIR, 'public.pem'), publicKey);
    console.log('  Generated RSA key pair in ./certs/');
  }
}
ensureKeys();

const PRIVATE_KEY = fs.readFileSync(path.join(CERTS_DIR, 'private.pem'), 'utf8');
const PUBLIC_KEY  = fs.readFileSync(path.join(CERTS_DIR, 'public.pem'),  'utf8');

// ── In-memory stores ────────────────────────────────────────
const authCodes    = new Map();
const sessions     = new Map();
const refreshTokens = new Map();

// ── Users & Clients ─────────────────────────────────────────
const USERS = JSON.parse(process.env.MOCK_USERS || JSON.stringify([
  {
    id: 'user-001', username: 'alice@contoso.dev', password: 'Password1!',
    displayName: 'Alice Johnson', givenName: 'Alice', familyName: 'Johnson',
    email: 'alice@contoso.dev', roles: ['Admin', 'User'],
    groups: ['grp-admins', 'grp-users'], tenantId: TENANT_ID,
    jobTitle: 'Software Engineer', department: 'Engineering',
  },
  {
    id: 'user-002', username: 'bob@contoso.dev', password: 'Password2!',
    displayName: 'Bob Smith', givenName: 'Bob', familyName: 'Smith',
    email: 'bob@contoso.dev', roles: ['User'],
    groups: ['grp-users'], tenantId: TENANT_ID,
    jobTitle: 'Product Manager', department: 'Product',
  },
]));

const CLIENTS = JSON.parse(process.env.MOCK_CLIENTS || JSON.stringify([
  {
    clientId: 'my-dev-app',
    clientSecret: 'dev-secret-change-me',
    redirectUris: ['http://127.0.0.1:8080/callback', 'http://localhost:3001/callback'],
    allowedScopes: ['openid', 'profile', 'email', 'offline_access', 'User.Read'],
  },
]));

// ── JWT (zero-dep RS256) ────────────────────────────────────
function b64url(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function signJwt(payload, privateKeyPem, kid) {
  const header = { alg: 'RS256', typ: 'JWT', kid };
  const data = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(payload));
  const sig = crypto.createSign('RSA-SHA256').update(data).sign(privateKeyPem);
  return data + '.' + b64url(sig);
}

function verifyJwt(token, publicKeyPem) {
  const [h, p, s] = token.split('.');
  if (!h || !p || !s) throw new Error('malformed token');
  const data = h + '.' + p;
  const sig = Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  const ok = crypto.createVerify('RSA-SHA256').update(data).verify(publicKeyPem, sig);
  if (!ok) throw new Error('invalid signature');
  const claims = JSON.parse(Buffer.from(p, 'base64url').toString());
  if (claims.exp && claims.exp < Math.floor(Date.now() / 1000)) throw new Error('token expired');
  return claims;
}

// ── JWKS ────────────────────────────────────────────────────
function buildJwks() {
  const key = crypto.createPublicKey(PUBLIC_KEY);
  const { n, e } = key.export({ format: 'jwk' });
  return { keys: [{ kty: 'RSA', use: 'sig', kid: KEY_ID, alg: 'RS256', n, e }] };
}

// ── Token factory ───────────────────────────────────────────
function makeTokens(user, clientId, scope, nonce) {
  const now = Math.floor(Date.now() / 1000);
  const scopes = scope.split(' ');
  const base = {
    iss: `${BASE_URL}/${TENANT_ID}/v2.0`, sub: user.id, aud: clientId,
    iat: now, exp: now + 3600, tid: TENANT_ID, oid: user.id,
    preferred_username: user.username, name: user.displayName,
    email: user.email, roles: user.roles, groups: user.groups, ver: '2.0',
  };
  const idToken     = signJwt({ ...base, given_name: user.givenName, family_name: user.familyName, ...(nonce ? { nonce } : {}) }, PRIVATE_KEY, KEY_ID);
  const accessToken = signJwt({ ...base, scp: scopes.filter(s => s !== 'openid' && s !== 'offline_access').join(' '), appid: clientId }, PRIVATE_KEY, KEY_ID);

  const refreshToken = crypto.randomUUID();
  if (scopes.includes('offline_access')) {
    refreshTokens.set(refreshToken, { clientId, userId: user.id, scope });
  }
  return {
    token_type: 'Bearer', scope, expires_in: 3600,
    access_token: accessToken,
    id_token: scopes.includes('openid') ? idToken : undefined,
    refresh_token: scopes.includes('offline_access') ? refreshToken : undefined,
  };
}

// ── PKCE ────────────────────────────────────────────────────
function verifyPkce(verifier, challenge, method) {
  if (!challenge) return true;
  if (method === 'S256') return crypto.createHash('sha256').update(verifier).digest('base64url') === challenge;
  return verifier === challenge;
}

// ── Helpers ─────────────────────────────────────────────────
const findUser   = (u, p) => USERS.find(x => (x.username === u || x.email === u) && x.password === p);
const findById   = id     => USERS.find(x => x.id === id);
const findClient = id     => CLIENTS.find(x => x.clientId === id);

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    if (k) out[k.trim()] = decodeURIComponent(v.join('='));
  });
  return out;
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', d => { raw += d; if (raw.length > 1e6) reject(new Error('too large')); });
    req.on('end', () => {
      try {
        const ct = req.headers['content-type'] || '';
        if (ct.includes('application/json')) return resolve(JSON.parse(raw || '{}'));
        if (ct.includes('application/x-www-form-urlencoded')) {
          const p = new URLSearchParams(raw);
          const o = {};
          for (const [k, v] of p) o[k] = v;
          return resolve(o);
        }
        resolve({});
      } catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

function send(res, status, body, headers = {}) {
  const isObj = typeof body === 'object' && body !== null;
  const payload = isObj ? JSON.stringify(body) : body;
  res.writeHead(status, {
    'Content-Type': isObj ? 'application/json' : 'text/html; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Credentials': 'true',
    ...headers,
  });
  res.end(payload);
}

function redirect(res, url, cookies = []) {
  res.writeHead(302, { Location: url, 'Set-Cookie': cookies });
  res.end();
}

// ── Router ───────────────────────────────────────────────────
async function handle(req, res) {
  const url  = new URL(req.url, BASE_URL);
  const path_ = url.pathname;
  const q    = Object.fromEntries(url.searchParams);
  const method = req.method.toUpperCase();

  // CORS preflight
  if (method === 'OPTIONS') return send(res, 204, '');

  // ── Health ───────────────────────────────────────────────
  if (path_ === '/health') {
    return send(res, 200, { status: 'ok', tenant: TENANT_ID, users: USERS.length, clients: CLIENTS.length });
  }

  // ── Dev portal ───────────────────────────────────────────
  if (path_ === '/') return send(res, 200, renderPortal());

  // ── Discovery ────────────────────────────────────────────
  const discMatch = path_.match(/^\/([^/]+)\/v2\.0\/\.well-known\/openid-configuration$/);
  if (discMatch) {
    const tid = discMatch[1];
    return send(res, 200, {
      issuer: `${BASE_URL}/${tid}/v2.0`,
      authorization_endpoint:  `${BASE_URL}/${tid}/oauth2/v2.0/authorize`,
      token_endpoint:          `${BASE_URL}/${tid}/oauth2/v2.0/token`,
      end_session_endpoint:    `${BASE_URL}/${tid}/oauth2/v2.0/logout`,
      jwks_uri:                `${BASE_URL}/${tid}/discovery/v2.0/keys`,
      userinfo_endpoint:       `${BASE_URL}/oidc/userinfo`,
      response_types_supported: ['code', 'id_token', 'code id_token'],
      subject_types_supported: ['pairwise'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
      claims_supported: ['sub','iss','aud','exp','iat','name','email','given_name','family_name','preferred_username','roles','groups','tid','oid'],
      code_challenge_methods_supported: ['plain', 'S256'],
      grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    });
  }

  // common alias
  if (path_ === '/common/v2.0/.well-known/openid-configuration') {
    res.writeHead(302, { Location: `/${TENANT_ID}/v2.0/.well-known/openid-configuration` });
    return res.end();
  }

  // ── JWKS ─────────────────────────────────────────────────
  if (path_.match(/^\/[^/]+\/discovery\/v2\.0\/keys$/)) {
    return send(res, 200, buildJwks());
  }

  // ── Authorize GET (show login page or SSO redirect) ───────
  const authMatch = path_.match(/^\/([^/]+)\/oauth2\/v2\.0\/authorize$/);
  if (authMatch && method === 'GET') {
    const { client_id, redirect_uri, scope = 'openid', state, nonce,
            code_challenge, code_challenge_method, prompt } = q;
    const client = findClient(client_id);
    if (!client) return send(res, 400, '<h1>Unknown client_id</h1>');
    if (!client.redirectUris.includes(redirect_uri)) return send(res, 400, `<h1>redirect_uri not registered</h1>`);

    // SSO check
    const cookies = parseCookies(req);
    if (cookies.mock_session && sessions.has(cookies.mock_session) && prompt !== 'login') {
      const user = findById(sessions.get(cookies.mock_session));
      if (user) {
        const code = crypto.randomUUID();
        authCodes.set(code, { clientId: client_id, redirectUri: redirect_uri, scope, nonce,
          userId: user.id, codeChallenge: code_challenge, codeChallengeMethod: code_challenge_method,
          expiresAt: Date.now() + 60000 });
        const dest = new URL(redirect_uri);
        dest.searchParams.set('code', code);
        if (state) dest.searchParams.set('state', state);
        return redirect(res, dest.toString());
      }
    }

    const params = JSON.stringify({ client_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method });
    return send(res, 200, renderLoginPage(params, client_id));
  }

  // ── Authorize POST (login form submit) ────────────────────
  if (authMatch && method === 'POST') {
    const body = await parseBody(req);
    const params = JSON.parse(body.params || '{}');
    const user = findUser(body.username, body.password);
    if (!user) {
      return send(res, 200, renderLoginPage(body.params, params.client_id, 'Invalid username or password.'));
    }
    const sessionId = crypto.randomUUID();
    sessions.set(sessionId, user.id);
    const code = crypto.randomUUID();
    authCodes.set(code, {
      clientId: params.client_id, redirectUri: params.redirect_uri,
      scope: params.scope || 'openid', nonce: params.nonce, userId: user.id,
      codeChallenge: params.code_challenge, codeChallengeMethod: params.code_challenge_method,
      expiresAt: Date.now() + 60000,
    });
    const dest = new URL(params.redirect_uri);
    dest.searchParams.set('code', code);
    if (params.state) dest.searchParams.set('state', params.state);
    return redirect(res, dest.toString(), [`mock_session=${sessionId}; HttpOnly; Path=/; Max-Age=86400`]);
  }

  // ── Token endpoint ────────────────────────────────────────
  const tokenMatch = path_.match(/^\/([^/]+)\/oauth2\/v2\.0\/token$/);
  if (tokenMatch && method === 'POST') {
    const body = await parseBody(req);
    let { client_id, client_secret } = body;

    // Basic auth header
    const auth = req.headers.authorization || '';
    if (auth.startsWith('Basic ')) {
      const decoded = Buffer.from(auth.slice(6), 'base64').toString();
      [client_id, client_secret] = decoded.split(':');
    }

    const { grant_type, code, redirect_uri, refresh_token, scope = 'openid', code_verifier } = body;

    if (grant_type === 'authorization_code') {
      const entry = authCodes.get(code);
      if (!entry) return send(res, 400, { error: 'invalid_grant', error_description: 'Code not found' });
      if (Date.now() > entry.expiresAt) { authCodes.delete(code); return send(res, 400, { error: 'invalid_grant', error_description: 'Code expired' }); }
      if (entry.clientId !== client_id) return send(res, 400, { error: 'invalid_client' });
      if (entry.redirectUri !== redirect_uri) return send(res, 400, { error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
      if (!verifyPkce(code_verifier, entry.codeChallenge, entry.codeChallengeMethod)) return send(res, 400, { error: 'invalid_grant', error_description: 'PKCE verification failed' });
      authCodes.delete(code);
      return send(res, 200, makeTokens(findById(entry.userId), client_id, entry.scope, entry.nonce));
    }

    if (grant_type === 'refresh_token') {
      const entry = refreshTokens.get(refresh_token);
      if (!entry || entry.clientId !== client_id) return send(res, 400, { error: 'invalid_grant' });
      refreshTokens.delete(refresh_token);
      return send(res, 200, makeTokens(findById(entry.userId), client_id, scope || entry.scope));
    }

    if (grant_type === 'client_credentials') {
      const client = findClient(client_id);
      if (!client || client.clientSecret !== client_secret) return send(res, 401, { error: 'invalid_client' });
      const now = Math.floor(Date.now() / 1000);
      const token = signJwt({ iss: `${BASE_URL}/${TENANT_ID}/v2.0`, sub: client_id, aud: client_id,
        iat: now, exp: now + 3600, tid: TENANT_ID, appid: client_id, ver: '2.0', roles: ['Service'] }, PRIVATE_KEY, KEY_ID);
      return send(res, 200, { token_type: 'Bearer', expires_in: 3600, access_token: token });
    }

    return send(res, 400, { error: 'unsupported_grant_type' });
  }

  // ── UserInfo ──────────────────────────────────────────────
  if (path_ === '/oidc/userinfo') {
    const bearer = (req.headers.authorization || '').replace('Bearer ', '');
    try {
      const payload = verifyJwt(bearer, PUBLIC_KEY);
      const user = findById(payload.sub);
      if (!user) return send(res, 404, { error: 'user_not_found' });
      return send(res, 200, { sub: user.id, name: user.displayName, given_name: user.givenName,
        family_name: user.familyName, email: user.email, preferred_username: user.username,
        roles: user.roles, groups: user.groups, job_title: user.jobTitle, department: user.department });
    } catch { return send(res, 401, { error: 'invalid_token' }); }
  }

  // ── Graph /me ─────────────────────────────────────────────
  if (path_ === '/v1.0/me') {
    const bearer = (req.headers.authorization || '').replace('Bearer ', '');
    try {
      const payload = verifyJwt(bearer, PUBLIC_KEY);
      const user = findById(payload.sub);
      if (!user) return send(res, 404, { error: { code: 'Request_ResourceNotFound' } });
      return send(res, 200, { id: user.id, displayName: user.displayName, givenName: user.givenName,
        surname: user.familyName, mail: user.email, userPrincipalName: user.username,
        jobTitle: user.jobTitle, department: user.department });
    } catch { return send(res, 401, { error: 'unauthorized' }); }
  }

  // ── Graph /me/memberOf ────────────────────────────────────
  if (path_ === '/v1.0/me/memberOf') {
    const bearer = (req.headers.authorization || '').replace('Bearer ', '');
    try {
      const payload = verifyJwt(bearer, PUBLIC_KEY);
      const user = findById(payload.sub);
      if (!user) return send(res, 404, { error: { code: 'Request_ResourceNotFound' } });
      return send(res, 200, { value: user.groups.map(g => ({ id: g, displayName: g, '@odata.type': '#microsoft.graph.group' })) });
    } catch { return send(res, 401, { error: 'unauthorized' }); }
  }

  // ── Graph /users ──────────────────────────────────────────
  if (path_ === '/v1.0/users') {
    return send(res, 200, { value: USERS.map(u => ({ id: u.id, displayName: u.displayName, mail: u.email, userPrincipalName: u.username })) });
  }

  // ── Logout ────────────────────────────────────────────────
  const logoutMatch = path_.match(/^\/([^/]+)\/oauth2\/v2\.0\/logout$/);
  if (logoutMatch) {
    const cookies = parseCookies(req);
    if (cookies.mock_session) sessions.delete(cookies.mock_session);
    const post = q.post_logout_redirect_uri;
    if (post) return redirect(res, post, ['mock_session=; HttpOnly; Path=/; Max-Age=0']);
    return send(res, 200, `<html><body style="font-family:sans-serif;padding:2rem"><h2>Signed out</h2><p>You have been signed out of Mock Entra ID.</p></body></html>`,
      { 'Set-Cookie': 'mock_session=; HttpOnly; Path=/; Max-Age=0' });
  }

  // ── Admin: list users ─────────────────────────────────────
  if (path_ === '/admin/users' && method === 'GET') {
    return send(res, 200, USERS.map(u => ({ ...u, password: '***' })));
  }

  // ── Admin: add user ───────────────────────────────────────
  if (path_ === '/admin/users' && method === 'POST') {
    const body = await parseBody(req);
    const u = { id: crypto.randomUUID(), tenantId: TENANT_ID, roles: ['User'], groups: ['grp-users'], ...body };
    USERS.push(u);
    return send(res, 201, { ...u, password: '***' });
  }

  // ── Admin: delete user ────────────────────────────────────
  const delMatch = path_.match(/^\/admin\/users\/([^/]+)$/);
  if (delMatch && method === 'DELETE') {
    const idx = USERS.findIndex(u => u.id === delMatch[1]);
    if (idx === -1) return send(res, 404, { error: 'not_found' });
    USERS.splice(idx, 1);
    return send(res, 204, '');
  }

  return send(res, 404, { error: 'not_found', path: path_ });
}

// ── HTML templates ───────────────────────────────────────────
function renderLoginPage(paramsJson, clientId, error = '') {
  const client = findClient(clientId) || { clientId };
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in — Mock Entra ID</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',sans-serif;background:#f3f2f1;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh}.card{background:#fff;border-radius:4px;padding:44px 44px 32px;width:440px;max-width:100vw;box-shadow:0 2px 6px rgba(0,0,0,.1)}.ms-logo{display:flex;align-items:center;gap:8px;margin-bottom:28px}.ms-squares{display:grid;grid-template-columns:1fr 1fr;gap:2px;width:20px;height:20px}.sq1{background:#f25022}.sq2{background:#7fba00}.sq3{background:#00a4ef}.sq4{background:#ffb900}.ms-logo span{font-size:20px;font-weight:300;color:#1b1b1b}h1{font-size:24px;font-weight:600;color:#1b1b1b;margin-bottom:4px}.subtitle{font-size:13px;color:#666;margin-bottom:24px}label{display:block;font-size:13px;color:#1b1b1b;margin-bottom:4px}input[type=text],input[type=email],input[type=password]{display:block;width:100%;border:1px solid #8a8886;border-radius:2px;padding:7px 10px;font-size:14px;margin-bottom:16px;outline:none;color:#1b1b1b}input:focus{border-color:#0078d4;box-shadow:0 0 0 1px #0078d4}.error{background:#fde7e9;color:#a4262c;border:1px solid #f1707b;border-radius:2px;padding:8px 12px;font-size:13px;margin-bottom:16px}.link{font-size:13px;color:#0078d4;text-decoration:none}.link:hover{text-decoration:underline}.row{display:flex;justify-content:space-between;align-items:center;margin-top:24px}button{background:#0078d4;color:#fff;border:none;border-radius:2px;padding:8px 20px;font-size:14px;font-weight:600;cursor:pointer}button:hover{background:#106ebe}.badge{display:inline-block;background:#e8e8e8;border-radius:2px;padding:2px 8px;font-size:11px;color:#444;margin-bottom:8px}.footer{margin-top:16px;font-size:11px;color:#999;display:flex;gap:12px}</style></head>
<body><div class="card">
  <div class="ms-logo"><div class="ms-squares"><div class="sq1"></div><div class="sq2"></div><div class="sq3"></div><div class="sq4"></div></div><span>Microsoft</span></div>
  <div class="badge">Mock Entra ID · Dev</div>
  <h1>Sign in</h1>
  <p class="subtitle">to continue to <strong>${client.clientId}</strong></p>
  ${error ? `<div class="error">${error}</div>` : ''}
  <form method="POST">
    <input type="hidden" name="params" value='${paramsJson.replace(/'/g, "&#39;")}'>
    <label>Email or username</label>
    <input type="email" name="username" placeholder="user@contoso.dev" autocomplete="username" required>
    <label>Password</label>
    <input type="password" name="password" placeholder="Password" autocomplete="current-password" required>
    <div class="row"><a href="/" class="link">Forgot password?</a><button type="submit">Sign in</button></div>
  </form>
  <div style="margin-top:20px;padding-top:16px;border-top:1px solid #eee">
    <p style="font-size:12px;color:#888;margin-bottom:8px">Test accounts</p>
    ${USERS.map(u => `<p style="font-size:12px;color:#444">${u.username} / ${u.password}</p>`).join('')}
  </div>
</div>
<div class="footer"><a href="/health" class="link">Health</a><a href="/" class="link">Dev portal</a></div>
</body></html>`;
}

function renderPortal() {
  const discovery = `${BASE_URL}/${TENANT_ID}/v2.0/.well-known/openid-configuration`;
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mock Entra ID — Dev Portal</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',sans-serif;background:#f3f2f1;padding:32px 16px}.wrap{max-width:800px;margin:0 auto}.ms-logo{display:flex;align-items:center;gap:8px;margin-bottom:8px}.ms-squares{display:grid;grid-template-columns:1fr 1fr;gap:2px;width:20px;height:20px}.sq1{background:#f25022}.sq2{background:#7fba00}.sq3{background:#00a4ef}.sq4{background:#ffb900}.ms-logo span{font-size:20px;font-weight:300}.badge{display:inline-block;background:#fff3cd;border:1px solid #ffc107;border-radius:2px;padding:2px 10px;font-size:12px;color:#856404;margin-bottom:24px}h1{font-size:28px;font-weight:600;margin-bottom:4px}h2{font-size:16px;font-weight:600;margin-bottom:12px;color:#1b1b1b}.card{background:#fff;border-radius:4px;padding:24px;margin-bottom:20px;border:1px solid #e1dfdd}table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:8px 10px;border-bottom:1px solid #f3f2f1;text-align:left}th{font-weight:600;color:#555}code{font-family:Consolas,monospace;font-size:12px;background:#f3f2f1;padding:2px 6px;border-radius:2px;word-break:break-all}.tag{display:inline-block;background:#e8f4fd;color:#0078d4;border-radius:2px;padding:1px 6px;font-size:11px;margin:1px}</style></head>
<body><div class="wrap">
  <div class="ms-logo"><div class="ms-squares"><div class="sq1"></div><div class="sq2"></div><div class="sq3"></div><div class="sq4"></div></div><span>Microsoft Entra ID</span></div>
  <div class="badge">&#9888; Mock — Development only</div>
  <h1>Dev Portal</h1>
  <p style="color:#666;font-size:14px;margin-bottom:24px">Local OAuth 2.0 / OIDC identity provider emulating Microsoft Entra ID</p>
  <div class="card"><h2>Configuration</h2><table>
    <tr><th>Setting</th><th>Value</th></tr>
    <tr><td>Tenant ID</td><td><code>${TENANT_ID}</code></td></tr>
    <tr><td>Base URL</td><td><code>${BASE_URL}</code></td></tr>
    <tr><td>Discovery</td><td><code><a href="${discovery}">${discovery}</a></code></td></tr>
    <tr><td>JWKS</td><td><code><a href="${BASE_URL}/${TENANT_ID}/discovery/v2.0/keys">${BASE_URL}/${TENANT_ID}/discovery/v2.0/keys</a></code></td></tr>
  </table></div>
  <div class="card"><h2>Endpoints</h2><table>
    <tr><th>Endpoint</th><th>Path</th></tr>
    <tr><td>Authorize</td><td><code>GET /${TENANT_ID}/oauth2/v2.0/authorize</code></td></tr>
    <tr><td>Token</td><td><code>POST /${TENANT_ID}/oauth2/v2.0/token</code></td></tr>
    <tr><td>Logout</td><td><code>GET /${TENANT_ID}/oauth2/v2.0/logout</code></td></tr>
    <tr><td>UserInfo</td><td><code>GET /oidc/userinfo</code></td></tr>
    <tr><td>Graph /me</td><td><code>GET /v1.0/me</code></td></tr>
    <tr><td>Graph /users</td><td><code>GET /v1.0/users</code></td></tr>
  </table></div>
  <div class="card"><h2>Registered clients</h2><table>
    <tr><th>Client ID</th><th>Secret</th><th>Redirect URIs</th></tr>
    ${CLIENTS.map(c => `<tr><td><code>${c.clientId}</code></td><td><code>${c.clientSecret}</code></td><td>${c.redirectUris.map(u => `<span class="tag">${u}</span>`).join('')}</td></tr>`).join('')}
  </table></div>
  <div class="card"><h2>Test users</h2><table>
    <tr><th>Username</th><th>Password</th><th>Roles</th><th>Groups</th></tr>
    ${USERS.map(u => `<tr><td>${u.username}</td><td><code>${u.password}</code></td><td>${u.roles.map(r => `<span class="tag">${r}</span>`).join('')}</td><td>${u.groups.map(g => `<span class="tag">${g}</span>`).join('')}</td></tr>`).join('')}
  </table></div>
  <div class="card"><h2>Admin API</h2><table>
    <tr><th>Method</th><th>Path</th><th>Description</th></tr>
    <tr><td>GET</td><td><code>/admin/users</code></td><td>List all users</td></tr>
    <tr><td>POST</td><td><code>/admin/users</code></td><td>Add a user (JSON body)</td></tr>
    <tr><td>DELETE</td><td><code>/admin/users/:id</code></td><td>Remove a user</td></tr>
    <tr><td>GET</td><td><code>/health</code></td><td>Health check</td></tr>
  </table></div>
</div></body></html>`;
}

// ── Start ────────────────────────────────────────────────────
http.createServer(async (req, res) => {
  try { await handle(req, res); }
  catch (err) { console.error(err); send(res, 500, { error: 'internal_server_error' }); }
}).listen(PORT, () => {
  console.log(`\n Mock Entra ID (zero-dep) running at ${BASE_URL}`);
  console.log(`   Tenant:    ${TENANT_ID}`);
  console.log(`   Discovery: ${BASE_URL}/${TENANT_ID}/v2.0/.well-known/openid-configuration`);
  console.log(`   Portal:    ${BASE_URL}/\n`);
});
