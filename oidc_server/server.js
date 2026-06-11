'use strict';

const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const TENANT_ID = process.env.TENANT_ID || 'mock-tenant-id';
const KEY_ID = 'mock-signing-key-1';

// Load signing keys
const PRIVATE_KEY = fs.readFileSync(path.join(__dirname, '../certs/private.pem'), 'utf8');
const PUBLIC_KEY = fs.readFileSync(path.join(__dirname, '../certs/public.pem'), 'utf8');

// In-memory stores (swap for Redis/DB in staging)
const authCodes = new Map();     // code -> { clientId, redirectUri, scope, nonce, userId, codeChallenge, codeChallengeMethod }
const sessions = new Map();      // sessionId -> userId
const refreshTokens = new Map(); // token -> { clientId, userId, scope }

// ──────────────────────────────────────────────
// User directory — edit or replace with env/DB
// ──────────────────────────────────────────────
const USERS = JSON.parse(process.env.MOCK_USERS || JSON.stringify([
  {
    id: 'user-001',
    username: 'alice@contoso.dev',
    password: 'Password1!',
    displayName: 'Alice Johnson',
    givenName: 'Alice',
    familyName: 'Johnson',
    email: 'alice@contoso.dev',
    roles: ['Admin', 'User'],
    groups: ['grp-admins', 'grp-users'],
    tenantId: TENANT_ID,
    jobTitle: 'Software Engineer',
    department: 'Engineering',
  },
  {
    id: 'user-002',
    username: 'bob@contoso.dev',
    password: 'Password2!',
    displayName: 'Bob Smith',
    givenName: 'Bob',
    familyName: 'Smith',
    email: 'bob@contoso.dev',
    roles: ['User'],
    groups: ['grp-users'],
    tenantId: TENANT_ID,
    jobTitle: 'Product Manager',
    department: 'Product',
  },
]));

// ──────────────────────────────────────────────
// Registered clients — add your app(s) here
// ──────────────────────────────────────────────
const CLIENTS = JSON.parse(process.env.MOCK_CLIENTS || JSON.stringify([
  {
    clientId: 'my-dev-app',
    clientSecret: 'dev-secret-change-me',
    redirectUris: ['http://localhost:8080/callback', 'http://localhost:3001/callback'],
    allowedScopes: ['openid', 'profile', 'email', 'offline_access', 'User.Read'],
  },
]));

// ──────────────────────────────────────────────
// JWKS helpers
// ──────────────────────────────────────────────
function buildJwks() {
  const pubDer = Buffer.from(
    PUBLIC_KEY.replace(/-----[A-Z ]+-----\n?/g, '').replace(/\n/g, ''),
    'base64'
  );
  // Parse SPKI DER to extract modulus + exponent
  const key = crypto.createPublicKey(PUBLIC_KEY);
  const { n, e } = key.export({ format: 'jwk' });
  return {
    keys: [{
      kty: 'RSA', use: 'sig', kid: KEY_ID,
      alg: 'RS256', n, e,
    }],
  };
}

// ──────────────────────────────────────────────
// Token factory
// ──────────────────────────────────────────────
function makeTokens(user, clientId, scope, nonce) {
  const now = Math.floor(Date.now() / 1000);
  const scopes = scope.split(' ');

  const idTokenClaims = {
    iss: `${BASE_URL}/${TENANT_ID}/v2.0`,
    sub: user.id,
    aud: clientId,
    iat: now,
    exp: now + 3600,
    tid: TENANT_ID,
    oid: user.id,
    preferred_username: user.username,
    name: user.displayName,
    email: user.email,
    given_name: user.givenName,
    family_name: user.familyName,
    roles: user.roles,
    groups: user.groups,
    ver: '2.0',
    ...(nonce ? { nonce } : {}),
  };

  const accessTokenClaims = {
    iss: `${BASE_URL}/${TENANT_ID}/v2.0`,
    sub: user.id,
    aud: clientId,
    iat: now,
    exp: now + 3600,
    tid: TENANT_ID,
    oid: user.id,
    preferred_username: user.username,
    name: user.displayName,
    email: user.email,
    roles: user.roles,
    groups: user.groups,
    scp: scopes.filter(s => s !== 'openid' && s !== 'offline_access').join(' '),
    ver: '2.0',
    appid: clientId,
    idp: `${BASE_URL}/${TENANT_ID}`,
  };

  const signOpts = { algorithm: 'RS256', keyid: KEY_ID };
  const idToken = jwt.sign(idTokenClaims, PRIVATE_KEY, signOpts);
  const accessToken = jwt.sign(accessTokenClaims, PRIVATE_KEY, signOpts);

  const refreshToken = uuidv4();
  if (scopes.includes('offline_access')) {
    refreshTokens.set(refreshToken, { clientId, userId: user.id, scope });
  }

  return {
    token_type: 'Bearer',
    scope,
    expires_in: 3600,
    access_token: accessToken,
    id_token: scopes.includes('openid') ? idToken : undefined,
    refresh_token: scopes.includes('offline_access') ? refreshToken : undefined,
  };
}

// ──────────────────────────────────────────────
// PKCE helpers
// ──────────────────────────────────────────────
function verifyCodeChallenge(verifier, challenge, method) {
  if (!challenge) return true; // PKCE not required in dev
  if (method === 'S256') {
    const hash = crypto.createHash('sha256').update(verifier).digest('base64url');
    return hash === challenge;
  }
  return verifier === challenge; // plain
}

// ──────────────────────────────────────────────
// Middleware
// ──────────────────────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

function findUser(username, password) {
  return USERS.find(u =>
    (u.username === username || u.email === username) && u.password === password
  );
}
function findUserById(id) { return USERS.find(u => u.id === id); }
function findClient(clientId) { return CLIENTS.find(c => c.clientId === clientId); }

// ──────────────────────────────────────────────
// OIDC Discovery
// ──────────────────────────────────────────────
app.get('/:tenantId/v2.0/.well-known/openid-configuration', (req, res) => {
  const base = `${BASE_URL}/${req.params.tenantId}/v2.0`;
  res.json({
    issuer: base,
    authorization_endpoint: `${BASE_URL}/${req.params.tenantId}/oauth2/v2.0/authorize`,
    token_endpoint: `${BASE_URL}/${req.params.tenantId}/oauth2/v2.0/token`,
    end_session_endpoint: `${BASE_URL}/${req.params.tenantId}/oauth2/v2.0/logout`,
    jwks_uri: `${BASE_URL}/${req.params.tenantId}/discovery/v2.0/keys`,
    userinfo_endpoint: `${BASE_URL}/oidc/userinfo`,
    response_types_supported: ['code', 'id_token', 'code id_token'],
    subject_types_supported: ['pairwise'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'name', 'email',
      'given_name', 'family_name', 'preferred_username', 'roles', 'groups', 'tid', 'oid'],
    code_challenge_methods_supported: ['plain', 'S256'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
  });
});

// Also serve at the common /common endpoint
app.get('/common/v2.0/.well-known/openid-configuration', (req, res) => {
  res.redirect(`/${TENANT_ID}/v2.0/.well-known/openid-configuration`);
});

// ──────────────────────────────────────────────
// JWKS
// ──────────────────────────────────────────────
app.get('/:tenantId/discovery/v2.0/keys', (req, res) => {
  res.json(buildJwks());
});

// ──────────────────────────────────────────────
// Authorization endpoint — serves login UI
// ──────────────────────────────────────────────
app.get('/:tenantId/oauth2/v2.0/authorize', (req, res) => {
  const {
    client_id, redirect_uri, response_type, scope = 'openid',
    state, nonce, code_challenge, code_challenge_method, prompt,
  } = req.query;

  const client = findClient(client_id);
  if (!client) return res.status(400).send('Unknown client_id');
  if (!client.redirectUris.includes(redirect_uri)) {
    return res.status(400).send(`redirect_uri not registered: ${redirect_uri}`);
  }

  // Check for existing session (SSO)
  const sessionId = req.cookies['mock_session'];
  if (sessionId && sessions.has(sessionId) && prompt !== 'login') {
    const userId = sessions.get(sessionId);
    const user = findUserById(userId);
    if (user) {
      const code = uuidv4();
      authCodes.set(code, {
        clientId: client_id, redirectUri: redirect_uri, scope, nonce,
        userId: user.id, codeChallenge: code_challenge,
        codeChallengeMethod: code_challenge_method, expiresAt: Date.now() + 60000,
      });
      const url = new URL(redirect_uri);
      url.searchParams.set('code', code);
      if (state) url.searchParams.set('state', state);
      return res.redirect(url.toString());
    }
  }

  // Render login page — embed params as JSON for the form handler
  const params = JSON.stringify({
    client_id, redirect_uri, scope, state, nonce,
    code_challenge, code_challenge_method,
  });
  res.send(renderLoginPage(params, client_id));
});

// Handle login form POST
app.post('/:tenantId/oauth2/v2.0/authorize', (req, res) => {
  const { username, password, params: paramsJson } = req.body;
  const params = JSON.parse(paramsJson || '{}');

  const user = findUser(username, password);
  if (!user) {
    return res.send(renderLoginPage(paramsJson, params.client_id, 'Invalid username or password.'));
  }

  // Set session cookie
  const sessionId = uuidv4();
  sessions.set(sessionId, user.id);
  res.cookie('mock_session', sessionId, { httpOnly: true, maxAge: 86400000 });

  // Issue auth code
  const code = uuidv4();
  authCodes.set(code, {
    clientId: params.client_id,
    redirectUri: params.redirect_uri,
    scope: params.scope || 'openid',
    nonce: params.nonce,
    userId: user.id,
    codeChallenge: params.code_challenge,
    codeChallengeMethod: params.code_challenge_method,
    expiresAt: Date.now() + 60000,
  });

  const url = new URL(params.redirect_uri);
  url.searchParams.set('code', code);
  if (params.state) url.searchParams.set('state', params.state);
  res.redirect(url.toString());
});

// ──────────────────────────────────────────────
// Token endpoint
// ──────────────────────────────────────────────
app.post('/:tenantId/oauth2/v2.0/token', (req, res) => {
  // Support Basic auth header for client credentials
  let { client_id, client_secret } = req.body;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Basic ')) {
    const decoded = Buffer.from(authHeader.slice(6), 'base64').toString();
    [client_id, client_secret] = decoded.split(':');
  }

  const { grant_type, code, redirect_uri, refresh_token,
    scope, code_verifier } = req.body;

  // ── Authorization Code ──
  if (grant_type === 'authorization_code') {
    const entry = authCodes.get(code);
    if (!entry) return res.status(400).json({ error: 'invalid_grant', error_description: 'Code not found or expired' });
    if (Date.now() > entry.expiresAt) {
      authCodes.delete(code);
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Code expired' });
    }
    if (entry.clientId !== client_id) return res.status(400).json({ error: 'invalid_client' });
    if (entry.redirectUri !== redirect_uri) return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
    if (!verifyCodeChallenge(code_verifier, entry.codeChallenge, entry.codeChallengeMethod)) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
    }
    authCodes.delete(code);
    const user = findUserById(entry.userId);
    return res.json(makeTokens(user, client_id, entry.scope, entry.nonce));
  }

  // ── Refresh Token ──
  if (grant_type === 'refresh_token') {
    const entry = refreshTokens.get(refresh_token);
    if (!entry || entry.clientId !== client_id) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    refreshTokens.delete(refresh_token);
    const user = findUserById(entry.userId);
    return res.json(makeTokens(user, client_id, scope || entry.scope));
  }

  // ── Client Credentials ──
  if (grant_type === 'client_credentials') {
    const client = findClient(client_id);
    if (!client || client.clientSecret !== client_secret) {
      return res.status(401).json({ error: 'invalid_client' });
    }
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: `${BASE_URL}/${TENANT_ID}/v2.0`,
      sub: client_id,
      aud: client_id,
      iat: now, exp: now + 3600,
      tid: TENANT_ID,
      appid: client_id,
      ver: '2.0',
      roles: ['Service'],
    };
    const accessToken = jwt.sign(claims, PRIVATE_KEY, { algorithm: 'RS256', keyid: KEY_ID });
    return res.json({ token_type: 'Bearer', expires_in: 3600, access_token: accessToken });
  }

  res.status(400).json({ error: 'unsupported_grant_type' });
});

// ──────────────────────────────────────────────
// UserInfo endpoint
// ──────────────────────────────────────────────
app.get('/oidc/userinfo', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'unauthorized' });
  try {
    const payload = jwt.verify(auth.slice(7), PUBLIC_KEY, { algorithms: ['RS256'] });
    const user = findUserById(payload.sub);
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    res.json({
      sub: user.id, name: user.displayName,
      given_name: user.givenName, family_name: user.familyName,
      email: user.email, preferred_username: user.username,
      roles: user.roles, groups: user.groups,
      job_title: user.jobTitle, department: user.department,
    });
  } catch {
    res.status(401).json({ error: 'invalid_token' });
  }
});

// ──────────────────────────────────────────────
// Microsoft Graph stubs
// ──────────────────────────────────────────────
function requireBearer(req, res) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) { res.status(401).json({ error: 'unauthorized' }); return null; }
  try {
    return jwt.verify(auth.slice(7), PUBLIC_KEY, { algorithms: ['RS256'] });
  } catch { res.status(401).json({ error: 'invalid_token' }); return null; }
}

app.get('/v1.0/me', (req, res) => {
  const payload = requireBearer(req, res);
  if (!payload) return;
  const user = findUserById(payload.sub);
  if (!user) return res.status(404).json({ error: { code: 'Request_ResourceNotFound' } });
  res.json({
    '@odata.context': `${BASE_URL}/v1.0/$metadata#users/$entity`,
    id: user.id, displayName: user.displayName,
    givenName: user.givenName, surname: user.familyName,
    mail: user.email, userPrincipalName: user.username,
    jobTitle: user.jobTitle, department: user.department,
  });
});

app.get('/v1.0/me/memberOf', (req, res) => {
  const payload = requireBearer(req, res);
  if (!payload) return;
  const user = findUserById(payload.sub);
  if (!user) return res.status(404).json({ error: { code: 'Request_ResourceNotFound' } });
  res.json({
    '@odata.context': `${BASE_URL}/v1.0/$metadata#directoryObjects`,
    value: user.groups.map(g => ({ id: g, displayName: g, '@odata.type': '#microsoft.graph.group' })),
  });
});

app.get('/v1.0/users', (req, res) => {
  requireBearer(req, res);
  res.json({
    '@odata.context': `${BASE_URL}/v1.0/$metadata#users`,
    value: USERS.map(u => ({
      id: u.id, displayName: u.displayName, mail: u.email,
      userPrincipalName: u.username, jobTitle: u.jobTitle,
    })),
  });
});

// ──────────────────────────────────────────────
// Logout
// ──────────────────────────────────────────────
app.get('/:tenantId/oauth2/v2.0/logout', (req, res) => {
  const sessionId = req.cookies['mock_session'];
  if (sessionId) sessions.delete(sessionId);
  res.clearCookie('mock_session');
  const postLogout = req.query.post_logout_redirect_uri;
  if (postLogout) return res.redirect(postLogout);
  res.send(`<html><body style="font-family:sans-serif;padding:2rem">
    <h2>Signed out</h2><p>You have been signed out of Mock Entra ID.</p>
  </body></html>`);
});

// ──────────────────────────────────────────────
// Admin API — list users, add user at runtime
// ──────────────────────────────────────────────
app.get('/admin/users', (req, res) => {
  res.json(USERS.map(u => ({ ...u, password: '***' })));
});

app.post('/admin/users', (req, res) => {
  const u = { id: uuidv4(), tenantId: TENANT_ID, roles: ['User'], groups: ['grp-users'], ...req.body };
  USERS.push(u);
  res.status(201).json({ ...u, password: '***' });
});

app.delete('/admin/users/:id', (req, res) => {
  const idx = USERS.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'not_found' });
  USERS.splice(idx, 1);
  res.status(204).end();
});

// ──────────────────────────────────────────────
// Dev portal (health + config summary)
// ──────────────────────────────────────────────
app.get('/', (req, res) => res.send(renderPortal()));
app.get('/health', (req, res) => res.json({ status: 'ok', tenant: TENANT_ID, users: USERS.length, clients: CLIENTS.length }));

// ──────────────────────────────────────────────
// HTML templates
// ──────────────────────────────────────────────
function renderLoginPage(paramsJson, clientId, error = '') {
  const client = findClient(clientId) || { clientId };
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — Mock Entra ID</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',sans-serif;background:#f3f2f1;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh}
  .card{background:#fff;border-radius:4px;padding:44px 44px 32px;width:440px;max-width:100vw;box-shadow:0 2px 6px rgba(0,0,0,.1)}
  .ms-logo{display:flex;align-items:center;gap:8px;margin-bottom:28px}
  .ms-squares{display:grid;grid-template-columns:1fr 1fr;gap:2px;width:20px;height:20px}
  .sq1{background:#f25022}.sq2{background:#7fba00}.sq3{background:#00a4ef}.sq4{background:#ffb900}
  .ms-logo span{font-size:20px;font-weight:300;color:#1b1b1b}
  h1{font-size:24px;font-weight:600;color:#1b1b1b;margin-bottom:4px}
  .subtitle{font-size:13px;color:#666;margin-bottom:24px}
  label{display:block;font-size:13px;color:#1b1b1b;margin-bottom:4px}
  input[type=text],input[type=email],input[type=password]{
    display:block;width:100%;border:1px solid #8a8886;border-radius:2px;
    padding:7px 10px;font-size:14px;margin-bottom:16px;outline:none;color:#1b1b1b
  }
  input:focus{border-color:#0078d4;box-shadow:0 0 0 1px #0078d4}
  .error{background:#fde7e9;color:#a4262c;border:1px solid #f1707b;border-radius:2px;padding:8px 12px;font-size:13px;margin-bottom:16px}
  .link{font-size:13px;color:#0078d4;text-decoration:none}.link:hover{text-decoration:underline}
  .row{display:flex;justify-content:space-between;align-items:center;margin-top:24px}
  button{background:#0078d4;color:#fff;border:none;border-radius:2px;padding:8px 20px;font-size:14px;font-weight:600;cursor:pointer}
  button:hover{background:#106ebe}
  .badge{display:inline-block;background:#e8e8e8;border-radius:2px;padding:2px 8px;font-size:11px;color:#444;margin-bottom:8px}
  .footer{margin-top:16px;font-size:11px;color:#999;display:flex;gap:12px}
</style>
</head>
<body>
<div class="card">
  <div class="ms-logo">
    <div class="ms-squares"><div class="sq1"></div><div class="sq2"></div><div class="sq3"></div><div class="sq4"></div></div>
    <span>Microsoft</span>
  </div>
  <div class="badge">Mock Entra ID · Dev</div>
  <h1>Sign in</h1>
  <p class="subtitle">to continue to <strong>${client.clientId}</strong></p>
  ${error ? `<div class="error">${error}</div>` : ''}
  <form method="POST">
    <input type="hidden" name="params" value='${paramsJson}'>
    <label>Email or username</label>
    <input type="email" name="username" placeholder="user@contoso.dev" autocomplete="username" required>
    <label>Password</label>
    <input type="password" name="password" placeholder="Password" autocomplete="current-password" required>
    <div class="row">
      <a href="/" class="link">Forgot password?</a>
      <button type="submit">Sign in</button>
    </div>
  </form>
  <div style="margin-top:20px;padding-top:16px;border-top:1px solid #eee">
    <p style="font-size:12px;color:#888;margin-bottom:8px">Test accounts</p>
    ${USERS.map(u => `<p style="font-size:12px;color:#444">${u.username} / ${u.password}</p>`).join('')}
  </div>
</div>
<div class="footer">
  <a href="/health" class="link">Health</a>
  <a href="/" class="link">Dev portal</a>
</div>
</body></html>`;
}

function renderPortal() {
  const discovery = `${BASE_URL}/${TENANT_ID}/v2.0/.well-known/openid-configuration`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mock Entra ID — Dev Portal</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',sans-serif;background:#f3f2f1;padding:32px 16px}
  .wrap{max-width:800px;margin:0 auto}
  .ms-logo{display:flex;align-items:center;gap:8px;margin-bottom:8px}
  .ms-squares{display:grid;grid-template-columns:1fr 1fr;gap:2px;width:20px;height:20px}
  .sq1{background:#f25022}.sq2{background:#7fba00}.sq3{background:#00a4ef}.sq4{background:#ffb900}
  .ms-logo span{font-size:20px;font-weight:300}
  .badge{display:inline-block;background:#fff3cd;border:1px solid #ffc107;border-radius:2px;padding:2px 10px;font-size:12px;color:#856404;margin-bottom:24px}
  h1{font-size:28px;font-weight:600;margin-bottom:4px}
  h2{font-size:16px;font-weight:600;margin-bottom:12px;color:#1b1b1b}
  .card{background:#fff;border-radius:4px;padding:24px;margin-bottom:20px;border:1px solid #e1dfdd}
  table{width:100%;border-collapse:collapse;font-size:13px}
  td,th{padding:8px 10px;border-bottom:1px solid #f3f2f1;text-align:left}
  th{font-weight:600;color:#555}
  code{font-family:Consolas,monospace;font-size:12px;background:#f3f2f1;padding:2px 6px;border-radius:2px;word-break:break-all}
  .tag{display:inline-block;background:#e8f4fd;color:#0078d4;border-radius:2px;padding:1px 6px;font-size:11px;margin:1px}
</style>
</head>
<body>
<div class="wrap">
  <div class="ms-logo">
    <div class="ms-squares"><div class="sq1"></div><div class="sq2"></div><div class="sq3"></div><div class="sq4"></div></div>
    <span>Microsoft Entra ID</span>
  </div>
  <div class="badge">⚠ Mock — Development only</div>
  <h1>Dev Portal</h1>
  <p style="color:#666;font-size:14px;margin-bottom:24px">Local OAuth 2.0 / OIDC identity provider emulating Microsoft Entra ID</p>

  <div class="card">
    <h2>Configuration</h2>
    <table>
      <tr><th>Setting</th><th>Value</th></tr>
      <tr><td>Tenant ID</td><td><code>${TENANT_ID}</code></td></tr>
      <tr><td>Base URL</td><td><code>${BASE_URL}</code></td></tr>
      <tr><td>Discovery</td><td><code><a href="${discovery}">${discovery}</a></code></td></tr>
      <tr><td>JWKS</td><td><code><a href="${BASE_URL}/${TENANT_ID}/discovery/v2.0/keys">${BASE_URL}/${TENANT_ID}/discovery/v2.0/keys</a></code></td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Endpoints</h2>
    <table>
      <tr><th>Endpoint</th><th>URL</th></tr>
      <tr><td>Authorize</td><td><code>GET /${TENANT_ID}/oauth2/v2.0/authorize</code></td></tr>
      <tr><td>Token</td><td><code>POST /${TENANT_ID}/oauth2/v2.0/token</code></td></tr>
      <tr><td>Logout</td><td><code>GET /${TENANT_ID}/oauth2/v2.0/logout</code></td></tr>
      <tr><td>UserInfo</td><td><code>GET /oidc/userinfo</code></td></tr>
      <tr><td>Graph /me</td><td><code>GET /v1.0/me</code></td></tr>
      <tr><td>Graph /me/memberOf</td><td><code>GET /v1.0/me/memberOf</code></td></tr>
      <tr><td>Graph /users</td><td><code>GET /v1.0/users</code></td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Registered clients</h2>
    <table>
      <tr><th>Client ID</th><th>Secret</th><th>Redirect URIs</th></tr>
      ${CLIENTS.map(c => `<tr>
        <td><code>${c.clientId}</code></td>
        <td><code>${c.clientSecret}</code></td>
        <td>${c.redirectUris.map(u => `<span class="tag">${u}</span>`).join('')}</td>
      </tr>`).join('')}
    </table>
  </div>

  <div class="card">
    <h2>Test users</h2>
    <table>
      <tr><th>Username</th><th>Password</th><th>Roles</th><th>Groups</th></tr>
      ${USERS.map(u => `<tr>
        <td>${u.username}</td>
        <td><code>${u.password}</code></td>
        <td>${u.roles.map(r => `<span class="tag">${r}</span>`).join('')}</td>
        <td>${u.groups.map(g => `<span class="tag">${g}</span>`).join('')}</td>
      </tr>`).join('')}
    </table>
  </div>

  <div class="card">
    <h2>Admin API</h2>
    <table>
      <tr><th>Method</th><th>Path</th><th>Description</th></tr>
      <tr><td>GET</td><td><code>/admin/users</code></td><td>List all users</td></tr>
      <tr><td>POST</td><td><code>/admin/users</code></td><td>Add a user (JSON body)</td></tr>
      <tr><td>DELETE</td><td><code>/admin/users/:id</code></td><td>Remove a user</td></tr>
      <tr><td>GET</td><td><code>/health</code></td><td>Health check</td></tr>
    </table>
  </div>
</div>
</body></html>`;
}

app.listen(PORT, () => {
  console.log(`\n🔵 Mock Entra ID running at ${BASE_URL}`);
  console.log(`   Tenant:    ${TENANT_ID}`);
  console.log(`   Discovery: ${BASE_URL}/${TENANT_ID}/v2.0/.well-known/openid-configuration`);
  console.log(`   Portal:    ${BASE_URL}/\n`);
});
