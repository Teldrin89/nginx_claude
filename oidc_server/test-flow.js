#!/usr/bin/env node
/**
 * Integration smoke-test for Mock Entra ID.
 * Run with:  node scripts/test-flow.js
 * Requires the server to be running on PORT (default 3000).
 */
'use strict';

const http = require('http');
const https = require('https');
const { URL, URLSearchParams } = require('url');
const crypto = require('crypto');

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const TENANT = process.env.TENANT_ID || 'mock-tenant-id';
const CLIENT_ID = 'my-dev-app';
const CLIENT_SECRET = 'dev-secret-change-me';
const REDIRECT_URI = 'http://localhost:8080/callback';

let passed = 0;
let failed = 0;

function fetch(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === 'https:' ? https : http;
    const req = lib.request(parsed, {
      method: opts.method || 'GET',
      headers: opts.headers || {},
    }, res => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

function assert(label, condition, detail = '') {
  if (condition) {
    console.log(`  ✅ ${label}`);
    passed++;
  } else {
    console.log(`  ❌ ${label}${detail ? ': ' + detail : ''}`);
    failed++;
  }
}

async function run() {
  console.log(`\n🧪 Mock Entra ID — Integration Tests`);
  console.log(`   Target: ${BASE}\n`);

  // ── Health ──────────────────────────────────────────
  console.log('[ Health ]');
  const health = await fetch(`${BASE}/health`);
  assert('200 OK', health.status === 200);
  const hj = JSON.parse(health.body);
  assert('status=ok', hj.status === 'ok');

  // ── Discovery ───────────────────────────────────────
  console.log('\n[ OIDC Discovery ]');
  const disc = await fetch(`${BASE}/${TENANT}/v2.0/.well-known/openid-configuration`);
  assert('200 OK', disc.status === 200);
  const dj = JSON.parse(disc.body);
  assert('has authorization_endpoint', !!dj.authorization_endpoint);
  assert('has token_endpoint', !!dj.token_endpoint);
  assert('has jwks_uri', !!dj.jwks_uri);
  assert('issuer matches tenant', dj.issuer.includes(TENANT));

  // ── JWKS ────────────────────────────────────────────
  console.log('\n[ JWKS ]');
  const jwks = await fetch(`${BASE}/${TENANT}/discovery/v2.0/keys`);
  assert('200 OK', jwks.status === 200);
  const jj = JSON.parse(jwks.body);
  assert('has keys array', Array.isArray(jj.keys) && jj.keys.length > 0);
  assert('key is RS256', jj.keys[0].alg === 'RS256');
  assert('key has n and e', !!jj.keys[0].n && !!jj.keys[0].e);

  // ── Client Credentials ──────────────────────────────
  console.log('\n[ Client Credentials Grant ]');
  const ccBody = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    scope: 'openid',
  }).toString();
  const cc = await fetch(`${BASE}/${TENANT}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: ccBody,
  });
  assert('200 OK', cc.status === 200);
  const ccj = JSON.parse(cc.body);
  assert('has access_token', !!ccj.access_token);
  assert('token_type=Bearer', ccj.token_type === 'Bearer');

  // ── Auth Code Flow (manual code injection via admin) ─
  console.log('\n[ Authorization Code Flow ]');

  // Get a code by hitting the authorize endpoint (server redirects to redirect_uri with code)
  // We simulate the full POST login flow
  const loginParams = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'openid profile email offline_access',
    state: 'test-state-abc',
    nonce: 'test-nonce-xyz',
  });

  // POST the login form
  const formBody = new URLSearchParams({
    username: 'alice@contoso.dev',
    password: 'Password1!',
    params: JSON.stringify({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: 'openid profile email offline_access',
      state: 'test-state-abc',
      nonce: 'test-nonce-xyz',
    }),
  }).toString();

  const loginRes = await fetch(`${BASE}/${TENANT}/oauth2/v2.0/authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: formBody,
  });

  assert('302 redirect', loginRes.status === 302);
  const location = loginRes.headers.location || '';
  assert('redirects to redirect_uri', location.startsWith(REDIRECT_URI));
  const locationUrl = new URL(location);
  const code = locationUrl.searchParams.get('code');
  const state = locationUrl.searchParams.get('state');
  assert('has code', !!code);
  assert('state preserved', state === 'test-state-abc');

  // Exchange code for tokens
  const tokenBody = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    redirect_uri: REDIRECT_URI,
    code,
  }).toString();

  const tokenRes = await fetch(`${BASE}/${TENANT}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: tokenBody,
  });
  assert('token 200 OK', tokenRes.status === 200);
  const tj = JSON.parse(tokenRes.body);
  assert('has access_token', !!tj.access_token);
  assert('has id_token', !!tj.id_token);
  assert('has refresh_token', !!tj.refresh_token);

  // ── UserInfo ─────────────────────────────────────────
  console.log('\n[ UserInfo ]');
  const ui = await fetch(`${BASE}/oidc/userinfo`, {
    headers: { Authorization: `Bearer ${tj.access_token}` },
  });
  assert('200 OK', ui.status === 200);
  const uij = JSON.parse(ui.body);
  assert('email correct', uij.email === 'alice@contoso.dev');
  assert('has roles', Array.isArray(uij.roles));

  // ── Graph /me ────────────────────────────────────────
  console.log('\n[ Microsoft Graph /me ]');
  const me = await fetch(`${BASE}/v1.0/me`, {
    headers: { Authorization: `Bearer ${tj.access_token}` },
  });
  assert('200 OK', me.status === 200);
  const mej = JSON.parse(me.body);
  assert('displayName present', !!mej.displayName);
  assert('userPrincipalName correct', mej.userPrincipalName === 'alice@contoso.dev');

  // ── Refresh Token ────────────────────────────────────
  console.log('\n[ Refresh Token ]');
  const rtBody = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    refresh_token: tj.refresh_token,
    scope: 'openid profile email offline_access',
  }).toString();
  const rtRes = await fetch(`${BASE}/${TENANT}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: rtBody,
  });
  assert('200 OK', rtRes.status === 200);
  const rtj = JSON.parse(rtRes.body);
  assert('new access_token issued', !!rtj.access_token);
  assert('new refresh_token issued', !!rtj.refresh_token);

  // ── Admin API ────────────────────────────────────────
  console.log('\n[ Admin API ]');
  const adminUsers = await fetch(`${BASE}/admin/users`);
  assert('200 OK', adminUsers.status === 200);
  const auj = JSON.parse(adminUsers.body);
  assert('returns array', Array.isArray(auj));
  assert('passwords masked', auj.every(u => u.password === '***'));

  // Add a user
  const newUser = JSON.stringify({
    username: 'carol@contoso.dev', password: 'Carol1!',
    displayName: 'Carol Test', email: 'carol@contoso.dev',
    givenName: 'Carol', familyName: 'Test',
  });
  const addRes = await fetch(`${BASE}/admin/users`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: newUser,
  });
  assert('201 Created', addRes.status === 201);
  const addj = JSON.parse(addRes.body);
  assert('new user has id', !!addj.id);

  // Delete the user
  const delRes = await fetch(`${BASE}/admin/users/${addj.id}`, { method: 'DELETE' });
  assert('204 No Content', delRes.status === 204);

  // ── PKCE Flow ────────────────────────────────────────
  console.log('\n[ PKCE (S256) ]');
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');

  const pkceForm = new URLSearchParams({
    username: 'bob@contoso.dev',
    password: 'Password2!',
    params: JSON.stringify({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: 'openid profile',
      state: 'pkce-state',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    }),
  }).toString();

  const pkceLogin = await fetch(`${BASE}/${TENANT}/oauth2/v2.0/authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: pkceForm,
  });
  assert('302 redirect', pkceLogin.status === 302);
  const pkceCode = new URL(pkceLogin.headers.location).searchParams.get('code');
  assert('has code', !!pkceCode);

  const pkceToken = await fetch(`${BASE}/${TENANT}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code: pkceCode,
      code_verifier: verifier,
    }).toString(),
  });
  assert('token 200 OK', pkceToken.status === 200);

  // Wrong verifier should fail
  const pkceLogin2 = await fetch(`${BASE}/${TENANT}/oauth2/v2.0/authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      username: 'bob@contoso.dev', password: 'Password2!',
      params: JSON.stringify({
        client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
        scope: 'openid', code_challenge: challenge, code_challenge_method: 'S256',
      }),
    }).toString(),
  });
  const badCode = new URL(pkceLogin2.headers.location).searchParams.get('code');
  const badToken = await fetch(`${BASE}/${TENANT}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI, code: badCode, code_verifier: 'wrong-verifier',
    }).toString(),
  });
  assert('PKCE mismatch returns 400', badToken.status === 400);

  // ── Summary ──────────────────────────────────────────
  console.log(`\n${'─'.repeat(40)}`);
  console.log(`  Passed: ${passed}   Failed: ${failed}`);
  if (failed > 0) {
    console.log('  ⚠️  Some tests failed.\n');
    process.exit(1);
  } else {
    console.log('  🎉 All tests passed!\n');
  }
}

run().catch(err => { console.error(err); process.exit(1); });
