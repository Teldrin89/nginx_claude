# Mock Entra ID

A lightweight local OAuth 2.0 / OIDC identity provider that faithfully emulates **Microsoft Entra ID** (formerly Azure AD) for web application development.

Drop it into any dev environment as a zero-config replacement for real Entra ID — no Azure subscription needed.

---

## Features

| Feature | Detail |
|---|---|
| OIDC Discovery | `/.well-known/openid-configuration` at the real Entra ID path |
| Authorization Code flow | With or without PKCE (S256 / plain) |
| Client Credentials grant | For service-to-service auth |
| Refresh Token grant | `offline_access` scope |
| RS256 JWT signing | Real RSA key pair, verified with JWKS |
| SSO session cookies | Re-login skipped within a browser session |
| Microsoft Graph stubs | `/v1.0/me`, `/v1.0/me/memberOf`, `/v1.0/users` |
| UserInfo endpoint | Standard OIDC `/oidc/userinfo` |
| Roles & groups claims | In both `id_token` and `access_token` |
| Admin REST API | Add / remove users at runtime without restart |
| Dev portal | Browser UI at `/` listing endpoints, users, clients |
| Docker support | `Dockerfile` + `docker-compose.yml` included |

---

## Quick start

```bash
# 1. Install dependencies
npm install

# 2. Generate RSA signing keys
npm run generate-keys

# 3. Start the server
npm start
# or for hot-reload:
npm run dev
```

Open **http://localhost:3000** for the dev portal.

---

## Pointing your app at Mock Entra ID

Replace your Entra ID discovery URL with:

```
http://localhost:3000/<TENANT_ID>/v2.0/.well-known/openid-configuration
```

Default `TENANT_ID` is `mock-tenant-id`.

### Next.js / NextAuth.js

```js
// pages/api/auth/[...nextauth].js
import NextAuth from 'next-auth';
import AzureADProvider from 'next-auth/providers/azure-ad';

export default NextAuth({
  providers: [
    AzureADProvider({
      clientId: 'my-dev-app',
      clientSecret: 'dev-secret-change-me',
      tenantId: 'mock-tenant-id',
      wellKnown: 'http://localhost:3000/mock-tenant-id/v2.0/.well-known/openid-configuration',
    }),
  ],
});
```

### passport-azure-ad (Node.js)

```js
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy;

passport.use(new OIDCStrategy({
  identityMetadata: 'http://localhost:3000/mock-tenant-id/v2.0/.well-known/openid-configuration',
  clientID: 'my-dev-app',
  clientSecret: 'dev-secret-change-me',
  redirectUrl: 'http://localhost:8080/callback',
  responseType: 'code',
  responseMode: 'query',
  scope: ['openid', 'profile', 'email'],
}, (iss, sub, profile, done) => done(null, profile)));
```

### MSAL.js (SPA / React)

```js
import { PublicClientApplication } from '@azure/msal-browser';

const msalConfig = {
  auth: {
    clientId: 'my-dev-app',
    authority: 'http://localhost:3000/mock-tenant-id',
    redirectUri: 'http://localhost:3001/callback',
    knownAuthorities: ['localhost'],
  },
};

export const msalInstance = new PublicClientApplication(msalConfig);
```

> **Note**: MSAL validates the `iss` claim — make sure `BASE_URL` and `TENANT_ID` match what your app expects.

### Python (msal / requests-oauthlib)

```python
import msal

app = msal.ConfidentialClientApplication(
    client_id='my-dev-app',
    client_credential='dev-secret-change-me',
    authority='http://localhost:3000/mock-tenant-id',
)
```

### Spring Boot

```yaml
# application.yml
spring:
  security:
    oauth2:
      client:
        registration:
          azure:
            client-id: my-dev-app
            client-secret: dev-secret-change-me
            scope: openid,profile,email
        provider:
          azure:
            issuer-uri: http://localhost:3000/mock-tenant-id/v2.0
```

---

## Configuration

Copy `.env.example` to `.env` and edit:

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP port |
| `BASE_URL` | `http://localhost:3000` | Public base URL (used in token `iss`, discovery) |
| `TENANT_ID` | `mock-tenant-id` | Tenant ID embedded in all OIDC paths |
| `MOCK_USERS` | *(see server.js)* | JSON array overriding the built-in user list |
| `MOCK_CLIENTS` | *(see server.js)* | JSON array overriding the built-in client list |

### Adding clients

Edit `CLIENTS` in `src/server.js` or set `MOCK_CLIENTS` env var:

```json
[
  {
    "clientId": "my-app",
    "clientSecret": "my-secret",
    "redirectUris": ["http://localhost:8080/callback"],
    "allowedScopes": ["openid", "profile", "email", "offline_access"]
  }
]
```

### Adding / modifying users

Edit `USERS` in `src/server.js`, set `MOCK_USERS` env var, or use the Admin API at runtime.

---

## OIDC Endpoints

All paths match real Entra ID exactly.

| Method | Path | Description |
|---|---|---|
| `GET` | `/:tenantId/v2.0/.well-known/openid-configuration` | OIDC Discovery |
| `GET` | `/common/v2.0/.well-known/openid-configuration` | Discovery (common endpoint) |
| `GET` | `/:tenantId/discovery/v2.0/keys` | JWKS public keys |
| `GET` | `/:tenantId/oauth2/v2.0/authorize` | Authorization (serves login UI) |
| `POST` | `/:tenantId/oauth2/v2.0/authorize` | Login form submission |
| `POST` | `/:tenantId/oauth2/v2.0/token` | Token exchange |
| `GET` | `/:tenantId/oauth2/v2.0/logout` | Logout + session clear |
| `GET` | `/oidc/userinfo` | UserInfo (Bearer token required) |

## Microsoft Graph Stubs

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1.0/me` | Signed-in user profile |
| `GET` | `/v1.0/me/memberOf` | Group memberships |
| `GET` | `/v1.0/users` | All users |

## Admin API

| Method | Path | Description |
|---|---|---|
| `GET` | `/admin/users` | List all users (passwords masked) |
| `POST` | `/admin/users` | Create a user (JSON body) |
| `DELETE` | `/admin/users/:id` | Delete a user |
| `GET` | `/health` | Health check |

---

## Running tests

Start the server first, then:

```bash
npm test
```

The test script exercises the full auth-code flow, PKCE, client credentials, refresh token, UserInfo, Graph stubs, and the Admin API.

---

## Docker

```bash
# Build and run
docker compose up --build

# Or directly
docker build -t mock-entra-id .
docker run -p 3000:3000 mock-entra-id
```

To persist RSA keys across restarts:

```bash
docker run -p 3000:3000 -v $(pwd)/certs:/app/certs mock-entra-id
```

---

## Security note

This service is **for development only**. It stores credentials in plaintext and has no rate limiting. Never deploy it to a public-facing environment.
