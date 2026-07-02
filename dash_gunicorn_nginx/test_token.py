import os, sys
os.environ["OIDC_BASE_URL"]          = "http://localhost:3000"
os.environ["OIDC_INTERNAL_BASE_URL"] = "http://127.0.0.1:3000"
os.environ["OIDC_TENANT_ID"]         = "mock-tenant-id"
os.environ["OIDC_CLIENT_ID"]         = "my-dev-app"
os.environ["OIDC_CLIENT_SECRET"]     = "dev-secret-change-me"
os.environ["OIDC_REDIRECT_URI"]      = "http://localhost:8080/callback"
os.environ["FLASK_SECRET_KEY"]       = "test-key-32-chars-abcdefghijklmn"

from main import verify_id_token, OIDC_TOKEN_URL, OIDC_ISSUER, OIDC_CLIENT_ID
import urllib.request, urllib.parse, json

print("OIDC_TOKEN_URL:", OIDC_TOKEN_URL)
print("OIDC_ISSUER:   ", OIDC_ISSUER)
print("OIDC_CLIENT_ID:", OIDC_CLIENT_ID)

data = urllib.parse.urlencode({
    "grant_type": "client_credentials",
    "client_id": "my-dev-app",
    "client_secret": "dev-secret-change-me",
}).encode()
with urllib.request.urlopen(urllib.request.Request(
    OIDC_TOKEN_URL, data=data,
    headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
)) as r:
    tokens = json.loads(r.read())

token = tokens["access_token"]

# decode without verification to show what the token actually contains
import jwt as pyjwt
raw = pyjwt.decode(token, options={"verify_signature": False,
                                    "verify_aud": False, "verify_iss": False})
print("\nToken iss:", raw["iss"])
print("Token aud:", raw["aud"])
print("Token sub:", raw["sub"])

print("\nCalling verify_id_token()...")
try:
    claims = verify_id_token(token)
    print("SUCCESS:", claims["sub"])
except Exception as e:
    print("FAILED:", type(e).__name__, e)
