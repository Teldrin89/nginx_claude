import time, urllib.request, json

# local Python clock
local_ts = int(time.time())

# Node.js clock (from Mock Entra ID token)
import urllib.parse
data = urllib.parse.urlencode({
    'grant_type': 'client_credentials',
    'client_id': 'my-dev-app',
    'client_secret': 'dev-secret-change-me',
}).encode()
import jwt
with urllib.request.urlopen(urllib.request.Request(
    'http://localhost:3000/mock-tenant-id/oauth2/v2.0/token', data=data,
    headers={'Content-Type': 'application/x-www-form-urlencoded'}, method='POST'
)) as r:
    token = json.loads(r.read())['access_token']

payload = jwt.decode(token, options={'verify_signature': False,
                                      'verify_aud': False, 'verify_iss': False})
node_iat = payload['iat']

print(f'Python clock : {local_ts}')
print(f'Node iat     : {node_iat}')
print(f'Difference   : {node_iat - local_ts} seconds (positive = Node is ahead)')