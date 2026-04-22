-- /etc/nginx/conf.d/oidc_access.lua
--
-- Nginx access_by_lua_file handler.
-- Authenticates every request via Entra ID using lua-resty-openidc,
-- then injects identity headers for the upstream Flask application.

local openidc = require("resty.openidc")
local cjson   = require("cjson.safe")

-- Load OIDC options from the shared config file
local opts = dofile("/etc/nginx/conf.d/oidc_config.lua")

-- -------------------------------------------------------------------------
-- Authenticate / authorise the request
-- -------------------------------------------------------------------------
-- authenticate() will:
--   1. Check for a valid session cookie.
--   2. If absent/expired, redirect the user to Entra ID login.
--   3. Handle the /oidc/callback exchange and create a session.
--   4. Return the validated id_token claims and (optionally) access_token.
--
-- Returns: err, target_url, session, id_token_claims, access_token, userinfo

local res, err, target, session = openidc.authenticate(opts)

if err then
    ngx.log(ngx.ERR, "OIDC authentication error: ", err)
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- -------------------------------------------------------------------------
-- Optional: authorisation check
-- Verify the user belongs to a required Entra ID group / role.
-- Remove or adjust this block to match your access policy.
-- -------------------------------------------------------------------------
--[[
local REQUIRED_GROUP = os.getenv("REQUIRED_GROUP_ID")  -- e.g. "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

if REQUIRED_GROUP then
    local groups = res.groups or {}
    local authorized = false
    for _, g in ipairs(groups) do
        if g == REQUIRED_GROUP then
            authorized = true
            break
        end
    end
    if not authorized then
        ngx.log(ngx.WARN, "Access denied for user: ", res.preferred_username or res.sub)
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end
--]]

-- -------------------------------------------------------------------------
-- Inject validated identity into upstream request headers
-- Flask reads these via request.headers.get("X-Auth-User") etc.
-- -------------------------------------------------------------------------

-- Basic identity
ngx.req.set_header("X-Auth-User",  res.preferred_username or res.upn or res.sub)
ngx.req.set_header("X-Auth-Email", res.email or res.preferred_username or "")
ngx.req.set_header("X-Auth-Name",  res.name or "")
ngx.req.set_header("X-Auth-Sub",   res.sub  or "")  -- immutable user object ID

-- Roles / groups (if included in the token)
-- Enable "groupMembershipClaims": "SecurityGroup" or "All" in the App Manifest
-- to have group GUIDs included automatically.
if res.roles then
    ngx.req.set_header("X-Auth-Roles", table.concat(res.roles, ","))
end

if res.groups then
    ngx.req.set_header("X-Auth-Groups", table.concat(res.groups, ","))
end

-- Forward the raw access token so Flask can call downstream APIs on behalf
-- of the user (e.g. Microsoft Graph).  Remove if not needed.
if session and session.data and session.data.access_token then
    ngx.req.set_header("X-Access-Token", session.data.access_token)
end

-- Remove any client-supplied auth headers to prevent spoofing
ngx.req.clear_header("Authorization")
