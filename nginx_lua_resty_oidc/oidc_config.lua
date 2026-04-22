-- /etc/nginx/conf.d/oidc_config.lua
--
-- Central configuration for lua-resty-openidc + Microsoft Entra ID
-- Sourced by oidc_access.lua and oidc_logout.lua via dofile()
--
-- Required environment variables (set in systemd unit or Docker env):
--   ENTRA_TENANT_ID      - Azure AD / Entra ID tenant GUID or "common"
--   ENTRA_CLIENT_ID      - App registration client (application) ID
--   ENTRA_CLIENT_SECRET  - App registration client secret value
--   APP_BASE_URL         - Public base URL of this application, e.g. https://your.domain.example.com

local function env(name)
    local val = os.getenv(name)
    if not val or val == "" then
        ngx.log(ngx.ERR, "Required environment variable not set: ", name)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    return val
end

local tenant_id     = env("ENTRA_TENANT_ID")
local client_id     = env("ENTRA_CLIENT_ID")
local client_secret = env("ENTRA_CLIENT_SECRET")
local base_url      = env("APP_BASE_URL")

-- -------------------------------------------------------------------------
-- OIDC options passed to lua-resty-openidc
-- Reference: https://github.com/zmartzone/lua-resty-openidc#documentation
-- -------------------------------------------------------------------------
local opts = {
    -- Microsoft Entra ID (Azure AD) discovery endpoint
    -- For single-tenant apps, replace "common" with your tenant_id
    discovery = string.format(
        "https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration",
        tenant_id
    ),

    client_id     = client_id,
    client_secret = client_secret,

    -- Must exactly match a URI registered in the Entra ID app registration
    -- Platform → Web → Redirect URIs
    redirect_uri = base_url .. "/oidc/callback",

    -- Logout redirect after Entra ID signs the user out
    post_logout_redirect_uri = base_url .. "/",

    -- Scopes: openid + profile + email are standard OIDC
    -- Add "offline_access" if you need refresh tokens
    scope = "openid profile email",

    -- Response type for Authorization Code flow (recommended)
    response_type = "code",

    -- Token endpoint auth method
    -- "client_secret_post" or "client_secret_basic"
    token_endpoint_auth_method = "client_secret_post",

    -- SSL verification of Entra ID endpoints (keep true in production)
    ssl_verify = "yes",

    -- Session cookie settings
    -- Use lua-resty-session v3 or v4 (opaque / cookie-based)
    session_contents = { id_token = true, user = true, access_token = true },

    -- Timeout for calls to the Entra ID endpoints (milliseconds)
    timeout = 10000,

    -- Shared memory zones defined in nginx.conf
    discovery_cache = ngx.shared.discovery,

    -- Validate the "aud" claim matches our client_id
    -- (Entra ID v2.0 tokens always include client_id in aud)
    accept_none_alg = false,
    accept_unsupported_alg = false,

    -- Extra Entra ID-specific parameters
    authorization_params = {
        -- prompt = "select_account",  -- Uncomment to force account picker
        -- domain_hint = "yourdomain.com",  -- Uncomment to pre-fill tenant
    },

    -- Renew access token automatically using refresh token
    renew_access_token_on_expiry = true,
    access_token_expires_leeway = 30,  -- seconds before expiry to renew

    -- Logout endpoint (Entra ID v2.0)
    -- Automatically derived from discovery, but can be overridden:
    -- end_session_endpoint = string.format(
    --     "https://login.microsoftonline.com/%s/oauth2/v2.0/logout", tenant_id
    -- ),
}

-- Return so callers can do:  local opts = dofile("oidc_config.lua")
return opts
