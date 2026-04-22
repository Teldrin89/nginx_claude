-- /etc/nginx/conf.d/oidc_logout.lua
--
-- Nginx access_by_lua_file handler for /oidc/logout.
-- Destroys the local session and redirects the browser to
-- Entra ID's end_session endpoint so the SSO session is also cleared.

local openidc = require("resty.openidc")
local cjson   = require("cjson.safe")

local opts = dofile("/etc/nginx/conf.d/oidc_config.lua")

-- -------------------------------------------------------------------------
-- Perform logout
-- lua-resty-openidc >= 1.7 supports openidc.logout()
-- It destroys the local session and issues the end_session redirect.
-- -------------------------------------------------------------------------
local err = openidc.logout(opts)

if err then
    ngx.log(ngx.ERR, "OIDC logout error: ", err)
    -- Fall back: destroy session manually and redirect home
    local session = require("resty.session").open()
    if session then
        session:destroy()
    end
    ngx.redirect(opts.post_logout_redirect_uri or "/")
end

-- openidc.logout() issues the redirect itself; execution should not reach here.
ngx.exit(ngx.HTTP_OK)
