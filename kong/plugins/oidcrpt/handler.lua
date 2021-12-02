local BasePlugin = require "kong.plugins.base_plugin"
local OidcRptHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidcrpt.utils")
local filter = require("kong.plugins.oidcrpt.filter")
local session = require("kong.plugins.oidcrpt.session")
local http = require("resty.http")
local cjson = require("cjson")

OidcRptHandler.PRIORITY = 999

local F = {}

function F.handle(oidcConfig)
  local response
  if oidcConfig.introspection_endpoint then
    response = F.introspect(oidcConfig)
    if response then
      utils.injectUser(response)
    end
  end

  if response == nil then
    response = F.make_oidc(oidcConfig)
    -- patch begin
    if response and response.user then
      utils.injectUser(response.user)
    end
    -- if response then
    --   if (response.user) then
    --     utils.injectUser(response.user)
    --   end
    --   if (response.access_token) then
    --     utils.injectAccessToken(response.access_token)
    --   end
    --   if (response.id_token) then
    --     utils.injectIDToken(response.id_token)
    --   end
    -- end
    -- patch end
  end
end

function F.make_oidc(oidcConfig)
  ngx.log(ngx.DEBUG, "OidcRptHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  local res, err = require("resty.openidc").authenticate(oidcConfig)
  if err then
    if oidcConfig.recovery_page_path then
      ngx.log(ngx.DEBUG, "Entering recovery page: " .. oidcConfig.recovery_page_path)
      ngx.redirect(oidcConfig.recovery_page_path)
    end
    utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  return res
end

function F.introspect(oidcConfig)
  if utils.has_bearer_access_token() or oidcConfig.bearer_only == "yes" then
    local res, err = require("resty.openidc").introspect(oidcConfig)
    if err then
      if oidcConfig.bearer_only == "yes" then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
        utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
      end
      return nil
    end
    -- patch begin
    local authz = res["authorization"]
    if authz == nil then
      ngx.log(ngx.DEBUG, "No Authorization, will obtain Request Party Token.")

      local discovery, err = require("resty.openidc").get_discovery_doc(oidcConfig)
      if discovery then 
        ngx.log(ngx.DEBUG, "token_endpoint: " .. discovery.token_endpoint)
        F.obtainRPT(oidcConfig, discovery.token_endpoint)
      end
      -- utils.exit(ngx.HTTP_UNAUTHORIZED, "Authz Error, No Authorization", ngx.HTTP_UNAUTHORIZED)
    end
    -- patch end
    ngx.log(ngx.DEBUG, "OidcRptHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    return res
  end
  return nil
end

function F.obtainRPT(oidcConfig, endpoint) 
  local ep_name = 'rpt'
  local headers = {
      ["Authorization"] = ngx.req.get_headers()["Authorization"],
      ["Content-Type"] = "application/x-www-form-urlencoded"
  }
  local body = {
    grant_type="urn:ietf:params:oauth:grant-type:uma-ticket",
    audience=oidcConfig.client_id,
    -- permission=ngx.var.request_uri",
    response_mode="decision"
  }

  ngx.log(ngx.DEBUG, "request body for "..ep_name.." endpoint call: ", ngx.encode_args(body))

  local httpc = http.new()
  local res, err = httpc:request_uri(endpoint, {
    method = "POST",
    body = ngx.encode_args(body),
    headers = headers,
    ssl_verify = "no"
  })
  if not res then
    err = "accessing "..ep_name.." endpoint ("..endpoint..") failed: "..err
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  ngx.log(ngx.DEBUG, ep_name.." endpoint response: ", res.body)
  ngx.log(ngx.DEBUG, ep_name.." endpoint response: ", type(cjson.decode(res.body)["result"]))

  if res.body and cjson.decode(res.body)["result"] == true then
    ngx.log(ngx.DEBUG, "RPT success." .. ep_name.." endpoint response: ", res.body)
  else
    utils.exit(ngx.HTTP_UNAUTHORIZED, "Access Deny", ngx.HTTP_UNAUTHORIZED)
  end

end

function OidcRptHandler:new()
  OidcRptHandler.super.new(self, "oidcrpt")
end

function OidcRptHandler:access(config)
  OidcRptHandler.super.access(self)
  local oidcConfig = utils.get_options(config, ngx)

  if filter.shouldProcessRequest(oidcConfig) then
    session.configure(config)
    F.handle(oidcConfig)
  else
    ngx.log(ngx.DEBUG, "OidcRptHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "OidcRptHandler done")
end

return OidcRptHandler
