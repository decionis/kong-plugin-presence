-- Integration test — runs the plugin inside a real Kong via pongo (Docker):
--   pongo run spec/presence/03-integration_spec.lua      (or `make test-integration`)
--
-- The gate cases are mock-free: the token-missing gate answers before any call
-- to the Presence API, and the unprotected path is forwarded untouched. The
-- proof fast-path cases need a JWKS to verify against, so they stand up a small
-- `http_mock` nginx server that serves both the enforcement-proof JWKS and an
-- echo upstream (the full mint/verify happy path is documented in the README).
local helpers = require "spec.helpers"
local http_mock = require "spec.helpers.http_mock"
local cjson = require "cjson"
local Util = require "kong.plugins.presence.util"

local PLUGIN_NAME = "presence"

for _, strategy in helpers.each_strategy() do
  describe(PLUGIN_NAME .. " gate [#" .. strategy .. "]", function()
    local proxy_client

    lazy_setup(function()
      -- The third arg loads the custom plugin's schema so bp.plugins:insert
      -- validates it (it is not one of Kong's bundled plugins).
      local bp = helpers.get_db_utils(strategy, { "routes", "services", "plugins" }, { PLUGIN_NAME })

      local service = bp.services:insert({
        url = "http://" .. helpers.mock_upstream_host .. ":" .. helpers.mock_upstream_port,
      })
      local route = bp.routes:insert({ service = service, paths = { "/" } })
      bp.plugins:insert({
        name = PLUGIN_NAME,
        route = { id = route.id },
        config = {
          api_host = "http://" .. helpers.mock_upstream_host .. ":" .. helpers.mock_upstream_port,
          api_secret = "sec_test",
          tenant_id = "tn_test",
          protected_routes = "/api/v1/checkout/*",
        },
      })

      assert(helpers.start_kong({
        database = strategy,
        plugins = "bundled," .. PLUGIN_NAME,
      }))
    end)

    lazy_teardown(function()
      helpers.stop_kong()
    end)

    before_each(function()
      proxy_client = helpers.proxy_client()
    end)

    after_each(function()
      if proxy_client then
        proxy_client:close()
      end
    end)

    it("terminates a protected write with no Presence token at the gate", function()
      local res = proxy_client:post("/api/v1/checkout/confirm", {
        headers = { ["Content-Type"] = "application/json" },
        body = "{}",
      })
      local body = assert.res_status(403, res)
      assert.matches("PRESENCE_TOKEN_MISSING", body)
    end)

    it("passes an unprotected path through to the upstream", function()
      local res = proxy_client:get("/anything")
      -- The gate never fires on an unprotected path: the request reaches the
      -- upstream (the mock echoes 200) rather than being 403'd.
      assert.not_equal(403, res.status)
    end)
  end)

  -- ---------------------------------------------------------------------------
  -- Fast path (docs/41): a valid ES256 PASS proof is verified LOCALLY against
  -- the JWKS and forwarded with no /v1/verify round-trip. This is the only
  -- suite that exercises the real OpenSSL ECDSA verify — busted (plain Lua) can
  -- parse a proof but cannot check its signature.
  --
  -- A single standalone http_mock server (a separate nginx, not Kong) plays two
  -- roles: it serves the JWKS at the well-known path (so api_host points off-box
  -- exactly as in production) and echoes the forwarded request headers as JSON
  -- on every other path (so the test can assert the request reached the upstream
  -- edge-enriched). mock_upstream is not relied upon — it is not started here.
  -- ---------------------------------------------------------------------------
  describe(PLUGIN_NAME .. " proof fast path [#" .. strategy .. "]", function()
    local proxy_client
    local mock

    -- A proof and JWKS minted offline (spec/fixtures/gen-proof.mjs): a fixed
    -- ES256 keypair, aud "tn_test", disp PASS, exp far in the future. Only the
    -- public JWK ships here; the private key never leaves the generator.
    local PROOF_JWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InByZXNlbmNlLXByb29mLWVzMjU2LTEifQ"
      .. ".eyJpc3MiOiJodHRwOi8vbW9jayIsInN1YiI6InByc19maXh0dXJlIiwiYXVkIjoidG5fdGVzdCIsImRpc3AiOiJQQVNT"
      .. "IiwiaW50ZW50IjoiY2hlY2tvdXQuc3VibWl0IiwiYXNzdXJhbmNlIjp7ImJlaGF2aW9yYWwiOnRydWUsIndlYmF1dGhu"
      .. "IjpmYWxzZSwibGl2ZW5lc3MiOmZhbHNlfSwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDB9"
      .. ".ahqLoQIGN54vMZ4kv8xeOJ3OWWxnxSPTX6lJsb2ZQXIFAK_uTjasoFv9RO2rRsEwGLu7jrDqXcQQWtEtmxr92g"
    -- The same token with the first signature byte flipped: a well-formed proof
    -- whose ES256 signature no longer verifies. (Flipping the LAST base64url
    -- char would only change padding bits, leaving the decoded bytes intact, so
    -- the mutation must land at the start of the signature segment.)
    local TAMPERED_JWT = (PROOF_JWT:gsub("%.ahqLoQ", ".bhqLoQ"))
    local JWKS_JSON = '{"keys":[{"kty":"EC","crv":"P-256",'
      .. '"x":"Wa_Me6Nyaqcv-ttpIT7AmtikJWVUrkuutW4kYycBAxI",'
      .. '"y":"izXXiq65gDrTiCAIVBaauECFWUN-vxrcChFk0r2qZLg",'
      .. '"kid":"presence-proof-es256-1","alg":"ES256","use":"sig"}]}'

    lazy_setup(function()
      -- Stand up one mock on its own port (separate nginx process): the JWKS at
      -- the well-known path, and an echo of the X-Presence-* headers on any
      -- other path (the forwarded upstream).
      local mock_port
      mock, mock_port = http_mock.new(nil, {
        [Util.PROOF_JWKS_PATH] = {
          access = string.format([[
            ngx.header["Content-Type"] = "application/json"
            ngx.print(%q)
            ngx.exit(200)
          ]], JWKS_JSON),
        },
        ["/"] = {
          access = [[
            local cjson = require "cjson"
            local h = ngx.req.get_headers()
            ngx.header["Content-Type"] = "application/json"
            ngx.print(cjson.encode({
              presence_status = h["x-presence-status"],
              disposition = h["x-presence-disposition"],
              risk = h["x-presence-risk-score"],
            }))
            ngx.exit(200)
          ]],
        },
      })
      assert(mock:start())
      local mock_url = "http://127.0.0.1:" .. mock_port

      local bp = helpers.get_db_utils(strategy, { "routes", "services", "plugins" }, { PLUGIN_NAME })

      -- The protected route forwards a verified proof to the mock's echo, which
      -- returns the request headers this filter set.
      local echo = bp.services:insert({ url = mock_url })
      local protected = bp.routes:insert({ service = echo, paths = { "/proofcheck" } })
      bp.plugins:insert({
        name = PLUGIN_NAME,
        route = { id = protected.id },
        config = {
          api_host = mock_url,
          api_secret = "sec_test",
          tenant_id = "tn_test",
          protected_routes = "/proofcheck",
        },
      })

      assert(helpers.start_kong({
        database = strategy,
        plugins = "bundled," .. PLUGIN_NAME,
      }))
    end)

    lazy_teardown(function()
      helpers.stop_kong()
      if mock then
        mock:stop()
      end
    end)

    before_each(function()
      proxy_client = helpers.proxy_client()
    end)

    after_each(function()
      if proxy_client then
        proxy_client:close()
      end
    end)

    it("forwards a valid proof locally, enriched, with no verify round-trip", function()
      local res = proxy_client:post("/proofcheck", {
        headers = {
          ["Content-Type"] = "application/json",
          [Util.PROOF_HEADER] = PROOF_JWT,
        },
        body = "{}",
      })
      -- The fast path let the write through to the upstream, which echoed the
      -- edge-computed headers: a local ES256 verify succeeded inside Kong.
      local body = assert.res_status(200, res)
      local echoed = cjson.decode(body)
      assert.equals("VERIFIED", echoed.presence_status)
      assert.equals("verified", echoed.disposition)
      assert.equals("0", echoed.risk)
    end)

    it("falls through to the token gate when the proof signature is invalid", function()
      local res = proxy_client:post("/proofcheck", {
        headers = {
          ["Content-Type"] = "application/json",
          [Util.PROOF_HEADER] = TAMPERED_JWT,
        },
        body = "{}",
      })
      -- Signature verify failed, so the proof bought nothing: the request fell
      -- through to the token gate and, with no token, failed closed.
      local body = assert.res_status(403, res)
      assert.matches("PRESENCE_TOKEN_MISSING", body)
    end)
  end)
end
