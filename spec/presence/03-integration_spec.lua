-- Integration test — runs the plugin inside a real Kong via pongo (Docker):
--   pongo run spec/presence/03-integration_spec.lua      (or `make test-integration`)
--
-- These cases are mock-free: the token-missing gate answers before any call to
-- the Presence API, and the unprotected path is forwarded untouched. The full
-- mint/verify happy path additionally needs a Presence API mock (helpers.http_mock
-- against conf.api_host); it is documented in the README.
local helpers = require "spec.helpers"

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
end
