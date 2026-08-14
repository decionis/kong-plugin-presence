local typedefs = require "kong.db.schema.typedefs"

-- Config for the Presence gateway filter. Thin adapter: it holds only the
-- coordinates of the remote Presence API and which routes to gate — all
-- decisions are made by the Presence Edge / Decision API.
return {
  name = "presence",
  fields = {
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          -- Presence API base host (POST /v1/verify, POST /v1/sessions).
          {
            api_host = {
              type = "string",
              required = true,
              default = "https://presence.decionis.com",
            },
          },
          -- Tenant bearer secret. `referenceable` so it can be a Vault reference
          -- ({vault://...}) rather than a plaintext value in the Kong config.
          {
            api_secret = {
              type = "string",
              required = true,
              referenceable = true,
            },
          },
          { tenant_id = { type = "string", required = true } },
          -- Comma-separated exact paths and trailing-wildcard prefixes. Optional:
          -- a mint/inject-only deployment gates nothing here (nil is nil-safe in
          -- the handler's route matcher).
          { protected_routes = { type = "string" } },
          -- Widget runtime injected by Flow A. Pinned to an exact version so the
          -- injected bundle is immutable; self-host this file and override the
          -- default under a strict CSP.
          {
            runtime_src = {
              type = "string",
              default = "https://cdn.jsdelivr.net/npm/@decionis/presence-widget@0.2.0/dist/presence.js",
            },
          },
          {
            verify_timeout_ms = {
              type = "integer",
              default = 500,
              between = { 50, 5000 },
            },
          },
          -- Off by default: an API gateway usually gates JSON endpoints, where
          -- there is no HTML to inject. Turn on in front of a server-rendered app.
          { inject_runtime = { type = "boolean", required = true, default = false } },
        },
      },
    },
  },
}
