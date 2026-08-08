# Presence Kong Plugin

`apps/kong-filter` is the **API-gateway** channel from the
[ecosystem roadmap](../../docs/27-ecosystem-roadmap.md): a Kong plugin that gates sensitive
endpoints on a verified Presence session and mints browser-safe Session Tokens — the same
CAPTCHA-replacement + presence-verification the [Cloudflare edge filter](../edge-filter) delivers at
the CDN, expressed as a native Kong plugin. Enable it by config rule; no application code changes.

It is a **thin Lua adapter** of the language-neutral Presence enforcement contract. Kong extracts
request context, delegates every decision to the Presence Edge / Decision API, and enforces the
returned disposition — the rich logic lives remotely, exactly as the Cloudflare Worker is one
adapter of the same contract.

## What it does

| Flow                             | Trigger                                             | Behavior                                                                                                                                                                                                                                                                                         |
| -------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **B — verify gate**              | `POST`/`PUT`/`DELETE` on a `protected_routes` match | Requires `X-Presence-Token`; verifies it (cache-first, then `POST /v1/verify`) and forwards to the upstream with `X-Presence-Status: VERIFIED` + `X-Presence-Risk-Score` + `X-Presence-Disposition`. Missing/invalid/high-risk → `403`. API unavailable or slow → **fail closed** `503`.         |
| **C — session mint**             | `POST /__presence/session`                          | Proxies session creation to `POST /v1/sessions` with the tenant credential (which never reaches the browser), building the action context at the gateway — opaque digest actor id, `web_widget` surface, the gateway host as target. Returns only `session_token` / `session_id` / `expires_in`. |
| **A — widget inject** (optional) | `GET` HTML responses, when `inject_runtime = true`  | Injects the Presence runtime `<script>` into `<head>` and `<presence-widget>` into every `<form>`. Off by default — an API gateway usually fronts JSON endpoints with no HTML to inject.                                                                                                         |

Verdict verification is **cache-first** via `kong.cache` (cluster-aware): a hit resolves without an
API call; a miss calls `POST /v1/verify` under `verify_timeout_ms`, negative verdicts are cached,
and any failure or timeout returns nothing cached so the gate fails closed. Cache keys are the
SHA-256 digest of the token — raw tokens never become keys. Thresholds (`0.75` block / `0.5`
challenge) match the API's `SignalRiskModel` (docs/06 §9).

## Configuration

| Field               | Type    | Notes                                                                                  |
| ------------------- | ------- | -------------------------------------------------------------------------------------- |
| `api_host`          | string  | Presence API base (default `https://api.presence.decionis.com`)                        |
| `api_secret`        | string  | Tenant bearer secret; `referenceable` (use a `{vault://…}` reference)                  |
| `tenant_id`         | string  | Presence tenant id                                                                     |
| `protected_routes`  | string  | Comma-separated exact paths + trailing-wildcard prefixes (`/login,/api/v1/checkout/*`) |
| `runtime_src`       | string  | Widget runtime URL for Flow A (default Decionis CDN)                                   |
| `verify_timeout_ms` | integer | Hard `/v1/verify` timeout before failing closed (default `500`)                        |
| `inject_runtime`    | boolean | Enable Flow A HTML injection (default `false`)                                         |

```yaml
# Declarative (decK / kong.yml) — gate a checkout route:
plugins:
  - name: presence
    route: checkout-route
    config:
      api_host: https://api.presence.decionis.com
      api_secret: "{vault://env/presence-api-secret}"
      tenant_id: tn_prod_998124
      protected_routes: /api/v1/checkout/*
```

## Install

```sh
luarocks install kong-plugin-presence
```

Then add `presence` to Kong's `plugins` directive (`plugins = bundled,presence`) and enable it on a
service or route. Packaged for **Kong Hub** via the bundled rockspec.

## Verification

Requires `luacheck` + `busted` on `PATH` (`eval "$(luarocks path --bin)"`); integration requires
Kong's [pongo](https://github.com/Kong/kong-pongo) and a running Docker daemon.

```sh
make lint              # luacheck across kong/ and spec/
make test              # busted — pure route-matching + HTML/threshold helpers
make test-integration  # pongo — loads the plugin in a real Kong and gates a route
```

`make lint` and `make test` run without Kong. The integration suite (`03-integration_spec.lua`)
boots a real Kong via pongo and asserts the token-missing gate (`403 PRESENCE_TOKEN_MISSING`) and
untouched pass-through; the mint/verify happy path extends it with a `helpers.http_mock` standing in
for the Presence API.

## File map

| Path                                | Responsibility                                                                               |
| ----------------------------------- | -------------------------------------------------------------------------------------------- |
| `kong/plugins/presence/handler.lua` | Phases: `access` (verify gate + session mint), `header_filter`/`body_filter` (widget inject) |
| `kong/plugins/presence/schema.lua`  | Plugin config schema                                                                         |
| `kong/plugins/presence/routes.lua`  | `protected_routes` matching (pure, unit-tested)                                              |
| `kong/plugins/presence/util.lua`    | HTML-escape / inject + disposition banding (pure, unit-tested)                               |
| `kong-plugin-presence-*.rockspec`   | LuaRocks / Kong Hub packaging                                                                |
| `spec/presence/`                    | busted unit specs + pongo integration spec                                                   |

## Scope

This first release ships the CAPTCHA-replacement core: Flow B verify gate, Flow C session mint, and
optional Flow A injection. The adaptive-ladder relays (`/__presence/{signals,check,webauthn,liveness}`,
docs/32) and other gateways (Tyk, Envoy, Apigee) are the documented follow-on, mirroring how the
edge filter grew its ladder incrementally.
