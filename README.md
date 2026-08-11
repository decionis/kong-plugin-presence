<!--
  Maintainers: this file is published VERBATIM as the README of
  github.com/decionis/kong-plugin-presence. Keep it public-facing: no
  monorepo paths, no docs/NN references, and only links that resolve from
  the public repository. Internal channel context lives in
  docs/27-ecosystem-roadmap.md, which points here.
-->

# Presence plugin for Kong Gateway

[![LuaRocks](https://img.shields.io/badge/luarocks-kong--plugin--presence-blue.svg)](https://luarocks.org/modules/ocularminds/kong-plugin-presence)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**`kong-plugin-presence`** — CAPTCHA replacement and human presence verification at the API gateway. Gate sensitive routes on a verified Presence session by config rule; no application code changes.

> Applications send intent and context.
> Presence verifies the person.
> Decionis decides whether execution proceeds.

The plugin is a thin Kong (Lua/OpenResty) adapter of the language-neutral [Presence](https://presence.decionis.com) enforcement contract: Kong extracts request context, delegates every decision to the Presence API, and enforces the returned disposition. The rich logic lives remotely; the gateway stays thin and fails closed.

## Install

```sh
luarocks install kong-plugin-presence
```

Add `presence` to Kong's `plugins` directive (`plugins = bundled,presence`) and enable it on a service or route:

```yaml
# Declarative (decK / kong.yml) — gate a checkout route:
plugins:
  - name: presence
    route: checkout-route
    config:
      api_host: https://presence.decionis.com
      api_secret: "{vault://env/presence-api-secret}"
      tenant_id: tn_prod_998124
      protected_routes: /api/v1/checkout/*
```

## What it does

| Flow                             | Trigger                                             | Behavior                                                                                                                                                                                                                                                                                         |
| -------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **B — verify gate**              | `POST`/`PUT`/`DELETE` on a `protected_routes` match | Requires `X-Presence-Token`; verifies it (cache-first, then `POST /v1/verify`) and forwards to the upstream with `X-Presence-Status: VERIFIED` + `X-Presence-Risk-Score` + `X-Presence-Disposition`. Missing/invalid/high-risk → `403`. API unavailable or slow → **fail closed** `503`.         |
| **C — session mint**             | `POST /__presence/session`                          | Proxies session creation to `POST /v1/sessions` with the tenant credential (which never reaches the browser), building the action context at the gateway — opaque digest actor id, `web_widget` surface, the gateway host as target. Returns only `session_token` / `session_id` / `expires_in`. |
| **A — widget inject** (optional) | `GET` HTML responses, when `inject_runtime = true`  | Injects the Presence runtime `<script>` into `<head>` and `<presence-widget>` into every `<form>`. Off by default — an API gateway usually fronts JSON endpoints with no HTML to inject.                                                                                                         |

## Fail-closed guarantees

- Verdict verification is **cache-first** via `kong.cache` (cluster-aware): a hit resolves without an API call; a miss calls `POST /v1/verify` under `verify_timeout_ms`.
- Any verification failure or timeout caches nothing and the gate fails closed (`503`); missing, invalid, or high-risk tokens are rejected (`403`).
- Cache keys are the SHA-256 digest of the token — raw tokens never become cache keys; negative verdicts are cached too.
- Risk thresholds (`0.75` block / `0.5` challenge) match the Presence API's risk model, so the gateway and the API band identically.
- The tenant credential is `referenceable` config (use a `{vault://…}` reference); it is sent only to the Presence API and never reaches the browser.

## Configuration

| Field               | Type    | Notes                                                                                  |
| ------------------- | ------- | -------------------------------------------------------------------------------------- |
| `api_host`          | string  | Presence API base (default `https://presence.decionis.com`)                            |
| `api_secret`        | string  | Tenant bearer secret; `referenceable` (use a `{vault://…}` reference)                  |
| `tenant_id`         | string  | Presence tenant id                                                                     |
| `protected_routes`  | string  | Comma-separated exact paths + trailing-wildcard prefixes (`/login,/api/v1/checkout/*`) |
| `runtime_src`       | string  | Widget runtime URL for Flow A (default Decionis CDN)                                   |
| `verify_timeout_ms` | integer | Hard `/v1/verify` timeout before failing closed (default `500`)                        |
| `inject_runtime`    | boolean | Enable Flow A HTML injection (default `false`)                                         |

## Code layout

The plugin is small on purpose — auditable in one sitting:

| Path                                | Responsibility                                                                               |
| ----------------------------------- | -------------------------------------------------------------------------------------------- |
| `kong/plugins/presence/handler.lua` | Phases: `access` (verify gate + session mint), `header_filter`/`body_filter` (widget inject) |
| `kong/plugins/presence/schema.lua`  | Plugin config schema                                                                         |
| `kong/plugins/presence/routes.lua`  | `protected_routes` matching (pure, unit-tested)                                              |
| `kong/plugins/presence/util.lua`    | HTML-escape / inject + disposition banding (pure, unit-tested)                               |
| `kong-plugin-presence-*.rockspec`   | LuaRocks packaging                                                                           |
| `spec/presence/`                    | busted unit specs + pongo integration spec                                                   |

## Development

Requires `luacheck` + `busted` on `PATH` (`eval "$(luarocks path --bin)"`); the integration suite additionally requires Kong's [pongo](https://github.com/Kong/kong-pongo) and a running Docker daemon.

```sh
make lint              # luacheck across kong/ and spec/
make test              # busted — pure route-matching + HTML/threshold helpers
make test-integration  # pongo — loads the plugin in a real Kong and gates a route
```

`make lint` and `make test` run without Kong. The integration suite boots a real Kong via pongo and asserts the token-missing gate (`403 PRESENCE_TOKEN_MISSING`) and untouched pass-through; the mint/verify happy path runs against a mock standing in for the Presence API.

## Scope

This release ships the CAPTCHA-replacement core: the verify gate (Flow B), session mint (Flow C), and optional widget injection (Flow A). Adaptive step-up relays and additional gateways are planned follow-ons.

## Support

- [GitHub Issues](https://github.com/decionis/kong-plugin-presence/issues)
- [presence.decionis.com/developers/kong](https://presence.decionis.com/developers/kong)
- Security reports: [security.txt](https://presence.decionis.com/.well-known/security.txt)

## License

Apache-2.0. Use of the hosted Presence service is governed separately.
