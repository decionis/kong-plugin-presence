-- Presence gateway filter — a deliberately thin Kong (Lua/OpenResty) adapter of
-- the language-neutral Presence enforcement contract. It extracts request
-- context, delegates every decision to the Presence Edge / Decision API, and
-- enforces the returned disposition. The rich logic lives remotely; Kong is one
-- adapter beside the Cloudflare Worker (docs/28, docs/33).
local http = require "resty.http"
local sha256 = require "resty.sha256"
local to_hex = require("resty.string").to_hex
local cjson = require "cjson.safe"
local pkey = require "resty.openssl.pkey"
local Routes = require "kong.plugins.presence.routes"
local Util = require "kong.plugins.presence.util"

local PresenceHandler = {
  -- After auth/rate-limiting, before the request leaves for the upstream.
  PRIORITY = 1000,
  VERSION = "1.0.1",
}

local SESSION_PATH = "/__presence/session"
local WRITE_METHODS = { POST = true, PUT = true, DELETE = true }
local DEFAULT_INTENT = "web.form.submit"
local MAX_INTENT_LENGTH = 200
local MAX_MINT_BODY_BYTES = 8192
local MINT_TIMEOUT_MS = 1500
local WIDGET_TAG = '<presence-widget theme="auto"></presence-widget>'

-- ---------------------------------------------------------------------------
-- Digests (need the OpenResty sha256; not pure, so they live here)
-- ---------------------------------------------------------------------------

local function sha256_hex(input)
  local digest = sha256:new()
  digest:update(input)
  return to_hex(digest:final())
end

-- Raw tokens never become cache keys; the digest does.
local function token_cache_key(token)
  return "presence:token:" .. sha256_hex(token)
end

-- Opaque per-caller actor id: a digest of connection metadata, so the action
-- context carries no raw client address while distinct callers still triage as
-- distinct actors (12 bytes = 24 hex chars, matching the edge filter).
local function anon_actor_id()
  local material = (kong.client.get_ip() or "") .. "|" .. (kong.request.get_header("user-agent") or "")
  return "anon_" .. sha256_hex(material):sub(1, 24)
end

-- ---------------------------------------------------------------------------
-- Remote calls (the "rich remote service" the thin adapter delegates to)
-- ---------------------------------------------------------------------------

-- kong.cache L3 callback: POST /v1/verify. Returns (verdict, nil, ttl) on a
-- resolved verdict — cached, including negatives — or (nil, err) on any failure
-- so the gate fails closed and nothing is cached.
local function fetch_verdict(conf, token)
  local httpc = http.new()
  httpc:set_timeout(conf.verify_timeout_ms)
  local res, err = httpc:request_uri(conf.api_host .. "/v1/verify", {
    method = "POST",
    headers = {
      ["Authorization"] = "Bearer " .. conf.api_secret,
      ["Content-Type"] = "application/json",
    },
    body = cjson.encode({
      token = token,
      tenant_id = conf.tenant_id,
      client_ip = kong.client.get_ip(),
      user_agent = kong.request.get_header("user-agent"),
    }),
  })
  if not res then
    return nil, "verify_unreachable:" .. tostring(err)
  end
  if res.status ~= 200 then
    return nil, "verify_http_" .. res.status
  end
  local data = cjson.decode(res.body)
  if type(data) ~= "table" then
    return nil, "verify_malformed"
  end
  local verdict = {
    valid = data.valid == true,
    score = tonumber(data.score) or 1,
    disposition = data.disposition,
  }
  -- API-supplied TTL, clamped to the same 60–300s band as the edge cache.
  local ttl = math.min(math.max(tonumber(data.ttl) or 300, 60), 300)
  return verdict, nil, ttl
end

local function verify_token(conf, token)
  return kong.cache:get(token_cache_key(token), nil, fetch_verdict, conf, token)
end

-- ---------------------------------------------------------------------------
-- Fast path (docs/41) — verify a short-lived signed proof LOCALLY and forward
-- with no /v1/verify round-trip. The proof only speeds a pass: any defect falls
-- through to the token gate, which fails closed on its own.
-- ---------------------------------------------------------------------------

-- kong.cache L3 callback: GET the enforcement-proof JWKS (cached, so only the
-- first proof per rotation pays a fetch; the fast path never calls /v1/verify).
local function fetch_jwks(conf)
  local httpc = http.new()
  httpc:set_timeout(conf.verify_timeout_ms)
  local res, err = httpc:request_uri(conf.api_host .. Util.PROOF_JWKS_PATH, { method = "GET" })
  if not res then
    return nil, "jwks_unreachable:" .. tostring(err)
  end
  if res.status ~= 200 then
    return nil, "jwks_http_" .. res.status
  end
  local jwks = cjson.decode(res.body)
  if type(jwks) ~= "table" or type(jwks.keys) ~= "table" then
    return nil, "jwks_malformed"
  end
  return jwks, nil, 300
end

-- True when `proof` is a valid, unexpired ES256 PASS proof for this tenant.
local function proof_passes(conf, proof)
  local parts = Util.split_jwt(proof)
  if not parts then
    return false
  end
  local header = cjson.decode(Util.b64url_decode(parts.header_b64) or "")
  local claims = cjson.decode(Util.b64url_decode(parts.payload_b64) or "")
  if type(header) ~= "table" or header.alg ~= "ES256" then
    return false
  end
  if not Util.proof_claims_ok(claims, conf.tenant_id, ngx.time()) then
    return false
  end

  local jwks = kong.cache:get("presence:proof:jwks", nil, fetch_jwks, conf)
  if type(jwks) ~= "table" then
    return false
  end
  local jwk
  for _, candidate in ipairs(jwks.keys or {}) do
    if candidate.kid == header.kid then
      jwk = candidate
      break
    end
  end
  jwk = jwk or (jwks.keys or {})[1]
  if not jwk then
    return false
  end

  -- Import the public JWK. The key kind is inferred from the JWK (a public key
  -- has no `d`); passing an explicit `type` is rejected by lua-resty-openssl's
  -- JWK loader ("explicitly load ... from JWK format is not supported").
  local key = pkey.new(cjson.encode(jwk), { format = "JWK" })
  local sig = Util.b64url_decode(parts.sig_b64)
  if not key or not sig then
    return false
  end
  -- lua-resty-openssl converts the raw JOSE r‖s to DER (ecdsa_use_raw).
  return key:verify(sig, parts.signing_input, "sha256", nil, { ecdsa_use_raw = true }) == true
end

-- ---------------------------------------------------------------------------
-- Flow C — same-origin Session Token mint (the tenant credential lives here,
-- never in the browser). The client controls only an optional intent label.
-- ---------------------------------------------------------------------------

local function session_unavailable()
  return kong.response.exit(503, {
    error = "Presence session is temporarily unavailable",
    code = "PRESENCE_SESSION_UNAVAILABLE",
  }, { ["Cache-Control"] = "no-store", ["Retry-After"] = "1" })
end

local function read_intent()
  local body = kong.request.get_raw_body()
  if not body or #body == 0 or #body > MAX_MINT_BODY_BYTES then
    return DEFAULT_INTENT
  end
  local parsed = cjson.decode(body)
  if type(parsed) == "table" and type(parsed.intent) == "string"
    and #parsed.intent > 0 and #parsed.intent <= MAX_INTENT_LENGTH then
    return parsed.intent
  end
  return DEFAULT_INTENT
end

local function mint_session(conf)
  local httpc = http.new()
  httpc:set_timeout(MINT_TIMEOUT_MS)
  local res = httpc:request_uri(conf.api_host .. "/v1/sessions", {
    method = "POST",
    headers = {
      ["Authorization"] = "Bearer " .. conf.api_secret,
      ["Content-Type"] = "application/json",
    },
    body = cjson.encode({
      intent = read_intent(),
      surface = "web_widget",
      actor_id = anon_actor_id(),
      target_resource_id = kong.request.get_scheme() .. "://" .. kong.request.get_host(),
    }),
  })
  if not res or res.status < 200 or res.status >= 300 then
    return session_unavailable()
  end
  local session = cjson.decode(res.body)
  if type(session) ~= "table" or type(session.session_token) ~= "string"
    or #session.session_token == 0 then
    return session_unavailable()
  end
  return kong.response.exit(200, {
    session_token = session.session_token,
    session_id = type(session.session_id) == "string" and session.session_id or cjson.null,
    expires_in = tonumber(session.session_token_expires_in) or tonumber(session.expires_in) or 240,
  }, { ["Cache-Control"] = "no-store" })
end

-- ---------------------------------------------------------------------------
-- Flow B — edge verification of protected writes
-- ---------------------------------------------------------------------------

-- Strip any client-supplied Presence headers, then set edge-computed ones: the
-- origin sees only values this filter produced.
local function forward_verified(score, disposition)
  kong.service.request.clear_header("X-Presence-Status")
  kong.service.request.clear_header("X-Presence-Risk-Score")
  kong.service.request.clear_header("X-Presence-Disposition")
  kong.service.request.set_header("X-Presence-Status", "VERIFIED")
  kong.service.request.set_header("X-Presence-Risk-Score", score)
  kong.service.request.set_header("X-Presence-Disposition", disposition)
end

local function enforce(conf)
  -- Fast path: a valid PASS proof forwards with no /v1/verify round-trip.
  local proof = kong.request.get_header(Util.PROOF_HEADER)
  if proof and proof ~= "" and proof_passes(conf, proof) then
    return forward_verified("0", "verified")
  end

  local token = kong.request.get_header("X-Presence-Token")
  if not token or token == "" then
    return kong.response.exit(403, {
      error = "Presence token required",
      code = "PRESENCE_TOKEN_MISSING",
    })
  end

  local verdict, err = verify_token(conf, token)
  if not verdict then
    kong.log.warn("presence verify degraded: ", err)
    return kong.response.exit(503, {
      error = "Presence verification unavailable",
      code = "PRESENCE_VERIFICATION_UNAVAILABLE",
    }, { ["Retry-After"] = "1" })
  end

  if not verdict.valid or verdict.score > Util.RISK_THRESHOLD then
    return kong.response.exit(403, {
      error = "Human presence verification failed",
      code = "PRESENCE_CHALLENGE_FAILED",
    })
  end

  forward_verified(string.format("%.4g", verdict.score),
    Util.disposition_of(verdict.score, verdict.disposition))
end

-- ---------------------------------------------------------------------------
-- Phases
-- ---------------------------------------------------------------------------

function PresenceHandler:access(conf)
  local method = kong.request.get_method()
  local path = kong.request.get_path()

  if method == "POST" and path == SESSION_PATH then
    return mint_session(conf)
  end

  if WRITE_METHODS[method] and Routes.matches(conf.protected_routes, path) then
    return enforce(conf)
  end
end

function PresenceHandler:header_filter(conf)
  if not conf.inject_runtime or kong.request.get_method() ~= "GET" then
    return
  end
  local accept = kong.request.get_header("accept") or ""
  local content_type = kong.response.get_header("Content-Type") or ""
  if accept:find("text/html", 1, true) and content_type:find("text/html", 1, true) then
    kong.ctx.plugin.inject = true
    -- The body length changes; let Kong re-chunk it.
    kong.response.clear_header("Content-Length")
  end
end

function PresenceHandler:body_filter(conf)
  if not kong.ctx.plugin.inject then
    return
  end
  local chunk = ngx.arg[1]
  local eof = ngx.arg[2]
  local buffer = kong.ctx.plugin.buffer or {}
  if chunk and #chunk > 0 then
    buffer[#buffer + 1] = chunk
  end
  kong.ctx.plugin.buffer = buffer

  if not eof then
    -- Withhold output until the whole document is buffered.
    ngx.arg[1] = nil
    return
  end

  local html = table.concat(buffer)
  local script = '<script src="' .. Util.esc_attr(conf.runtime_src)
    .. '" data-tenant="' .. Util.esc_attr(conf.tenant_id) .. '" async defer></script>'
  html = Util.insert_before_close(html, "head", script, 1)
  html = Util.insert_before_close(html, "form", WIDGET_TAG)
  ngx.arg[1] = html
end

return PresenceHandler
