-- Pure, dependency-free helpers shared by the handler. No OpenResty/Kong or
-- resty.* requires, so this unit-tests standalone with plain busted.
local Util = {}

-- Flow B bands — must equal the API's SignalRiskModel (docs/06 §9).
Util.RISK_THRESHOLD = 0.75
Util.CHALLENGE_FLOOR = 0.5

-- Escape a value for an HTML attribute (& first, so we never double-escape).
function Util.esc_attr(value)
  return (value:gsub("&", "&amp;"):gsub('"', "&quot;"):gsub("<", "&lt;"))
end

-- Case-insensitive "</tag>" Lua pattern, e.g. "</[Hh][Ee][Aa][Dd]>".
function Util.close_tag_pattern(tag)
  local pattern = "</"
  for i = 1, #tag do
    local c = tag:sub(i, i)
    pattern = pattern .. "[" .. c:lower() .. c:upper() .. "]"
  end
  return pattern .. ">"
end

-- Insert `snippet` immediately before each (up to `max`) close tag `</tag>`.
function Util.insert_before_close(html, tag, snippet, max)
  return (html:gsub(Util.close_tag_pattern(tag), function(close)
    return snippet .. close
  end, max))
end

-- The disposition band for a verified score: trust the API's when present,
-- else derive it against the same thresholds the API uses.
function Util.disposition_of(score, api_disposition)
  if api_disposition ~= nil then
    return api_disposition
  end
  if score > Util.RISK_THRESHOLD then
    return "blocked"
  end
  return score > Util.CHALLENGE_FLOOR and "challenge" or "verified"
end

-- ---------------------------------------------------------------------------
-- Enforcement proof (docs/41) — pure parsing/claim checks. The ES256 signature
-- verification needs OpenSSL and lives in the handler; everything here is pure
-- string work, so it runs under plain Lua (busted) as well as OpenResty.
-- ---------------------------------------------------------------------------

Util.PROOF_HEADER = "X-Presence-Proof"
Util.PROOF_JWKS_PATH = "/.well-known/presence-proof-jwks.json"

local B64URL = {}
do
  local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
  for i = 1, #alphabet do
    B64URL[alphabet:byte(i)] = i - 1
  end
end

-- Decode a base64url string to raw bytes (no bit ops, so LuaJIT-safe). Trailing
-- '=' padding is tolerated; any other stray byte rejects the input.
function Util.b64url_decode(input)
  if type(input) ~= "string" then
    return nil
  end
  local bytes = {}
  local acc, bits = 0, 0
  for i = 1, #input do
    local value = B64URL[input:byte(i)]
    if value == nil then
      if input:byte(i) ~= 61 then -- '='
        return nil
      end
    else
      acc = acc * 64 + value
      bits = bits + 6
      if bits >= 8 then
        bits = bits - 8
        local shift = 1
        for _ = 1, bits do
          shift = shift * 2
        end
        bytes[#bytes + 1] = string.char(math.floor(acc / shift) % 256)
        acc = acc % shift
      end
    end
  end
  return table.concat(bytes)
end

-- Split a compact JWS into its three segments plus the signing input, or nil.
function Util.split_jwt(jwt)
  if type(jwt) ~= "string" then
    return nil
  end
  local header, payload, signature = jwt:match("^([^.]+)%.([^.]+)%.([^.]+)$")
  if not header then
    return nil
  end
  return {
    header_b64 = header,
    payload_b64 = payload,
    sig_b64 = signature,
    signing_input = header .. "." .. payload,
  }
end

-- The pure claim gate: only a PASS proof for this tenant, not yet expired.
function Util.proof_claims_ok(claims, tenant_id, now)
  return type(claims) == "table"
    and claims.disp == "PASS"
    and claims.aud == tenant_id
    and type(claims.exp) == "number"
    and claims.exp > now
end

return Util
