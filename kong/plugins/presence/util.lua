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

return Util
