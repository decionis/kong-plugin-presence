-- Pure path matching against a PROTECTED_ROUTES-style list: comma-separated
-- exact paths ("/login") and trailing-wildcard prefixes ("/api/v1/checkout/*").
-- No Kong dependency, so it unit-tests standalone with plain busted. This is
-- the Lua port of the Cloudflare edge filter's RouteMatcher (docs/28).
local Routes = {}

-- Parse a pattern list into { exact = <set>, prefixes = <list> }.
function Routes.parse(pattern_list)
  local exact, prefixes = {}, {}
  for pattern in string.gmatch(pattern_list or "", "([^,]+)") do
    local trimmed = pattern:gsub("^%s+", ""):gsub("%s+$", "")
    if #trimmed > 0 then
      if trimmed:sub(-2) == "/*" then
        -- "/api/v1/checkout/*" -> prefix "/api/v1/checkout/"
        prefixes[#prefixes + 1] = trimmed:sub(1, -2)
      else
        exact[trimmed] = true
      end
    end
  end
  return { exact = exact, prefixes = prefixes }
end

-- Does `path` match the parsed route set? A prefix "/api/v1/checkout/" matches
-- both "/api/v1/checkout/anything" and the bare "/api/v1/checkout".
function Routes.is_protected(parsed, path)
  if parsed.exact[path] then
    return true
  end
  for _, prefix in ipairs(parsed.prefixes) do
    if path:sub(1, #prefix) == prefix or path == prefix:sub(1, -2) then
      return true
    end
  end
  return false
end

-- Convenience: parse + match in one call.
function Routes.matches(pattern_list, path)
  return Routes.is_protected(Routes.parse(pattern_list), path)
end

return Routes
