-- luacheck configuration for the Presence Kong plugin.
std = "luajit" -- Kong runs on LuaJIT
max_line_length = 120

-- Kong PDK and OpenResty globals — writable, since the handler sets fields like
-- kong.ctx.plugin.* and ngx.arg[1].
globals = { "kong", "ngx" }

-- Kong plugin phase methods are declared with `:` (handler:access(conf)), so the
-- implicit `self` is unused by design.
ignore = { "212/self" }

-- The specs use the busted DSL.
files["spec/"] = {
  std = "+busted",
}

exclude_files = { ".luarocks", "lua_modules", "**/lua_modules" }
