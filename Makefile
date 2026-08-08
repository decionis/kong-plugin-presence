# Presence Kong plugin — verification entrypoints.
# Requires luacheck + busted on PATH: `eval "$(luarocks path --bin)"`.
# Integration requires Kong's pongo + a running Docker daemon.

.PHONY: lint test test-integration verify

lint:
	luacheck kong spec

test:
	busted spec/presence/01-routes_spec.lua spec/presence/02-util_spec.lua

test-integration:
	pongo run spec/presence/03-integration_spec.lua

verify: lint test
