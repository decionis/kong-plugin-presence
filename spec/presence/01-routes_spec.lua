local Routes = require "kong.plugins.presence.routes"

describe("Routes.matches", function()
  it("matches exact paths only exactly", function()
    assert.is_true(Routes.matches("/login", "/login"))
    assert.is_false(Routes.matches("/login", "/logout"))
    assert.is_false(Routes.matches("/login", "/login/extra"))
  end)

  it("matches a trailing-wildcard prefix and its bare form", function()
    local list = "/api/v1/checkout/*"
    assert.is_true(Routes.matches(list, "/api/v1/checkout/confirm"))
    assert.is_true(Routes.matches(list, "/api/v1/checkout/"))
    assert.is_true(Routes.matches(list, "/api/v1/checkout")) -- bare prefix
  end)

  it("does not treat a prefix as a substring match", function()
    -- The trailing slash guards the boundary: "checkoutish" is not "checkout/*".
    assert.is_false(Routes.matches("/api/v1/checkout/*", "/api/v1/checkoutish"))
  end)

  it("handles a comma-separated list with whitespace", function()
    local list = " /login , /api/v1/checkout/* ,/api/v1/auth/* "
    assert.is_true(Routes.matches(list, "/login"))
    assert.is_true(Routes.matches(list, "/api/v1/checkout/confirm"))
    assert.is_true(Routes.matches(list, "/api/v1/auth/token"))
    assert.is_false(Routes.matches(list, "/public"))
  end)

  it("protects nothing for an empty configuration", function()
    assert.is_false(Routes.matches("", "/login"))
    assert.is_false(Routes.matches(nil, "/login"))
  end)
end)
