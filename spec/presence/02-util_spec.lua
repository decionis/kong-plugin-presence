local Util = require "kong.plugins.presence.util"

describe("Util.esc_attr", function()
  it("escapes &, \" and < with & first", function()
    assert.equals("a&amp;b&quot;c&lt;d", Util.esc_attr('a&b"c<d'))
    assert.equals("plain", Util.esc_attr("plain"))
  end)
end)

describe("Util.insert_before_close", function()
  it("injects before every close tag, case-insensitively", function()
    local html = "<form>a</form><FORM>b</FORM>"
    local out = Util.insert_before_close(html, "form", "[W]")
    assert.truthy(out:find("[W]</form>", 1, true))
    assert.truthy(out:find("[W]</FORM>", 1, true))
  end)

  it("caps to the first match when max is given", function()
    local out = Util.insert_before_close("</head></head>", "head", "[S]", 1)
    local _, count = out:gsub("%[S%]", "")
    assert.equals(1, count)
  end)

  it("leaves html without the tag untouched", function()
    assert.equals("<p>hi</p>", Util.insert_before_close("<p>hi</p>", "form", "[W]"))
  end)
end)

describe("Util.disposition_of", function()
  it("bands a score against the thresholds", function()
    assert.equals("verified", Util.disposition_of(0.2))
    assert.equals("verified", Util.disposition_of(0.5)) -- floor is exclusive
    assert.equals("challenge", Util.disposition_of(0.6))
    assert.equals("blocked", Util.disposition_of(0.9))
  end)

  it("trusts the API's band when present", function()
    assert.equals("challenge", Util.disposition_of(0.9, "challenge"))
    assert.equals("verified", Util.disposition_of(0.9, "verified"))
  end)
end)
