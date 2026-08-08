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

describe("Util.b64url_decode", function()
  it("decodes base64url to raw bytes", function()
    assert.equals("Hello", Util.b64url_decode("SGVsbG8"))
    assert.equals('{"a":1}', Util.b64url_decode("eyJhIjoxfQ"))
  end)

  it("handles the URL-safe alphabet and tolerates padding", function()
    -- All-ones bytes exercise `_` (63); `-` (62) appears in 0xFB 0xF0.
    assert.equals("\255\255\255", Util.b64url_decode("____"))
    assert.equals("\251\240", Util.b64url_decode("-_A="))
    assert.equals("\251\240", Util.b64url_decode("-_A"))
  end)

  it("rejects a stray character", function()
    assert.is_nil(Util.b64url_decode("abc$def"))
    assert.is_nil(Util.b64url_decode(42))
  end)
end)

describe("Util.split_jwt", function()
  it("splits a three-segment token and exposes the signing input", function()
    local parts = Util.split_jwt("aaa.bbb.ccc")
    assert.equals("aaa", parts.header_b64)
    assert.equals("bbb", parts.payload_b64)
    assert.equals("ccc", parts.sig_b64)
    assert.equals("aaa.bbb", parts.signing_input)
  end)

  it("returns nil for anything that is not exactly three segments", function()
    assert.is_nil(Util.split_jwt("only.two"))
    assert.is_nil(Util.split_jwt("a.b.c.d"))
    assert.is_nil(Util.split_jwt(nil))
  end)
end)

describe("Util.proof_claims_ok", function()
  local now = 1000
  local function claims(over)
    local base = { disp = "PASS", aud = "tn_1", exp = now + 120 }
    for k, v in pairs(over or {}) do base[k] = v end
    return base
  end

  it("accepts a PASS proof for the tenant that is not expired", function()
    assert.is_true(Util.proof_claims_ok(claims(), "tn_1", now))
  end)

  it("rejects a non-PASS disposition, a foreign tenant, and an expired proof", function()
    assert.is_false(Util.proof_claims_ok(claims({ disp = "CHALLENGE" }), "tn_1", now))
    assert.is_false(Util.proof_claims_ok(claims(), "tn_other", now))
    assert.is_false(Util.proof_claims_ok(claims({ exp = now - 1 }), "tn_1", now))
    assert.is_false(Util.proof_claims_ok(claims({ exp = "soon" }), "tn_1", now))
    assert.is_false(Util.proof_claims_ok("nope", "tn_1", now))
  end)
end)
