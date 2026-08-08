// Regenerates the ES256 proof + JWKS fixtures embedded in
// spec/presence/03-integration_spec.lua. The keypair is FIXED (below) so the
// output is byte-for-byte reproducible: run `node spec/fixtures/gen-proof.mjs`
// and paste PROOF_JWT / JWKS_JSON into the spec if the claims ever change.
//
// Kong (Lua) cannot mint an ES256 proof in-process, so the fast-path
// integration test verifies a proof signed offline here. Only the PUBLIC JWK
// ships in the spec (as the JWKS the plugin fetches); the private key never
// leaves this file. The proof is deliberately long-lived (exp in 2100) and
// scoped to the test tenant (aud "tn_test").
import { webcrypto } from "node:crypto";

const { subtle } = webcrypto;
const b64 = (s) => Buffer.from(s, "utf8").toString("base64url");
const KID = "presence-proof-es256-1";

// Fixed P-256 keypair — the private half is used only to sign the fixture.
const PRIVATE_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "Wa_Me6Nyaqcv-ttpIT7AmtikJWVUrkuutW4kYycBAxI",
  y: "izXXiq65gDrTiCAIVBaauECFWUN-vxrcChFk0r2qZLg",
  d: "dXrlhe04Ejh5wWK2deU-P7_GS6QtdvEOYRkbUu9l1Ys",
};

const claims = {
  iss: "http://mock",
  sub: "prs_fixture",
  aud: "tn_test",
  disp: "PASS",
  intent: "checkout.submit",
  assurance: { behavioral: true, webauthn: false, liveness: false },
  iat: 1700000000,
  exp: 4102444800, // 2100-01-01
};

const privateKey = await subtle.importKey(
  "jwk",
  PRIVATE_JWK,
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["sign"],
);
const signingInput = `${b64(JSON.stringify({ alg: "ES256", typ: "JWT", kid: KID }))}.${b64(JSON.stringify(claims))}`;
const sig = await subtle.sign(
  { name: "ECDSA", hash: "SHA-256" },
  privateKey,
  new TextEncoder().encode(signingInput),
);
const jwt = `${signingInput}.${Buffer.from(new Uint8Array(sig)).toString("base64url")}`;

const jwks = {
  keys: [
    {
      kty: "EC",
      crv: "P-256",
      x: PRIVATE_JWK.x,
      y: PRIVATE_JWK.y,
      kid: KID,
      alg: "ES256",
      use: "sig",
    },
  ],
};

// Self-check: the JWKS public key verifies the signature we just produced.
const publicKey = await subtle.importKey(
  "jwk",
  jwks.keys[0],
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["verify"],
);
const [h, p, s] = jwt.split(".");
const ok = await subtle.verify(
  { name: "ECDSA", hash: "SHA-256" },
  publicKey,
  Buffer.from(s, "base64url"),
  new TextEncoder().encode(`${h}.${p}`),
);
if (!ok) {
  throw new Error("self-check failed: JWKS does not verify the proof");
}

console.log("PROOF_JWT=" + jwt);
console.log("JWKS_JSON=" + JSON.stringify(jwks));
