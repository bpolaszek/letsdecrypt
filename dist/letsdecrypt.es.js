import { Buffer as o } from "buffer";
const T = "AES-GCM", R = "SHA-256", A = async (e) => {
  const t = new TextEncoder(), r = await crypto.subtle.importKey("raw", t.encode(e), "PBKDF2", !1, [
    "deriveBits",
    "deriveKey"
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: t.encode("salt"),
      iterations: 1e5,
      hash: R
    },
    r,
    {
      name: T,
      length: 256
    },
    !0,
    ["encrypt", "decrypt"]
  );
}, k = async (e, t, r, a) => ({
  fingerprint: r,
  wrappedKey: o.from(await crypto.subtle.exportKey("spki", e)).toString("base64"),
  iv: o.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64"),
  format: "spki",
  algorithm: t,
  namedCurve: a
}), P = async (e, t, r, a, n) => {
  const c = "jwk", s = await crypto.subtle.exportKey(c, e), y = new TextEncoder().encode(JSON.stringify(s)), i = await A(t), p = crypto.getRandomValues(new Uint8Array(12)), K = await crypto.subtle.encrypt({ name: T, iv: p }, i, y);
  return {
    fingerprint: a,
    wrappedKey: o.from(K).toString("base64"),
    iv: o.from(p).toString("base64"),
    algorithm: r,
    format: c,
    namedCurve: n,
    protected: t.length > 0 ? !0 : void 0
  };
}, u = async (e, t = "spki") => {
  const r = await crypto.subtle.exportKey(t, e), a = await crypto.subtle.digest(R, r);
  return o.from(a).toString("hex");
}, f = "RSA-OAEP", l = "AES-GCM", M = 2048, C = "SHA-256", N = (e) => ({
  name: f,
  modulusLength: (e == null ? void 0 : e.rsaModulusLength) || M,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: C
}), g = {
  async generateKeyPair(e) {
    const t = N(e), r = await crypto.subtle.generateKey(t, !0, ["encrypt", "decrypt"]), a = await u(r.publicKey), n = await P(
      r.privateKey,
      (e == null ? void 0 : e.passphrase) ?? "",
      t.name,
      a
    );
    return {
      publicKey: await k(r.publicKey, t.name, a),
      privateKey: n,
      fingerprint: a
    };
  },
  async importPublicKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? JSON.parse(e) : e, { wrappedKey: r, algorithm: a, format: n } = t, c = { name: a, hash: C }, s = o.from(r, "base64");
    return await crypto.subtle.importKey(n, s, c, !0, ["encrypt"]);
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? JSON.parse(e) : e, a = await A(t), n = o.from(r.wrappedKey, "base64"), c = o.from(r.iv, "base64"), s = await crypto.subtle.decrypt({ name: l, iv: c }, a, n), y = r.format || "pkcs8", i = y === "jwk" ? JSON.parse(new TextDecoder().decode(s)) : s;
    return crypto.subtle.importKey(
      y,
      i,
      {
        name: f,
        hash: C
      },
      !0,
      ["decrypt"]
    );
  },
  async encrypt(e, t) {
    t = await this.importPublicKey(t);
    const r = await crypto.subtle.generateKey(
      {
        name: l,
        length: 256
      },
      !0,
      ["encrypt", "decrypt"]
    ), a = crypto.getRandomValues(new Uint8Array(12)), n = new TextEncoder().encode(e), c = await crypto.subtle.encrypt(
      {
        name: l,
        iv: a
      },
      r,
      n
    ), s = await crypto.subtle.exportKey("raw", r), y = await crypto.subtle.encrypt(
      {
        name: f
      },
      t,
      s
    ), i = {
      algorithm: f,
      keyHash: await u(t),
      iv: o.from(a).toString("base64"),
      symmetricKey: o.from(y).toString("base64")
    };
    return {
      encryptedData: o.from(c).toString("base64"),
      metadata: i
    };
  },
  async decrypt(e, t, r) {
    const a = typeof e == "string" ? JSON.parse(e) : e;
    t = await this.importPrivateKey(t, r ?? "");
    const n = a.metadata, c = o.from(n.symmetricKey, "base64"), s = await crypto.subtle.decrypt(
      {
        name: f
      },
      t,
      c
    ), y = await crypto.subtle.importKey(
      "raw",
      s,
      {
        name: l,
        length: 256
      },
      !1,
      ["decrypt"]
    ), i = o.from(a.encryptedData, "base64"), p = o.from(n.iv, "base64"), K = await crypto.subtle.decrypt(
      {
        name: l,
        iv: p
      },
      y,
      i
    );
    return new TextDecoder().decode(K);
  }
}, m = "ECDH", x = "P-256", w = "AES-GCM", J = (e) => ({
  name: m,
  namedCurve: (e == null ? void 0 : e.eccCurve) || x
}), b = {
  async generateKeyPair(e) {
    const t = J(e), r = await crypto.subtle.generateKey(t, !0, ["deriveKey", "deriveBits"]), a = await u(r.publicKey), n = await P(
      r.privateKey,
      (e == null ? void 0 : e.passphrase) ?? "",
      t.name,
      a,
      t.namedCurve
    );
    return {
      publicKey: await k(r.publicKey, t.name, a, t.namedCurve),
      privateKey: n,
      fingerprint: a
    };
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? JSON.parse(e) : e, a = await A(t), n = o.from(r.wrappedKey, "base64"), c = o.from(r.iv, "base64"), s = await crypto.subtle.decrypt({ name: w, iv: c }, a, n), y = r.format || (r.algorithm === m ? "jwk" : "pkcs8"), i = y === "jwk" ? JSON.parse(new TextDecoder().decode(s)) : s, p = { name: m, namedCurve: r.namedCurve };
    return crypto.subtle.importKey(y, i, p, !0, ["deriveKey", "deriveBits"]);
  },
  async importPublicKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? JSON.parse(e) : e, { wrappedKey: r, algorithm: a, format: n, namedCurve: c } = t, s = { name: a, namedCurve: c }, y = o.from(r, "base64");
    return await crypto.subtle.importKey(n, y, s, !0, []);
  },
  async encrypt(e, t) {
    t = await this.importPublicKey(t);
    const r = t.algorithm, a = await crypto.subtle.generateKey(
      {
        name: m,
        namedCurve: r.namedCurve
      },
      !0,
      ["deriveKey", "deriveBits"]
    ), n = await crypto.subtle.deriveKey(
      {
        name: m,
        public: t
      },
      a.privateKey,
      {
        name: w,
        length: 256
      },
      !1,
      ["encrypt"]
    ), c = crypto.getRandomValues(new Uint8Array(12)), s = new TextEncoder().encode(e), y = await crypto.subtle.encrypt(
      {
        name: w,
        iv: c
      },
      n,
      s
    ), i = await crypto.subtle.exportKey("spki", a.publicKey), p = {
      algorithm: m,
      keyHash: await u(t),
      iv: o.from(c).toString("base64"),
      symmetricKey: "",
      // Not needed for ECC
      publicKey: o.from(i).toString("base64"),
      namedCurve: r.namedCurve
    };
    return {
      encryptedData: o.from(y).toString("base64"),
      metadata: p
    };
  },
  async decrypt(e, t, r) {
    const a = typeof e == "string" ? JSON.parse(e) : e;
    t = await this.importPrivateKey(t, r ?? "");
    const n = await crypto.subtle.importKey(
      "spki",
      o.from(a.metadata.publicKey, "base64"),
      {
        name: m,
        namedCurve: a.metadata.namedCurve ?? x
      },
      !0,
      []
    ), c = await crypto.subtle.deriveKey(
      {
        name: m,
        public: n
      },
      t,
      {
        name: w,
        length: 256
      },
      !1,
      ["decrypt"]
    ), s = o.from(a.encryptedData, "base64"), y = o.from(a.metadata.iv, "base64"), i = await crypto.subtle.decrypt(
      {
        name: w,
        iv: y
      },
      c,
      s
    );
    return new TextDecoder().decode(i);
  }
}, S = "AES-CTR", G = "AES-GCM", O = { name: S, length: 256 }, h = {
  async generateKeyPair(e) {
    const t = await crypto.subtle.generateKey(O, !0, ["encrypt", "decrypt"]), r = await u(t, "raw"), a = (e == null ? void 0 : e.passphrase) || "", n = {
      fingerprint: r,
      wrappedKey: o.from(JSON.stringify(await crypto.subtle.exportKey("jwk", t))).toString("base64"),
      algorithm: S,
      format: "jwk"
    }, c = a.length > 0 ? await P(t, a, S, r) : n;
    return {
      publicKey: n,
      privateKey: c,
      fingerprint: r
    };
  },
  async importPublicKey(e) {
    return this.importPrivateKey(e, "");
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? JSON.parse(e) : e, { wrappedKey: a, format: n, iv: c, protected: s } = r, y = O;
    if (s) {
      const K = await A(t), D = await crypto.subtle.decrypt(
        { name: G, iv: o.from(c, "base64") },
        K,
        o.from(a, "base64")
      ), H = JSON.parse(new TextDecoder().decode(D));
      return await crypto.subtle.importKey(n, H, y, !0, ["encrypt", "decrypt"]);
    }
    const i = o.from(a, "base64").toString(), p = JSON.parse(i);
    return await crypto.subtle.importKey(n, p, y, !0, ["encrypt", "decrypt"]);
  },
  async encrypt(e, t) {
    t = await this.importPublicKey(t);
    const r = new TextEncoder().encode(e), a = { name: "AES-CTR", counter: new Uint8Array(16), length: 16 * 8 }, n = await crypto.subtle.encrypt(a, t, r), c = {
      algorithm: S,
      keyHash: await u(t, "raw")
    };
    return {
      encryptedData: o.from(n).toString("base64"),
      metadata: c
    };
  },
  async decrypt(e, t, r) {
    const a = typeof e == "string" ? JSON.parse(e) : e;
    t = await this.importPrivateKey(t, r ?? "");
    const n = { name: "AES-CTR", counter: new Uint8Array(16), length: 16 * 8 };
    return new TextDecoder("utf-8").decode(
      await crypto.subtle.decrypt(n, t, o.from(a.encryptedData, "base64"))
    );
  }
};
class E extends Error {
  constructor(t, ...r) {
    super(...r), this.name = "UnhandledMatchError", this.message = `Unhandled match value of type ${typeof t} - ${t}`, Error.captureStackTrace(this, E);
  }
}
function I(e) {
  throw e;
}
const v = Symbol(), L = (e) => I(new E(e)), d = (e, t, r = L) => {
  const a = /* @__PURE__ */ new Map(), n = Array.isArray(t) ? t : Object.entries(t).map(([s, y]) => [s, y]);
  for (const [...s] of n) {
    const y = s.pop();
    for (const i of s.flat())
      a.has(i) || a.set(i, y);
  }
  a.has(v) || a.set(v, r);
  const c = a.get(e) ?? a.get(v);
  return typeof c == "function" ? c(e) : c;
};
d.default = v;
const U = async (e) => {
  let t;
  if (typeof e == "string")
    t = JSON.parse(e);
  else if (typeof e == "object")
    t = e;
  else
    return e;
  return d(t.algorithm, [
    ["RSA-OAEP", () => g.importPublicKey(t)],
    ["ECDH", () => b.importPublicKey(t)],
    ["AES-CTR", () => h.importPublicKey(t)]
  ]);
}, j = async (e, t, r) => {
  const a = typeof e == "string" ? JSON.parse(e) : e, n = await d(a.algorithm, [
    ["RSA-OAEP", () => g.importPrivateKey(a, t ?? "")],
    ["ECDH", () => b.importPrivateKey(a, t ?? "")],
    ["AES-CTR", () => h.importPrivateKey(a, t ?? "")]
  ]);
  return P(
    n,
    r ?? "",
    a.algorithm,
    a.fingerprint,
    a.namedCurve
  );
}, B = async (e) => d((e == null ? void 0 : e.algorithm) ?? "RSA", [
  ["RSA", () => g.generateKeyPair(e)],
  ["ECC", () => b.generateKeyPair(e)],
  ["AES", () => h.generateKeyPair(e)]
]), F = async (e) => ({
  publicKey: JSON.stringify(e.publicKey),
  privateKey: JSON.stringify(e.privateKey),
  fingerprint: e.fingerprint
}), V = async (e, t) => {
  const r = await U(t);
  return d(r.algorithm.name, [
    ["RSA-OAEP", async () => g.encrypt(e, r)],
    ["ECDH", async () => b.encrypt(e, r)],
    ["AES-CTR", async () => h.encrypt(e, r)]
  ]);
}, $ = async (e, t, r) => (typeof e == "string" && (e = JSON.parse(e)), d(e.metadata.algorithm, [
  ["RSA-OAEP", async () => g.decrypt(e, t, r)],
  ["ECDH", async () => b.decrypt(e, t, r)],
  ["AES-CTR", async () => h.decrypt(e, t, r)]
]));
export {
  j as changePassphrase,
  $ as decrypt,
  V as encrypt,
  F as exportKeyPair,
  B as generateKeyPair
};
