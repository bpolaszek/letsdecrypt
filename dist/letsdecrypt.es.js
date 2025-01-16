import { Buffer as o } from "buffer";
const D = "AES-GCM", M = "SHA-256", P = async (e) => {
  const t = new TextEncoder(), r = await crypto.subtle.importKey("raw", t.encode(e), "PBKDF2", !1, [
    "deriveBits",
    "deriveKey"
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: t.encode("salt"),
      iterations: 1e5,
      hash: M
    },
    r,
    {
      name: D,
      length: 256
    },
    !0,
    ["encrypt", "decrypt"]
  );
}, H = async (e, t, r, a) => ({
  fingerprint: r,
  wrappedKey: o.from(await crypto.subtle.exportKey("spki", e)).toString("base64"),
  iv: o.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64"),
  format: "spki",
  algorithm: t,
  namedCurve: a
}), C = async (e, t, r, a, n) => {
  const c = "jwk", s = await crypto.subtle.exportKey(c, e), y = new TextEncoder().encode(JSON.stringify(s)), i = await P(t), p = crypto.getRandomValues(new Uint8Array(12)), K = await crypto.subtle.encrypt({ name: D, iv: p }, i, y);
  return {
    fingerprint: a,
    wrappedKey: o.from(K).toString("base64"),
    iv: o.from(p).toString("base64"),
    algorithm: r,
    format: c,
    namedCurve: n,
    protected: t.length > 0 ? !0 : void 0
  };
}, d = async (e, t = "spki") => {
  const r = await crypto.subtle.exportKey(t, e), a = await crypto.subtle.digest(M, r);
  return o.from(a).toString("hex");
}, g = "RSA-OAEP", w = "AES-GCM", U = 2048, E = "SHA-256", B = (e) => ({
  name: g,
  modulusLength: (e == null ? void 0 : e.rsaModulusLength) || U,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: E
}), b = {
  async generateKeyPair(e) {
    const t = B(e), r = await crypto.subtle.generateKey(t, !0, ["encrypt", "decrypt"]), a = await d(r.publicKey), n = await C(
      r.privateKey,
      (e == null ? void 0 : e.passphrase) ?? "",
      t.name,
      a
    );
    return {
      publicKey: await H(r.publicKey, t.name, a),
      privateKey: n,
      fingerprint: a
    };
  },
  async importPublicKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? u(e) : e, { wrappedKey: r, algorithm: a, format: n } = t, c = { name: a, hash: E }, s = o.from(r, "base64");
    return await crypto.subtle.importKey(n, s, c, !0, ["encrypt"]);
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? u(e) : e, a = await P(t), n = o.from(r.wrappedKey, "base64"), c = o.from(r.iv, "base64"), s = await crypto.subtle.decrypt({ name: w, iv: c }, a, n), y = r.format || "pkcs8", i = y === "jwk" ? JSON.parse(new TextDecoder().decode(s)) : s;
    return crypto.subtle.importKey(
      y,
      i,
      {
        name: g,
        hash: E
      },
      !0,
      ["decrypt"]
    );
  },
  async encrypt(e, t) {
    t = await this.importPublicKey(t);
    const r = await crypto.subtle.generateKey(
      {
        name: w,
        length: 256
      },
      !0,
      ["encrypt", "decrypt"]
    ), a = crypto.getRandomValues(new Uint8Array(12)), n = new TextEncoder().encode(e), c = await crypto.subtle.encrypt(
      {
        name: w,
        iv: a
      },
      r,
      n
    ), s = await crypto.subtle.exportKey("raw", r), y = await crypto.subtle.encrypt(
      {
        name: g
      },
      t,
      s
    ), i = {
      algorithm: g,
      keyFingerprint: await d(t),
      iv: o.from(a).toString("base64"),
      symmetricKey: o.from(y).toString("base64")
    };
    return {
      encryptedData: o.from(c).toString("base64"),
      metadata: i
    };
  },
  async decrypt(e, t, r) {
    const a = typeof e == "string" ? R(e) : e;
    t = await this.importPrivateKey(t, r ?? "");
    const n = a.metadata, c = o.from(n.symmetricKey, "base64"), s = await crypto.subtle.decrypt(
      {
        name: g
      },
      t,
      c
    ), y = await crypto.subtle.importKey(
      "raw",
      s,
      {
        name: w,
        length: 256
      },
      !1,
      ["decrypt"]
    ), i = o.from(a.encryptedData, "base64"), p = o.from(n.iv, "base64"), K = await crypto.subtle.decrypt(
      {
        name: w,
        iv: p
      },
      y,
      i
    );
    return new TextDecoder().decode(K);
  }
}, m = "ECDH", G = "P-256", f = "AES-GCM", _ = (e) => ({
  name: m,
  namedCurve: (e == null ? void 0 : e.eccCurve) || G
}), h = {
  async generateKeyPair(e) {
    const t = _(e), r = await crypto.subtle.generateKey(t, !0, ["deriveKey", "deriveBits"]), a = await d(r.publicKey), n = await C(
      r.privateKey,
      (e == null ? void 0 : e.passphrase) ?? "",
      t.name,
      a,
      t.namedCurve
    );
    return {
      publicKey: await H(r.publicKey, t.name, a, t.namedCurve),
      privateKey: n,
      fingerprint: a
    };
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? u(e) : e, a = await P(t), n = o.from(r.wrappedKey, "base64"), c = o.from(r.iv, "base64"), s = await crypto.subtle.decrypt({ name: f, iv: c }, a, n), y = r.format || (r.algorithm === m ? "jwk" : "pkcs8"), i = y === "jwk" ? JSON.parse(new TextDecoder().decode(s)) : s, p = { name: m, namedCurve: r.namedCurve };
    return crypto.subtle.importKey(y, i, p, !0, ["deriveKey", "deriveBits"]);
  },
  async importPublicKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? u(e) : e, { wrappedKey: r, algorithm: a, format: n, namedCurve: c } = t, s = { name: a, namedCurve: c }, y = o.from(r, "base64");
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
        name: f,
        length: 256
      },
      !1,
      ["encrypt"]
    ), c = crypto.getRandomValues(new Uint8Array(12)), s = new TextEncoder().encode(e), y = await crypto.subtle.encrypt(
      {
        name: f,
        iv: c
      },
      n,
      s
    ), i = await crypto.subtle.exportKey("spki", a.publicKey), p = {
      algorithm: m,
      keyFingerprint: await d(t),
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
    const a = typeof e == "string" ? R(e) : e;
    t = await this.importPrivateKey(t, r ?? "");
    const n = await crypto.subtle.importKey(
      "spki",
      o.from(a.metadata.publicKey, "base64"),
      {
        name: m,
        namedCurve: a.metadata.namedCurve ?? G
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
        name: f,
        length: 256
      },
      !1,
      ["decrypt"]
    ), s = o.from(a.encryptedData, "base64"), y = o.from(a.metadata.iv, "base64"), i = await crypto.subtle.decrypt(
      {
        name: f,
        iv: y
      },
      c,
      s
    );
    return new TextDecoder().decode(i);
  }
}, v = "AES-CTR", j = "AES-GCM", k = { name: v, length: 256 }, S = {
  async generateKeyPair(e) {
    const t = await crypto.subtle.generateKey(k, !0, ["encrypt", "decrypt"]), r = await d(t, "raw"), a = (e == null ? void 0 : e.passphrase) || "", n = {
      fingerprint: r,
      wrappedKey: o.from(JSON.stringify(await crypto.subtle.exportKey("jwk", t))).toString("base64"),
      algorithm: v,
      format: "jwk"
    }, c = a.length > 0 ? await C(t, a, v, r) : n;
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
    const r = typeof e == "string" ? u(e) : e, { wrappedKey: a, format: n, iv: c, protected: s } = r, y = k;
    if (s) {
      const K = await P(t), L = await crypto.subtle.decrypt(
        { name: j, iv: o.from(c, "base64") },
        K,
        o.from(a, "base64")
      ), N = JSON.parse(new TextDecoder().decode(L));
      return await crypto.subtle.importKey(n, N, y, !0, ["encrypt", "decrypt"]);
    }
    const i = o.from(a, "base64").toString(), p = JSON.parse(i);
    return await crypto.subtle.importKey(n, p, y, !0, ["encrypt", "decrypt"]);
  },
  async encrypt(e, t) {
    t = await this.importPublicKey(t);
    const r = new TextEncoder().encode(e), a = { name: "AES-CTR", counter: new Uint8Array(16), length: 16 * 8 }, n = await crypto.subtle.encrypt(a, t, r), c = {
      algorithm: v,
      keyFingerprint: await d(t, "raw")
    };
    return {
      encryptedData: o.from(n).toString("base64"),
      metadata: c
    };
  },
  async decrypt(e, t, r) {
    const a = typeof e == "string" ? R(e) : e;
    t = await this.importPrivateKey(t, r ?? "");
    const n = { name: "AES-CTR", counter: new Uint8Array(16), length: 16 * 8 };
    return new TextDecoder("utf-8").decode(
      await crypto.subtle.decrypt(n, t, o.from(a.encryptedData, "base64"))
    );
  }
};
class T extends Error {
  constructor(t, ...r) {
    super(...r), this.name = "UnhandledMatchError", this.message = `Unhandled match value of type ${typeof t} - ${t}`, Error.captureStackTrace(this, T);
  }
}
function J(e) {
  throw e;
}
const A = Symbol(), F = (e) => J(new T(e)), l = (e, t, r = F) => {
  const a = /* @__PURE__ */ new Map(), n = Array.isArray(t) ? t : Object.entries(t).map(([s, y]) => [s, y]);
  for (const [...s] of n) {
    const y = s.pop();
    for (const i of s.flat())
      a.has(i) || a.set(i, y);
  }
  a.has(A) || a.set(A, r);
  const c = a.get(e) ?? a.get(A);
  return typeof c == "function" ? c(e) : c;
};
l.default = A;
function I(e) {
  return btoa(encodeURIComponent(e));
}
function O(e) {
  return decodeURIComponent(atob(e));
}
const V = async (e) => {
  let t;
  if (typeof e == "string")
    t = u(e);
  else if (typeof e == "object")
    t = e;
  else
    return e;
  return l(t.algorithm, [
    ["RSA-OAEP", () => b.importPublicKey(t)],
    ["ECDH", () => h.importPublicKey(t)],
    ["AES-CTR", () => S.importPublicKey(t)]
  ]);
}, z = async (e, t, r) => {
  const a = typeof e == "string" ? u(e) : e, n = await l(a.algorithm, [
    ["RSA-OAEP", () => b.importPrivateKey(a, t ?? "")],
    ["ECDH", () => h.importPrivateKey(a, t ?? "")],
    ["AES-CTR", () => S.importPrivateKey(a, t ?? "")]
  ]);
  return C(
    n,
    r ?? "",
    a.algorithm,
    a.fingerprint,
    a.namedCurve
  );
}, Y = async (e) => l((e == null ? void 0 : e.algorithm) ?? "RSA", [
  ["RSA", () => b.generateKeyPair(e)],
  ["ECC", () => h.generateKeyPair(e)],
  ["AES", () => S.generateKeyPair(e)]
]), x = (e) => I(JSON.stringify(e)), u = (e) => JSON.parse(O(e)), q = async (e) => ({
  publicKey: x(e.publicKey),
  privateKey: x(e.privateKey),
  fingerprint: e.fingerprint
}), Q = async (e, t) => {
  const r = await V(t);
  return l(r.algorithm.name, [
    ["RSA-OAEP", async () => b.encrypt(e, r)],
    ["ECDH", async () => h.encrypt(e, r)],
    ["AES-CTR", async () => S.encrypt(e, r)]
  ]);
}, W = (e) => I(JSON.stringify(e)), R = (e) => JSON.parse(O(e)), X = async (e, t, r) => (typeof e == "string" && (e = JSON.parse(O(e))), l(e.metadata.algorithm, [
  ["RSA-OAEP", async () => b.decrypt(e, t, r)],
  ["ECDH", async () => h.decrypt(e, t, r)],
  ["AES-CTR", async () => S.decrypt(e, t, r)]
]));
export {
  z as changePassphrase,
  X as decrypt,
  Q as encrypt,
  q as exportKeyPair,
  Y as generateKeyPair,
  x as serializeKey,
  W as serializeSecret,
  u as unserializeKey,
  R as unserializeSecret
};
