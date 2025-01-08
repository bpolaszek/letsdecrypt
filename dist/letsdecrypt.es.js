import { Buffer as c } from "buffer";
const T = "AES-GCM", R = "SHA-256", v = async (e) => {
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
}, k = async (e, t, r) => ({
  wrappedKey: c.from(await crypto.subtle.exportKey("spki", e)).toString("base64"),
  iv: c.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64"),
  format: "spki",
  algorithm: t,
  namedCurve: r
}), A = async (e, t, r, a) => {
  const n = "jwk", o = await crypto.subtle.exportKey(n, e), s = new TextEncoder().encode(JSON.stringify(o)), y = await v(t), i = crypto.getRandomValues(new Uint8Array(12)), p = await crypto.subtle.encrypt({ name: T, iv: i }, y, s);
  return {
    wrappedKey: c.from(p).toString("base64"),
    iv: c.from(i).toString("base64"),
    algorithm: r,
    format: n,
    namedCurve: a,
    protected: t.length > 0 ? !0 : void 0
  };
}, u = async (e, t = "spki") => {
  const r = await crypto.subtle.exportKey(t, e), a = await crypto.subtle.digest(R, r);
  return c.from(a).toString("hex");
}, w = "RSA-OAEP", K = "AES-GCM", M = 2048, C = "SHA-256", N = (e) => ({
  name: w,
  modulusLength: (e == null ? void 0 : e.rsaModulusLength) || M,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: C
}), f = {
  async generateKeyPair(e) {
    const t = N(e), r = await crypto.subtle.generateKey(t, !0, ["encrypt", "decrypt"]), a = await A(r.privateKey, (e == null ? void 0 : e.passphrase) ?? "", t.name);
    return {
      publicKey: await k(r.publicKey, t.name),
      privateKey: a,
      fingerprint: await u(r.publicKey)
    };
  },
  async importPublicKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? JSON.parse(e) : e, { wrappedKey: r, algorithm: a, format: n } = t, o = { name: a, hash: C }, s = c.from(r, "base64");
    return await crypto.subtle.importKey(n, s, o, !0, ["encrypt"]);
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? JSON.parse(e) : e, a = await v(t), n = c.from(r.wrappedKey, "base64"), o = c.from(r.iv, "base64"), s = await crypto.subtle.decrypt({ name: K, iv: o }, a, n), y = r.format || "pkcs8", i = y === "jwk" ? JSON.parse(new TextDecoder().decode(s)) : s;
    return crypto.subtle.importKey(
      y,
      i,
      {
        name: w,
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
        name: K,
        length: 256
      },
      !0,
      ["encrypt", "decrypt"]
    ), a = crypto.getRandomValues(new Uint8Array(12)), n = new TextEncoder().encode(e), o = await crypto.subtle.encrypt(
      {
        name: K,
        iv: a
      },
      r,
      n
    ), s = await crypto.subtle.exportKey("raw", r), y = await crypto.subtle.encrypt(
      {
        name: w
      },
      t,
      s
    ), i = {
      algorithm: w,
      keyHash: await u(t),
      iv: c.from(a).toString("base64"),
      symmetricKey: c.from(y).toString("base64")
    };
    return {
      encryptedData: c.from(o).toString("base64"),
      metadata: i
    };
  },
  async decrypt(e, t, r) {
    const a = typeof e == "string" ? JSON.parse(e) : e;
    t = await this.importPrivateKey(t, r ?? "");
    const n = a.metadata, o = c.from(n.symmetricKey, "base64"), s = await crypto.subtle.decrypt(
      {
        name: w
      },
      t,
      o
    ), y = await crypto.subtle.importKey(
      "raw",
      s,
      {
        name: K,
        length: 256
      },
      !1,
      ["decrypt"]
    ), i = c.from(a.encryptedData, "base64"), p = c.from(n.iv, "base64"), P = await crypto.subtle.decrypt(
      {
        name: K,
        iv: p
      },
      y,
      i
    );
    return new TextDecoder().decode(P);
  }
}, m = "ECDH", x = "P-256", l = "AES-GCM", J = (e) => ({
  name: m,
  namedCurve: (e == null ? void 0 : e.eccCurve) || x
}), g = {
  async generateKeyPair(e) {
    const t = J(e), r = await crypto.subtle.generateKey(t, !0, ["deriveKey", "deriveBits"]), a = await A(
      r.privateKey,
      (e == null ? void 0 : e.passphrase) ?? "",
      t.name,
      t.namedCurve
    );
    return {
      publicKey: await k(r.publicKey, t.name, t.namedCurve),
      privateKey: a,
      fingerprint: await u(r.publicKey)
    };
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? JSON.parse(e) : e, a = await v(t), n = c.from(r.wrappedKey, "base64"), o = c.from(r.iv, "base64"), s = await crypto.subtle.decrypt({ name: l, iv: o }, a, n), y = r.format || (r.algorithm === m ? "jwk" : "pkcs8"), i = y === "jwk" ? JSON.parse(new TextDecoder().decode(s)) : s, p = { name: m, namedCurve: r.namedCurve };
    return crypto.subtle.importKey(y, i, p, !0, ["deriveKey", "deriveBits"]);
  },
  async importPublicKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? JSON.parse(e) : e, { wrappedKey: r, algorithm: a, format: n, namedCurve: o } = t, s = { name: a, namedCurve: o }, y = c.from(r, "base64");
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
        name: l,
        length: 256
      },
      !1,
      ["encrypt"]
    ), o = crypto.getRandomValues(new Uint8Array(12)), s = new TextEncoder().encode(e), y = await crypto.subtle.encrypt(
      {
        name: l,
        iv: o
      },
      n,
      s
    ), i = await crypto.subtle.exportKey("spki", a.publicKey), p = {
      algorithm: m,
      keyHash: await u(t),
      iv: c.from(o).toString("base64"),
      symmetricKey: "",
      // Not needed for ECC
      publicKey: c.from(i).toString("base64"),
      namedCurve: r.namedCurve
    };
    return {
      encryptedData: c.from(y).toString("base64"),
      metadata: p
    };
  },
  async decrypt(e, t, r) {
    const a = typeof e == "string" ? JSON.parse(e) : e;
    t = await this.importPrivateKey(t, r ?? "");
    const n = await crypto.subtle.importKey(
      "spki",
      c.from(a.metadata.publicKey, "base64"),
      {
        name: m,
        namedCurve: a.metadata.namedCurve ?? x
      },
      !0,
      []
    ), o = await crypto.subtle.deriveKey(
      {
        name: m,
        public: n
      },
      t,
      {
        name: l,
        length: 256
      },
      !1,
      ["decrypt"]
    ), s = c.from(a.encryptedData, "base64"), y = c.from(a.metadata.iv, "base64"), i = await crypto.subtle.decrypt(
      {
        name: l,
        iv: y
      },
      o,
      s
    );
    return new TextDecoder().decode(i);
  }
}, h = "AES-CTR", G = "AES-GCM", O = { name: h, length: 256 }, b = {
  async generateKeyPair(e) {
    const t = await crypto.subtle.generateKey(O, !0, ["encrypt", "decrypt"]), r = (e == null ? void 0 : e.passphrase) || "", a = {
      wrappedKey: c.from(JSON.stringify(await crypto.subtle.exportKey("jwk", t))).toString("base64"),
      algorithm: h,
      format: "jwk"
    }, n = r.length > 0 ? await A(t, r, h) : a;
    return {
      publicKey: a,
      privateKey: n,
      fingerprint: await u(t, "raw")
    };
  },
  async importPublicKey(e) {
    return this.importPrivateKey(e, "");
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? JSON.parse(e) : e, { wrappedKey: a, format: n, iv: o, protected: s } = r, y = O;
    if (s) {
      const P = await v(t), D = await crypto.subtle.decrypt(
        { name: G, iv: c.from(o, "base64") },
        P,
        c.from(a, "base64")
      ), H = JSON.parse(new TextDecoder().decode(D));
      return await crypto.subtle.importKey(n, H, y, !0, ["encrypt", "decrypt"]);
    }
    const i = c.from(a, "base64").toString(), p = JSON.parse(i);
    return await crypto.subtle.importKey(n, p, y, !0, ["encrypt", "decrypt"]);
  },
  async encrypt(e, t) {
    t = await this.importPublicKey(t);
    const r = new TextEncoder().encode(e), a = { name: "AES-CTR", counter: new Uint8Array(16), length: 16 * 8 }, n = await crypto.subtle.encrypt(a, t, r), o = {
      algorithm: h,
      keyHash: await u(t, "raw")
    };
    return {
      encryptedData: c.from(n).toString("base64"),
      metadata: o
    };
  },
  async decrypt(e, t, r) {
    const a = typeof e == "string" ? JSON.parse(e) : e;
    t = await this.importPrivateKey(t, r ?? "");
    const n = { name: "AES-CTR", counter: new Uint8Array(16), length: 16 * 8 };
    return new TextDecoder("utf-8").decode(
      await crypto.subtle.decrypt(n, t, c.from(a.encryptedData, "base64"))
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
const S = Symbol(), L = (e) => I(new E(e)), d = (e, t, r = L) => {
  const a = /* @__PURE__ */ new Map(), n = Array.isArray(t) ? t : Object.entries(t).map(([s, y]) => [s, y]);
  for (const [...s] of n) {
    const y = s.pop();
    for (const i of s.flat())
      a.has(i) || a.set(i, y);
  }
  a.has(S) || a.set(S, r);
  const o = a.get(e) ?? a.get(S);
  return typeof o == "function" ? o(e) : o;
};
d.default = S;
const U = async (e) => {
  let t;
  if (typeof e == "string")
    t = JSON.parse(e);
  else if (typeof e == "object")
    t = e;
  else
    return e;
  return d(t.algorithm, [
    ["RSA-OAEP", () => f.importPublicKey(t)],
    ["ECDH", () => g.importPublicKey(t)],
    ["AES-CTR", () => b.importPublicKey(t)]
  ]);
}, j = async (e, t, r) => {
  const a = typeof e == "string" ? JSON.parse(e) : e, n = await d(a.algorithm, [
    ["RSA-OAEP", () => f.importPrivateKey(a, t ?? "")],
    ["ECDH", () => g.importPrivateKey(a, t ?? "")],
    ["AES-CTR", () => b.importPrivateKey(a, t ?? "")]
  ]);
  return A(n, r ?? "", a.algorithm, a.namedCurve);
}, B = async (e) => d((e == null ? void 0 : e.algorithm) ?? "RSA", [
  ["RSA", () => f.generateKeyPair(e)],
  ["ECC", () => g.generateKeyPair(e)],
  ["AES", () => b.generateKeyPair(e)]
]), F = async (e) => ({
  publicKey: JSON.stringify(e.publicKey),
  privateKey: JSON.stringify(e.privateKey),
  fingerprint: e.fingerprint
}), V = async (e, t) => {
  const r = await U(t);
  return d(r.algorithm.name, [
    ["RSA-OAEP", async () => f.encrypt(e, r)],
    ["ECDH", async () => g.encrypt(e, r)],
    ["AES-CTR", async () => b.encrypt(e, r)]
  ]);
}, $ = async (e, t, r) => (typeof e == "string" && (e = JSON.parse(e)), d(e.metadata.algorithm, [
  ["RSA-OAEP", async () => f.decrypt(e, t, r)],
  ["ECDH", async () => g.decrypt(e, t, r)],
  ["AES-CTR", async () => b.decrypt(e, t, r)]
]));
export {
  j as changePassphrase,
  $ as decrypt,
  V as encrypt,
  F as exportKeyPair,
  B as generateKeyPair
};
