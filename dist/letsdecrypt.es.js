import { Buffer as c } from "buffer";
const T = "AES-GCM", R = "SHA-256", b = async (e) => {
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
  const n = "jwk", o = await crypto.subtle.exportKey(n, e), s = new TextEncoder().encode(JSON.stringify(o)), y = await b(t), i = crypto.getRandomValues(new Uint8Array(12)), p = await crypto.subtle.encrypt({ name: T, iv: i }, y, s);
  return {
    wrappedKey: c.from(p).toString("base64"),
    iv: c.from(i).toString("base64"),
    algorithm: r,
    format: n,
    namedCurve: a,
    protected: t.length > 0 ? !0 : void 0
  };
}, C = async (e, t = "spki") => {
  const r = await crypto.subtle.exportKey(t, e), a = await crypto.subtle.digest(R, r);
  return c.from(a).toString("hex");
}, l = "RSA-OAEP", d = "AES-GCM", H = 2048, P = "SHA-256", N = (e) => ({
  name: l,
  modulusLength: (e == null ? void 0 : e.rsaModulusLength) || H,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: P
}), g = {
  async generateKeyPair(e) {
    const t = N(e), r = await crypto.subtle.generateKey(t, !0, ["encrypt", "decrypt"]), a = await A(r.privateKey, (e == null ? void 0 : e.passphrase) ?? "", t.name);
    return {
      publicKey: await k(r.publicKey, t.name),
      privateKey: a
    };
  },
  async importPublicKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? JSON.parse(e) : e, { wrappedKey: r, algorithm: a, format: n } = t, o = { name: a, hash: P }, s = c.from(r, "base64");
    return await crypto.subtle.importKey(n, s, o, !0, ["encrypt"]);
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? JSON.parse(e) : e, a = await b(t), n = c.from(r.wrappedKey, "base64"), o = c.from(r.iv, "base64"), s = await crypto.subtle.decrypt({ name: d, iv: o }, a, n), y = r.format || "pkcs8", i = y === "jwk" ? JSON.parse(new TextDecoder().decode(s)) : s;
    return crypto.subtle.importKey(
      y,
      i,
      {
        name: l,
        hash: P
      },
      !0,
      ["decrypt"]
    );
  },
  async encrypt(e, t) {
    t = await this.importPublicKey(t);
    const r = await crypto.subtle.generateKey(
      {
        name: d,
        length: 256
      },
      !0,
      ["encrypt", "decrypt"]
    ), a = crypto.getRandomValues(new Uint8Array(12)), n = new TextEncoder().encode(e), o = await crypto.subtle.encrypt(
      {
        name: d,
        iv: a
      },
      r,
      n
    ), s = await crypto.subtle.exportKey("raw", r), y = await crypto.subtle.encrypt(
      {
        name: l
      },
      t,
      s
    ), i = {
      algorithm: l,
      keyHash: await C(t),
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
        name: l
      },
      t,
      o
    ), y = await crypto.subtle.importKey(
      "raw",
      s,
      {
        name: d,
        length: 256
      },
      !1,
      ["decrypt"]
    ), i = c.from(a.encryptedData, "base64"), p = c.from(n.iv, "base64"), v = await crypto.subtle.decrypt(
      {
        name: d,
        iv: p
      },
      y,
      i
    );
    return new TextDecoder().decode(v);
  }
}, m = "ECDH", x = "P-256", u = "AES-GCM", G = (e) => ({
  name: m,
  namedCurve: (e == null ? void 0 : e.eccCurve) || x
}), h = {
  async generateKeyPair(e) {
    const t = G(e), r = await crypto.subtle.generateKey(t, !0, ["deriveKey", "deriveBits"]), a = await A(
      r.privateKey,
      (e == null ? void 0 : e.passphrase) ?? "",
      t.name,
      t.namedCurve
    );
    return {
      publicKey: await k(r.publicKey, t.name, t.namedCurve),
      privateKey: a
    };
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? JSON.parse(e) : e, a = await b(t), n = c.from(r.wrappedKey, "base64"), o = c.from(r.iv, "base64"), s = await crypto.subtle.decrypt({ name: u, iv: o }, a, n), y = r.format || (r.algorithm === m ? "jwk" : "pkcs8"), i = y === "jwk" ? JSON.parse(new TextDecoder().decode(s)) : s, p = { name: m, namedCurve: r.namedCurve };
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
        name: u,
        length: 256
      },
      !1,
      ["encrypt"]
    ), o = crypto.getRandomValues(new Uint8Array(12)), s = new TextEncoder().encode(e), y = await crypto.subtle.encrypt(
      {
        name: u,
        iv: o
      },
      n,
      s
    ), i = await crypto.subtle.exportKey("spki", a.publicKey), p = {
      algorithm: m,
      keyHash: await C(t),
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
        name: u,
        length: 256
      },
      !1,
      ["decrypt"]
    ), s = c.from(a.encryptedData, "base64"), y = c.from(a.metadata.iv, "base64"), i = await crypto.subtle.decrypt(
      {
        name: u,
        iv: y
      },
      o,
      s
    );
    return new TextDecoder().decode(i);
  }
}, w = "AES-CTR", J = "AES-GCM", E = { name: w, length: 256 }, S = {
  async generateKeyPair(e) {
    const t = await crypto.subtle.generateKey(E, !0, ["encrypt", "decrypt"]), r = (e == null ? void 0 : e.passphrase) || "", a = {
      wrappedKey: c.from(JSON.stringify(await crypto.subtle.exportKey("jwk", t))).toString("base64"),
      algorithm: w,
      format: "jwk"
    }, n = r.length > 0 ? await A(t, r, w) : a;
    return {
      publicKey: a,
      privateKey: n
    };
  },
  async importPublicKey(e) {
    return this.importPrivateKey(e, "");
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? JSON.parse(e) : e, { wrappedKey: a, format: n, iv: o, protected: s } = r, y = E;
    if (s) {
      const v = await b(t), M = await crypto.subtle.decrypt(
        { name: J, iv: c.from(o, "base64") },
        v,
        c.from(a, "base64")
      ), D = JSON.parse(new TextDecoder().decode(M));
      return await crypto.subtle.importKey(n, D, y, !0, ["encrypt", "decrypt"]);
    }
    const i = c.from(a, "base64").toString(), p = JSON.parse(i);
    return await crypto.subtle.importKey(n, p, y, !0, ["encrypt", "decrypt"]);
  },
  async encrypt(e, t) {
    t = await this.importPublicKey(t);
    const r = new TextEncoder().encode(e), a = { name: "AES-CTR", counter: new Uint8Array(16), length: 16 * 8 }, n = await crypto.subtle.encrypt(a, t, r), o = {
      algorithm: w,
      keyHash: await C(t, "raw")
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
class O extends Error {
  constructor(t, ...r) {
    super(...r), this.name = "UnhandledMatchError", this.message = `Unhandled match value of type ${typeof t} - ${t}`, Error.captureStackTrace(this, O);
  }
}
function I(e) {
  throw e;
}
const f = Symbol(), L = (e) => I(new O(e)), K = (e, t, r = L) => {
  const a = /* @__PURE__ */ new Map(), n = Array.isArray(t) ? t : Object.entries(t).map(([s, y]) => [s, y]);
  for (const [...s] of n) {
    const y = s.pop();
    for (const i of s.flat())
      a.has(i) || a.set(i, y);
  }
  a.has(f) || a.set(f, r);
  const o = a.get(e) ?? a.get(f);
  return typeof o == "function" ? o(e) : o;
};
K.default = f;
const U = async (e) => {
  let t;
  if (typeof e == "string")
    t = JSON.parse(e);
  else if (typeof e == "object")
    t = e;
  else
    return e;
  return K(t.algorithm, [
    ["RSA-OAEP", () => g.importPublicKey(t)],
    ["ECDH", () => h.importPublicKey(t)],
    ["AES-CTR", () => S.importPublicKey(t)]
  ]);
}, j = async (e) => K((e == null ? void 0 : e.algorithm) ?? "RSA", [
  ["RSA", () => g.generateKeyPair(e)],
  ["ECC", () => h.generateKeyPair(e)],
  ["AES", () => S.generateKeyPair(e)]
]), B = async (e) => ({
  publicKey: JSON.stringify(e.publicKey),
  privateKey: JSON.stringify(e.privateKey)
}), F = async (e, t) => {
  const r = await U(t);
  return K(r.algorithm.name, [
    ["RSA-OAEP", async () => g.encrypt(e, r)],
    ["ECDH", async () => h.encrypt(e, r)],
    ["AES-CTR", async () => S.encrypt(e, r)]
  ]);
}, V = async (e, t, r) => (typeof e == "string" && (e = JSON.parse(e)), K(e.metadata.algorithm, [
  ["RSA-OAEP", async () => g.decrypt(e, t, r)],
  ["ECDH", async () => h.decrypt(e, t, r)],
  ["AES-CTR", async () => S.decrypt(e, t, r)]
]));
export {
  V as decrypt,
  F as encrypt,
  B as exportKeyPair,
  j as generateKeyPair
};
