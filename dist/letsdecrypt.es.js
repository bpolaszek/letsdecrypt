import { Buffer as y } from "buffer";
const H = "ECDH", S = "AES-GCM", v = "SHA-256", f = async (e) => {
  const t = new TextEncoder(), r = await crypto.subtle.importKey("raw", t.encode(e), "PBKDF2", !1, [
    "deriveBits",
    "deriveKey"
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: t.encode("salt"),
      iterations: 1e5,
      hash: v
    },
    r,
    {
      name: S,
      length: 256
    },
    !0,
    ["encrypt", "decrypt"]
  );
}, P = async (e, t, r) => ({
  wrappedKey: y.from(await crypto.subtle.exportKey("spki", e)).toString("base64"),
  iv: y.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64"),
  format: "spki",
  algorithm: t,
  namedCurve: r
}), A = async (e, t, r, a) => {
  const n = r === H ? "jwk" : "pkcs8", s = await crypto.subtle.exportKey(n, e), c = n === "jwk" ? new TextEncoder().encode(JSON.stringify(s)) : new Uint8Array(s), o = await f(t), i = crypto.getRandomValues(new Uint8Array(12)), m = await crypto.subtle.encrypt({ name: S, iv: i }, o, c);
  return {
    wrappedKey: y.from(m).toString("base64"),
    iv: y.from(i).toString("base64"),
    algorithm: r,
    format: n,
    namedCurve: a
  };
}, E = async (e) => {
  const t = await crypto.subtle.exportKey("spki", e), r = await crypto.subtle.digest(v, t);
  return y.from(r).toString("hex");
}, l = "RSA-OAEP", d = "AES-GCM", R = 2048, C = "SHA-256", U = (e) => ({
  name: l,
  modulusLength: (e == null ? void 0 : e.rsaModulusLength) || R,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: C
}), w = {
  getPublicKeyUsages() {
    return ["encrypt"];
  },
  getPrivateKeyUsages() {
    return ["decrypt"];
  },
  getKeyPairUsages() {
    return ["encrypt", "decrypt"];
  },
  getAlgorithm() {
    return "RSA-OAEP";
  },
  async generateKeyPair(e) {
    const t = U(e), r = await crypto.subtle.generateKey(t, !0, this.getKeyPairUsages()), a = await A(r.privateKey, (e == null ? void 0 : e.passphrase) ?? "", t.name);
    return {
      publicKey: await P(r.publicKey, t.name),
      privateKey: a
    };
  },
  async unwrapKey(e, t) {
    const r = await f(t), a = y.from(e.wrappedKey, "base64"), n = y.from(e.iv, "base64"), s = await crypto.subtle.decrypt({ name: d, iv: n }, r, a), c = e.format || "pkcs8", o = c === "jwk" ? JSON.parse(new TextDecoder().decode(s)) : s;
    return crypto.subtle.importKey(
      c,
      o,
      {
        name: l,
        hash: C
      },
      !0,
      this.getPrivateKeyUsages()
    );
  },
  async importPrivateKey(e, t) {
    const r = JSON.parse(e);
    return this.unwrapKey(r, t ?? "");
  },
  async encrypt(e, t) {
    const r = await crypto.subtle.generateKey(
      {
        name: d,
        length: 256
      },
      !0,
      ["encrypt", "decrypt"]
    ), a = crypto.getRandomValues(new Uint8Array(12)), n = new TextEncoder().encode(e), s = await crypto.subtle.encrypt(
      {
        name: d,
        iv: a
      },
      r,
      n
    ), c = await crypto.subtle.exportKey("raw", r), o = await crypto.subtle.encrypt(
      {
        name: l
      },
      t,
      c
    ), i = {
      algorithm: l,
      keyHash: await E(t),
      iv: y.from(a).toString("base64"),
      symmetricKey: y.from(o).toString("base64")
    };
    return {
      encryptedData: y.from(s).toString("base64"),
      metadata: i
    };
  },
  async decrypt(e, t, r) {
    const a = typeof e == "string" ? JSON.parse(e) : e;
    let n;
    typeof t == "string" ? n = await this.importPrivateKey(t, r) : "wrappedKey" in t ? n = await this.unwrapKey(t, r ?? "") : n = t;
    const s = a.metadata, c = y.from(s.symmetricKey, "base64"), o = await crypto.subtle.decrypt(
      {
        name: l
      },
      n,
      c
    ), i = await crypto.subtle.importKey(
      "raw",
      o,
      {
        name: d,
        length: 256
      },
      !1,
      ["decrypt"]
    ), m = y.from(a.encryptedData, "base64"), O = y.from(s.iv, "base64"), k = await crypto.subtle.decrypt(
      {
        name: d,
        iv: O
      },
      i,
      m
    );
    return new TextDecoder().decode(k);
  }
}, p = "ECDH", D = "P-256", K = "AES-GCM", T = (e) => ({
  name: p,
  namedCurve: (e == null ? void 0 : e.eccCurve) || D
}), g = {
  getPublicKeyUsages() {
    return [];
  },
  getPrivateKeyUsages() {
    return ["deriveKey", "deriveBits"];
  },
  getKeyPairUsages() {
    return ["deriveKey", "deriveBits"];
  },
  getAlgorithm() {
    return "ECDH";
  },
  async generateKeyPair(e) {
    const t = T(e), r = await crypto.subtle.generateKey(t, !0, this.getKeyPairUsages()), a = await A(
      r.privateKey,
      (e == null ? void 0 : e.passphrase) ?? "",
      t.name,
      t.namedCurve
    );
    return {
      publicKey: await P(r.publicKey, t.name, t.namedCurve),
      privateKey: a
    };
  },
  async importPrivateKey(e, t) {
    const r = JSON.parse(e);
    return this.unwrapKey(r, t ?? "");
  },
  async unwrapKey(e, t) {
    const r = await f(t), a = y.from(e.wrappedKey, "base64"), n = y.from(e.iv, "base64"), s = await crypto.subtle.decrypt({ name: K, iv: n }, r, a), c = e.format || (e.algorithm === p ? "jwk" : "pkcs8"), o = c === "jwk" ? JSON.parse(new TextDecoder().decode(s)) : s, i = { name: p, namedCurve: e.namedCurve };
    return crypto.subtle.importKey(c, o, i, !0, this.getPrivateKeyUsages());
  },
  async encrypt(e, t) {
    const r = t.algorithm, a = await crypto.subtle.generateKey(
      {
        name: p,
        namedCurve: r.namedCurve
      },
      !0,
      ["deriveKey", "deriveBits"]
    ), n = await crypto.subtle.deriveKey(
      {
        name: p,
        public: t
      },
      a.privateKey,
      {
        name: K,
        length: 256
      },
      !1,
      ["encrypt"]
    ), s = crypto.getRandomValues(new Uint8Array(12)), c = new TextEncoder().encode(e), o = await crypto.subtle.encrypt(
      {
        name: K,
        iv: s
      },
      n,
      c
    ), i = await crypto.subtle.exportKey("spki", a.publicKey), m = {
      algorithm: p,
      keyHash: await E(t),
      iv: y.from(s).toString("base64"),
      symmetricKey: "",
      // Not needed for ECC
      publicKey: y.from(i).toString("base64"),
      namedCurve: r.namedCurve
    };
    return {
      encryptedData: y.from(o).toString("base64"),
      metadata: m
    };
  },
  async decrypt(e, t, r) {
    const a = typeof e == "string" ? JSON.parse(e) : e;
    let n;
    typeof t == "string" ? n = await this.importPrivateKey(t, r) : "wrappedKey" in t ? n = await this.unwrapKey(t, r ?? "") : n = t;
    const s = await crypto.subtle.importKey(
      "spki",
      y.from(a.metadata.publicKey, "base64"),
      {
        name: p,
        namedCurve: a.metadata.namedCurve ?? D
      },
      !0,
      []
    ), c = await crypto.subtle.deriveKey(
      {
        name: p,
        public: s
      },
      n,
      {
        name: K,
        length: 256
      },
      !1,
      ["decrypt"]
    ), o = y.from(a.encryptedData, "base64"), i = y.from(a.metadata.iv, "base64"), m = await crypto.subtle.decrypt(
      {
        name: K,
        iv: i
      },
      c,
      o
    );
    return new TextDecoder().decode(m);
  }
};
class h extends Error {
  constructor(t, ...r) {
    super(...r), this.name = "UnhandledMatchError", this.message = `Unhandled match value of type ${typeof t} - ${t}`, Error.captureStackTrace(this, h);
  }
}
function x(e) {
  throw e;
}
const b = Symbol(), M = (e) => x(new h(e)), u = (e, t, r = M) => {
  const a = /* @__PURE__ */ new Map(), n = Array.isArray(t) ? t : Object.entries(t).map(([c, o]) => [c, o]);
  for (const [...c] of n) {
    const o = c.pop();
    for (const i of c.flat())
      a.has(i) || a.set(i, o);
  }
  a.has(b) || a.set(b, r);
  const s = a.get(e) ?? a.get(b);
  return typeof s == "function" ? s(e) : s;
};
u.default = b;
const G = "SHA-256", L = {
  async generateKeyPair(e) {
    return u((e == null ? void 0 : e.algorithm) ?? "RSA", [
      ["RSA", () => w.generateKeyPair(e)],
      ["ECC", () => g.generateKeyPair(e)]
    ]);
  },
  async exportKeyPair(e) {
    return {
      publicKey: JSON.stringify(e.publicKey),
      privateKey: JSON.stringify(e.privateKey)
    };
  },
  async importPublicKey(e) {
    const t = JSON.parse(e), { wrappedKey: r, algorithm: a, format: n, namedCurve: s } = t, c = u(a, [
      ["RSA-OAEP", () => w.getPublicKeyUsages()],
      ["ECDH", () => g.getPublicKeyUsages()]
    ]), o = u(a, [
      ["RSA-OAEP", () => ({ name: a, hash: G })],
      ["ECDH", () => ({ name: a, namedCurve: s })]
    ]), i = y.from(r, "base64");
    return await crypto.subtle.importKey(n, i, o, !0, c);
  },
  async encrypt(e, t) {
    const r = typeof t == "string" ? await this.importPublicKey(t) : t;
    return u(r.algorithm.name, [
      ["RSA-OAEP", async () => w.encrypt(e, r)],
      ["ECDH", async () => g.encrypt(e, r)]
    ]);
  },
  async decrypt(e, t, r) {
    return typeof e == "string" && (e = JSON.parse(e)), u(e.metadata.algorithm, [
      ["RSA-OAEP", async () => w.decrypt(e, t, r)],
      ["ECDH", async () => g.decrypt(e, t, r)]
    ]);
  }
};
export {
  L as CryptoService,
  G as HASHING_ALGORITHM,
  f as generateKeyFromPassphrase,
  E as hashKey,
  A as wrapPrivateKey,
  P as wrapPublicKey
};
