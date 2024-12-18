import { Buffer as o } from "buffer";
const v = "AES-GCM", P = "SHA-256", h = async (e) => {
  const t = new TextEncoder(), r = await crypto.subtle.importKey("raw", t.encode(e), "PBKDF2", !1, [
    "deriveBits",
    "deriveKey"
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: t.encode("salt"),
      iterations: 1e5,
      hash: P
    },
    r,
    {
      name: v,
      length: 256
    },
    !0,
    ["encrypt", "decrypt"]
  );
}, A = async (e, t, r) => ({
  wrappedKey: o.from(await crypto.subtle.exportKey("spki", e)).toString("base64"),
  iv: o.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64"),
  format: "spki",
  algorithm: t,
  namedCurve: r
}), C = async (e, t, r, a) => {
  const c = "jwk", s = await crypto.subtle.exportKey(c, e), n = new TextEncoder().encode(JSON.stringify(s)), y = await h(t), i = crypto.getRandomValues(new Uint8Array(12)), m = await crypto.subtle.encrypt({ name: v, iv: i }, y, n);
  return {
    wrappedKey: o.from(m).toString("base64"),
    iv: o.from(i).toString("base64"),
    algorithm: r,
    format: c,
    namedCurve: a,
    protected: t.length > 0 ? !0 : void 0
  };
}, E = async (e) => {
  const t = await crypto.subtle.exportKey("spki", e), r = await crypto.subtle.digest(P, t);
  return o.from(r).toString("hex");
}, K = "RSA-OAEP", d = "AES-GCM", k = 2048, g = "SHA-256", x = (e) => ({
  name: K,
  modulusLength: (e == null ? void 0 : e.rsaModulusLength) || k,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: g
}), f = {
  async generateKeyPair(e) {
    const t = x(e), r = await crypto.subtle.generateKey(t, !0, ["encrypt", "decrypt"]), a = await C(r.privateKey, (e == null ? void 0 : e.passphrase) ?? "", t.name);
    return {
      publicKey: await A(r.publicKey, t.name),
      privateKey: a
    };
  },
  async importPublicKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? JSON.parse(e) : e, { wrappedKey: r, algorithm: a, format: c } = t, s = { name: a, hash: g }, n = o.from(r, "base64");
    return await crypto.subtle.importKey(c, n, s, !0, ["encrypt"]);
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? JSON.parse(e) : e, a = await h(t), c = o.from(r.wrappedKey, "base64"), s = o.from(r.iv, "base64"), n = await crypto.subtle.decrypt({ name: d, iv: s }, a, c), y = r.format || "pkcs8", i = y === "jwk" ? JSON.parse(new TextDecoder().decode(n)) : n;
    return crypto.subtle.importKey(
      y,
      i,
      {
        name: K,
        hash: g
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
    ), a = crypto.getRandomValues(new Uint8Array(12)), c = new TextEncoder().encode(e), s = await crypto.subtle.encrypt(
      {
        name: d,
        iv: a
      },
      r,
      c
    ), n = await crypto.subtle.exportKey("raw", r), y = await crypto.subtle.encrypt(
      {
        name: K
      },
      t,
      n
    ), i = {
      algorithm: K,
      keyHash: await E(t),
      iv: o.from(a).toString("base64"),
      symmetricKey: o.from(y).toString("base64")
    };
    return {
      encryptedData: o.from(s).toString("base64"),
      metadata: i
    };
  },
  async decrypt(e, t, r) {
    const a = typeof e == "string" ? JSON.parse(e) : e;
    t = await this.importPrivateKey(t, r ?? "");
    const c = a.metadata, s = o.from(c.symmetricKey, "base64"), n = await crypto.subtle.decrypt(
      {
        name: K
      },
      t,
      s
    ), y = await crypto.subtle.importKey(
      "raw",
      n,
      {
        name: d,
        length: 256
      },
      !1,
      ["decrypt"]
    ), i = o.from(a.encryptedData, "base64"), m = o.from(c.iv, "base64"), R = await crypto.subtle.decrypt(
      {
        name: d,
        iv: m
      },
      y,
      i
    );
    return new TextDecoder().decode(R);
  }
}, p = "ECDH", O = "P-256", l = "AES-GCM", T = (e) => ({
  name: p,
  namedCurve: (e == null ? void 0 : e.eccCurve) || O
}), w = {
  async generateKeyPair(e) {
    const t = T(e), r = await crypto.subtle.generateKey(t, !0, ["deriveKey", "deriveBits"]), a = await C(
      r.privateKey,
      (e == null ? void 0 : e.passphrase) ?? "",
      t.name,
      t.namedCurve
    );
    return {
      publicKey: await A(r.publicKey, t.name, t.namedCurve),
      privateKey: a
    };
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? JSON.parse(e) : e, a = await h(t), c = o.from(r.wrappedKey, "base64"), s = o.from(r.iv, "base64"), n = await crypto.subtle.decrypt({ name: l, iv: s }, a, c), y = r.format || (r.algorithm === p ? "jwk" : "pkcs8"), i = y === "jwk" ? JSON.parse(new TextDecoder().decode(n)) : n, m = { name: p, namedCurve: r.namedCurve };
    return crypto.subtle.importKey(y, i, m, !0, ["deriveKey", "deriveBits"]);
  },
  async importPublicKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? JSON.parse(e) : e, { wrappedKey: r, algorithm: a, format: c, namedCurve: s } = t, n = { name: a, namedCurve: s }, y = o.from(r, "base64");
    return await crypto.subtle.importKey(c, y, n, !0, []);
  },
  async encrypt(e, t) {
    t = await this.importPublicKey(t);
    const r = t.algorithm, a = await crypto.subtle.generateKey(
      {
        name: p,
        namedCurve: r.namedCurve
      },
      !0,
      ["deriveKey", "deriveBits"]
    ), c = await crypto.subtle.deriveKey(
      {
        name: p,
        public: t
      },
      a.privateKey,
      {
        name: l,
        length: 256
      },
      !1,
      ["encrypt"]
    ), s = crypto.getRandomValues(new Uint8Array(12)), n = new TextEncoder().encode(e), y = await crypto.subtle.encrypt(
      {
        name: l,
        iv: s
      },
      c,
      n
    ), i = await crypto.subtle.exportKey("spki", a.publicKey), m = {
      algorithm: p,
      keyHash: await E(t),
      iv: o.from(s).toString("base64"),
      symmetricKey: "",
      // Not needed for ECC
      publicKey: o.from(i).toString("base64"),
      namedCurve: r.namedCurve
    };
    return {
      encryptedData: o.from(y).toString("base64"),
      metadata: m
    };
  },
  async decrypt(e, t, r) {
    const a = typeof e == "string" ? JSON.parse(e) : e;
    t = await this.importPrivateKey(t, r ?? "");
    const c = await crypto.subtle.importKey(
      "spki",
      o.from(a.metadata.publicKey, "base64"),
      {
        name: p,
        namedCurve: a.metadata.namedCurve ?? O
      },
      !0,
      []
    ), s = await crypto.subtle.deriveKey(
      {
        name: p,
        public: c
      },
      t,
      {
        name: l,
        length: 256
      },
      !1,
      ["decrypt"]
    ), n = o.from(a.encryptedData, "base64"), y = o.from(a.metadata.iv, "base64"), i = await crypto.subtle.decrypt(
      {
        name: l,
        iv: y
      },
      s,
      n
    );
    return new TextDecoder().decode(i);
  }
};
class S extends Error {
  constructor(t, ...r) {
    super(...r), this.name = "UnhandledMatchError", this.message = `Unhandled match value of type ${typeof t} - ${t}`, Error.captureStackTrace(this, S);
  }
}
function D(e) {
  throw e;
}
const b = Symbol(), H = (e) => D(new S(e)), u = (e, t, r = H) => {
  const a = /* @__PURE__ */ new Map(), c = Array.isArray(t) ? t : Object.entries(t).map(([n, y]) => [n, y]);
  for (const [...n] of c) {
    const y = n.pop();
    for (const i of n.flat())
      a.has(i) || a.set(i, y);
  }
  a.has(b) || a.set(b, r);
  const s = a.get(e) ?? a.get(b);
  return typeof s == "function" ? s(e) : s;
};
u.default = b;
const M = async (e) => {
  let t;
  if (typeof e == "string")
    t = JSON.parse(e);
  else if (typeof e == "object")
    t = e;
  else
    return e;
  return u(t.algorithm, [
    ["RSA-OAEP", () => f.importPublicKey(t)],
    ["ECDH", () => w.importPublicKey(t)]
  ]);
}, J = async (e, t) => {
  let r;
  if (typeof e == "string")
    r = JSON.parse(e);
  else if (typeof e == "object")
    r = e;
  else
    return e;
  return u(r.algorithm, [
    ["RSA-OAEP", () => f.importPrivateKey(r, t ?? "")],
    ["ECDH", () => w.importPrivateKey(r, t ?? "")]
  ]);
}, G = async (e) => u((e == null ? void 0 : e.algorithm) ?? "RSA", [
  ["RSA", () => f.generateKeyPair(e)],
  ["ECC", () => w.generateKeyPair(e)]
]), L = async (e) => ({
  publicKey: JSON.stringify(e.publicKey),
  privateKey: JSON.stringify(e.privateKey)
}), B = async (e, t) => {
  const r = await M(t);
  return u(r.algorithm.name, [
    ["RSA-OAEP", async () => f.encrypt(e, r)],
    ["ECDH", async () => w.encrypt(e, r)]
  ]);
}, I = async (e, t, r) => (typeof e == "string" && (e = JSON.parse(e)), u(e.metadata.algorithm, [
  ["RSA-OAEP", async () => f.decrypt(e, t, r)],
  ["ECDH", async () => w.decrypt(e, t, r)]
]));
export {
  I as decrypt,
  B as encrypt,
  L as exportKeyPair,
  G as generateKeyPair,
  J as importPrivateKey
};
