import { Buffer as o } from "buffer";
const H = "ECDH", S = "AES-GCM", v = "SHA-256", g = async (e) => {
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
  wrappedKey: o.from(await crypto.subtle.exportKey("spki", e)).toString("base64"),
  iv: o.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64"),
  format: "spki",
  algorithm: t,
  namedCurve: r
}), A = async (e, t, r, a) => {
  const n = r === H ? "jwk" : "pkcs8", s = await crypto.subtle.exportKey(n, e), c = n === "jwk" ? new TextEncoder().encode(JSON.stringify(s)) : new Uint8Array(s), y = await g(t), i = crypto.getRandomValues(new Uint8Array(12)), m = await crypto.subtle.encrypt({ name: S, iv: i }, y, c);
  return {
    wrappedKey: o.from(m).toString("base64"),
    iv: o.from(i).toString("base64"),
    algorithm: r,
    format: n,
    namedCurve: a
  };
}, C = async (e) => {
  const t = await crypto.subtle.exportKey("spki", e), r = await crypto.subtle.digest(v, t);
  return o.from(r).toString("hex");
}, K = "RSA-OAEP", u = "AES-GCM", R = 2048, E = "SHA-256", T = (e) => ({
  name: K,
  modulusLength: (e == null ? void 0 : e.rsaModulusLength) || R,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: E
}), f = {
  async generateKeyPair(e) {
    const t = T(e), r = await crypto.subtle.generateKey(t, !0, ["encrypt", "decrypt"]), a = await A(r.privateKey, (e == null ? void 0 : e.passphrase) ?? "", t.name);
    return {
      publicKey: await P(r.publicKey, t.name),
      privateKey: a
    };
  },
  async importPublicKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? JSON.parse(e) : e, { wrappedKey: r, algorithm: a, format: n } = t, s = { name: a, hash: N }, c = o.from(r, "base64");
    return await crypto.subtle.importKey(n, c, s, !0, ["encrypt"]);
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? JSON.parse(e) : e, a = await g(t), n = o.from(r.wrappedKey, "base64"), s = o.from(r.iv, "base64"), c = await crypto.subtle.decrypt({ name: u, iv: s }, a, n), y = r.format || "pkcs8", i = y === "jwk" ? JSON.parse(new TextDecoder().decode(c)) : c;
    return crypto.subtle.importKey(
      y,
      i,
      {
        name: K,
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
        name: u,
        length: 256
      },
      !0,
      ["encrypt", "decrypt"]
    ), a = crypto.getRandomValues(new Uint8Array(12)), n = new TextEncoder().encode(e), s = await crypto.subtle.encrypt(
      {
        name: u,
        iv: a
      },
      r,
      n
    ), c = await crypto.subtle.exportKey("raw", r), y = await crypto.subtle.encrypt(
      {
        name: K
      },
      t,
      c
    ), i = {
      algorithm: K,
      keyHash: await C(t),
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
    const n = a.metadata, s = o.from(n.symmetricKey, "base64"), c = await crypto.subtle.decrypt(
      {
        name: K
      },
      t,
      s
    ), y = await crypto.subtle.importKey(
      "raw",
      c,
      {
        name: u,
        length: 256
      },
      !1,
      ["decrypt"]
    ), i = o.from(a.encryptedData, "base64"), m = o.from(n.iv, "base64"), k = await crypto.subtle.decrypt(
      {
        name: u,
        iv: m
      },
      y,
      i
    );
    return new TextDecoder().decode(k);
  }
}, p = "ECDH", O = "P-256", d = "AES-GCM", x = (e) => ({
  name: p,
  namedCurve: (e == null ? void 0 : e.eccCurve) || O
}), w = {
  async generateKeyPair(e) {
    const t = x(e), r = await crypto.subtle.generateKey(t, !0, ["deriveKey", "deriveBits"]), a = await A(
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
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? JSON.parse(e) : e, a = await g(t), n = o.from(r.wrappedKey, "base64"), s = o.from(r.iv, "base64"), c = await crypto.subtle.decrypt({ name: d, iv: s }, a, n), y = r.format || (r.algorithm === p ? "jwk" : "pkcs8"), i = y === "jwk" ? JSON.parse(new TextDecoder().decode(c)) : c, m = { name: p, namedCurve: r.namedCurve };
    return crypto.subtle.importKey(y, i, m, !0, ["deriveKey", "deriveBits"]);
  },
  async importPublicKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? JSON.parse(e) : e, { wrappedKey: r, algorithm: a, format: n, namedCurve: s } = t, c = { name: a, namedCurve: s }, y = o.from(r, "base64");
    return await crypto.subtle.importKey(n, y, c, !0, []);
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
    ), n = await crypto.subtle.deriveKey(
      {
        name: p,
        public: t
      },
      a.privateKey,
      {
        name: d,
        length: 256
      },
      !1,
      ["encrypt"]
    ), s = crypto.getRandomValues(new Uint8Array(12)), c = new TextEncoder().encode(e), y = await crypto.subtle.encrypt(
      {
        name: d,
        iv: s
      },
      n,
      c
    ), i = await crypto.subtle.exportKey("spki", a.publicKey), m = {
      algorithm: p,
      keyHash: await C(t),
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
    const n = await crypto.subtle.importKey(
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
        public: n
      },
      t,
      {
        name: d,
        length: 256
      },
      !1,
      ["decrypt"]
    ), c = o.from(a.encryptedData, "base64"), y = o.from(a.metadata.iv, "base64"), i = await crypto.subtle.decrypt(
      {
        name: d,
        iv: y
      },
      s,
      c
    );
    return new TextDecoder().decode(i);
  }
};
class h extends Error {
  constructor(t, ...r) {
    super(...r), this.name = "UnhandledMatchError", this.message = `Unhandled match value of type ${typeof t} - ${t}`, Error.captureStackTrace(this, h);
  }
}
function M(e) {
  throw e;
}
const b = Symbol(), D = (e) => M(new h(e)), l = (e, t, r = D) => {
  const a = /* @__PURE__ */ new Map(), n = Array.isArray(t) ? t : Object.entries(t).map(([c, y]) => [c, y]);
  for (const [...c] of n) {
    const y = c.pop();
    for (const i of c.flat())
      a.has(i) || a.set(i, y);
  }
  a.has(b) || a.set(b, r);
  const s = a.get(e) ?? a.get(b);
  return typeof s == "function" ? s(e) : s;
};
l.default = b;
const N = "SHA-256", J = {
  async generateKeyPair(e) {
    return l((e == null ? void 0 : e.algorithm) ?? "RSA", [
      ["RSA", () => f.generateKeyPair(e)],
      ["ECC", () => w.generateKeyPair(e)]
    ]);
  },
  async exportKeyPair(e) {
    return {
      publicKey: JSON.stringify(e.publicKey),
      privateKey: JSON.stringify(e.privateKey)
    };
  },
  async importPublicKey(e) {
    let t;
    if (typeof e == "string")
      t = JSON.parse(e);
    else if (typeof e == "object")
      t = e;
    else
      return e;
    return l(t.algorithm, [
      ["RSA-OAEP", () => f.importPublicKey(t)],
      ["ECDH", () => w.importPublicKey(t)]
    ]);
  },
  async encrypt(e, t) {
    const r = await this.importPublicKey(t);
    return l(r.algorithm.name, [
      ["RSA-OAEP", async () => f.encrypt(e, r)],
      ["ECDH", async () => w.encrypt(e, r)]
    ]);
  },
  async decrypt(e, t, r) {
    return typeof e == "string" && (e = JSON.parse(e)), l(e.metadata.algorithm, [
      ["RSA-OAEP", async () => f.decrypt(e, t, r)],
      ["ECDH", async () => w.decrypt(e, t, r)]
    ]);
  }
};
export {
  J as CryptoService,
  N as HASHING_ALGORITHM,
  g as generateKeyFromPassphrase,
  C as hashKey,
  A as wrapPrivateKey,
  P as wrapPublicKey
};