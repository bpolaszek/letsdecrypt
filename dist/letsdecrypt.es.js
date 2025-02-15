import { Buffer as o } from "buffer";
const H = "AES-GCM", M = "SHA-256", C = async (e) => {
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
      name: H,
      length: 256
    },
    !0,
    ["encrypt", "decrypt"]
  );
}, R = async (e, t, r, a) => {
  if (e.type === "private")
    throw new Error("Cannot wrap a private key as public key");
  return {
    fingerprint: r,
    wrappedKey: o.from(await crypto.subtle.exportKey("spki", e)).toString("base64"),
    iv: o.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64"),
    format: "spki",
    algorithm: t,
    namedCurve: a
  };
}, E = async (e, t, r, a, n) => {
  const c = "jwk", y = await crypto.subtle.exportKey(c, e), i = new TextEncoder().encode(JSON.stringify(y)), s = await C(t), p = crypto.getRandomValues(new Uint8Array(12)), f = await crypto.subtle.encrypt({ name: H, iv: p }, s, i);
  return {
    fingerprint: a,
    wrappedKey: o.from(f).toString("base64"),
    iv: o.from(p).toString("base64"),
    algorithm: r,
    format: c,
    namedCurve: n,
    protected: t.length > 0 ? !0 : void 0
  };
}, b = async (e, t = "spki") => {
  const r = await crypto.subtle.exportKey(t, e), a = await crypto.subtle.digest(M, r);
  return o.from(a).toString("hex");
}, g = "RSA-OAEP", h = "AES-GCM", L = 2048, v = "SHA-256", U = (e) => ({
  name: g,
  modulusLength: (e == null ? void 0 : e.rsaModulusLength) || L,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: v
}), l = {
  async generateKeyPair(e) {
    const t = U(e), r = await crypto.subtle.generateKey(t, !0, ["encrypt", "decrypt"]), a = await b(r.publicKey), n = await E(
      r.privateKey,
      (e == null ? void 0 : e.passphrase) ?? "",
      t.name,
      a
    );
    return {
      publicKey: await R(r.publicKey, t.name, a),
      privateKey: n,
      fingerprint: a
    };
  },
  async importPublicKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? d(e) : e, { wrappedKey: r, algorithm: a, format: n } = t, c = { name: a, hash: v }, y = o.from(r, "base64");
    return await crypto.subtle.importKey(n, y, c, !0, ["encrypt"]);
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? d(e) : e, a = await C(t), n = o.from(r.wrappedKey, "base64"), c = o.from(r.iv, "base64"), y = await crypto.subtle.decrypt({ name: h, iv: c }, a, n), i = r.format || "pkcs8", s = i === "jwk" ? JSON.parse(new TextDecoder().decode(y)) : y;
    return crypto.subtle.importKey(
      i,
      s,
      {
        name: g,
        hash: v
      },
      !0,
      ["decrypt"]
    );
  },
  async derivePublicKey(e) {
    const t = await crypto.subtle.exportKey("jwk", e), r = {
      kty: t.kty,
      n: t.n,
      e: t.e,
      alg: t.alg,
      ext: !0
    };
    return crypto.subtle.importKey(
      "jwk",
      r,
      {
        name: g,
        hash: v
      },
      !0,
      ["encrypt"]
    );
  },
  async encrypt(e, t) {
    t = await this.importPublicKey(t);
    const r = await crypto.subtle.generateKey(
      {
        name: h,
        length: 256
      },
      !0,
      ["encrypt", "decrypt"]
    ), a = crypto.getRandomValues(new Uint8Array(12)), n = new TextEncoder().encode(e), c = await crypto.subtle.encrypt(
      {
        name: h,
        iv: a
      },
      r,
      n
    ), y = await crypto.subtle.exportKey("raw", r), i = await crypto.subtle.encrypt(
      {
        name: g
      },
      t,
      y
    ), s = {
      algorithm: g,
      keyFingerprint: await b(t),
      iv: o.from(a).toString("base64"),
      symmetricKey: o.from(i).toString("base64")
    };
    return {
      encryptedData: o.from(c).toString("base64"),
      metadata: s
    };
  },
  async decrypt(e, t, r) {
    const a = typeof e == "string" ? O(e) : e;
    t = await this.importPrivateKey(t, r ?? "");
    const n = a.metadata, c = o.from(n.symmetricKey, "base64"), y = await crypto.subtle.decrypt(
      {
        name: g
      },
      t,
      c
    ), i = await crypto.subtle.importKey(
      "raw",
      y,
      {
        name: h,
        length: 256
      },
      !1,
      ["decrypt"]
    ), s = o.from(a.encryptedData, "base64"), p = o.from(n.iv, "base64"), f = await crypto.subtle.decrypt(
      {
        name: h,
        iv: p
      },
      i,
      s
    );
    return new TextDecoder().decode(f);
  }
}, m = "ECDH", G = "P-256", S = "AES-GCM", J = (e) => ({
  name: m,
  namedCurve: (e == null ? void 0 : e.eccCurve) || G
}), K = {
  async generateKeyPair(e) {
    const t = J(e), r = await crypto.subtle.generateKey(t, !0, ["deriveKey", "deriveBits"]), a = await b(r.publicKey), n = await E(
      r.privateKey,
      (e == null ? void 0 : e.passphrase) ?? "",
      t.name,
      a,
      t.namedCurve
    );
    return {
      publicKey: await R(r.publicKey, t.name, a, t.namedCurve),
      privateKey: n,
      fingerprint: a
    };
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? d(e) : e, a = await C(t), n = o.from(r.wrappedKey, "base64"), c = o.from(r.iv, "base64"), y = await crypto.subtle.decrypt({ name: S, iv: c }, a, n), i = r.format || (r.algorithm === m ? "jwk" : "pkcs8"), s = i === "jwk" ? JSON.parse(new TextDecoder().decode(y)) : y, p = { name: m, namedCurve: r.namedCurve };
    return crypto.subtle.importKey(i, s, p, !0, ["deriveKey", "deriveBits"]);
  },
  async derivePublicKey(e) {
    const t = await crypto.subtle.exportKey("jwk", e), r = {
      kty: t.kty,
      crv: t.crv,
      x: t.x,
      y: t.y,
      ext: !0
    };
    return crypto.subtle.importKey(
      "jwk",
      r,
      {
        name: m,
        namedCurve: e.algorithm.namedCurve
      },
      !0,
      []
    );
  },
  async importPublicKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? d(e) : e, { wrappedKey: r, algorithm: a, format: n, namedCurve: c } = t, y = { name: a, namedCurve: c }, i = o.from(r, "base64");
    return await crypto.subtle.importKey(n, i, y, !0, []);
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
        name: S,
        length: 256
      },
      !1,
      ["encrypt"]
    ), c = crypto.getRandomValues(new Uint8Array(12)), y = new TextEncoder().encode(e), i = await crypto.subtle.encrypt(
      {
        name: S,
        iv: c
      },
      n,
      y
    ), s = await crypto.subtle.exportKey("spki", a.publicKey), p = {
      algorithm: m,
      keyFingerprint: await b(t),
      iv: o.from(c).toString("base64"),
      symmetricKey: "",
      // Not needed for ECC
      publicKey: o.from(s).toString("base64"),
      namedCurve: r.namedCurve
    };
    return {
      encryptedData: o.from(i).toString("base64"),
      metadata: p
    };
  },
  async decrypt(e, t, r) {
    const a = typeof e == "string" ? O(e) : e;
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
        name: S,
        length: 256
      },
      !1,
      ["decrypt"]
    ), y = o.from(a.encryptedData, "base64"), i = o.from(a.metadata.iv, "base64"), s = await crypto.subtle.decrypt(
      {
        name: S,
        iv: i
      },
      c,
      y
    );
    return new TextDecoder().decode(s);
  }
}, P = "AES-CTR", B = "AES-GCM", x = { name: P, length: 256 }, w = {
  async generateKeyPair(e) {
    const t = await crypto.subtle.generateKey(x, !0, ["encrypt", "decrypt"]), r = await b(t, "raw"), a = (e == null ? void 0 : e.passphrase) || "", n = {
      fingerprint: r,
      wrappedKey: o.from(JSON.stringify(await crypto.subtle.exportKey("jwk", t))).toString("base64"),
      algorithm: P,
      format: "jwk"
    }, c = a.length > 0 ? await E(t, a, P, r) : n;
    return {
      publicKey: n,
      privateKey: c,
      fingerprint: r
    };
  },
  derivePublicKey() {
    throw Error("Not implemented");
  },
  async importPublicKey(e) {
    return this.importPrivateKey(e, "");
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? d(e) : e, { wrappedKey: a, format: n, iv: c, protected: y } = r, i = x;
    if (y) {
      const f = await C(t), I = await crypto.subtle.decrypt(
        { name: B, iv: o.from(c, "base64") },
        f,
        o.from(a, "base64")
      ), N = JSON.parse(new TextDecoder().decode(I));
      return await crypto.subtle.importKey(n, N, i, !0, ["encrypt", "decrypt"]);
    }
    const s = o.from(a, "base64").toString(), p = JSON.parse(s);
    return await crypto.subtle.importKey(n, p, i, !0, ["encrypt", "decrypt"]);
  },
  async encrypt(e, t) {
    t = await this.importPublicKey(t);
    const r = new TextEncoder().encode(e), a = { name: "AES-CTR", counter: new Uint8Array(16), length: 16 * 8 }, n = await crypto.subtle.encrypt(a, t, r), c = {
      algorithm: P,
      keyFingerprint: await b(t, "raw")
    };
    return {
      encryptedData: o.from(n).toString("base64"),
      metadata: c
    };
  },
  async decrypt(e, t, r) {
    const a = typeof e == "string" ? O(e) : e;
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
function _(e) {
  throw e;
}
const A = Symbol(), F = (e) => _(new T(e)), u = (e, t, r = F) => {
  const a = /* @__PURE__ */ new Map(), n = Array.isArray(t) ? t : Object.entries(t).map(([y, i]) => [y, i]);
  for (const [...y] of n) {
    const i = y.pop();
    for (const s of y.flat())
      a.has(s) || a.set(s, i);
  }
  a.has(A) || a.set(A, r);
  const c = a.get(e) ?? a.get(A);
  return typeof c == "function" ? c(e) : c;
};
u.default = A;
function j(e) {
  return btoa(encodeURIComponent(e));
}
function k(e) {
  return decodeURIComponent(atob(e));
}
const z = async (e, t) => {
  try {
    const r = typeof e == "string" ? d(e) : e;
    return r.protected && await u(r.algorithm, [
      ["RSA-OAEP", () => l.importPrivateKey(r, t)],
      ["ECDH", () => K.importPrivateKey(r, t)],
      ["AES-CTR", () => w.importPrivateKey(r, t)]
    ]), !0;
  } catch {
    return !1;
  }
}, V = async (e) => {
  let t;
  if (typeof e == "string")
    t = d(e);
  else if (typeof e == "object")
    t = e;
  else
    return e;
  return u(t.algorithm, [
    ["RSA-OAEP", () => l.importPublicKey(t)],
    ["ECDH", () => K.importPublicKey(t)],
    ["AES-CTR", () => w.importPublicKey(t)]
  ]);
}, Y = async (e, t, r) => {
  const a = typeof e == "string" ? d(e) : e, n = await u(a.algorithm, [
    ["RSA-OAEP", () => l.importPrivateKey(a, t ?? "")],
    ["ECDH", () => K.importPrivateKey(a, t ?? "")],
    ["AES-CTR", () => w.importPrivateKey(a, t ?? "")]
  ]);
  return E(
    n,
    r ?? "",
    a.algorithm,
    a.fingerprint,
    a.namedCurve
  );
}, q = async (e) => u((e == null ? void 0 : e.algorithm) ?? "RSA", [
  ["RSA", () => l.generateKeyPair(e)],
  ["ECC", () => K.generateKeyPair(e)],
  ["AES", () => w.generateKeyPair(e)]
]), D = (e) => j(JSON.stringify(e)), d = (e) => JSON.parse(k(e)), Q = async (e) => ({
  publicKey: D(e.publicKey),
  privateKey: D(e.privateKey),
  fingerprint: e.fingerprint
}), W = async (e, t) => {
  const r = await V(t);
  return u(r.algorithm.name, [
    ["RSA-OAEP", async () => l.encrypt(e, r)],
    ["ECDH", async () => K.encrypt(e, r)],
    ["AES-CTR", async () => w.encrypt(e, r)]
  ]);
}, X = (e) => j(JSON.stringify(e)), O = (e) => JSON.parse(k(e)), Z = async (e, t, r) => (typeof e == "string" && (e = JSON.parse(k(e))), u(e.metadata.algorithm, [
  ["RSA-OAEP", async () => l.decrypt(e, t, r)],
  ["ECDH", async () => K.decrypt(e, t, r)],
  ["AES-CTR", async () => w.decrypt(e, t, r)]
])), ee = async (e, t = "") => {
  const r = typeof e == "string" ? d(e) : e, a = await u(r.algorithm, [
    ["RSA-OAEP", () => l.importPrivateKey(r, t)],
    ["ECDH", () => K.importPrivateKey(r, t)],
    ["AES-CTR", () => w.importPrivateKey(r, t)]
  ]);
  if (r.algorithm === "AES-CTR")
    return r;
  const n = await u(r.algorithm, [
    ["RSA-OAEP", () => l.derivePublicKey(a)],
    ["ECDH", () => K.derivePublicKey(a)],
    ["AES-CTR", () => w.derivePublicKey(a)]
  ]);
  return R(n, r.algorithm, r.fingerprint, r.namedCurve);
};
export {
  Y as changePassphrase,
  z as checkPassphrase,
  Z as decrypt,
  ee as derivePublicKey,
  W as encrypt,
  Q as exportKeyPair,
  q as generateKeyPair,
  D as serializeKey,
  X as serializeSecret,
  d as unserializeKey,
  O as unserializeSecret
};
