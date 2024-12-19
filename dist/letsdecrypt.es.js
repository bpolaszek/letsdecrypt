import { Buffer as c } from "buffer";
const C = "AES-GCM", E = "SHA-256", v = async (e) => {
  const t = new TextEncoder(), r = await crypto.subtle.importKey("raw", t.encode(e), "PBKDF2", !1, [
    "deriveBits",
    "deriveKey"
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: t.encode("salt"),
      iterations: 1e5,
      hash: E
    },
    r,
    {
      name: C,
      length: 256
    },
    !0,
    ["encrypt", "decrypt"]
  );
}, O = async (e, t, r) => ({
  wrappedKey: c.from(await crypto.subtle.exportKey("spki", e)).toString("base64"),
  iv: c.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64"),
  format: "spki",
  algorithm: t,
  namedCurve: r
}), R = async (e, t, r, a) => {
  const n = "jwk", o = await crypto.subtle.exportKey(n, e), s = new TextEncoder().encode(JSON.stringify(o)), y = await v(t), i = crypto.getRandomValues(new Uint8Array(12)), m = await crypto.subtle.encrypt({ name: C, iv: i }, y, s);
  return {
    wrappedKey: c.from(m).toString("base64"),
    iv: c.from(i).toString("base64"),
    algorithm: r,
    format: n,
    namedCurve: a,
    protected: t.length > 0 ? !0 : void 0
  };
}, P = async (e, t = "spki") => {
  const r = await crypto.subtle.exportKey(t, e), a = await crypto.subtle.digest(E, r);
  return c.from(a).toString("hex");
}, l = "RSA-OAEP", u = "AES-GCM", x = 2048, S = "SHA-256", H = (e) => ({
  name: l,
  modulusLength: (e == null ? void 0 : e.rsaModulusLength) || x,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: S
}), g = {
  async generateKeyPair(e) {
    const t = H(e), r = await crypto.subtle.generateKey(t, !0, ["encrypt", "decrypt"]), a = await R(r.privateKey, (e == null ? void 0 : e.passphrase) ?? "", t.name);
    return {
      publicKey: await O(r.publicKey, t.name),
      privateKey: a
    };
  },
  async importPublicKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? JSON.parse(e) : e, { wrappedKey: r, algorithm: a, format: n } = t, o = { name: a, hash: S }, s = c.from(r, "base64");
    return await crypto.subtle.importKey(n, s, o, !0, ["encrypt"]);
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? JSON.parse(e) : e, a = await v(t), n = c.from(r.wrappedKey, "base64"), o = c.from(r.iv, "base64"), s = await crypto.subtle.decrypt({ name: u, iv: o }, a, n), y = r.format || "pkcs8", i = y === "jwk" ? JSON.parse(new TextDecoder().decode(s)) : s;
    return crypto.subtle.importKey(
      y,
      i,
      {
        name: l,
        hash: S
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
    ), a = crypto.getRandomValues(new Uint8Array(12)), n = new TextEncoder().encode(e), o = await crypto.subtle.encrypt(
      {
        name: u,
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
      keyHash: await P(t),
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
        name: u,
        length: 256
      },
      !1,
      ["decrypt"]
    ), i = c.from(a.encryptedData, "base64"), m = c.from(n.iv, "base64"), k = await crypto.subtle.decrypt(
      {
        name: u,
        iv: m
      },
      y,
      i
    );
    return new TextDecoder().decode(k);
  }
}, p = "ECDH", T = "P-256", d = "AES-GCM", D = (e) => ({
  name: p,
  namedCurve: (e == null ? void 0 : e.eccCurve) || T
}), b = {
  async generateKeyPair(e) {
    const t = D(e), r = await crypto.subtle.generateKey(t, !0, ["deriveKey", "deriveBits"]), a = await R(
      r.privateKey,
      (e == null ? void 0 : e.passphrase) ?? "",
      t.name,
      t.namedCurve
    );
    return {
      publicKey: await O(r.publicKey, t.name, t.namedCurve),
      privateKey: a
    };
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? JSON.parse(e) : e, a = await v(t), n = c.from(r.wrappedKey, "base64"), o = c.from(r.iv, "base64"), s = await crypto.subtle.decrypt({ name: d, iv: o }, a, n), y = r.format || (r.algorithm === p ? "jwk" : "pkcs8"), i = y === "jwk" ? JSON.parse(new TextDecoder().decode(s)) : s, m = { name: p, namedCurve: r.namedCurve };
    return crypto.subtle.importKey(y, i, m, !0, ["deriveKey", "deriveBits"]);
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
    ), o = crypto.getRandomValues(new Uint8Array(12)), s = new TextEncoder().encode(e), y = await crypto.subtle.encrypt(
      {
        name: d,
        iv: o
      },
      n,
      s
    ), i = await crypto.subtle.exportKey("spki", a.publicKey), m = {
      algorithm: p,
      keyHash: await P(t),
      iv: c.from(o).toString("base64"),
      symmetricKey: "",
      // Not needed for ECC
      publicKey: c.from(i).toString("base64"),
      namedCurve: r.namedCurve
    };
    return {
      encryptedData: c.from(y).toString("base64"),
      metadata: m
    };
  },
  async decrypt(e, t, r) {
    const a = typeof e == "string" ? JSON.parse(e) : e;
    t = await this.importPrivateKey(t, r ?? "");
    const n = await crypto.subtle.importKey(
      "spki",
      c.from(a.metadata.publicKey, "base64"),
      {
        name: p,
        namedCurve: a.metadata.namedCurve ?? T
      },
      !0,
      []
    ), o = await crypto.subtle.deriveKey(
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
    ), s = c.from(a.encryptedData, "base64"), y = c.from(a.metadata.iv, "base64"), i = await crypto.subtle.decrypt(
      {
        name: d,
        iv: y
      },
      o,
      s
    );
    return new TextDecoder().decode(i);
  }
}, w = "AES-CTR", M = () => ({ name: w, length: 256 }), h = {
  async generateKeyPair() {
    const e = M(), t = await crypto.subtle.generateKey(e, !0, ["encrypt", "decrypt"]), r = {
      wrappedKey: c.from(JSON.stringify(await crypto.subtle.exportKey("jwk", t))).toString("base64"),
      algorithm: w,
      format: "jwk"
    };
    return {
      publicKey: r,
      privateKey: r
    };
  },
  async importPublicKey(e) {
    return this.importPrivateKey(e, "");
  },
  async importPrivateKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? JSON.parse(e) : e, { wrappedKey: r, format: a } = t, n = { name: w, length: 256 };
    return await crypto.subtle.importKey(
      a,
      JSON.parse(c.from(r, "base64").toString("ascii")),
      n,
      !0,
      ["encrypt", "decrypt"]
    );
  },
  async encrypt(e, t) {
    t = await this.importPublicKey(t);
    const r = new TextEncoder().encode(e), a = { name: "AES-CTR", counter: new Uint8Array(16), length: 16 * 8 }, n = await crypto.subtle.encrypt(
      a,
      t,
      r
    ), o = {
      algorithm: w,
      keyHash: await P(t, "raw")
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
      await crypto.subtle.decrypt(
        n,
        t,
        c.from(a.encryptedData, "base64")
      )
    );
  }
};
class A extends Error {
  constructor(t, ...r) {
    super(...r), this.name = "UnhandledMatchError", this.message = `Unhandled match value of type ${typeof t} - ${t}`, Error.captureStackTrace(this, A);
  }
}
function N(e) {
  throw e;
}
const f = Symbol(), J = (e) => N(new A(e)), K = (e, t, r = J) => {
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
const G = async (e) => {
  let t;
  if (typeof e == "string")
    t = JSON.parse(e);
  else if (typeof e == "object")
    t = e;
  else
    return e;
  return K(t.algorithm, [
    ["RSA-OAEP", () => g.importPublicKey(t)],
    ["ECDH", () => b.importPublicKey(t)],
    ["AES-CTR", () => h.importPublicKey(t)]
  ]);
}, U = async (e) => K((e == null ? void 0 : e.algorithm) ?? "RSA", [
  ["RSA", () => g.generateKeyPair(e)],
  ["ECC", () => b.generateKeyPair(e)],
  ["AES", () => h.generateKeyPair(e)]
]), j = async (e) => ({
  publicKey: JSON.stringify(e.publicKey),
  privateKey: JSON.stringify(e.privateKey)
}), I = async (e, t) => {
  const r = await G(t);
  return K(r.algorithm.name, [
    ["RSA-OAEP", async () => g.encrypt(e, r)],
    ["ECDH", async () => b.encrypt(e, r)],
    ["AES-CTR", async () => h.encrypt(e, r)]
  ]);
}, B = async (e, t, r) => (typeof e == "string" && (e = JSON.parse(e)), K(e.metadata.algorithm, [
  ["RSA-OAEP", async () => g.decrypt(e, t, r)],
  ["ECDH", async () => b.decrypt(e, t, r)],
  ["AES-CTR", async () => h.decrypt(e, t, r)]
]));
export {
  B as decrypt,
  I as encrypt,
  j as exportKeyPair,
  U as generateKeyPair
};
