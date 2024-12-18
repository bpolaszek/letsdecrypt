var f = Object.defineProperty;
var M = (o, e, t) => e in o ? f(o, e, { enumerable: !0, configurable: !0, writable: !0, value: t }) : o[e] = t;
var p = (o, e, t) => M(o, typeof e != "symbol" ? e + "" : e, t);
import { Buffer as i } from "buffer";
class u {
  constructor(e, t) {
    p(this, "encryptedData");
    p(this, "metadata");
    this.encryptedData = e, this.metadata = t;
  }
  serialize() {
    return JSON.stringify({
      data: this.encryptedData,
      metadata: this.metadata
    });
  }
  static deserialize(e) {
    const t = JSON.parse(e);
    return new u(t.data, t.metadata);
  }
  getEncryptedData() {
    return this.encryptedData;
  }
  getMetadata() {
    return this.metadata;
  }
}
class h {
  static getPublicKeyUsages() {
    throw Error("Abstract static method getPublicKeyUsages has not been implemented.");
  }
  static getPrivateKeyUsages() {
    throw Error("Abstract static method getPrivateKeyUsages has not been implemented.");
  }
  static getKeyPairUsages() {
    throw Error("Abstract static method getKeyPairUsages has not been implemented.");
  }
  static getAlgorithm() {
    throw Error("Abstract static method getAlgorithm has not been implemented.");
  }
  static getKeyGenParams(e) {
    throw Error("Abstract static method getKeyGenParams has not been implemented.");
  }
  // @ts-ignore
  static async unwrapKey(e, t) {
    throw Error("Abstract static method unwrapKey has not been implemented.");
  }
  static async generateKeyFromPassphrase(e) {
    const t = new TextEncoder(), a = await crypto.subtle.importKey("raw", t.encode(e), "PBKDF2", !1, [
      "deriveBits",
      "deriveKey"
    ]);
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: t.encode("salt"),
        iterations: 1e5,
        hash: this.HASH
      },
      a,
      {
        name: this.SYMMETRIC_ALGORITHM,
        length: 256
      },
      !0,
      ["encrypt", "decrypt"]
    );
  }
  static async wrapPublicKey(e, t, a) {
    return {
      wrappedKey: i.from(await crypto.subtle.exportKey("spki", e)).toString("base64"),
      iv: i.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64"),
      format: "spki",
      algorithm: t,
      namedCurve: a
    };
  }
  static async wrapPrivateKey(e, t, a, r) {
    const s = a === this.ECC_ALGORITHM ? "jwk" : "pkcs8", n = await crypto.subtle.exportKey(s, e), c = s === "jwk" ? new TextEncoder().encode(JSON.stringify(n)) : new Uint8Array(n), y = await this.generateKeyFromPassphrase(t), m = crypto.getRandomValues(new Uint8Array(12)), d = await crypto.subtle.encrypt({ name: this.SYMMETRIC_ALGORITHM, iv: m }, y, c);
    return {
      wrappedKey: i.from(d).toString("base64"),
      iv: i.from(m).toString("base64"),
      algorithm: a,
      format: s,
      namedCurve: r
    };
  }
  static async generateKeyPair(e) {
    const t = this.getKeyGenParams(e), a = await crypto.subtle.generateKey(t, !0, this.getKeyPairUsages()), r = await this.wrapPrivateKey(
      a.privateKey,
      (e == null ? void 0 : e.passphrase) ?? "",
      t.name,
      t.namedCurve
    );
    return {
      publicKey: await this.wrapPublicKey(a.publicKey, t.name, t.namedCurve),
      privateKey: r
    };
  }
  static async hashKey(e) {
    const t = await crypto.subtle.exportKey("spki", e), a = await crypto.subtle.digest(this.HASH, t);
    return i.from(a).toString("hex");
  }
  static async importPrivateKey(e, t) {
    const a = JSON.parse(e);
    return this.unwrapKey(a, t ?? "");
  }
}
p(h, "RSA_ALGORITHM", "RSA-OAEP"), p(h, "ECC_ALGORITHM", "ECDH"), p(h, "SYMMETRIC_ALGORITHM", "AES-GCM"), p(h, "DEFAULT_RSA_LENGTH", 2048), p(h, "HASH", "SHA-256");
class K extends h {
  static getPublicKeyUsages() {
    return ["encrypt"];
  }
  static getPrivateKeyUsages() {
    return ["decrypt"];
  }
  static getKeyPairUsages() {
    return ["encrypt", "decrypt"];
  }
  static getAlgorithm() {
    return "RSA-OAEP";
  }
  static getKeyGenParams(e) {
    return {
      name: this.RSA_ALGORITHM,
      modulusLength: (e == null ? void 0 : e.rsaModulusLength) || this.DEFAULT_RSA_LENGTH,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: this.HASH
    };
  }
  static async unwrapKey(e, t) {
    const a = await this.generateKeyFromPassphrase(t), r = i.from(e.wrappedKey, "base64"), s = i.from(e.iv, "base64"), n = await crypto.subtle.decrypt({ name: this.SYMMETRIC_ALGORITHM, iv: s }, a, r), c = e.format || "pkcs8", y = c === "jwk" ? JSON.parse(new TextDecoder().decode(n)) : n;
    return crypto.subtle.importKey(
      c,
      y,
      {
        name: this.RSA_ALGORITHM,
        hash: this.HASH
      },
      !0,
      this.getPrivateKeyUsages()
    );
  }
  static async encrypt(e, t) {
    const a = await crypto.subtle.generateKey(
      {
        name: this.SYMMETRIC_ALGORITHM,
        length: 256
      },
      !0,
      ["encrypt", "decrypt"]
    ), r = crypto.getRandomValues(new Uint8Array(12)), s = new TextEncoder().encode(e), n = await crypto.subtle.encrypt(
      {
        name: this.SYMMETRIC_ALGORITHM,
        iv: r
      },
      a,
      s
    ), c = await crypto.subtle.exportKey("raw", a), y = await crypto.subtle.encrypt(
      {
        name: this.RSA_ALGORITHM
      },
      t,
      c
    ), m = {
      algorithm: this.RSA_ALGORITHM,
      keyHash: await this.hashKey(t),
      iv: i.from(r).toString("base64"),
      symmetricKey: i.from(y).toString("base64")
    };
    return new u(i.from(n).toString("base64"), m);
  }
  static async decrypt(e, t, a) {
    const r = typeof e == "string" ? u.deserialize(e) : e;
    let s;
    typeof t == "string" ? s = await this.importPrivateKey(t, a) : "wrappedKey" in t ? s = await this.unwrapKey(t, a ?? "") : s = t;
    const n = r.getMetadata(), c = i.from(n.symmetricKey, "base64"), y = await crypto.subtle.decrypt(
      {
        name: this.RSA_ALGORITHM
      },
      s,
      c
    ), m = await crypto.subtle.importKey(
      "raw",
      y,
      {
        name: this.SYMMETRIC_ALGORITHM,
        length: 256
      },
      !1,
      ["decrypt"]
    ), d = i.from(r.getEncryptedData(), "base64"), b = i.from(n.iv, "base64"), E = await crypto.subtle.decrypt(
      {
        name: this.SYMMETRIC_ALGORITHM,
        iv: b
      },
      m,
      d
    );
    return new TextDecoder().decode(E);
  }
}
class l extends h {
  static getPublicKeyUsages() {
    return [];
  }
  static getPrivateKeyUsages() {
    return ["deriveKey", "deriveBits"];
  }
  static getKeyPairUsages() {
    return ["deriveKey", "deriveBits"];
  }
  static getAlgorithm() {
    return "ECDH";
  }
  static getKeyGenParams(e) {
    return {
      name: this.ECC_ALGORITHM,
      namedCurve: (e == null ? void 0 : e.eccCurve) || this.DEFAULT_ECC_CURVE
    };
  }
  static async unwrapKey(e, t) {
    const a = await this.generateKeyFromPassphrase(t), r = i.from(e.wrappedKey, "base64"), s = i.from(e.iv, "base64"), n = await crypto.subtle.decrypt({ name: this.SYMMETRIC_ALGORITHM, iv: s }, a, r), c = e.format || (e.algorithm === this.ECC_ALGORITHM ? "jwk" : "pkcs8"), y = c === "jwk" ? JSON.parse(new TextDecoder().decode(n)) : n, m = { name: this.ECC_ALGORITHM, namedCurve: e.namedCurve };
    return crypto.subtle.importKey(c, y, m, !0, this.getPrivateKeyUsages());
  }
  static async encrypt(e, t) {
    const a = t.algorithm, r = await crypto.subtle.generateKey(
      {
        name: this.ECC_ALGORITHM,
        namedCurve: a.namedCurve
      },
      !0,
      ["deriveKey", "deriveBits"]
    ), s = await crypto.subtle.deriveKey(
      {
        name: this.ECC_ALGORITHM,
        public: t
      },
      r.privateKey,
      {
        name: this.SYMMETRIC_ALGORITHM,
        length: 256
      },
      !1,
      ["encrypt"]
    ), n = crypto.getRandomValues(new Uint8Array(12)), c = new TextEncoder().encode(e), y = await crypto.subtle.encrypt(
      {
        name: this.SYMMETRIC_ALGORITHM,
        iv: n
      },
      s,
      c
    ), m = await crypto.subtle.exportKey("spki", r.publicKey), d = {
      algorithm: this.ECC_ALGORITHM,
      keyHash: await this.hashKey(t),
      iv: i.from(n).toString("base64"),
      symmetricKey: "",
      // Not needed for ECC
      publicKey: i.from(m).toString("base64"),
      namedCurve: a.namedCurve
    };
    return new u(i.from(y).toString("base64"), d);
  }
  static async decrypt(e, t, a) {
    const r = typeof e == "string" ? u.deserialize(e) : e;
    let s;
    typeof t == "string" ? s = await this.importPrivateKey(t, a) : "wrappedKey" in t ? s = await this.unwrapKey(t, a ?? "") : s = t;
    const n = await crypto.subtle.importKey(
      "spki",
      i.from(r.getMetadata().publicKey, "base64"),
      {
        name: this.ECC_ALGORITHM,
        namedCurve: r.getMetadata().namedCurve ?? this.DEFAULT_ECC_CURVE
      },
      !0,
      []
    ), c = await crypto.subtle.deriveKey(
      {
        name: this.ECC_ALGORITHM,
        public: n
      },
      s,
      {
        name: this.SYMMETRIC_ALGORITHM,
        length: 256
      },
      !1,
      ["decrypt"]
    ), y = i.from(r.getEncryptedData(), "base64"), m = i.from(r.getMetadata().iv, "base64"), d = await crypto.subtle.decrypt(
      {
        name: this.SYMMETRIC_ALGORITHM,
        iv: m
      },
      c,
      y
    );
    return new TextDecoder().decode(d);
  }
}
p(l, "DEFAULT_ECC_CURVE", "P-256");
class A extends Error {
  constructor(e, ...t) {
    super(...t), this.name = "UnhandledMatchError", this.message = `Unhandled match value of type ${typeof e} - ${e}`, Error.captureStackTrace(this, A);
  }
}
function R(o) {
  throw o;
}
const w = Symbol(), S = (o) => R(new A(o)), g = (o, e, t = S) => {
  const a = /* @__PURE__ */ new Map(), r = Array.isArray(e) ? e : Object.entries(e).map(([n, c]) => [n, c]);
  for (const [...n] of r) {
    const c = n.pop();
    for (const y of n.flat())
      a.has(y) || a.set(y, c);
  }
  a.has(w) || a.set(w, t);
  const s = a.get(o) ?? a.get(w);
  return typeof s == "function" ? s(o) : s;
};
g.default = w;
class C {
  static async generateKeyPair(e) {
    return g((e == null ? void 0 : e.algorithm) ?? "RSA", [
      ["RSA", () => K.generateKeyPair(e)],
      ["ECC", () => l.generateKeyPair(e)]
    ]);
  }
  static async exportKeyPair(e) {
    return {
      publicKey: JSON.stringify(e.publicKey),
      privateKey: JSON.stringify(e.privateKey)
    };
  }
  static async importPublicKey(e) {
    const t = JSON.parse(e), { wrappedKey: a, algorithm: r, format: s, namedCurve: n } = t, c = g(r, [
      ["RSA-OAEP", () => K.getPublicKeyUsages()],
      ["ECDH", () => l.getPublicKeyUsages()]
    ]), y = g(r, [
      ["RSA-OAEP", () => ({ name: r, hash: this.HASH })],
      ["ECDH", () => ({ name: r, namedCurve: n })]
    ]), m = i.from(a, "base64");
    return await crypto.subtle.importKey(s, m, y, !0, c);
  }
  static async encrypt(e, t) {
    const a = typeof t == "string" ? await this.importPublicKey(t) : t;
    return g(a.algorithm.name, [
      ["RSA-OAEP", async () => K.encrypt(e, a)],
      ["ECDH", async () => l.encrypt(e, a)]
    ]);
  }
  static async decrypt(e, t, a) {
    return typeof e == "string" && (e = u.deserialize(e)), g(e.getMetadata().algorithm, [
      ["RSA-OAEP", async () => K.decrypt(e, t, a)],
      ["ECDH", async () => l.decrypt(e, t, a)]
    ]);
  }
}
p(C, "HASH", "SHA-256");
export {
  h as AbstractCryptoService,
  C as CryptoService,
  u as Secret
};
