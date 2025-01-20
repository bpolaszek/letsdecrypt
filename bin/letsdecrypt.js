#!/usr/bin/env node
import { Buffer as y } from "node:buffer";
function oe(e) {
  return e && e.__esModule && Object.prototype.hasOwnProperty.call(e, "default") ? e.default : e;
}
var j, X;
function ce() {
  if (X) return j;
  X = 1;
  function e(n, o) {
    var a = n;
    o.slice(0, -1).forEach(function(s) {
      a = a[s] || {};
    });
    var c = o[o.length - 1];
    return c in a;
  }
  function t(n) {
    return typeof n == "number" || /^0x[0-9a-f]+$/i.test(n) ? !0 : /^[-+]?(?:\d+(?:\.\d*)?|\.\d+)(e[-+]?\d+)?$/.test(n);
  }
  function r(n, o) {
    return o === "constructor" && typeof n[o] == "function" || o === "__proto__";
  }
  return j = function(n, o) {
    o || (o = {});
    var a = {
      bools: {},
      strings: {},
      unknownFn: null
    };
    typeof o.unknown == "function" && (a.unknownFn = o.unknown), typeof o.boolean == "boolean" && o.boolean ? a.allBools = !0 : [].concat(o.boolean).filter(Boolean).forEach(function(i) {
      a.bools[i] = !0;
    });
    var c = {};
    function s(i) {
      return c[i].some(function(d) {
        return a.bools[d];
      });
    }
    Object.keys(o.alias || {}).forEach(function(i) {
      c[i] = [].concat(o.alias[i]), c[i].forEach(function(d) {
        c[d] = [i].concat(c[i].filter(function(S) {
          return d !== S;
        }));
      });
    }), [].concat(o.string).filter(Boolean).forEach(function(i) {
      a.strings[i] = !0, c[i] && [].concat(c[i]).forEach(function(d) {
        a.strings[d] = !0;
      });
    });
    var m = o.default || {}, l = { _: [] };
    function C(i, d) {
      return a.allBools && /^--[^=]+$/.test(d) || a.strings[i] || a.bools[i] || c[i];
    }
    function R(i, d, S) {
      for (var p = i, N = 0; N < d.length - 1; N++) {
        var g = d[N];
        if (r(p, g))
          return;
        p[g] === void 0 && (p[g] = {}), (p[g] === Object.prototype || p[g] === Number.prototype || p[g] === String.prototype) && (p[g] = {}), p[g] === Array.prototype && (p[g] = []), p = p[g];
      }
      var E = d[d.length - 1];
      r(p, E) || ((p === Object.prototype || p === Number.prototype || p === String.prototype) && (p = {}), p === Array.prototype && (p = []), p[E] === void 0 || a.bools[E] || typeof p[E] == "boolean" ? p[E] = S : Array.isArray(p[E]) ? p[E].push(S) : p[E] = [p[E], S]);
    }
    function b(i, d, S) {
      if (!(S && a.unknownFn && !C(i, S) && a.unknownFn(S) === !1)) {
        var p = !a.strings[i] && t(d) ? Number(d) : d;
        R(l, i.split("."), p), (c[i] || []).forEach(function(N) {
          R(l, N.split("."), p);
        });
      }
    }
    Object.keys(a.bools).forEach(function(i) {
      b(i, m[i] === void 0 ? !1 : m[i]);
    });
    var J = [];
    n.indexOf("--") !== -1 && (J = n.slice(n.indexOf("--") + 1), n = n.slice(0, n.indexOf("--")));
    for (var w = 0; w < n.length; w++) {
      var u = n[w], f, h;
      if (/^--.+=/.test(u)) {
        var Q = u.match(/^--([^=]+)=([\s\S]*)$/);
        f = Q[1];
        var $ = Q[2];
        a.bools[f] && ($ = $ !== "false"), b(f, $, u);
      } else if (/^--no-.+/.test(u))
        f = u.match(/^--no-(.+)/)[1], b(f, !1, u);
      else if (/^--.+/.test(u))
        f = u.match(/^--(.+)/)[1], h = n[w + 1], h !== void 0 && !/^(-|--)[^-]/.test(h) && !a.bools[f] && !a.allBools && (!c[f] || !s(f)) ? (b(f, h, u), w += 1) : /^(true|false)$/.test(h) ? (b(f, h === "true", u), w += 1) : b(f, a.strings[f] ? "" : !0, u);
      else if (/^-[^-]+/.test(u)) {
        for (var v = u.slice(1, -1).split(""), x = !1, K = 0; K < v.length; K++) {
          if (h = u.slice(K + 2), h === "-") {
            b(v[K], h, u);
            continue;
          }
          if (/[A-Za-z]/.test(v[K]) && h[0] === "=") {
            b(v[K], h.slice(1), u), x = !0;
            break;
          }
          if (/[A-Za-z]/.test(v[K]) && /-?\d+(\.\d*)?(e-?\d+)?$/.test(h)) {
            b(v[K], h, u), x = !0;
            break;
          }
          if (v[K + 1] && v[K + 1].match(/\W/)) {
            b(v[K], u.slice(K + 2), u), x = !0;
            break;
          } else
            b(v[K], a.strings[v[K]] ? "" : !0, u);
        }
        f = u.slice(-1)[0], !x && f !== "-" && (n[w + 1] && !/^(-|--)[^-]/.test(n[w + 1]) && !a.bools[f] && (!c[f] || !s(f)) ? (b(f, n[w + 1], u), w += 1) : n[w + 1] && /^(true|false)$/.test(n[w + 1]) ? (b(f, n[w + 1] === "true", u), w += 1) : b(f, a.strings[f] ? "" : !0, u));
      } else if ((!a.unknownFn || a.unknownFn(u) !== !1) && l._.push(a.strings._ || !t(u) ? u : Number(u)), o.stopEarly) {
        l._.push.apply(l._, n.slice(w + 1));
        break;
      }
    }
    return Object.keys(m).forEach(function(i) {
      e(l, i.split(".")) || (R(l, i.split("."), m[i]), (c[i] || []).forEach(function(d) {
        R(l, d.split("."), m[i]);
      }));
    }), o["--"] ? l["--"] = J.slice() : J.forEach(function(i) {
      l._.push(i);
    }), l;
  }, j;
}
var ie = ce();
const se = /* @__PURE__ */ oe(ie);
class V extends Error {
  constructor(t, ...r) {
    super(...r), this.name = "UnhandledMatchError", this.message = `Unhandled match value of type ${typeof t} - ${t}`, Error.captureStackTrace(this, V);
  }
}
function ye(e) {
  throw e;
}
const I = Symbol(), ue = (e) => ye(new V(e)), A = (e, t, r = ue) => {
  const n = /* @__PURE__ */ new Map(), o = Array.isArray(t) ? t : Object.entries(t).map(([c, s]) => [c, s]);
  for (const [...c] of o) {
    const s = c.pop();
    for (const m of c.flat())
      n.has(m) || n.set(m, s);
  }
  n.has(I) || n.set(I, r);
  const a = n.get(e) ?? n.get(I);
  return typeof a == "function" ? a(e) : a;
};
A.default = I;
const te = "AES-GCM", re = "SHA-256", U = async (e) => {
  const t = new TextEncoder(), r = await crypto.subtle.importKey("raw", t.encode(e), "PBKDF2", !1, [
    "deriveBits",
    "deriveKey"
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: t.encode("salt"),
      iterations: 1e5,
      hash: re
    },
    r,
    {
      name: te,
      length: 256
    },
    !0,
    ["encrypt", "decrypt"]
  );
}, q = async (e, t, r, n) => {
  if (e.type === "private")
    throw new Error("Cannot wrap a private key as public key");
  return {
    fingerprint: r,
    wrappedKey: y.from(await crypto.subtle.exportKey("spki", e)).toString("base64"),
    iv: y.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64"),
    format: "spki",
    algorithm: t,
    namedCurve: n
  };
}, k = async (e, t, r, n, o) => {
  const a = "jwk", c = await crypto.subtle.exportKey(a, e), s = new TextEncoder().encode(JSON.stringify(c)), m = await U(t), l = crypto.getRandomValues(new Uint8Array(12)), C = await crypto.subtle.encrypt({ name: te, iv: l }, m, s);
  return {
    fingerprint: n,
    wrappedKey: y.from(C).toString("base64"),
    iv: y.from(l).toString("base64"),
    algorithm: r,
    format: a,
    namedCurve: o,
    protected: t.length > 0 ? !0 : void 0
  };
}, D = async (e, t = "spki") => {
  const r = await crypto.subtle.exportKey(t, e), n = await crypto.subtle.digest(re, r);
  return y.from(n).toString("hex");
}, T = "RSA-OAEP", B = "AES-GCM", pe = 2048, F = "SHA-256", me = (e) => ({
  name: T,
  modulusLength: (e == null ? void 0 : e.rsaModulusLength) || pe,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: F
}), _ = {
  async generateKeyPair(e) {
    const t = me(e), r = await crypto.subtle.generateKey(t, !0, ["encrypt", "decrypt"]), n = await D(r.publicKey), o = await k(
      r.privateKey,
      (e == null ? void 0 : e.passphrase) ?? "",
      t.name,
      n
    );
    return {
      publicKey: await q(r.publicKey, t.name, n),
      privateKey: o,
      fingerprint: n
    };
  },
  async importPublicKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? O(e) : e, { wrappedKey: r, algorithm: n, format: o } = t, a = { name: n, hash: F }, c = y.from(r, "base64");
    return await crypto.subtle.importKey(o, c, a, !0, ["encrypt"]);
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? O(e) : e, n = await U(t), o = y.from(r.wrappedKey, "base64"), a = y.from(r.iv, "base64"), c = await crypto.subtle.decrypt({ name: B, iv: a }, n, o), s = r.format || "pkcs8", m = s === "jwk" ? JSON.parse(new TextDecoder().decode(c)) : c;
    return crypto.subtle.importKey(
      s,
      m,
      {
        name: T,
        hash: F
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
        name: T,
        hash: F
      },
      !0,
      ["encrypt"]
    );
  },
  async encrypt(e, t) {
    t = await this.importPublicKey(t);
    const r = await crypto.subtle.generateKey(
      {
        name: B,
        length: 256
      },
      !0,
      ["encrypt", "decrypt"]
    ), n = crypto.getRandomValues(new Uint8Array(12)), o = new TextEncoder().encode(e), a = await crypto.subtle.encrypt(
      {
        name: B,
        iv: n
      },
      r,
      o
    ), c = await crypto.subtle.exportKey("raw", r), s = await crypto.subtle.encrypt(
      {
        name: T
      },
      t,
      c
    ), m = {
      algorithm: T,
      keyFingerprint: await D(t),
      iv: y.from(n).toString("base64"),
      symmetricKey: y.from(s).toString("base64")
    };
    return {
      encryptedData: y.from(a).toString("base64"),
      metadata: m
    };
  },
  async decrypt(e, t, r) {
    const n = typeof e == "string" ? Z(e) : e;
    t = await this.importPrivateKey(t, r ?? "");
    const o = n.metadata, a = y.from(o.symmetricKey, "base64"), c = await crypto.subtle.decrypt(
      {
        name: T
      },
      t,
      a
    ), s = await crypto.subtle.importKey(
      "raw",
      c,
      {
        name: B,
        length: 256
      },
      !1,
      ["decrypt"]
    ), m = y.from(n.encryptedData, "base64"), l = y.from(o.iv, "base64"), C = await crypto.subtle.decrypt(
      {
        name: B,
        iv: l
      },
      s,
      m
    );
    return new TextDecoder().decode(C);
  }
}, P = "ECDH", ne = "P-256", G = "AES-GCM", le = (e) => ({
  name: P,
  namedCurve: (e == null ? void 0 : e.eccCurve) || ne
}), M = {
  async generateKeyPair(e) {
    const t = le(e), r = await crypto.subtle.generateKey(t, !0, ["deriveKey", "deriveBits"]), n = await D(r.publicKey), o = await k(
      r.privateKey,
      (e == null ? void 0 : e.passphrase) ?? "",
      t.name,
      n,
      t.namedCurve
    );
    return {
      publicKey: await q(r.publicKey, t.name, n, t.namedCurve),
      privateKey: o,
      fingerprint: n
    };
  },
  async importPrivateKey(e, t) {
    if (e instanceof CryptoKey)
      return e;
    const r = typeof e == "string" ? O(e) : e, n = await U(t), o = y.from(r.wrappedKey, "base64"), a = y.from(r.iv, "base64"), c = await crypto.subtle.decrypt({ name: G, iv: a }, n, o), s = r.format || (r.algorithm === P ? "jwk" : "pkcs8"), m = s === "jwk" ? JSON.parse(new TextDecoder().decode(c)) : c, l = { name: P, namedCurve: r.namedCurve };
    return crypto.subtle.importKey(s, m, l, !0, ["deriveKey", "deriveBits"]);
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
        name: P,
        namedCurve: e.algorithm.namedCurve
      },
      !0,
      []
    );
  },
  async importPublicKey(e) {
    if (e instanceof CryptoKey)
      return e;
    const t = typeof e == "string" ? O(e) : e, { wrappedKey: r, algorithm: n, format: o, namedCurve: a } = t, c = { name: n, namedCurve: a }, s = y.from(r, "base64");
    return await crypto.subtle.importKey(o, s, c, !0, []);
  },
  async encrypt(e, t) {
    t = await this.importPublicKey(t);
    const r = t.algorithm, n = await crypto.subtle.generateKey(
      {
        name: P,
        namedCurve: r.namedCurve
      },
      !0,
      ["deriveKey", "deriveBits"]
    ), o = await crypto.subtle.deriveKey(
      {
        name: P,
        public: t
      },
      n.privateKey,
      {
        name: G,
        length: 256
      },
      !1,
      ["encrypt"]
    ), a = crypto.getRandomValues(new Uint8Array(12)), c = new TextEncoder().encode(e), s = await crypto.subtle.encrypt(
      {
        name: G,
        iv: a
      },
      o,
      c
    ), m = await crypto.subtle.exportKey("spki", n.publicKey), l = {
      algorithm: P,
      keyFingerprint: await D(t),
      iv: y.from(a).toString("base64"),
      symmetricKey: "",
      // Not needed for ECC
      publicKey: y.from(m).toString("base64"),
      namedCurve: r.namedCurve
    };
    return {
      encryptedData: y.from(s).toString("base64"),
      metadata: l
    };
  },
  async decrypt(e, t, r) {
    const n = typeof e == "string" ? Z(e) : e;
    t = await this.importPrivateKey(t, r ?? "");
    const o = await crypto.subtle.importKey(
      "spki",
      y.from(n.metadata.publicKey, "base64"),
      {
        name: P,
        namedCurve: n.metadata.namedCurve ?? ne
      },
      !0,
      []
    ), a = await crypto.subtle.deriveKey(
      {
        name: P,
        public: o
      },
      t,
      {
        name: G,
        length: 256
      },
      !1,
      ["decrypt"]
    ), c = y.from(n.encryptedData, "base64"), s = y.from(n.metadata.iv, "base64"), m = await crypto.subtle.decrypt(
      {
        name: G,
        iv: s
      },
      a,
      c
    );
    return new TextDecoder().decode(m);
  }
}, L = "AES-CTR", fe = "AES-GCM", ee = { name: L, length: 256 }, H = {
  async generateKeyPair(e) {
    const t = await crypto.subtle.generateKey(ee, !0, ["encrypt", "decrypt"]), r = await D(t, "raw"), n = (e == null ? void 0 : e.passphrase) || "", o = {
      fingerprint: r,
      wrappedKey: y.from(JSON.stringify(await crypto.subtle.exportKey("jwk", t))).toString("base64"),
      algorithm: L,
      format: "jwk"
    }, a = n.length > 0 ? await k(t, n, L, r) : o;
    return {
      publicKey: o,
      privateKey: a,
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
    const r = typeof e == "string" ? O(e) : e, { wrappedKey: n, format: o, iv: a, protected: c } = r, s = ee;
    if (c) {
      const C = await U(t), R = await crypto.subtle.decrypt(
        { name: fe, iv: y.from(a, "base64") },
        C,
        y.from(n, "base64")
      ), b = JSON.parse(new TextDecoder().decode(R));
      return await crypto.subtle.importKey(o, b, s, !0, ["encrypt", "decrypt"]);
    }
    const m = y.from(n, "base64").toString(), l = JSON.parse(m);
    return await crypto.subtle.importKey(o, l, s, !0, ["encrypt", "decrypt"]);
  },
  async encrypt(e, t) {
    t = await this.importPublicKey(t);
    const r = new TextEncoder().encode(e), n = { name: "AES-CTR", counter: new Uint8Array(16), length: 16 * 8 }, o = await crypto.subtle.encrypt(n, t, r), a = {
      algorithm: L,
      keyFingerprint: await D(t, "raw")
    };
    return {
      encryptedData: y.from(o).toString("base64"),
      metadata: a
    };
  },
  async decrypt(e, t, r) {
    const n = typeof e == "string" ? Z(e) : e;
    t = await this.importPrivateKey(t, r ?? "");
    const o = { name: "AES-CTR", counter: new Uint8Array(16), length: 16 * 8 };
    return new TextDecoder("utf-8").decode(
      await crypto.subtle.decrypt(o, t, y.from(n.encryptedData, "base64"))
    );
  }
};
function ae(e) {
  return btoa(encodeURIComponent(e));
}
function Y(e) {
  return decodeURIComponent(atob(e));
}
const de = async (e) => {
  let t;
  if (typeof e == "string")
    t = O(e);
  else if (typeof e == "object")
    t = e;
  else
    return e;
  return A(t.algorithm, [
    ["RSA-OAEP", () => _.importPublicKey(t)],
    ["ECDH", () => M.importPublicKey(t)],
    ["AES-CTR", () => H.importPublicKey(t)]
  ]);
}, be = async (e) => A((e == null ? void 0 : e.algorithm) ?? "RSA", [
  ["RSA", () => _.generateKeyPair(e)],
  ["ECC", () => M.generateKeyPair(e)],
  ["AES", () => H.generateKeyPair(e)]
]), z = (e) => ae(JSON.stringify(e)), O = (e) => JSON.parse(Y(e)), we = async (e) => ({
  publicKey: z(e.publicKey),
  privateKey: z(e.privateKey),
  fingerprint: e.fingerprint
}), Ke = async (e, t) => {
  const r = await de(t);
  return A(r.algorithm.name, [
    ["RSA-OAEP", async () => _.encrypt(e, r)],
    ["ECDH", async () => M.encrypt(e, r)],
    ["AES-CTR", async () => H.encrypt(e, r)]
  ]);
}, he = (e) => ae(JSON.stringify(e)), Z = (e) => JSON.parse(Y(e)), ve = async (e, t, r) => (typeof e == "string" && (e = JSON.parse(Y(e))), A(e.metadata.algorithm, [
  ["RSA-OAEP", async () => _.decrypt(e, t, r)],
  ["ECDH", async () => M.decrypt(e, t, r)],
  ["AES-CTR", async () => H.decrypt(e, t, r)]
])), ge = async (e, t = "") => {
  const r = typeof e == "string" ? O(e) : e, n = await A(r.algorithm, [
    ["RSA-OAEP", () => _.importPrivateKey(r, t)],
    ["ECDH", () => M.importPrivateKey(r, t)],
    ["AES-CTR", () => H.importPrivateKey(r, t)]
  ]);
  if (r.algorithm === "AES-CTR")
    return r;
  const o = await A(r.algorithm, [
    ["RSA-OAEP", () => _.derivePublicKey(n)],
    ["ECDH", () => M.derivePublicKey(n)],
    ["AES-CTR", () => H.derivePublicKey(n)]
  ]);
  return q(o, r.algorithm, r.fingerprint, r.namedCurve);
}, Se = async (e, t) => {
  const { privateKey: r } = await we(await be(t));
  return r;
}, W = () => {
  throw new Error("A required value was not provided");
};
async function Ee(e, t) {
  const r = t["private-key"] ?? W();
  return z(await ge(r, t.passphrase ?? ""));
}
async function Pe([e], t) {
  try {
    const r = t["public-key"] ?? W();
    return he(await Ke(e, r));
  } catch (r) {
    throw console.error("Error reading stdin:", r), r;
  }
}
async function Ae([e], t) {
  try {
    const r = t["private-key"] ?? W();
    return await ve(e, r, t.passphrase ?? "");
  } catch (r) {
    throw console.error("Error reading stdin:", r), r;
  }
}
(async () => {
  const e = se(process.argv.slice(2)), t = e._[0] ?? void 0;
  e._.shift();
  const r = e._, n = e;
  delete n._, console.log(await A(t, [
    ["private-key:generate", () => Se(r, n)],
    ["public-key:generate", () => Ee(r, n)],
    ["encrypt", () => Pe(r, n)],
    ["decrypt", () => Ae(r, n)]
  ]));
})();
