(function(p,c){typeof exports=="object"&&typeof module<"u"?c(exports,require("buffer")):typeof define=="function"&&define.amd?define(["exports","buffer"],c):(p=typeof globalThis<"u"?globalThis:p||self,c(p.letsdecrypt={},p.buffer))})(this,function(p,c){"use strict";const D="AES-GCM",M="SHA-256",P=async e=>{const t=new TextEncoder,r=await crypto.subtle.importKey("raw",t.encode(e),"PBKDF2",!1,["deriveBits","deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt:t.encode("salt"),iterations:1e5,hash:M},r,{name:D,length:256},!0,["encrypt","decrypt"])},H=async(e,t,r,n)=>({fingerprint:r,wrappedKey:c.Buffer.from(await crypto.subtle.exportKey("spki",e)).toString("base64"),iv:c.Buffer.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64"),format:"spki",algorithm:t,namedCurve:n}),A=async(e,t,r,n,a)=>{const o="jwk",s=await crypto.subtle.exportKey(o,e),y=new TextEncoder().encode(JSON.stringify(s)),i=await P(t),m=crypto.getRandomValues(new Uint8Array(12)),v=await crypto.subtle.encrypt({name:D,iv:m},i,y);return{fingerprint:n,wrappedKey:c.Buffer.from(v).toString("base64"),iv:c.Buffer.from(m).toString("base64"),algorithm:r,format:o,namedCurve:a,protected:t.length>0?!0:void 0}},l=async(e,t="spki")=>{const r=await crypto.subtle.exportKey(t,e),n=await crypto.subtle.digest(M,r);return c.Buffer.from(n).toString("hex")},K="RSA-OAEP",g="AES-GCM",B="SHA-256",L=e=>({name:K,modulusLength:(e==null?void 0:e.rsaModulusLength)||2048,publicExponent:new Uint8Array([1,0,1]),hash:B}),w={async generateKeyPair(e){const t=L(e),r=await crypto.subtle.generateKey(t,!0,["encrypt","decrypt"]),n=await l(r.publicKey),a=await A(r.privateKey,(e==null?void 0:e.passphrase)??"",t.name,n);return{publicKey:await H(r.publicKey,t.name,n),privateKey:a,fingerprint:n}},async importPublicKey(e){if(e instanceof CryptoKey)return e;const t=typeof e=="string"?d(e):e,{wrappedKey:r,algorithm:n,format:a}=t,o={name:n,hash:B},s=c.Buffer.from(r,"base64");return await crypto.subtle.importKey(a,s,o,!0,["encrypt"])},async importPrivateKey(e,t){if(e instanceof CryptoKey)return e;const r=typeof e=="string"?d(e):e,n=await P(t),a=c.Buffer.from(r.wrappedKey,"base64"),o=c.Buffer.from(r.iv,"base64"),s=await crypto.subtle.decrypt({name:g,iv:o},n,a),y=r.format||"pkcs8",i=y==="jwk"?JSON.parse(new TextDecoder().decode(s)):s;return crypto.subtle.importKey(y,i,{name:K,hash:B},!0,["decrypt"])},async encrypt(e,t){t=await this.importPublicKey(t);const r=await crypto.subtle.generateKey({name:g,length:256},!0,["encrypt","decrypt"]),n=crypto.getRandomValues(new Uint8Array(12)),a=new TextEncoder().encode(e),o=await crypto.subtle.encrypt({name:g,iv:n},r,a),s=await crypto.subtle.exportKey("raw",r),y=await crypto.subtle.encrypt({name:K},t,s),i={algorithm:K,keyFingerprint:await l(t),iv:c.Buffer.from(n).toString("base64"),symmetricKey:c.Buffer.from(y).toString("base64")};return{encryptedData:c.Buffer.from(o).toString("base64"),metadata:i}},async decrypt(e,t,r){const n=typeof e=="string"?T(e):e;t=await this.importPrivateKey(t,r??"");const a=n.metadata,o=c.Buffer.from(a.symmetricKey,"base64"),s=await crypto.subtle.decrypt({name:K},t,o),y=await crypto.subtle.importKey("raw",s,{name:g,length:256},!1,["decrypt"]),i=c.Buffer.from(n.encryptedData,"base64"),m=c.Buffer.from(a.iv,"base64"),v=await crypto.subtle.decrypt({name:g,iv:m},y,i);return new TextDecoder().decode(v)}},u="ECDH",x="P-256",h="AES-GCM",N=e=>({name:u,namedCurve:(e==null?void 0:e.eccCurve)||x}),S={async generateKeyPair(e){const t=N(e),r=await crypto.subtle.generateKey(t,!0,["deriveKey","deriveBits"]),n=await l(r.publicKey),a=await A(r.privateKey,(e==null?void 0:e.passphrase)??"",t.name,n,t.namedCurve);return{publicKey:await H(r.publicKey,t.name,n,t.namedCurve),privateKey:a,fingerprint:n}},async importPrivateKey(e,t){if(e instanceof CryptoKey)return e;const r=typeof e=="string"?d(e):e,n=await P(t),a=c.Buffer.from(r.wrappedKey,"base64"),o=c.Buffer.from(r.iv,"base64"),s=await crypto.subtle.decrypt({name:h,iv:o},n,a),y=r.format||(r.algorithm===u?"jwk":"pkcs8"),i=y==="jwk"?JSON.parse(new TextDecoder().decode(s)):s,m={name:u,namedCurve:r.namedCurve};return crypto.subtle.importKey(y,i,m,!0,["deriveKey","deriveBits"])},async importPublicKey(e){if(e instanceof CryptoKey)return e;const t=typeof e=="string"?d(e):e,{wrappedKey:r,algorithm:n,format:a,namedCurve:o}=t,s={name:n,namedCurve:o},y=c.Buffer.from(r,"base64");return await crypto.subtle.importKey(a,y,s,!0,[])},async encrypt(e,t){t=await this.importPublicKey(t);const r=t.algorithm,n=await crypto.subtle.generateKey({name:u,namedCurve:r.namedCurve},!0,["deriveKey","deriveBits"]),a=await crypto.subtle.deriveKey({name:u,public:t},n.privateKey,{name:h,length:256},!1,["encrypt"]),o=crypto.getRandomValues(new Uint8Array(12)),s=new TextEncoder().encode(e),y=await crypto.subtle.encrypt({name:h,iv:o},a,s),i=await crypto.subtle.exportKey("spki",n.publicKey),m={algorithm:u,keyFingerprint:await l(t),iv:c.Buffer.from(o).toString("base64"),symmetricKey:"",publicKey:c.Buffer.from(i).toString("base64"),namedCurve:r.namedCurve};return{encryptedData:c.Buffer.from(y).toString("base64"),metadata:m}},async decrypt(e,t,r){const n=typeof e=="string"?T(e):e;t=await this.importPrivateKey(t,r??"");const a=await crypto.subtle.importKey("spki",c.Buffer.from(n.metadata.publicKey,"base64"),{name:u,namedCurve:n.metadata.namedCurve??x},!0,[]),o=await crypto.subtle.deriveKey({name:u,public:a},t,{name:h,length:256},!1,["decrypt"]),s=c.Buffer.from(n.encryptedData,"base64"),y=c.Buffer.from(n.metadata.iv,"base64"),i=await crypto.subtle.decrypt({name:h,iv:y},o,s);return new TextDecoder().decode(i)}},C="AES-CTR",U="AES-GCM",G={name:C,length:256},b={async generateKeyPair(e){const t=await crypto.subtle.generateKey(G,!0,["encrypt","decrypt"]),r=await l(t,"raw"),n=(e==null?void 0:e.passphrase)||"",a={fingerprint:r,wrappedKey:c.Buffer.from(JSON.stringify(await crypto.subtle.exportKey("jwk",t))).toString("base64"),algorithm:C,format:"jwk"},o=n.length>0?await A(t,n,C,r):a;return{publicKey:a,privateKey:o,fingerprint:r}},async importPublicKey(e){return this.importPrivateKey(e,"")},async importPrivateKey(e,t){if(e instanceof CryptoKey)return e;const r=typeof e=="string"?d(e):e,{wrappedKey:n,format:a,iv:o,protected:s}=r,y=G;if(s){const v=await P(t),Q=await crypto.subtle.decrypt({name:U,iv:c.Buffer.from(o,"base64")},v,c.Buffer.from(n,"base64")),W=JSON.parse(new TextDecoder().decode(Q));return await crypto.subtle.importKey(a,W,y,!0,["encrypt","decrypt"])}const i=c.Buffer.from(n,"base64").toString(),m=JSON.parse(i);return await crypto.subtle.importKey(a,m,y,!0,["encrypt","decrypt"])},async encrypt(e,t){t=await this.importPublicKey(t);const r=new TextEncoder().encode(e),n={name:"AES-CTR",counter:new Uint8Array(16),length:16*8},a=await crypto.subtle.encrypt(n,t,r),o={algorithm:C,keyFingerprint:await l(t,"raw")};return{encryptedData:c.Buffer.from(a).toString("base64"),metadata:o}},async decrypt(e,t,r){const n=typeof e=="string"?T(e):e;t=await this.importPrivateKey(t,r??"");const a={name:"AES-CTR",counter:new Uint8Array(16),length:16*8};return new TextDecoder("utf-8").decode(await crypto.subtle.decrypt(a,t,c.Buffer.from(n.encryptedData,"base64")))}};class O extends Error{constructor(t,...r){super(...r),this.name="UnhandledMatchError",this.message=`Unhandled match value of type ${typeof t} - ${t}`,Error.captureStackTrace(this,O)}}function _(e){throw e}const E=Symbol(),j=e=>_(new O(e)),f=(e,t,r=j)=>{const n=new Map,a=Array.isArray(t)?t:Object.entries(t).map(([s,y])=>[s,y]);for(const[...s]of a){const y=s.pop();for(const i of s.flat())n.has(i)||n.set(i,y)}n.has(E)||n.set(E,r);const o=n.get(e)??n.get(E);return typeof o=="function"?o(e):o};f.default=E;function I(e){return btoa(encodeURIComponent(e))}function R(e){return decodeURIComponent(atob(e))}const J=async e=>{let t;if(typeof e=="string")t=d(e);else if(typeof e=="object")t=e;else return e;return f(t.algorithm,[["RSA-OAEP",()=>w.importPublicKey(t)],["ECDH",()=>S.importPublicKey(t)],["AES-CTR",()=>b.importPublicKey(t)]])},F=async(e,t,r)=>{const n=typeof e=="string"?d(e):e,a=await f(n.algorithm,[["RSA-OAEP",()=>w.importPrivateKey(n,t??"")],["ECDH",()=>S.importPrivateKey(n,t??"")],["AES-CTR",()=>b.importPrivateKey(n,t??"")]]);return A(a,r??"",n.algorithm,n.fingerprint,n.namedCurve)},z=async e=>f((e==null?void 0:e.algorithm)??"RSA",[["RSA",()=>w.generateKeyPair(e)],["ECC",()=>S.generateKeyPair(e)],["AES",()=>b.generateKeyPair(e)]]),k=e=>I(JSON.stringify(e)),d=e=>JSON.parse(R(e)),V=async e=>({publicKey:k(e.publicKey),privateKey:k(e.privateKey),fingerprint:e.fingerprint}),$=async(e,t)=>{const r=await J(t);return f(r.algorithm.name,[["RSA-OAEP",async()=>w.encrypt(e,r)],["ECDH",async()=>S.encrypt(e,r)],["AES-CTR",async()=>b.encrypt(e,r)]])},Y=e=>I(JSON.stringify(e)),T=e=>JSON.parse(R(e)),q=async(e,t,r)=>(typeof e=="string"&&(e=JSON.parse(R(e))),f(e.metadata.algorithm,[["RSA-OAEP",async()=>w.decrypt(e,t,r)],["ECDH",async()=>S.decrypt(e,t,r)],["AES-CTR",async()=>b.decrypt(e,t,r)]]));p.changePassphrase=F,p.decrypt=q,p.encrypt=$,p.exportKeyPair=V,p.generateKeyPair=z,p.serializeKey=k,p.serializeSecret=Y,p.unserializeKey=d,p.unserializeSecret=T,Object.defineProperty(p,Symbol.toStringTag,{value:"Module"})});
