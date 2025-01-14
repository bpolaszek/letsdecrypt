(function(p,c){typeof exports=="object"&&typeof module<"u"?c(exports,require("buffer")):typeof define=="function"&&define.amd?define(["exports","buffer"],c):(p=typeof globalThis<"u"?globalThis:p||self,c(p.letsdecrypt={},p.buffer))})(this,function(p,c){"use strict";const T="AES-GCM",B="SHA-256",v=async e=>{const t=new TextEncoder,r=await crypto.subtle.importKey("raw",t.encode(e),"PBKDF2",!1,["deriveBits","deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt:t.encode("salt"),iterations:1e5,hash:B},r,{name:T,length:256},!0,["encrypt","decrypt"])},R=async(e,t,r,a)=>({fingerprint:r,wrappedKey:c.Buffer.from(await crypto.subtle.exportKey("spki",e)).toString("base64"),iv:c.Buffer.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64"),format:"spki",algorithm:t,namedCurve:a}),P=async(e,t,r,a,n)=>{const o="jwk",s=await crypto.subtle.exportKey(o,e),y=new TextEncoder().encode(JSON.stringify(s)),i=await v(t),m=crypto.getRandomValues(new Uint8Array(12)),b=await crypto.subtle.encrypt({name:T,iv:m},i,y);return{fingerprint:a,wrappedKey:c.Buffer.from(b).toString("base64"),iv:c.Buffer.from(m).toString("base64"),algorithm:r,format:o,namedCurve:n,protected:t.length>0?!0:void 0}},d=async(e,t="spki")=>{const r=await crypto.subtle.exportKey(t,e),a=await crypto.subtle.digest(B,r);return c.Buffer.from(a).toString("hex")},l="RSA-OAEP",K="AES-GCM",E="SHA-256",H=e=>({name:l,modulusLength:(e==null?void 0:e.rsaModulusLength)||2048,publicExponent:new Uint8Array([1,0,1]),hash:E}),w={async generateKeyPair(e){const t=H(e),r=await crypto.subtle.generateKey(t,!0,["encrypt","decrypt"]),a=await d(r.publicKey),n=await P(r.privateKey,(e==null?void 0:e.passphrase)??"",t.name,a);return{publicKey:await R(r.publicKey,t.name,a),privateKey:n,fingerprint:a}},async importPublicKey(e){if(e instanceof CryptoKey)return e;const t=typeof e=="string"?JSON.parse(e):e,{wrappedKey:r,algorithm:a,format:n}=t,o={name:a,hash:E},s=c.Buffer.from(r,"base64");return await crypto.subtle.importKey(n,s,o,!0,["encrypt"])},async importPrivateKey(e,t){if(e instanceof CryptoKey)return e;const r=typeof e=="string"?JSON.parse(e):e,a=await v(t),n=c.Buffer.from(r.wrappedKey,"base64"),o=c.Buffer.from(r.iv,"base64"),s=await crypto.subtle.decrypt({name:K,iv:o},a,n),y=r.format||"pkcs8",i=y==="jwk"?JSON.parse(new TextDecoder().decode(s)):s;return crypto.subtle.importKey(y,i,{name:l,hash:E},!0,["decrypt"])},async encrypt(e,t){t=await this.importPublicKey(t);const r=await crypto.subtle.generateKey({name:K,length:256},!0,["encrypt","decrypt"]),a=crypto.getRandomValues(new Uint8Array(12)),n=new TextEncoder().encode(e),o=await crypto.subtle.encrypt({name:K,iv:a},r,n),s=await crypto.subtle.exportKey("raw",r),y=await crypto.subtle.encrypt({name:l},t,s),i={algorithm:l,keyHash:await d(t),iv:c.Buffer.from(a).toString("base64"),symmetricKey:c.Buffer.from(y).toString("base64")};return{encryptedData:c.Buffer.from(o).toString("base64"),metadata:i}},async decrypt(e,t,r){const a=typeof e=="string"?JSON.parse(e):e;t=await this.importPrivateKey(t,r??"");const n=a.metadata,o=c.Buffer.from(n.symmetricKey,"base64"),s=await crypto.subtle.decrypt({name:l},t,o),y=await crypto.subtle.importKey("raw",s,{name:K,length:256},!1,["decrypt"]),i=c.Buffer.from(a.encryptedData,"base64"),m=c.Buffer.from(n.iv,"base64"),b=await crypto.subtle.decrypt({name:K,iv:m},y,i);return new TextDecoder().decode(b)}},u="ECDH",k="P-256",g="AES-GCM",M=e=>({name:u,namedCurve:(e==null?void 0:e.eccCurve)||k}),h={async generateKeyPair(e){const t=M(e),r=await crypto.subtle.generateKey(t,!0,["deriveKey","deriveBits"]),a=await d(r.publicKey),n=await P(r.privateKey,(e==null?void 0:e.passphrase)??"",t.name,a,t.namedCurve);return{publicKey:await R(r.publicKey,t.name,a,t.namedCurve),privateKey:n,fingerprint:a}},async importPrivateKey(e,t){if(e instanceof CryptoKey)return e;const r=typeof e=="string"?JSON.parse(e):e,a=await v(t),n=c.Buffer.from(r.wrappedKey,"base64"),o=c.Buffer.from(r.iv,"base64"),s=await crypto.subtle.decrypt({name:g,iv:o},a,n),y=r.format||(r.algorithm===u?"jwk":"pkcs8"),i=y==="jwk"?JSON.parse(new TextDecoder().decode(s)):s,m={name:u,namedCurve:r.namedCurve};return crypto.subtle.importKey(y,i,m,!0,["deriveKey","deriveBits"])},async importPublicKey(e){if(e instanceof CryptoKey)return e;const t=typeof e=="string"?JSON.parse(e):e,{wrappedKey:r,algorithm:a,format:n,namedCurve:o}=t,s={name:a,namedCurve:o},y=c.Buffer.from(r,"base64");return await crypto.subtle.importKey(n,y,s,!0,[])},async encrypt(e,t){t=await this.importPublicKey(t);const r=t.algorithm,a=await crypto.subtle.generateKey({name:u,namedCurve:r.namedCurve},!0,["deriveKey","deriveBits"]),n=await crypto.subtle.deriveKey({name:u,public:t},a.privateKey,{name:g,length:256},!1,["encrypt"]),o=crypto.getRandomValues(new Uint8Array(12)),s=new TextEncoder().encode(e),y=await crypto.subtle.encrypt({name:g,iv:o},n,s),i=await crypto.subtle.exportKey("spki",a.publicKey),m={algorithm:u,keyHash:await d(t),iv:c.Buffer.from(o).toString("base64"),symmetricKey:"",publicKey:c.Buffer.from(i).toString("base64"),namedCurve:r.namedCurve};return{encryptedData:c.Buffer.from(y).toString("base64"),metadata:m}},async decrypt(e,t,r){const a=typeof e=="string"?JSON.parse(e):e;t=await this.importPrivateKey(t,r??"");const n=await crypto.subtle.importKey("spki",c.Buffer.from(a.metadata.publicKey,"base64"),{name:u,namedCurve:a.metadata.namedCurve??k},!0,[]),o=await crypto.subtle.deriveKey({name:u,public:n},t,{name:g,length:256},!1,["decrypt"]),s=c.Buffer.from(a.encryptedData,"base64"),y=c.Buffer.from(a.metadata.iv,"base64"),i=await crypto.subtle.decrypt({name:g,iv:y},o,s);return new TextDecoder().decode(i)}},A="AES-CTR",x="AES-GCM",D={name:A,length:256},S={async generateKeyPair(e){const t=await crypto.subtle.generateKey(D,!0,["encrypt","decrypt"]),r=await d(t,"raw"),a=(e==null?void 0:e.passphrase)||"",n={fingerprint:r,wrappedKey:c.Buffer.from(JSON.stringify(await crypto.subtle.exportKey("jwk",t))).toString("base64"),algorithm:A,format:"jwk"},o=a.length>0?await P(t,a,A,r):n;return{publicKey:n,privateKey:o,fingerprint:r}},async importPublicKey(e){return this.importPrivateKey(e,"")},async importPrivateKey(e,t){if(e instanceof CryptoKey)return e;const r=typeof e=="string"?JSON.parse(e):e,{wrappedKey:a,format:n,iv:o,protected:s}=r,y=D;if(s){const b=await v(t),F=await crypto.subtle.decrypt({name:x,iv:c.Buffer.from(o,"base64")},b,c.Buffer.from(a,"base64")),V=JSON.parse(new TextDecoder().decode(F));return await crypto.subtle.importKey(n,V,y,!0,["encrypt","decrypt"])}const i=c.Buffer.from(a,"base64").toString(),m=JSON.parse(i);return await crypto.subtle.importKey(n,m,y,!0,["encrypt","decrypt"])},async encrypt(e,t){t=await this.importPublicKey(t);const r=new TextEncoder().encode(e),a={name:"AES-CTR",counter:new Uint8Array(16),length:16*8},n=await crypto.subtle.encrypt(a,t,r),o={algorithm:A,keyHash:await d(t,"raw")};return{encryptedData:c.Buffer.from(n).toString("base64"),metadata:o}},async decrypt(e,t,r){const a=typeof e=="string"?JSON.parse(e):e;t=await this.importPrivateKey(t,r??"");const n={name:"AES-CTR",counter:new Uint8Array(16),length:16*8};return new TextDecoder("utf-8").decode(await crypto.subtle.decrypt(n,t,c.Buffer.from(a.encryptedData,"base64")))}};class O extends Error{constructor(t,...r){super(...r),this.name="UnhandledMatchError",this.message=`Unhandled match value of type ${typeof t} - ${t}`,Error.captureStackTrace(this,O)}}function N(e){throw e}const C=Symbol(),G=e=>N(new O(e)),f=(e,t,r=G)=>{const a=new Map,n=Array.isArray(t)?t:Object.entries(t).map(([s,y])=>[s,y]);for(const[...s]of n){const y=s.pop();for(const i of s.flat())a.has(i)||a.set(i,y)}a.has(C)||a.set(C,r);const o=a.get(e)??a.get(C);return typeof o=="function"?o(e):o};f.default=C;const J=async e=>{let t;if(typeof e=="string")t=JSON.parse(e);else if(typeof e=="object")t=e;else return e;return f(t.algorithm,[["RSA-OAEP",()=>w.importPublicKey(t)],["ECDH",()=>h.importPublicKey(t)],["AES-CTR",()=>S.importPublicKey(t)]])},L=async(e,t,r)=>{const a=typeof e=="string"?JSON.parse(e):e,n=await f(a.algorithm,[["RSA-OAEP",()=>w.importPrivateKey(a,t??"")],["ECDH",()=>h.importPrivateKey(a,t??"")],["AES-CTR",()=>S.importPrivateKey(a,t??"")]]);return P(n,r??"",a.algorithm,a.fingerprint,a.namedCurve)},I=async e=>f((e==null?void 0:e.algorithm)??"RSA",[["RSA",()=>w.generateKeyPair(e)],["ECC",()=>h.generateKeyPair(e)],["AES",()=>S.generateKeyPair(e)]]),_=async e=>({publicKey:JSON.stringify(e.publicKey),privateKey:JSON.stringify(e.privateKey),fingerprint:e.fingerprint}),j=async(e,t)=>{const r=await J(t);return f(r.algorithm.name,[["RSA-OAEP",async()=>w.encrypt(e,r)],["ECDH",async()=>h.encrypt(e,r)],["AES-CTR",async()=>S.encrypt(e,r)]])},U=async(e,t,r)=>(typeof e=="string"&&(e=JSON.parse(e)),f(e.metadata.algorithm,[["RSA-OAEP",async()=>w.decrypt(e,t,r)],["ECDH",async()=>h.decrypt(e,t,r)],["AES-CTR",async()=>S.decrypt(e,t,r)]]));p.changePassphrase=L,p.decrypt=U,p.encrypt=j,p.exportKeyPair=_,p.generateKeyPair=I,Object.defineProperty(p,Symbol.toStringTag,{value:"Module"})});
