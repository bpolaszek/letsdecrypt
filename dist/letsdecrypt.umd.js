(function(p,c){typeof exports=="object"&&typeof module<"u"?c(exports,require("buffer")):typeof define=="function"&&define.amd?define(["exports","buffer"],c):(p=typeof globalThis<"u"?globalThis:p||self,c(p.letsdecrypt={},p.buffer))})(this,function(p,c){"use strict";const H="AES-GCM",M="SHA-256",v=async e=>{const t=new TextEncoder,r=await crypto.subtle.importKey("raw",t.encode(e),"PBKDF2",!1,["deriveBits","deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt:t.encode("salt"),iterations:1e5,hash:M},r,{name:H,length:256},!0,["encrypt","decrypt"])},k=async(e,t,r,n)=>{if(e.type==="private")throw new Error("Cannot wrap a private key as public key");return{fingerprint:r,wrappedKey:c.Buffer.from(await crypto.subtle.exportKey("spki",e)).toString("base64"),iv:c.Buffer.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64"),format:"spki",algorithm:t,namedCurve:n}},A=async(e,t,r,n,a)=>{const o="jwk",i=await crypto.subtle.exportKey(o,e),y=new TextEncoder().encode(JSON.stringify(i)),s=await v(t),u=crypto.getRandomValues(new Uint8Array(12)),P=await crypto.subtle.encrypt({name:H,iv:u},s,y);return{fingerprint:n,wrappedKey:c.Buffer.from(P).toString("base64"),iv:c.Buffer.from(u).toString("base64"),algorithm:r,format:o,namedCurve:a,protected:t.length>0?!0:void 0}},g=async(e,t="spki")=>{const r=await crypto.subtle.exportKey(t,e),n=await crypto.subtle.digest(M,r);return c.Buffer.from(n).toString("hex")},b="RSA-OAEP",h="AES-GCM",C="SHA-256",I=e=>({name:b,modulusLength:(e==null?void 0:e.rsaModulusLength)||2048,publicExponent:new Uint8Array([1,0,1]),hash:C}),K={async generateKeyPair(e){const t=I(e),r=await crypto.subtle.generateKey(t,!0,["encrypt","decrypt"]),n=await g(r.publicKey),a=await A(r.privateKey,(e==null?void 0:e.passphrase)??"",t.name,n);return{publicKey:await k(r.publicKey,t.name,n),privateKey:a,fingerprint:n}},async importPublicKey(e){if(e instanceof CryptoKey)return e;const t=typeof e=="string"?m(e):e,{wrappedKey:r,algorithm:n,format:a}=t,o={name:n,hash:C},i=c.Buffer.from(r,"base64");return await crypto.subtle.importKey(a,i,o,!0,["encrypt"])},async importPrivateKey(e,t){if(e instanceof CryptoKey)return e;const r=typeof e=="string"?m(e):e,n=await v(t),a=c.Buffer.from(r.wrappedKey,"base64"),o=c.Buffer.from(r.iv,"base64"),i=await crypto.subtle.decrypt({name:h,iv:o},n,a),y=r.format||"pkcs8",s=y==="jwk"?JSON.parse(new TextDecoder().decode(i)):i;return crypto.subtle.importKey(y,s,{name:b,hash:C},!0,["decrypt"])},async derivePublicKey(e){const t=await crypto.subtle.exportKey("jwk",e),r={kty:t.kty,n:t.n,e:t.e,alg:t.alg,ext:!0};return crypto.subtle.importKey("jwk",r,{name:b,hash:C},!0,["encrypt"])},async encrypt(e,t){t=await this.importPublicKey(t);const r=await crypto.subtle.generateKey({name:h,length:256},!0,["encrypt","decrypt"]),n=crypto.getRandomValues(new Uint8Array(12)),a=new TextEncoder().encode(e),o=await crypto.subtle.encrypt({name:h,iv:n},r,a),i=await crypto.subtle.exportKey("raw",r),y=await crypto.subtle.encrypt({name:b},t,i),s={algorithm:b,keyFingerprint:await g(t),iv:c.Buffer.from(n).toString("base64"),symmetricKey:c.Buffer.from(y).toString("base64")};return{encryptedData:c.Buffer.from(o).toString("base64"),metadata:s}},async decrypt(e,t,r){const n=typeof e=="string"?R(e):e;t=await this.importPrivateKey(t,r??"");const a=n.metadata,o=c.Buffer.from(a.symmetricKey,"base64"),i=await crypto.subtle.decrypt({name:b},t,o),y=await crypto.subtle.importKey("raw",i,{name:h,length:256},!1,["decrypt"]),s=c.Buffer.from(n.encryptedData,"base64"),u=c.Buffer.from(a.iv,"base64"),P=await crypto.subtle.decrypt({name:h,iv:u},y,s);return new TextDecoder().decode(P)}},d="ECDH",x="P-256",S="AES-GCM",L=e=>({name:d,namedCurve:(e==null?void 0:e.eccCurve)||x}),f={async generateKeyPair(e){const t=L(e),r=await crypto.subtle.generateKey(t,!0,["deriveKey","deriveBits"]),n=await g(r.publicKey),a=await A(r.privateKey,(e==null?void 0:e.passphrase)??"",t.name,n,t.namedCurve);return{publicKey:await k(r.publicKey,t.name,n,t.namedCurve),privateKey:a,fingerprint:n}},async importPrivateKey(e,t){if(e instanceof CryptoKey)return e;const r=typeof e=="string"?m(e):e,n=await v(t),a=c.Buffer.from(r.wrappedKey,"base64"),o=c.Buffer.from(r.iv,"base64"),i=await crypto.subtle.decrypt({name:S,iv:o},n,a),y=r.format||(r.algorithm===d?"jwk":"pkcs8"),s=y==="jwk"?JSON.parse(new TextDecoder().decode(i)):i,u={name:d,namedCurve:r.namedCurve};return crypto.subtle.importKey(y,s,u,!0,["deriveKey","deriveBits"])},async derivePublicKey(e){const t=await crypto.subtle.exportKey("jwk",e),r={kty:t.kty,crv:t.crv,x:t.x,y:t.y,ext:!0};return crypto.subtle.importKey("jwk",r,{name:d,namedCurve:e.algorithm.namedCurve},!0,[])},async importPublicKey(e){if(e instanceof CryptoKey)return e;const t=typeof e=="string"?m(e):e,{wrappedKey:r,algorithm:n,format:a,namedCurve:o}=t,i={name:n,namedCurve:o},y=c.Buffer.from(r,"base64");return await crypto.subtle.importKey(a,y,i,!0,[])},async encrypt(e,t){t=await this.importPublicKey(t);const r=t.algorithm,n=await crypto.subtle.generateKey({name:d,namedCurve:r.namedCurve},!0,["deriveKey","deriveBits"]),a=await crypto.subtle.deriveKey({name:d,public:t},n.privateKey,{name:S,length:256},!1,["encrypt"]),o=crypto.getRandomValues(new Uint8Array(12)),i=new TextEncoder().encode(e),y=await crypto.subtle.encrypt({name:S,iv:o},a,i),s=await crypto.subtle.exportKey("spki",n.publicKey),u={algorithm:d,keyFingerprint:await g(t),iv:c.Buffer.from(o).toString("base64"),symmetricKey:"",publicKey:c.Buffer.from(s).toString("base64"),namedCurve:r.namedCurve};return{encryptedData:c.Buffer.from(y).toString("base64"),metadata:u}},async decrypt(e,t,r){const n=typeof e=="string"?R(e):e;t=await this.importPrivateKey(t,r??"");const a=await crypto.subtle.importKey("spki",c.Buffer.from(n.metadata.publicKey,"base64"),{name:d,namedCurve:n.metadata.namedCurve??x},!0,[]),o=await crypto.subtle.deriveKey({name:d,public:a},t,{name:S,length:256},!1,["decrypt"]),i=c.Buffer.from(n.encryptedData,"base64"),y=c.Buffer.from(n.metadata.iv,"base64"),s=await crypto.subtle.decrypt({name:S,iv:y},o,i);return new TextDecoder().decode(s)}},E="AES-CTR",N="AES-GCM",j={name:E,length:256},w={async generateKeyPair(e){const t=await crypto.subtle.generateKey(j,!0,["encrypt","decrypt"]),r=await g(t,"raw"),n=(e==null?void 0:e.passphrase)||"",a={fingerprint:r,wrappedKey:c.Buffer.from(JSON.stringify(await crypto.subtle.exportKey("jwk",t))).toString("base64"),algorithm:E,format:"jwk"},o=n.length>0?await A(t,n,E,r):a;return{publicKey:a,privateKey:o,fingerprint:r}},derivePublicKey(){throw Error("Not implemented")},async importPublicKey(e){return this.importPrivateKey(e,"")},async importPrivateKey(e,t){if(e instanceof CryptoKey)return e;const r=typeof e=="string"?m(e):e,{wrappedKey:n,format:a,iv:o,protected:i}=r,y=j;if(i){const P=await v(t),X=await crypto.subtle.decrypt({name:N,iv:c.Buffer.from(o,"base64")},P,c.Buffer.from(n,"base64")),Z=JSON.parse(new TextDecoder().decode(X));return await crypto.subtle.importKey(a,Z,y,!0,["encrypt","decrypt"])}const s=c.Buffer.from(n,"base64").toString(),u=JSON.parse(s);return await crypto.subtle.importKey(a,u,y,!0,["encrypt","decrypt"])},async encrypt(e,t){t=await this.importPublicKey(t);const r=new TextEncoder().encode(e),n={name:"AES-CTR",counter:new Uint8Array(16),length:16*8},a=await crypto.subtle.encrypt(n,t,r),o={algorithm:E,keyFingerprint:await g(t,"raw")};return{encryptedData:c.Buffer.from(a).toString("base64"),metadata:o}},async decrypt(e,t,r){const n=typeof e=="string"?R(e):e;t=await this.importPrivateKey(t,r??"");const a={name:"AES-CTR",counter:new Uint8Array(16),length:16*8};return new TextDecoder("utf-8").decode(await crypto.subtle.decrypt(a,t,c.Buffer.from(n.encryptedData,"base64")))}};class B extends Error{constructor(t,...r){super(...r),this.name="UnhandledMatchError",this.message=`Unhandled match value of type ${typeof t} - ${t}`,Error.captureStackTrace(this,B)}}function U(e){throw e}const T=Symbol(),_=e=>U(new B(e)),l=(e,t,r=_)=>{const n=new Map,a=Array.isArray(t)?t:Object.entries(t).map(([i,y])=>[i,y]);for(const[...i]of a){const y=i.pop();for(const s of i.flat())n.has(s)||n.set(s,y)}n.has(T)||n.set(T,r);const o=n.get(e)??n.get(T);return typeof o=="function"?o(e):o};l.default=T;function G(e){return btoa(encodeURIComponent(e))}function O(e){return decodeURIComponent(atob(e))}const J=async(e,t)=>{try{const r=typeof e=="string"?m(e):e;return r.protected&&await l(r.algorithm,[["RSA-OAEP",()=>K.importPrivateKey(r,t)],["ECDH",()=>f.importPrivateKey(r,t)],["AES-CTR",()=>w.importPrivateKey(r,t)]]),!0}catch{return!1}},F=async e=>{let t;if(typeof e=="string")t=m(e);else if(typeof e=="object")t=e;else return e;return l(t.algorithm,[["RSA-OAEP",()=>K.importPublicKey(t)],["ECDH",()=>f.importPublicKey(t)],["AES-CTR",()=>w.importPublicKey(t)]])},z=async(e,t,r)=>{const n=typeof e=="string"?m(e):e,a=await l(n.algorithm,[["RSA-OAEP",()=>K.importPrivateKey(n,t??"")],["ECDH",()=>f.importPrivateKey(n,t??"")],["AES-CTR",()=>w.importPrivateKey(n,t??"")]]);return A(a,r??"",n.algorithm,n.fingerprint,n.namedCurve)},V=async e=>l((e==null?void 0:e.algorithm)??"RSA",[["RSA",()=>K.generateKeyPair(e)],["ECC",()=>f.generateKeyPair(e)],["AES",()=>w.generateKeyPair(e)]]),D=e=>G(JSON.stringify(e)),m=e=>JSON.parse(O(e)),$=async e=>({publicKey:D(e.publicKey),privateKey:D(e.privateKey),fingerprint:e.fingerprint}),Y=async(e,t)=>{const r=await F(t);return l(r.algorithm.name,[["RSA-OAEP",async()=>K.encrypt(e,r)],["ECDH",async()=>f.encrypt(e,r)],["AES-CTR",async()=>w.encrypt(e,r)]])},q=e=>G(JSON.stringify(e)),R=e=>JSON.parse(O(e)),Q=async(e,t,r)=>(typeof e=="string"&&(e=JSON.parse(O(e))),l(e.metadata.algorithm,[["RSA-OAEP",async()=>K.decrypt(e,t,r)],["ECDH",async()=>f.decrypt(e,t,r)],["AES-CTR",async()=>w.decrypt(e,t,r)]])),W=async(e,t="")=>{const r=typeof e=="string"?m(e):e,n=await l(r.algorithm,[["RSA-OAEP",()=>K.importPrivateKey(r,t)],["ECDH",()=>f.importPrivateKey(r,t)],["AES-CTR",()=>w.importPrivateKey(r,t)]]);if(r.algorithm==="AES-CTR")return r;const a=await l(r.algorithm,[["RSA-OAEP",()=>K.derivePublicKey(n)],["ECDH",()=>f.derivePublicKey(n)],["AES-CTR",()=>w.derivePublicKey(n)]]);return k(a,r.algorithm,r.fingerprint,r.namedCurve)};p.changePassphrase=z,p.checkPassphrase=J,p.decrypt=Q,p.derivePublicKey=W,p.encrypt=Y,p.exportKeyPair=$,p.generateKeyPair=V,p.serializeKey=D,p.serializeSecret=q,p.unserializeKey=m,p.unserializeSecret=R,Object.defineProperty(p,Symbol.toStringTag,{value:"Module"})});
