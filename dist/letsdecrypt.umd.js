(function(p,n){typeof exports=="object"&&typeof module<"u"?n(exports,require("buffer")):typeof define=="function"&&define.amd?define(["exports","buffer"],n):(p=typeof globalThis<"u"?globalThis:p||self,n(p.letsdecrypt={},p.buffer))})(this,function(p,n){"use strict";const R="ECDH",P="AES-GCM",A="SHA-256",b=async e=>{const t=new TextEncoder,r=await crypto.subtle.importKey("raw",t.encode(e),"PBKDF2",!1,["deriveBits","deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt:t.encode("salt"),iterations:1e5,hash:A},r,{name:P,length:256},!0,["encrypt","decrypt"])},C=async(e,t,r)=>({wrappedKey:n.Buffer.from(await crypto.subtle.exportKey("spki",e)).toString("base64"),iv:n.Buffer.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64"),format:"spki",algorithm:t,namedCurve:r}),E=async(e,t,r,a)=>{const c=r===R?"jwk":"pkcs8",s=await crypto.subtle.exportKey(c,e),o=c==="jwk"?new TextEncoder().encode(JSON.stringify(s)):new Uint8Array(s),y=await b(t),i=crypto.getRandomValues(new Uint8Array(12)),u=await crypto.subtle.encrypt({name:P,iv:i},y,o);return{wrappedKey:n.Buffer.from(u).toString("base64"),iv:n.Buffer.from(i).toString("base64"),algorithm:r,format:c,namedCurve:a,protected:t.length>0?!0:void 0}},B=async e=>{const t=await crypto.subtle.exportKey("spki",e),r=await crypto.subtle.digest(A,t);return n.Buffer.from(r).toString("hex")},f="RSA-OAEP",l="AES-GCM",S="SHA-256",k=e=>({name:f,modulusLength:(e==null?void 0:e.rsaModulusLength)||2048,publicExponent:new Uint8Array([1,0,1]),hash:S}),K={async generateKeyPair(e){const t=k(e),r=await crypto.subtle.generateKey(t,!0,["encrypt","decrypt"]),a=await E(r.privateKey,(e==null?void 0:e.passphrase)??"",t.name);return{publicKey:await C(r.publicKey,t.name),privateKey:a}},async importPublicKey(e){if(e instanceof CryptoKey)return e;const t=typeof e=="string"?JSON.parse(e):e,{wrappedKey:r,algorithm:a,format:c}=t,s={name:a,hash:S},o=n.Buffer.from(r,"base64");return await crypto.subtle.importKey(c,o,s,!0,["encrypt"])},async importPrivateKey(e,t){if(e instanceof CryptoKey)return e;const r=typeof e=="string"?JSON.parse(e):e,a=await b(t),c=n.Buffer.from(r.wrappedKey,"base64"),s=n.Buffer.from(r.iv,"base64"),o=await crypto.subtle.decrypt({name:l,iv:s},a,c),y=r.format||"pkcs8",i=y==="jwk"?JSON.parse(new TextDecoder().decode(o)):o;return crypto.subtle.importKey(y,i,{name:f,hash:S},!0,["decrypt"])},async encrypt(e,t){t=await this.importPublicKey(t);const r=await crypto.subtle.generateKey({name:l,length:256},!0,["encrypt","decrypt"]),a=crypto.getRandomValues(new Uint8Array(12)),c=new TextEncoder().encode(e),s=await crypto.subtle.encrypt({name:l,iv:a},r,c),o=await crypto.subtle.exportKey("raw",r),y=await crypto.subtle.encrypt({name:f},t,o),i={algorithm:f,keyHash:await B(t),iv:n.Buffer.from(a).toString("base64"),symmetricKey:n.Buffer.from(y).toString("base64")};return{encryptedData:n.Buffer.from(s).toString("base64"),metadata:i}},async decrypt(e,t,r){const a=typeof e=="string"?JSON.parse(e):e;t=await this.importPrivateKey(t,r??"");const c=a.metadata,s=n.Buffer.from(c.symmetricKey,"base64"),o=await crypto.subtle.decrypt({name:f},t,s),y=await crypto.subtle.importKey("raw",o,{name:l,length:256},!1,["decrypt"]),i=n.Buffer.from(a.encryptedData,"base64"),u=n.Buffer.from(c.iv,"base64"),j=await crypto.subtle.decrypt({name:l,iv:u},y,i);return new TextDecoder().decode(j)}},m="ECDH",O="P-256",w="AES-GCM",H=e=>({name:m,namedCurve:(e==null?void 0:e.eccCurve)||O}),g={async generateKeyPair(e){const t=H(e),r=await crypto.subtle.generateKey(t,!0,["deriveKey","deriveBits"]),a=await E(r.privateKey,(e==null?void 0:e.passphrase)??"",t.name,t.namedCurve);return{publicKey:await C(r.publicKey,t.name,t.namedCurve),privateKey:a}},async importPrivateKey(e,t){if(e instanceof CryptoKey)return e;const r=typeof e=="string"?JSON.parse(e):e,a=await b(t),c=n.Buffer.from(r.wrappedKey,"base64"),s=n.Buffer.from(r.iv,"base64"),o=await crypto.subtle.decrypt({name:w,iv:s},a,c),y=r.format||(r.algorithm===m?"jwk":"pkcs8"),i=y==="jwk"?JSON.parse(new TextDecoder().decode(o)):o,u={name:m,namedCurve:r.namedCurve};return crypto.subtle.importKey(y,i,u,!0,["deriveKey","deriveBits"])},async importPublicKey(e){if(e instanceof CryptoKey)return e;const t=typeof e=="string"?JSON.parse(e):e,{wrappedKey:r,algorithm:a,format:c,namedCurve:s}=t,o={name:a,namedCurve:s},y=n.Buffer.from(r,"base64");return await crypto.subtle.importKey(c,y,o,!0,[])},async encrypt(e,t){t=await this.importPublicKey(t);const r=t.algorithm,a=await crypto.subtle.generateKey({name:m,namedCurve:r.namedCurve},!0,["deriveKey","deriveBits"]),c=await crypto.subtle.deriveKey({name:m,public:t},a.privateKey,{name:w,length:256},!1,["encrypt"]),s=crypto.getRandomValues(new Uint8Array(12)),o=new TextEncoder().encode(e),y=await crypto.subtle.encrypt({name:w,iv:s},c,o),i=await crypto.subtle.exportKey("spki",a.publicKey),u={algorithm:m,keyHash:await B(t),iv:n.Buffer.from(s).toString("base64"),symmetricKey:"",publicKey:n.Buffer.from(i).toString("base64"),namedCurve:r.namedCurve};return{encryptedData:n.Buffer.from(y).toString("base64"),metadata:u}},async decrypt(e,t,r){const a=typeof e=="string"?JSON.parse(e):e;t=await this.importPrivateKey(t,r??"");const c=await crypto.subtle.importKey("spki",n.Buffer.from(a.metadata.publicKey,"base64"),{name:m,namedCurve:a.metadata.namedCurve??O},!0,[]),s=await crypto.subtle.deriveKey({name:m,public:c},t,{name:w,length:256},!1,["decrypt"]),o=n.Buffer.from(a.encryptedData,"base64"),y=n.Buffer.from(a.metadata.iv,"base64"),i=await crypto.subtle.decrypt({name:w,iv:y},s,o);return new TextDecoder().decode(i)}};class v extends Error{constructor(t,...r){super(...r),this.name="UnhandledMatchError",this.message=`Unhandled match value of type ${typeof t} - ${t}`,Error.captureStackTrace(this,v)}}function D(e){throw e}const h=Symbol(),M=e=>D(new v(e)),d=(e,t,r=M)=>{const a=new Map,c=Array.isArray(t)?t:Object.entries(t).map(([o,y])=>[o,y]);for(const[...o]of c){const y=o.pop();for(const i of o.flat())a.has(i)||a.set(i,y)}a.has(h)||a.set(h,r);const s=a.get(e)??a.get(h);return typeof s=="function"?s(e):s};d.default=h;const x=async e=>d((e==null?void 0:e.algorithm)??"RSA",[["RSA",()=>K.generateKeyPair(e)],["ECC",()=>g.generateKeyPair(e)]]),N=async e=>({publicKey:JSON.stringify(e.publicKey),privateKey:JSON.stringify(e.privateKey)}),T=async e=>{let t;if(typeof e=="string")t=JSON.parse(e);else if(typeof e=="object")t=e;else return e;return d(t.algorithm,[["RSA-OAEP",()=>K.importPublicKey(t)],["ECDH",()=>g.importPublicKey(t)]])},G=async(e,t)=>{let r;if(typeof e=="string")r=JSON.parse(e);else if(typeof e=="object")r=e;else return e;return d(r.algorithm,[["RSA-OAEP",()=>K.importPrivateKey(r,t??"")],["ECDH",()=>g.importPrivateKey(r,t??"")]])},J=async(e,t)=>{const r=await T(t);return d(r.algorithm.name,[["RSA-OAEP",async()=>K.encrypt(e,r)],["ECDH",async()=>g.encrypt(e,r)]])},L=async(e,t,r)=>(typeof e=="string"&&(e=JSON.parse(e)),d(e.metadata.algorithm,[["RSA-OAEP",async()=>K.decrypt(e,t,r)],["ECDH",async()=>g.decrypt(e,t,r)]]));p.decrypt=L,p.encrypt=J,p.exportKeyPair=N,p.generateKeyPair=x,p.importPrivateKey=G,p.importPublicKey=T,Object.defineProperty(p,Symbol.toStringTag,{value:"Module"})});
