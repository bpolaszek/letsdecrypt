#!/usr/bin/env node
"use strict";const y=require("node:buffer");function oe(e){return e&&e.__esModule&&Object.prototype.hasOwnProperty.call(e,"default")?e.default:e}var j,X;function ce(){if(X)return j;X=1;function e(n,o){var a=n;o.slice(0,-1).forEach(function(s){a=a[s]||{}});var c=o[o.length-1];return c in a}function t(n){return typeof n=="number"||/^0x[0-9a-f]+$/i.test(n)?!0:/^[-+]?(?:\d+(?:\.\d*)?|\.\d+)(e[-+]?\d+)?$/.test(n)}function r(n,o){return o==="constructor"&&typeof n[o]=="function"||o==="__proto__"}return j=function(n,o){o||(o={});var a={bools:{},strings:{},unknownFn:null};typeof o.unknown=="function"&&(a.unknownFn=o.unknown),typeof o.boolean=="boolean"&&o.boolean?a.allBools=!0:[].concat(o.boolean).filter(Boolean).forEach(function(i){a.bools[i]=!0});var c={};function s(i){return c[i].some(function(d){return a.bools[d]})}Object.keys(o.alias||{}).forEach(function(i){c[i]=[].concat(o.alias[i]),c[i].forEach(function(d){c[d]=[i].concat(c[i].filter(function(S){return d!==S}))})}),[].concat(o.string).filter(Boolean).forEach(function(i){a.strings[i]=!0,c[i]&&[].concat(c[i]).forEach(function(d){a.strings[d]=!0})});var p=o.default||{},m={_:[]};function C(i,d){return a.allBools&&/^--[^=]+$/.test(d)||a.strings[i]||a.bools[i]||c[i]}function B(i,d,S){for(var f=i,H=0;H<d.length-1;H++){var g=d[H];if(r(f,g))return;f[g]===void 0&&(f[g]={}),(f[g]===Object.prototype||f[g]===Number.prototype||f[g]===String.prototype)&&(f[g]={}),f[g]===Array.prototype&&(f[g]=[]),f=f[g]}var E=d[d.length-1];r(f,E)||((f===Object.prototype||f===Number.prototype||f===String.prototype)&&(f={}),f===Array.prototype&&(f=[]),f[E]===void 0||a.bools[E]||typeof f[E]=="boolean"?f[E]=S:Array.isArray(f[E])?f[E].push(S):f[E]=[f[E],S])}function b(i,d,S){if(!(S&&a.unknownFn&&!C(i,S)&&a.unknownFn(S)===!1)){var f=!a.strings[i]&&t(d)?Number(d):d;B(m,i.split("."),f),(c[i]||[]).forEach(function(H){B(m,H.split("."),f)})}}Object.keys(a.bools).forEach(function(i){b(i,p[i]===void 0?!1:p[i])});var $=[];n.indexOf("--")!==-1&&($=n.slice(n.indexOf("--")+1),n=n.slice(0,n.indexOf("--")));for(var w=0;w<n.length;w++){var u=n[w],l,h;if(/^--.+=/.test(u)){var Q=u.match(/^--([^=]+)=([\s\S]*)$/);l=Q[1];var J=Q[2];a.bools[l]&&(J=J!=="false"),b(l,J,u)}else if(/^--no-.+/.test(u))l=u.match(/^--no-(.+)/)[1],b(l,!1,u);else if(/^--.+/.test(u))l=u.match(/^--(.+)/)[1],h=n[w+1],h!==void 0&&!/^(-|--)[^-]/.test(h)&&!a.bools[l]&&!a.allBools&&(!c[l]||!s(l))?(b(l,h,u),w+=1):/^(true|false)$/.test(h)?(b(l,h==="true",u),w+=1):b(l,a.strings[l]?"":!0,u);else if(/^-[^-]+/.test(u)){for(var v=u.slice(1,-1).split(""),G=!1,K=0;K<v.length;K++){if(h=u.slice(K+2),h==="-"){b(v[K],h,u);continue}if(/[A-Za-z]/.test(v[K])&&h[0]==="="){b(v[K],h.slice(1),u),G=!0;break}if(/[A-Za-z]/.test(v[K])&&/-?\d+(\.\d*)?(e-?\d+)?$/.test(h)){b(v[K],h,u),G=!0;break}if(v[K+1]&&v[K+1].match(/\W/)){b(v[K],u.slice(K+2),u),G=!0;break}else b(v[K],a.strings[v[K]]?"":!0,u)}l=u.slice(-1)[0],!G&&l!=="-"&&(n[w+1]&&!/^(-|--)[^-]/.test(n[w+1])&&!a.bools[l]&&(!c[l]||!s(l))?(b(l,n[w+1],u),w+=1):n[w+1]&&/^(true|false)$/.test(n[w+1])?(b(l,n[w+1]==="true",u),w+=1):b(l,a.strings[l]?"":!0,u))}else if((!a.unknownFn||a.unknownFn(u)!==!1)&&m._.push(a.strings._||!t(u)?u:Number(u)),o.stopEarly){m._.push.apply(m._,n.slice(w+1));break}}return Object.keys(p).forEach(function(i){e(m,i.split("."))||(B(m,i.split("."),p[i]),(c[i]||[]).forEach(function(d){B(m,d.split("."),p[i])}))}),o["--"]?m["--"]=$.slice():$.forEach(function(i){m._.push(i)}),m},j}var ie=ce();const se=oe(ie);class q extends Error{constructor(t,...r){super(...r),this.name="UnhandledMatchError",this.message=`Unhandled match value of type ${typeof t} - ${t}`,Error.captureStackTrace(this,q)}}function ye(e){throw e}const I=Symbol(),ue=e=>ye(new q(e)),A=(e,t,r=ue)=>{const n=new Map,o=Array.isArray(t)?t:Object.entries(t).map(([c,s])=>[c,s]);for(const[...c]of o){const s=c.pop();for(const p of c.flat())n.has(p)||n.set(p,s)}n.has(I)||n.set(I,r);const a=n.get(e)??n.get(I);return typeof a=="function"?a(e):a};A.default=I;const te="AES-GCM",re="SHA-256",L=async e=>{const t=new TextEncoder,r=await crypto.subtle.importKey("raw",t.encode(e),"PBKDF2",!1,["deriveBits","deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt:t.encode("salt"),iterations:1e5,hash:re},r,{name:te,length:256},!0,["encrypt","decrypt"])},V=async(e,t,r,n)=>{if(e.type==="private")throw new Error("Cannot wrap a private key as public key");return{fingerprint:r,wrappedKey:y.Buffer.from(await crypto.subtle.exportKey("spki",e)).toString("base64"),iv:y.Buffer.from(crypto.getRandomValues(new Uint8Array(12))).toString("base64"),format:"spki",algorithm:t,namedCurve:n}},k=async(e,t,r,n,o)=>{const a="jwk",c=await crypto.subtle.exportKey(a,e),s=new TextEncoder().encode(JSON.stringify(c)),p=await L(t),m=crypto.getRandomValues(new Uint8Array(12)),C=await crypto.subtle.encrypt({name:te,iv:m},p,s);return{fingerprint:n,wrappedKey:y.Buffer.from(C).toString("base64"),iv:y.Buffer.from(m).toString("base64"),algorithm:r,format:a,namedCurve:o,protected:t.length>0?!0:void 0}},T=async(e,t="spki")=>{const r=await crypto.subtle.exportKey(t,e),n=await crypto.subtle.digest(re,r);return y.Buffer.from(n).toString("hex")},R="RSA-OAEP",N="AES-GCM",fe=2048,F="SHA-256",pe=e=>({name:R,modulusLength:(e==null?void 0:e.rsaModulusLength)||fe,publicExponent:new Uint8Array([1,0,1]),hash:F}),_={async generateKeyPair(e){const t=pe(e),r=await crypto.subtle.generateKey(t,!0,["encrypt","decrypt"]),n=await T(r.publicKey),o=await k(r.privateKey,(e==null?void 0:e.passphrase)??"",t.name,n);return{publicKey:await V(r.publicKey,t.name,n),privateKey:o,fingerprint:n}},async importPublicKey(e){if(e instanceof CryptoKey)return e;const t=typeof e=="string"?O(e):e,{wrappedKey:r,algorithm:n,format:o}=t,a={name:n,hash:F},c=y.Buffer.from(r,"base64");return await crypto.subtle.importKey(o,c,a,!0,["encrypt"])},async importPrivateKey(e,t){if(e instanceof CryptoKey)return e;const r=typeof e=="string"?O(e):e,n=await L(t),o=y.Buffer.from(r.wrappedKey,"base64"),a=y.Buffer.from(r.iv,"base64"),c=await crypto.subtle.decrypt({name:N,iv:a},n,o),s=r.format||"pkcs8",p=s==="jwk"?JSON.parse(new TextDecoder().decode(c)):c;return crypto.subtle.importKey(s,p,{name:R,hash:F},!0,["decrypt"])},async derivePublicKey(e){const t=await crypto.subtle.exportKey("jwk",e),r={kty:t.kty,n:t.n,e:t.e,alg:t.alg,ext:!0};return crypto.subtle.importKey("jwk",r,{name:R,hash:F},!0,["encrypt"])},async encrypt(e,t){t=await this.importPublicKey(t);const r=await crypto.subtle.generateKey({name:N,length:256},!0,["encrypt","decrypt"]),n=crypto.getRandomValues(new Uint8Array(12)),o=new TextEncoder().encode(e),a=await crypto.subtle.encrypt({name:N,iv:n},r,o),c=await crypto.subtle.exportKey("raw",r),s=await crypto.subtle.encrypt({name:R},t,c),p={algorithm:R,keyFingerprint:await T(t),iv:y.Buffer.from(n).toString("base64"),symmetricKey:y.Buffer.from(s).toString("base64")};return{encryptedData:y.Buffer.from(a).toString("base64"),metadata:p}},async decrypt(e,t,r){const n=typeof e=="string"?Z(e):e;t=await this.importPrivateKey(t,r??"");const o=n.metadata,a=y.Buffer.from(o.symmetricKey,"base64"),c=await crypto.subtle.decrypt({name:R},t,a),s=await crypto.subtle.importKey("raw",c,{name:N,length:256},!1,["decrypt"]),p=y.Buffer.from(n.encryptedData,"base64"),m=y.Buffer.from(o.iv,"base64"),C=await crypto.subtle.decrypt({name:N,iv:m},s,p);return new TextDecoder().decode(C)}},P="ECDH",ne="P-256",x="AES-GCM",me=e=>({name:P,namedCurve:(e==null?void 0:e.eccCurve)||ne}),D={async generateKeyPair(e){const t=me(e),r=await crypto.subtle.generateKey(t,!0,["deriveKey","deriveBits"]),n=await T(r.publicKey),o=await k(r.privateKey,(e==null?void 0:e.passphrase)??"",t.name,n,t.namedCurve);return{publicKey:await V(r.publicKey,t.name,n,t.namedCurve),privateKey:o,fingerprint:n}},async importPrivateKey(e,t){if(e instanceof CryptoKey)return e;const r=typeof e=="string"?O(e):e,n=await L(t),o=y.Buffer.from(r.wrappedKey,"base64"),a=y.Buffer.from(r.iv,"base64"),c=await crypto.subtle.decrypt({name:x,iv:a},n,o),s=r.format||(r.algorithm===P?"jwk":"pkcs8"),p=s==="jwk"?JSON.parse(new TextDecoder().decode(c)):c,m={name:P,namedCurve:r.namedCurve};return crypto.subtle.importKey(s,p,m,!0,["deriveKey","deriveBits"])},async derivePublicKey(e){const t=await crypto.subtle.exportKey("jwk",e),r={kty:t.kty,crv:t.crv,x:t.x,y:t.y,ext:!0};return crypto.subtle.importKey("jwk",r,{name:P,namedCurve:e.algorithm.namedCurve},!0,[])},async importPublicKey(e){if(e instanceof CryptoKey)return e;const t=typeof e=="string"?O(e):e,{wrappedKey:r,algorithm:n,format:o,namedCurve:a}=t,c={name:n,namedCurve:a},s=y.Buffer.from(r,"base64");return await crypto.subtle.importKey(o,s,c,!0,[])},async encrypt(e,t){t=await this.importPublicKey(t);const r=t.algorithm,n=await crypto.subtle.generateKey({name:P,namedCurve:r.namedCurve},!0,["deriveKey","deriveBits"]),o=await crypto.subtle.deriveKey({name:P,public:t},n.privateKey,{name:x,length:256},!1,["encrypt"]),a=crypto.getRandomValues(new Uint8Array(12)),c=new TextEncoder().encode(e),s=await crypto.subtle.encrypt({name:x,iv:a},o,c),p=await crypto.subtle.exportKey("spki",n.publicKey),m={algorithm:P,keyFingerprint:await T(t),iv:y.Buffer.from(a).toString("base64"),symmetricKey:"",publicKey:y.Buffer.from(p).toString("base64"),namedCurve:r.namedCurve};return{encryptedData:y.Buffer.from(s).toString("base64"),metadata:m}},async decrypt(e,t,r){const n=typeof e=="string"?Z(e):e;t=await this.importPrivateKey(t,r??"");const o=await crypto.subtle.importKey("spki",y.Buffer.from(n.metadata.publicKey,"base64"),{name:P,namedCurve:n.metadata.namedCurve??ne},!0,[]),a=await crypto.subtle.deriveKey({name:P,public:o},t,{name:x,length:256},!1,["decrypt"]),c=y.Buffer.from(n.encryptedData,"base64"),s=y.Buffer.from(n.metadata.iv,"base64"),p=await crypto.subtle.decrypt({name:x,iv:s},a,c);return new TextDecoder().decode(p)}},U="AES-CTR",le="AES-GCM",ee={name:U,length:256},M={async generateKeyPair(e){const t=await crypto.subtle.generateKey(ee,!0,["encrypt","decrypt"]),r=await T(t,"raw"),n=(e==null?void 0:e.passphrase)||"",o={fingerprint:r,wrappedKey:y.Buffer.from(JSON.stringify(await crypto.subtle.exportKey("jwk",t))).toString("base64"),algorithm:U,format:"jwk"},a=n.length>0?await k(t,n,U,r):o;return{publicKey:o,privateKey:a,fingerprint:r}},derivePublicKey(){throw Error("Not implemented")},async importPublicKey(e){return this.importPrivateKey(e,"")},async importPrivateKey(e,t){if(e instanceof CryptoKey)return e;const r=typeof e=="string"?O(e):e,{wrappedKey:n,format:o,iv:a,protected:c}=r,s=ee;if(c){const C=await L(t),B=await crypto.subtle.decrypt({name:le,iv:y.Buffer.from(a,"base64")},C,y.Buffer.from(n,"base64")),b=JSON.parse(new TextDecoder().decode(B));return await crypto.subtle.importKey(o,b,s,!0,["encrypt","decrypt"])}const p=y.Buffer.from(n,"base64").toString(),m=JSON.parse(p);return await crypto.subtle.importKey(o,m,s,!0,["encrypt","decrypt"])},async encrypt(e,t){t=await this.importPublicKey(t);const r=new TextEncoder().encode(e),n={name:"AES-CTR",counter:new Uint8Array(16),length:16*8},o=await crypto.subtle.encrypt(n,t,r),a={algorithm:U,keyFingerprint:await T(t,"raw")};return{encryptedData:y.Buffer.from(o).toString("base64"),metadata:a}},async decrypt(e,t,r){const n=typeof e=="string"?Z(e):e;t=await this.importPrivateKey(t,r??"");const o={name:"AES-CTR",counter:new Uint8Array(16),length:16*8};return new TextDecoder("utf-8").decode(await crypto.subtle.decrypt(o,t,y.Buffer.from(n.encryptedData,"base64")))}};function ae(e){return btoa(encodeURIComponent(e))}function Y(e){return decodeURIComponent(atob(e))}const de=async e=>{let t;if(typeof e=="string")t=O(e);else if(typeof e=="object")t=e;else return e;return A(t.algorithm,[["RSA-OAEP",()=>_.importPublicKey(t)],["ECDH",()=>D.importPublicKey(t)],["AES-CTR",()=>M.importPublicKey(t)]])},be=async e=>A((e==null?void 0:e.algorithm)??"RSA",[["RSA",()=>_.generateKeyPair(e)],["ECC",()=>D.generateKeyPair(e)],["AES",()=>M.generateKeyPair(e)]]),z=e=>ae(JSON.stringify(e)),O=e=>JSON.parse(Y(e)),we=async e=>({publicKey:z(e.publicKey),privateKey:z(e.privateKey),fingerprint:e.fingerprint}),Ke=async(e,t)=>{const r=await de(t);return A(r.algorithm.name,[["RSA-OAEP",async()=>_.encrypt(e,r)],["ECDH",async()=>D.encrypt(e,r)],["AES-CTR",async()=>M.encrypt(e,r)]])},he=e=>ae(JSON.stringify(e)),Z=e=>JSON.parse(Y(e)),ve=async(e,t,r)=>(typeof e=="string"&&(e=JSON.parse(Y(e))),A(e.metadata.algorithm,[["RSA-OAEP",async()=>_.decrypt(e,t,r)],["ECDH",async()=>D.decrypt(e,t,r)],["AES-CTR",async()=>M.decrypt(e,t,r)]])),ge=async(e,t="")=>{const r=typeof e=="string"?O(e):e,n=await A(r.algorithm,[["RSA-OAEP",()=>_.importPrivateKey(r,t)],["ECDH",()=>D.importPrivateKey(r,t)],["AES-CTR",()=>M.importPrivateKey(r,t)]]);if(r.algorithm==="AES-CTR")return r;const o=await A(r.algorithm,[["RSA-OAEP",()=>_.derivePublicKey(n)],["ECDH",()=>D.derivePublicKey(n)],["AES-CTR",()=>M.derivePublicKey(n)]]);return V(o,r.algorithm,r.fingerprint,r.namedCurve)},Se=async(e,t)=>{const{privateKey:r}=await we(await be(t));return r},W=()=>{throw new Error("A required value was not provided")};async function Ee(e,t){const r=t["private-key"]??W();return z(await ge(r,t.passphrase??""))}async function Pe([e],t){const r=t["public-key"]??W();return he(await Ke(e,r))}async function Ae([e],t){const r=t["private-key"]??W();return await ve(e,r,t.passphrase??"")}(async()=>{const e=se(process.argv.slice(2)),t=e._[0]??void 0;e._.shift();const r=e._,n=e;delete n._;const o=()=>A(t,[["private-key:generate",()=>Se(r,n)],["public-key:generate",()=>Ee(r,n)],["encrypt",()=>Pe(r,n)],["decrypt",()=>Ae(r,n)],[A.default,()=>{throw Error(`Unknown command: ${t}`)}]]);try{console.log(await o()),process.exit(0)}catch(a){console.error(a),process.exit(1)}})();
