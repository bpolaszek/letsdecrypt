import {Buffer} from 'buffer'

const ECC_ALGORITHM = 'ECDH'
const SYMMETRIC_ALGORITHM = 'AES-GCM'
const HASH = 'SHA-256'

export type Algorithm = 'RSA' | 'ECC'

export interface KeyPairOptions {
  passphrase?: string
  algorithm?: Algorithm
  rsaModulusLength?: number
  eccCurve?: 'P-256' | 'P-384' | 'P-521'
}

export interface SerializedKeyPair {
  publicKey: string
  privateKey: string
}

export interface SecretMetadata {
  algorithm: string
  keyHash: string
  iv: string
  symmetricKey: string
  publicKey?: string // For ECC, we need to store the ephemeral public key
  namedCurve?: string // The curve used for ECC keys
}

export interface WrappedKeyData {
  wrappedKey: string // base64 encoded
  iv: string // base64 encoded
  algorithm: string // The algorithm used for the key
  format: string // The format of the wrapped key
  namedCurve?: string // The curve used for ECC keys
}

export interface CryptoKeyPair {
  publicKey: CryptoKey
  privateKey: CryptoKey
}

export interface WrappedCryptoKeyPair {
  publicKey: WrappedKeyData
  privateKey: WrappedKeyData
}

export type Secret = {
  encryptedData: string
  metadata: SecretMetadata
}

export type MaybeSerializedKey = string | WrappedKeyData | CryptoKey

export const generateKeyFromPassphrase = async (passphrase: string): Promise<CryptoKey> => {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, [
    'deriveBits',
    'deriveKey',
  ])

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: encoder.encode('salt'),
      iterations: 100000,
      hash: HASH,
    },
    keyMaterial,
    {
      name: SYMMETRIC_ALGORITHM,
      length: 256,
    },
    true,
    ['encrypt', 'decrypt']
  )
}

export const wrapPublicKey = async (
  key: CryptoKey,
  algorithm: string,
  namedCurve?: string
): Promise<WrappedKeyData> => {
  return {
    wrappedKey: Buffer.from(await crypto.subtle.exportKey('spki', key)).toString('base64'),
    iv: Buffer.from(crypto.getRandomValues(new Uint8Array(12))).toString('base64'),
    format: 'spki',
    algorithm,
    namedCurve,
  }
}

export const wrapPrivateKey = async (
  key: CryptoKey,
  passphrase: string,
  algorithm: string,
  namedCurve?: string
): Promise<WrappedKeyData> => {
  // First export the private key to wrap it
  const format = algorithm === ECC_ALGORITHM ? 'jwk' : 'pkcs8'
  const keyData = await crypto.subtle.exportKey(format, key)
  const keyBytes =
    format === 'jwk' ? new TextEncoder().encode(JSON.stringify(keyData)) : new Uint8Array(keyData as ArrayBuffer)

  // Generate a wrapping key from the passphrase
  const wrappingKey = await generateKeyFromPassphrase(passphrase)

  // Generate IV for encryption
  const iv = crypto.getRandomValues(new Uint8Array(12))

  // Wrap the exported key data
  const wrapped = await crypto.subtle.encrypt({name: SYMMETRIC_ALGORITHM, iv}, wrappingKey, keyBytes)

  return {
    wrappedKey: Buffer.from(wrapped).toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
    algorithm,
    format,
    namedCurve,
  }
}

export const hashKey = async (key: CryptoKey): Promise<string> => {
  const exported = await crypto.subtle.exportKey('spki', key)
  const hashBuffer = await crypto.subtle.digest(HASH, exported)
  return Buffer.from(hashBuffer).toString('hex')
}
