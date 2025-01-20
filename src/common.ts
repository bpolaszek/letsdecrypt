import {Buffer} from 'buffer'

const SYMMETRIC_ALGORITHM = 'AES-GCM'
const HASH = 'SHA-256'

export type Algorithm = 'RSA' | 'ECC' | 'AES'

export interface KeyPairOptions {
  passphrase?: string
  algorithm?: Algorithm
  rsaModulusLength?: number
  eccCurve?: 'P-256' | 'P-384' | 'P-521'
}

export interface SerializedKeyPair {
  publicKey: string
  privateKey: string
  fingerprint: string
}

export interface SecretMetadata {
  algorithm: string
  keyFingerprint: string
  symmetricKey?: string
  iv?: string
  publicKey?: string // For ECC, we need to store the ephemeral public key
  namedCurve?: string // The curve used for ECC keys
}

export interface WrappedKeyData {
  fingerprint: string
  wrappedKey: string // base64 encoded
  algorithm: string // The algorithm used for the key
  format: string // The format of the wrapped key
  iv?: string // base64 encoded
  namedCurve?: string // The curve used for ECC keys
  protected?: boolean // Whether the key is protected by a passphrase
}

export interface CryptoKeyPair {
  publicKey: CryptoKey
  privateKey: CryptoKey
}

export interface WrappedCryptoKeyPair {
  publicKey: WrappedKeyData
  privateKey: WrappedKeyData
  fingerprint: string
}

export type Secret = {
  encryptedData: string
  metadata: SecretMetadata
}

export interface CryptoServiceAlgorithmInterface {
  generateKeyPair(options?: KeyPairOptions): Promise<WrappedCryptoKeyPair>
  encrypt(data: string, publicKey: MaybeSerializedKey): Promise<Secret>
  decrypt(secret: Secret | string, privateKey: MaybeSerializedKey, passphrase?: string): Promise<string>
  importPrivateKey(wrappedData: MaybeSerializedKey, passphrase: string): Promise<CryptoKey>
  importPublicKey(wrappedData: MaybeSerializedKey): Promise<CryptoKey>
  derivePublicKey(privateKey: CryptoKey): Promise<CryptoKey>
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
  fingerprint: string,
  namedCurve?: string
): Promise<WrappedKeyData> => {
  // Make sure we have a public key
  if (key.type === 'private') {
    throw new Error('Cannot wrap a private key as public key')
  }

  return {
    fingerprint,
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
  fingerprint: string,
  namedCurve?: string
): Promise<WrappedKeyData> => {
  // First export the private key to wrap it
  const format = 'jwk'
  const keyData = await crypto.subtle.exportKey(format, key)
  const keyBytes = new TextEncoder().encode(JSON.stringify(keyData))

  // Generate a wrapping key from the passphrase
  const wrappingKey = await generateKeyFromPassphrase(passphrase)

  // Generate IV for encryption
  const iv = crypto.getRandomValues(new Uint8Array(12))

  // Wrap the exported key data
  const wrapped = await crypto.subtle.encrypt({name: SYMMETRIC_ALGORITHM, iv}, wrappingKey, keyBytes)

  return {
    fingerprint,
    wrappedKey: Buffer.from(wrapped).toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
    algorithm,
    format,
    namedCurve,
    protected: passphrase.length > 0 ? true : undefined,
  }
}

export const hashKey = async (key: CryptoKey, format: string = 'spki'): Promise<string> => {
  const exported = await crypto.subtle.exportKey(format as any, key)
  const hashBuffer = await crypto.subtle.digest(HASH, exported as any)
  return Buffer.from(hashBuffer).toString('hex')
}
