import {
  CryptoServiceAlgorithmInterface,
  generateKeyFromPassphrase,
  hashKey,
  type KeyPairOptions,
  MaybeSerializedKey,
  Secret,
  type SecretMetadata,
  WrappedCryptoKeyPair,
  type WrappedKeyData,
  wrapPrivateKey,
  wrapPublicKey,
} from './common'
import {Buffer} from 'buffer'
import {unserializeKey, unserializeSecret} from './index.ts'

const RSA_ALGORITHM = 'RSA-OAEP'
const SYMMETRIC_ALGORITHM = 'AES-GCM'
const DEFAULT_RSA_LENGTH = 2048
const HASHING_ALGORITHM = 'SHA-256'

const getKeyGenParams = (options?: KeyPairOptions): RsaHashedKeyGenParams => {
  return {
    name: RSA_ALGORITHM,
    modulusLength: options?.rsaModulusLength || DEFAULT_RSA_LENGTH,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: HASHING_ALGORITHM,
  }
}

export const Rsa: CryptoServiceAlgorithmInterface = {
  async generateKeyPair(options?: KeyPairOptions): Promise<WrappedCryptoKeyPair> {
    const params = getKeyGenParams(options)
    const keyPair = await crypto.subtle.generateKey(params, true, ['encrypt', 'decrypt'])
    const fingerprint = await hashKey(keyPair.publicKey)
    // If passphrase provided, wrap the private key
    const wrappedPrivateKey = await wrapPrivateKey(
      keyPair.privateKey,
      options?.passphrase ?? '',
      params.name,
      fingerprint
    )
    const wrappedPublicKey = await wrapPublicKey(keyPair.publicKey, params.name, fingerprint)
    return {
      publicKey: wrappedPublicKey,
      privateKey: wrappedPrivateKey,
      fingerprint,
    }
  },
  async importPublicKey(wrappedData: MaybeSerializedKey): Promise<CryptoKey> {
    if (wrappedData instanceof CryptoKey) {
      return wrappedData
    }
    const wrappedKeyData: WrappedKeyData = 'string' === typeof wrappedData ? unserializeKey(wrappedData) : wrappedData
    const {wrappedKey, algorithm, format} = wrappedKeyData
    const algorithmOptions = {name: algorithm, hash: HASHING_ALGORITHM}
    const binaryKey = Buffer.from(wrappedKey, 'base64')
    return await crypto.subtle.importKey(format as any, binaryKey, algorithmOptions, true, ['encrypt'])
  },
  async importPrivateKey(wrappedData: MaybeSerializedKey, passphrase: string): Promise<CryptoKey> {
    if (wrappedData instanceof CryptoKey) {
      return wrappedData
    }
    const wrappedKeyData: WrappedKeyData = 'string' === typeof wrappedData ? unserializeKey(wrappedData) : wrappedData

    // Generate the unwrapping key from the passphrase
    const unwrappingKey = await generateKeyFromPassphrase(passphrase)

    // Decode the wrapped key and IV from base64
    const wrappedKey = Buffer.from(wrappedKeyData.wrappedKey, 'base64')
    const iv = Buffer.from(wrappedKeyData.iv!, 'base64')

    // Decrypt the wrapped key
    const unwrappedData = await crypto.subtle.decrypt({name: SYMMETRIC_ALGORITHM, iv}, unwrappingKey, wrappedKey)

    // Handle the unwrapped data based on the original format
    const format = (wrappedKeyData as any).format || 'pkcs8'
    const keyData = format === 'jwk' ? JSON.parse(new TextDecoder().decode(unwrappedData)) : unwrappedData

    return crypto.subtle.importKey(
      format,
      keyData,
      {
        name: RSA_ALGORITHM,
        hash: HASHING_ALGORITHM,
      },
      true,
      ['decrypt']
    )
  },
  async encrypt(data: string, publicKey: MaybeSerializedKey): Promise<Secret> {
    publicKey = await this.importPublicKey(publicKey)
    // RSA encryption path (unchanged)
    // Generate a symmetric key for the actual data encryption
    const symmetricKey = await crypto.subtle.generateKey(
      {
        name: SYMMETRIC_ALGORITHM,
        length: 256,
      },
      true,
      ['encrypt', 'decrypt']
    )

    // Generate IV
    const iv = crypto.getRandomValues(new Uint8Array(12))

    // Encrypt the data with the symmetric key
    const encodedData = new TextEncoder().encode(data)
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: SYMMETRIC_ALGORITHM,
        iv,
      },
      symmetricKey,
      encodedData
    )

    // Export and encrypt the symmetric key with the public key
    const exportedSymKey = await crypto.subtle.exportKey('raw', symmetricKey)
    const encryptedSymKey = await crypto.subtle.encrypt(
      {
        name: RSA_ALGORITHM,
      },
      publicKey,
      exportedSymKey
    )

    // Create metadata
    const metadata: SecretMetadata = {
      algorithm: RSA_ALGORITHM,
      keyFingerprint: await hashKey(publicKey),
      iv: Buffer.from(iv).toString('base64'),
      symmetricKey: Buffer.from(encryptedSymKey).toString('base64'),
    }

    return {
      encryptedData: Buffer.from(encryptedData).toString('base64'),
      metadata,
    }
  },
  async decrypt(secret: Secret | string, privateKey: MaybeSerializedKey, passphrase?: string): Promise<string> {
    const secretObj = typeof secret === 'string' ? unserializeSecret(secret) : secret
    privateKey = await this.importPrivateKey(privateKey, passphrase ?? '')

    const metadata = secretObj.metadata
    // Decrypt the symmetric key
    const encryptedSymKey = Buffer.from(metadata.symmetricKey!, 'base64')
    const symmetricKeyBuffer = await crypto.subtle.decrypt(
      {
        name: RSA_ALGORITHM,
      },
      privateKey,
      encryptedSymKey
    )

    // Import the symmetric key
    const symmetricKey = await crypto.subtle.importKey(
      'raw',
      symmetricKeyBuffer,
      {
        name: SYMMETRIC_ALGORITHM,
        length: 256,
      },
      false,
      ['decrypt']
    )

    // Decrypt the data
    const encryptedData = Buffer.from(secretObj.encryptedData, 'base64')
    const iv = Buffer.from(metadata.iv!, 'base64')

    const decryptedData = await crypto.subtle.decrypt(
      {
        name: SYMMETRIC_ALGORITHM,
        iv,
      },
      symmetricKey,
      encryptedData
    )

    return new TextDecoder().decode(decryptedData)
  },
}
