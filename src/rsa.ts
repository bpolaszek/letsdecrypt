import {
  type AlgorithmId,
  Secret,
  type SecretMetadata,
  type WrappedKeyData,
  type KeyPairOptions,
  generateKeyFromPassphrase,
  hashKey,
  WrappedCryptoKeyPair,
  wrapPrivateKey,
  wrapPublicKey,
} from './common'
import {Buffer} from 'buffer'
import {CryptoServiceAlgorithmInterface} from './index.ts'

const RSA_ALGORITHM = 'RSA-OAEP'
const SYMMETRIC_ALGORITHM = 'AES-GCM'
const DEFAULT_RSA_LENGTH = 2048
const HASH = 'SHA-256'

const getKeyGenParams = (options?: KeyPairOptions): RsaHashedKeyGenParams => {
  return {
    name: RSA_ALGORITHM,
    modulusLength: options?.rsaModulusLength || DEFAULT_RSA_LENGTH,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: HASH,
  }
}

export const Rsa: CryptoServiceAlgorithmInterface = {
  getPublicKeyUsages(): KeyUsage[] {
    return ['encrypt']
  },
  getPrivateKeyUsages(): KeyUsage[] {
    return ['decrypt']
  },
  getKeyPairUsages(): KeyUsage[] {
    return ['encrypt', 'decrypt']
  },
  getAlgorithm(): AlgorithmId {
    return 'RSA-OAEP'
  },
  async generateKeyPair(options?: KeyPairOptions): Promise<WrappedCryptoKeyPair> {
    const params = getKeyGenParams(options)
    const keyPair = await crypto.subtle.generateKey(params, true, this.getKeyPairUsages())
    // If passphrase provided, wrap the private key
    const wrappedPrivateKey = await wrapPrivateKey(keyPair.privateKey, options?.passphrase ?? '', params.name)
    const wrappedPublicKey = await wrapPublicKey(keyPair.publicKey, params.name)
    return {
      publicKey: wrappedPublicKey,
      privateKey: wrappedPrivateKey,
    }
  },
  async unwrapKey(wrappedData: WrappedKeyData, passphrase: string): Promise<CryptoKey> {
    // Generate the unwrapping key from the passphrase
    const unwrappingKey = await generateKeyFromPassphrase(passphrase)

    // Decode the wrapped key and IV from base64
    const wrappedKey = Buffer.from(wrappedData.wrappedKey, 'base64')
    const iv = Buffer.from(wrappedData.iv, 'base64')

    // Decrypt the wrapped key
    const unwrappedData = await crypto.subtle.decrypt({name: SYMMETRIC_ALGORITHM, iv}, unwrappingKey, wrappedKey)

    // Handle the unwrapped data based on the original format
    const format = (wrappedData as any).format || 'pkcs8'
    const keyData = format === 'jwk' ? JSON.parse(new TextDecoder().decode(unwrappedData)) : unwrappedData

    return crypto.subtle.importKey(
      format,
      keyData,
      {
        name: RSA_ALGORITHM,
        hash: HASH,
      },
      true,
      this.getPrivateKeyUsages()
    )
  },
  async importPrivateKey(serialized: string, passphrase?: string): Promise<CryptoKey> {
    const wrappedKeyData: WrappedKeyData = JSON.parse(serialized)
    return this.unwrapKey(wrappedKeyData, passphrase ?? '')
  },
  async encrypt(data: string, publicKey: CryptoKey): Promise<Secret> {
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
      keyHash: await hashKey(publicKey),
      iv: Buffer.from(iv).toString('base64'),
      symmetricKey: Buffer.from(encryptedSymKey).toString('base64'),
    }

    return {
      encryptedData: Buffer.from(encryptedData).toString('base64'),
      metadata,
    }
  },
  async decrypt(
    secret: Secret | string,
    privateKey: CryptoKey | string | WrappedKeyData,
    passphrase?: string
  ): Promise<string> {
    const secretObj = typeof secret === 'string' ? JSON.parse(secret) : secret
    let key: CryptoKey

    if (typeof privateKey === 'string') {
      key = await this.importPrivateKey(privateKey, passphrase)
    } else if ('wrappedKey' in privateKey) {
      key = await this.unwrapKey(privateKey, passphrase ?? '')
    } else {
      key = privateKey
    }

    const metadata = secretObj.metadata
    // Decrypt the symmetric key
    const encryptedSymKey = Buffer.from(metadata.symmetricKey, 'base64')
    const symmetricKeyBuffer = await crypto.subtle.decrypt(
      {
        name: RSA_ALGORITHM,
      },
      key,
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
    const iv = Buffer.from(metadata.iv, 'base64')

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
