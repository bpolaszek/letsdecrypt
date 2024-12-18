import {
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
import {CryptoServiceAlgorithmInterface} from './index.ts'

const ECC_ALGORITHM = 'ECDH'
const DEFAULT_ECC_CURVE = 'P-256'
const SYMMETRIC_ALGORITHM = 'AES-GCM'

const getKeyGenParams = (options?: KeyPairOptions): EcKeyGenParams & {namedCurve?: string} => {
  return {
    name: ECC_ALGORITHM,
    namedCurve: options?.eccCurve || DEFAULT_ECC_CURVE,
  }
}

export const Ecc: CryptoServiceAlgorithmInterface = {
  async generateKeyPair(options?: KeyPairOptions): Promise<WrappedCryptoKeyPair> {
    const params = getKeyGenParams(options)
    const keyPair = await crypto.subtle.generateKey(params, true, ['deriveKey', 'deriveBits'])
    // If passphrase provided, wrap the private key
    const wrappedPrivateKey = await wrapPrivateKey(
      keyPair.privateKey,
      options?.passphrase ?? '',
      params.name,
      params.namedCurve
    )
    const wrappedPublicKey = await wrapPublicKey(keyPair.publicKey, params.name, params.namedCurve)
    return {
      publicKey: wrappedPublicKey,
      privateKey: wrappedPrivateKey,
    }
  },
  async importPrivateKey(wrappedData: MaybeSerializedKey, passphrase: string): Promise<CryptoKey> {
    if (wrappedData instanceof CryptoKey) {
      return wrappedData
    }
    const wrappedKeyData: WrappedKeyData = 'string' === typeof wrappedData ? JSON.parse(wrappedData) : wrappedData

    // Generate the unwrapping key from the passphrase
    const unwrappingKey = await generateKeyFromPassphrase(passphrase)

    // Decode the wrapped key and IV from base64
    const wrappedKey = Buffer.from(wrappedKeyData.wrappedKey, 'base64')
    const iv = Buffer.from(wrappedKeyData.iv, 'base64')

    // Decrypt the wrapped key
    const unwrappedData = await crypto.subtle.decrypt({name: SYMMETRIC_ALGORITHM, iv}, unwrappingKey, wrappedKey)

    // Handle the unwrapped data based on the original format
    const format = (wrappedKeyData as any).format || (wrappedKeyData.algorithm === ECC_ALGORITHM ? 'jwk' : 'pkcs8')
    const keyData = format === 'jwk' ? JSON.parse(new TextDecoder().decode(unwrappedData)) : unwrappedData

    // Import the key with the correct algorithm parameters
    const importParams = {name: ECC_ALGORITHM, namedCurve: wrappedKeyData.namedCurve}

    return crypto.subtle.importKey(format, keyData, importParams, true, ['deriveKey', 'deriveBits'])
  },
  async importPublicKey(wrappedData: MaybeSerializedKey): Promise<CryptoKey> {
    if (wrappedData instanceof CryptoKey) {
      return wrappedData
    }
    const wrappedKeyData: WrappedKeyData = 'string' === typeof wrappedData ? JSON.parse(wrappedData) : wrappedData
    const {wrappedKey, algorithm, format, namedCurve} = wrappedKeyData
    const algorithmOptions = {name: algorithm, namedCurve}
    const binaryKey = Buffer.from(wrappedKey, 'base64')
    return await crypto.subtle.importKey(format as any, binaryKey, algorithmOptions, true, [])
  },
  async encrypt(data: string, publicKey: MaybeSerializedKey): Promise<Secret> {
    publicKey = await this.importPublicKey(publicKey)
    // For ECC, we need to:
    // 1. Generate an ephemeral key pair
    // 2. Derive a shared secret using ECDH
    // 3. Use the shared secret to encrypt the data
    const keyAlgorithm = publicKey.algorithm as EcKeyImportParams | RsaHashedImportParams
    const ephemeralKeyPair = (await crypto.subtle.generateKey(
      {
        name: ECC_ALGORITHM,
        namedCurve: (keyAlgorithm as EcKeyImportParams).namedCurve,
      },
      true,
      ['deriveKey', 'deriveBits']
    )) as CryptoKeyPair

    // Derive the shared secret
    const sharedSecret = await crypto.subtle.deriveKey(
      {
        name: ECC_ALGORITHM,
        public: publicKey,
      },
      ephemeralKeyPair.privateKey,
      {
        name: SYMMETRIC_ALGORITHM,
        length: 256,
      },
      false,
      ['encrypt']
    )

    // Generate IV
    const iv = crypto.getRandomValues(new Uint8Array(12))

    // Encrypt the data with the derived key
    const encodedData = new TextEncoder().encode(data)
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: SYMMETRIC_ALGORITHM,
        iv,
      },
      sharedSecret,
      encodedData
    )

    // Export the ephemeral public key - we'll need it for decryption
    const exportedEphemeralKey = await crypto.subtle.exportKey('spki', ephemeralKeyPair.publicKey)

    // Create metadata
    const metadata: SecretMetadata = {
      algorithm: ECC_ALGORITHM,
      keyHash: await hashKey(publicKey),
      iv: Buffer.from(iv).toString('base64'),
      symmetricKey: '', // Not needed for ECC
      publicKey: Buffer.from(exportedEphemeralKey).toString('base64'),
      namedCurve: (keyAlgorithm as EcKeyImportParams).namedCurve,
    }

    return {
      encryptedData: Buffer.from(encryptedData).toString('base64'),
      metadata,
    }
  },
  async decrypt(secret: Secret | string, privateKey: MaybeSerializedKey, passphrase?: string): Promise<string> {
    // Import the ephemeral public key
    const secretObj = typeof secret === 'string' ? JSON.parse(secret) : secret
    privateKey = await this.importPrivateKey(privateKey, passphrase ?? '')

    const ephemeralPublicKey = await crypto.subtle.importKey(
      'spki',
      Buffer.from(secretObj.metadata.publicKey!, 'base64'),
      {
        name: ECC_ALGORITHM,
        namedCurve: secretObj.metadata.namedCurve ?? DEFAULT_ECC_CURVE,
      },
      true,
      []
    )

    // Derive the same shared secret
    const sharedSecret = await crypto.subtle.deriveKey(
      {
        name: ECC_ALGORITHM,
        public: ephemeralPublicKey,
      },
      privateKey,
      {
        name: SYMMETRIC_ALGORITHM,
        length: 256,
      },
      false,
      ['decrypt']
    )

    // Decrypt the data
    const encryptedData = Buffer.from(secretObj.encryptedData, 'base64')
    const iv = Buffer.from(secretObj.metadata.iv!, 'base64')

    const decryptedData = await crypto.subtle.decrypt(
      {
        name: SYMMETRIC_ALGORITHM,
        iv,
      },
      sharedSecret,
      encryptedData
    )

    return new TextDecoder().decode(decryptedData)
  },
}
