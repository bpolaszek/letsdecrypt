import {
  CryptoServiceAlgorithmInterface,
  generateKeyFromPassphrase,
  hashKey,
  KeyPairOptions,
  MaybeSerializedKey,
  Secret,
  WrappedCryptoKeyPair,
  type WrappedKeyData,
  wrapPrivateKey,
} from './common.ts'
import {Buffer} from 'buffer'

const AES_ALGORITHM = 'AES-CTR'
const GCM_ALGORITHM = 'AES-GCM'
const ALGORITHM_OPTIONS = {name: AES_ALGORITHM, length: 256}

export const Aes: CryptoServiceAlgorithmInterface = {
  async generateKeyPair(options?: KeyPairOptions): Promise<WrappedCryptoKeyPair> {
    const privateKey = await crypto.subtle.generateKey(ALGORITHM_OPTIONS, true, ['encrypt', 'decrypt'])
    const passphrase = options?.passphrase || ''

    const wrappedPublicKey = {
      wrappedKey: Buffer.from(JSON.stringify(await crypto.subtle.exportKey('jwk', privateKey))).toString('base64'),
      algorithm: AES_ALGORITHM,
      format: 'jwk',
    }
    const wrappedPrivateKey =
      passphrase.length > 0 ? await wrapPrivateKey(privateKey, passphrase, AES_ALGORITHM) : wrappedPublicKey

    return {
      publicKey: wrappedPublicKey,
      privateKey: wrappedPrivateKey,
    }
  },

  async importPublicKey(wrappedData: MaybeSerializedKey): Promise<CryptoKey> {
    return this.importPrivateKey(wrappedData, '')
  },

  async importPrivateKey(wrappedData: MaybeSerializedKey, passphrase: string): Promise<CryptoKey> {
    if (wrappedData instanceof CryptoKey) {
      return wrappedData
    }
    const wrappedKeyData: WrappedKeyData = 'string' === typeof wrappedData ? JSON.parse(wrappedData) : wrappedData
    const {wrappedKey, format, iv, protected: isProtected} = wrappedKeyData
    const algorithmOptions = ALGORITHM_OPTIONS

    if (isProtected) {
      const wrappingKey = await generateKeyFromPassphrase(passphrase)

      const decryptedKeyBytes = await crypto.subtle.decrypt(
        {name: GCM_ALGORITHM, iv: Buffer.from(iv!, 'base64')},
        wrappingKey,
        Buffer.from(wrappedKey, 'base64')
      )

      const keyData = JSON.parse(new TextDecoder().decode(decryptedKeyBytes))
      return await crypto.subtle.importKey(format as any, keyData, algorithmOptions, true, ['encrypt', 'decrypt'])
    }

    const decodedKeyString = Buffer.from(wrappedKey, 'base64').toString()
    const keyData = JSON.parse(decodedKeyString)

    return await crypto.subtle.importKey(format as any, keyData, algorithmOptions, true, ['encrypt', 'decrypt'])
  },

  async encrypt(data: string, publicKey: MaybeSerializedKey): Promise<Secret> {
    publicKey = await this.importPublicKey(publicKey)
    const encodedData = new TextEncoder().encode(data)
    const algorithmOptions = {name: 'AES-CTR', counter: new Uint8Array(16), length: 16 * 8}
    const encryptedData = await crypto.subtle.encrypt(algorithmOptions, publicKey, encodedData)

    const metadata = {
      algorithm: AES_ALGORITHM,
      keyHash: await hashKey(publicKey, 'raw'),
    }

    return {
      encryptedData: Buffer.from(encryptedData).toString('base64'),
      metadata,
    }
  },

  async decrypt(secret: Secret | string, privateKey: MaybeSerializedKey, passphrase?: string): Promise<string> {
    const secretObj = typeof secret === 'string' ? JSON.parse(secret) : secret
    privateKey = await this.importPrivateKey(privateKey, passphrase ?? '')
    const algorithmOptions = {name: 'AES-CTR', counter: new Uint8Array(16), length: 16 * 8}
    return new TextDecoder('utf-8').decode(
      await crypto.subtle.decrypt(algorithmOptions, privateKey, Buffer.from(secretObj.encryptedData, 'base64'))
    )
  },
}
