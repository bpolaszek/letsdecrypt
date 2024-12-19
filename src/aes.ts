import {
  CryptoServiceAlgorithmInterface,
  hashKey,
  MaybeSerializedKey,
  Secret,
  WrappedCryptoKeyPair,
  type WrappedKeyData,
} from "./common.ts"
import { Buffer } from "buffer"

const AES_ALGORITHM = 'AES-CTR'

type AesHashedKeyGenParams = {
  name: string
  length: number
}

const getKeyGenParams = (): AesHashedKeyGenParams => {
  return {name: AES_ALGORITHM, length: 256}
}

export const Aes: CryptoServiceAlgorithmInterface = {
  async generateKeyPair(): Promise<WrappedCryptoKeyPair> {
    const params = getKeyGenParams()
    const privateKey = await crypto.subtle.generateKey(params, true, ['encrypt', 'decrypt'])
    // If passphrase provided, wrap the private key
    const wrappedPrivateKey: WrappedKeyData = {
      wrappedKey: Buffer.from(JSON.stringify(await crypto.subtle.exportKey('jwk', privateKey))).toString('base64'),
      algorithm: AES_ALGORITHM,
      format: 'jwk',
    }
    return {
      publicKey: wrappedPrivateKey,
      privateKey: wrappedPrivateKey,
    }
  },
  async importPublicKey(wrappedData: MaybeSerializedKey): Promise<CryptoKey> {
    return this.importPrivateKey(wrappedData, '')
  },
  async importPrivateKey(wrappedData: MaybeSerializedKey): Promise<CryptoKey> {
    if (wrappedData instanceof CryptoKey) {
      return wrappedData
    }
    const wrappedKeyData: WrappedKeyData = 'string' === typeof wrappedData ? JSON.parse(wrappedData) : wrappedData
    const {wrappedKey,  format} = wrappedKeyData
    const algorithmOptions = {name: AES_ALGORITHM, length: 256}
    return await crypto.subtle.importKey(
      format as any,
      JSON.parse(Buffer.from(wrappedKey, 'base64').toString('ascii')),
      algorithmOptions,
      true,
      ['encrypt', 'decrypt']
    )
  },
  async encrypt(data: string, publicKey: MaybeSerializedKey): Promise<Secret> {
    publicKey = await this.importPublicKey(publicKey)
    const encodedData = new TextEncoder().encode(data)
    const algorithmOptions = {name: 'AES-CTR', counter: new Uint8Array(16), length: 16 * 8}
    const encryptedData = await crypto.subtle.encrypt(
      algorithmOptions,
      publicKey,
      encodedData
    )

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
      await crypto.subtle.decrypt(
        algorithmOptions,
        privateKey,
        Buffer.from(secretObj.encryptedData, 'base64')
      )
    )
  }
}
