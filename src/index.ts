import {Rsa} from './rsa'
import {Ecc} from './ecc'
import type {
  AlgorithmId,
  CryptoKeyPair,
  KeyPairOptions,
  SerializedKeyPair,
  WrappedCryptoKeyPair,
  WrappedKeyData,
  Secret,
} from './common'
import match from 'match-operator'
import {Buffer} from 'buffer'

export * from './common'

export const HASHING_ALGORITHM = 'SHA-256'

type AlgorithmOptions = {
  name: string
  hash?: string
  namedCurve?: string
}

export interface CryptoServiceAlgorithmInterface {
  getPublicKeyUsages(): KeyUsage[]
  getPrivateKeyUsages(): KeyUsage[]
  getKeyPairUsages(): KeyUsage[]
  getAlgorithm(): AlgorithmId
  generateKeyPair(options?: KeyPairOptions): Promise<WrappedCryptoKeyPair>
  encrypt(data: string, publicKey: CryptoKey): Promise<Secret>
  decrypt(
    secret: Secret | string,
    privateKey: CryptoKey | string | WrappedKeyData,
    passphrase?: string
  ): Promise<string>
  unwrapKey(wrappedData: WrappedKeyData, passphrase: string): Promise<CryptoKey>
  importPrivateKey(serialized: string, passphrase?: string): Promise<CryptoKey>
}

export const CryptoService = {
  async generateKeyPair(options?: KeyPairOptions): Promise<WrappedCryptoKeyPair> {
    return match(options?.algorithm ?? 'RSA', [
      ['RSA', () => Rsa.generateKeyPair(options)],
      ['ECC', () => Ecc.generateKeyPair(options)],
    ]) as unknown as Promise<WrappedCryptoKeyPair>
  },
  async exportKeyPair(keyPair: CryptoKeyPair | WrappedCryptoKeyPair): Promise<SerializedKeyPair> {
    return {
      publicKey: JSON.stringify(keyPair.publicKey),
      privateKey: JSON.stringify(keyPair.privateKey),
    }
  },
  async importPublicKey(serialized: string): Promise<CryptoKey> {
    const unserialized = JSON.parse(serialized)
    const {wrappedKey, algorithm, format, namedCurve} = unserialized
    const usages = match(algorithm, [
      ['RSA-OAEP', () => Rsa.getPublicKeyUsages()],
      ['ECDH', () => Ecc.getPublicKeyUsages()],
    ]) as unknown as KeyUsage[]
    const algorithmOptions = match<AlgorithmId, AlgorithmOptions>(algorithm, [
      ['RSA-OAEP', () => ({name: algorithm, hash: HASHING_ALGORITHM})],
      ['ECDH', () => ({name: algorithm, namedCurve})],
    ])
    const binaryKey = Buffer.from(wrappedKey, 'base64')
    return await crypto.subtle.importKey(format, binaryKey, algorithmOptions, true, usages)
  },
  async encrypt(data: string, publicKey: string | CryptoKey): Promise<Secret> {
    const key = typeof publicKey === 'string' ? await this.importPublicKey(publicKey) : publicKey

    return match(key.algorithm.name, [
      ['RSA-OAEP', async () => Rsa.encrypt(data, key)],
      ['ECDH', async () => Ecc.encrypt(data, key)],
    ]) as unknown as Promise<Secret>
  },
  async decrypt(
    secret: Secret | string,
    privateKey: CryptoKey | string | WrappedKeyData,
    passphrase?: string
  ): Promise<string> {
    if ('string' === typeof secret) {
      secret = JSON.parse(secret)
    }
    return match((secret as Secret).metadata.algorithm, [
      ['RSA-OAEP', async () => Rsa.decrypt(secret, privateKey, passphrase)],
      ['ECDH', async () => Ecc.decrypt(secret, privateKey, passphrase)],
    ]) as unknown as Promise<string>
  },
}
