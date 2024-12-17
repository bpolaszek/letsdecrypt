import { Rsa } from "./rsa"
import { Ecc } from "./ecc"
import type {
  AlgorithmId,
  CryptoKeyPair,
  KeyPairOptions,
  SerializedKeyPair,
  WrappedCryptoKeyPair,
  WrappedKeyData,
} from "./common"
import { Secret } from "./common"
import match from "match-operator"
import { Buffer } from "buffer"

export * from './common'

type AlgorithmOptions = {
  name: string;
  hash?: string
  namedCurve?: string
}

export class CryptoService {
  protected static readonly HASH = 'SHA-256'
  private static readonly DEFAULT_ECC_CURVE = 'P-256';

  static async generateKeyPair(options?: KeyPairOptions): Promise<WrappedCryptoKeyPair> {
    return match(options?.algorithm ?? 'RSA', [
      ['RSA', () => Rsa.generateKeyPair(options)],
      ['ECC', () => Ecc.generateKeyPair(options)],
    ]) as unknown as Promise<WrappedCryptoKeyPair>
  }


  static async exportKeyPair(keyPair: CryptoKeyPair | WrappedCryptoKeyPair): Promise<SerializedKeyPair> {
    return {
      publicKey: JSON.stringify(keyPair.publicKey),
      privateKey: JSON.stringify(keyPair.privateKey),
    }
  }

  protected static async importPublicKey(serialized: string): Promise<CryptoKey> {
    const {wrappedKey, algorithm} = JSON.parse(serialized)
    const usages = match(algorithm, [
      ['RSA-OAEP', () => Rsa.getPublicKeyUsages()],
      ['ECDH', () => Ecc.getPublicKeyUsages()],
    ]) as unknown as KeyUsage[]
    const algorithmOptions = match<AlgorithmId, AlgorithmOptions>(algorithm, [
      ['RSA-OAEP', () => ({name: algorithm, hash: this.HASH})],
      ['ECDH', () => ({name: algorithm, namedCurve: this.DEFAULT_ECC_CURVE})],
    ])
    const binaryKey = Buffer.from(wrappedKey, 'base64')
    return await crypto.subtle.importKey(
      'spki',
      binaryKey,
      algorithmOptions,
      true,
      usages,
    )
  }

  static async encrypt(
    data: string,
    publicKey: string | CryptoKey,
  ): Promise<Secret> {
    const key = typeof publicKey === 'string'
      ? await this.importPublicKey(publicKey)
      : publicKey

    return match(key.algorithm.name, [
      ['RSA-OAEP', async () => Rsa.encrypt(data, key)],
      ['ECDH', async () => Ecc.encrypt(data, key)],
    ]) as unknown as Promise<Secret>
  }

  static async decrypt(
    secret: Secret | string,
    privateKey: CryptoKey | string | WrappedKeyData,
    passphrase?: string,
  ): Promise<string> {
    if ('string' === typeof secret) {
      secret = Secret.deserialize(secret)
    }
    return match(secret.getMetadata().algorithm, [
      ['RSA-OAEP', async () => Rsa.decrypt(secret, privateKey, passphrase)],
      ['ECDH', async () => Ecc.decrypt(secret, privateKey, passphrase)],
    ]) as unknown as Promise<string>
  }
}
