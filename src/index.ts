import {Rsa} from './rsa'
import {Ecc} from './ecc'
import {
  CryptoKeyPair,
  KeyPairOptions,
  MaybeSerializedKey,
  Secret,
  SerializedKeyPair,
  WrappedCryptoKeyPair,
  WrappedKeyData,
} from './common'
import match from 'match-operator'

export * from './common'

export const HASHING_ALGORITHM = 'SHA-256'

export interface CryptoServiceAlgorithmInterface {
  generateKeyPair(options?: KeyPairOptions): Promise<WrappedCryptoKeyPair>
  encrypt(data: string, publicKey: MaybeSerializedKey): Promise<Secret>
  decrypt(secret: Secret | string, privateKey: MaybeSerializedKey, passphrase?: string): Promise<string>
  importPrivateKey(wrappedData: MaybeSerializedKey, passphrase: string): Promise<CryptoKey>
  importPublicKey(wrappedData: MaybeSerializedKey): Promise<CryptoKey>
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
  async importPublicKey(publicKey: MaybeSerializedKey): Promise<CryptoKey> {
    let wrappedKeyData: WrappedKeyData
    if ('string' === typeof publicKey) {
      wrappedKeyData = JSON.parse(publicKey)
    } else if ('object' === typeof publicKey) {
      wrappedKeyData = publicKey as WrappedKeyData
    } else {
      return publicKey as CryptoKey
    }
    return match(wrappedKeyData.algorithm, [
      ['RSA-OAEP', () => Rsa.importPublicKey(wrappedKeyData)],
      ['ECDH', () => Ecc.importPublicKey(wrappedKeyData)],
    ]) as unknown as Promise<CryptoKey>
  },
  async encrypt(data: string, publicKey: MaybeSerializedKey): Promise<Secret> {
    const key = await this.importPublicKey(publicKey)

    return match(key.algorithm.name, [
      ['RSA-OAEP', async () => Rsa.encrypt(data, key)],
      ['ECDH', async () => Ecc.encrypt(data, key)],
    ]) as unknown as Promise<Secret>
  },
  async decrypt(secret: Secret | string, privateKey: MaybeSerializedKey, passphrase?: string): Promise<string> {
    if ('string' === typeof secret) {
      secret = JSON.parse(secret)
    }
    return match((secret as Secret).metadata.algorithm, [
      ['RSA-OAEP', async () => Rsa.decrypt(secret, privateKey, passphrase)],
      ['ECDH', async () => Ecc.decrypt(secret, privateKey, passphrase)],
    ]) as unknown as Promise<string>
  },
}
