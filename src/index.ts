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

export const generateKeyPair = async (options?: KeyPairOptions): Promise<WrappedCryptoKeyPair> => {
  return match(options?.algorithm ?? 'RSA', [
    ['RSA', () => Rsa.generateKeyPair(options)],
    ['ECC', () => Ecc.generateKeyPair(options)],
  ]) as unknown as Promise<WrappedCryptoKeyPair>
}

export const exportKeyPair = async (keyPair: CryptoKeyPair | WrappedCryptoKeyPair): Promise<SerializedKeyPair> => {
  return {
    publicKey: JSON.stringify(keyPair.publicKey),
    privateKey: JSON.stringify(keyPair.privateKey),
  }
}

export const importPublicKey = async (publicKey: MaybeSerializedKey): Promise<CryptoKey> => {
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
}

export const importPrivateKey = async (privateKey: MaybeSerializedKey, passphrase?: string): Promise<CryptoKey> => {
  let wrappedKeyData: WrappedKeyData
  if ('string' === typeof privateKey) {
    wrappedKeyData = JSON.parse(privateKey)
  } else if ('object' === typeof privateKey) {
    wrappedKeyData = privateKey as WrappedKeyData
  } else {
    return privateKey as CryptoKey
  }
  return match(wrappedKeyData.algorithm, [
    ['RSA-OAEP', () => Rsa.importPrivateKey(wrappedKeyData, passphrase ?? '')],
    ['ECDH', () => Ecc.importPrivateKey(wrappedKeyData, passphrase ?? '')],
  ]) as unknown as Promise<CryptoKey>
}

export const encrypt = async (data: string, publicKey: MaybeSerializedKey): Promise<Secret> => {
  const key = await importPublicKey(publicKey)

  return match(key.algorithm.name, [
    ['RSA-OAEP', async () => Rsa.encrypt(data, key)],
    ['ECDH', async () => Ecc.encrypt(data, key)],
  ]) as unknown as Promise<Secret>
}

export const decrypt = async (
  secret: Secret | string,
  privateKey: MaybeSerializedKey,
  passphrase?: string
): Promise<string> => {
  if ('string' === typeof secret) {
    secret = JSON.parse(secret)
  }
  return match((secret as Secret).metadata.algorithm, [
    ['RSA-OAEP', async () => Rsa.decrypt(secret, privateKey, passphrase)],
    ['ECDH', async () => Ecc.decrypt(secret, privateKey, passphrase)],
  ]) as unknown as Promise<string>
}
