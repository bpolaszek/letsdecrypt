import {Rsa} from './rsa'
import {Ecc} from './ecc'
import {Aes} from './aes'
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

const importPublicKey = async (publicKey: MaybeSerializedKey): Promise<CryptoKey> => {
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
    ['AES-CTR', () => Aes.importPublicKey(wrappedKeyData)],
  ]) as unknown as Promise<CryptoKey>
}

export const generateKeyPair = async (options?: KeyPairOptions): Promise<WrappedCryptoKeyPair> => {
  return match(options?.algorithm ?? 'RSA', [
    ['RSA', () => Rsa.generateKeyPair(options)],
    ['ECC', () => Ecc.generateKeyPair(options)],
    ['AES', () => Aes.generateKeyPair(options)],
  ]) as unknown as Promise<WrappedCryptoKeyPair>
}

export const exportKeyPair = async (keyPair: CryptoKeyPair | WrappedCryptoKeyPair): Promise<SerializedKeyPair> => {
  return {
    publicKey: JSON.stringify(keyPair.publicKey),
    privateKey: JSON.stringify(keyPair.privateKey),
  }
}

export const encrypt = async (data: string, publicKey: MaybeSerializedKey): Promise<Secret> => {
  const key = await importPublicKey(publicKey)

  return match(key.algorithm.name, [
    ['RSA-OAEP', async () => Rsa.encrypt(data, key)],
    ['ECDH', async () => Ecc.encrypt(data, key)],
    ['AES-CTR', async () => Aes.encrypt(data, key)],
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
    ['AES-CTR', async () => Aes.decrypt(secret, privateKey, passphrase)],
  ]) as unknown as Promise<string>
}
