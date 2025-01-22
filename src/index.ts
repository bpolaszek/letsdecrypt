import {Rsa} from './rsa'
import {Ecc} from './ecc'
import {Aes} from './aes'
import {
  KeyPairOptions,
  MaybeSerializedKey,
  WrappedKeyData,
  Secret,
  SerializedKeyPair,
  WrappedCryptoKeyPair,
  wrapPrivateKey,
  wrapPublicKey,
} from './common'
import match from 'match-operator'
import {base64ToString, stringToBase64} from './base64.ts'

export const checkPassphrase = async (privateKey: string | WrappedKeyData, passphrase: string): Promise<boolean> => {
  try {
    const wrappedKeyData: WrappedKeyData = typeof privateKey === 'string' ? unserializeKey(privateKey) : privateKey
    if (!wrappedKeyData.protected) {
      return true
    }
    await match(wrappedKeyData.algorithm, [
      ['RSA-OAEP', () => Rsa.importPrivateKey(wrappedKeyData, passphrase)],
      ['ECDH', () => Ecc.importPrivateKey(wrappedKeyData, passphrase)],
      ['AES-CTR', () => Aes.importPrivateKey(wrappedKeyData, passphrase)],
    ])
    return true
  } catch (error) {
    return false
  }
}

const importPublicKey = async (publicKey: MaybeSerializedKey): Promise<CryptoKey> => {
  let wrappedKeyData: WrappedKeyData
  if ('string' === typeof publicKey) {
    wrappedKeyData = unserializeKey(publicKey)
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

export const changePassphrase = async (
  privateKey: MaybeSerializedKey,
  oldPassphrase: string | null,
  newPassphrase: string | null
): Promise<WrappedKeyData> => {
  const wrappedKeyData: WrappedKeyData =
    typeof privateKey === 'string' ? unserializeKey(privateKey) : (privateKey as WrappedKeyData)

  // Import the private key using the old passphrase
  const cryptoKey = (await match(wrappedKeyData.algorithm, [
    ['RSA-OAEP', () => Rsa.importPrivateKey(wrappedKeyData, oldPassphrase ?? '')],
    ['ECDH', () => Ecc.importPrivateKey(wrappedKeyData, oldPassphrase ?? '')],
    ['AES-CTR', () => Aes.importPrivateKey(wrappedKeyData, oldPassphrase ?? '')],
  ])) as unknown as CryptoKey

  // Wrap the key with the new passphrase
  return wrapPrivateKey(
    cryptoKey,
    newPassphrase ?? '',
    wrappedKeyData.algorithm,
    wrappedKeyData.fingerprint,
    wrappedKeyData.namedCurve
  )
}

export const generateKeyPair = async (options?: KeyPairOptions): Promise<WrappedCryptoKeyPair> => {
  return match(options?.algorithm ?? 'RSA', [
    ['RSA', () => Rsa.generateKeyPair(options)],
    ['ECC', () => Ecc.generateKeyPair(options)],
    ['AES', () => Aes.generateKeyPair(options)],
  ]) as unknown as Promise<WrappedCryptoKeyPair>
}

export const serializeKey = (key: WrappedKeyData): string => stringToBase64(JSON.stringify(key))
export const unserializeKey = (serialized: string): WrappedKeyData => JSON.parse(base64ToString(serialized))

export const exportKeyPair = async (keyPair: WrappedCryptoKeyPair): Promise<SerializedKeyPair> => {
  return {
    publicKey: serializeKey(keyPair.publicKey),
    privateKey: serializeKey(keyPair.privateKey),
    fingerprint: keyPair.fingerprint,
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

export const serializeSecret = (secret: Secret): string => stringToBase64(JSON.stringify(secret))
export const unserializeSecret = (serialized: string): Secret => JSON.parse(base64ToString(serialized))

export const decrypt = async (
  secret: Secret | string,
  privateKey: MaybeSerializedKey,
  passphrase?: string
): Promise<string> => {
  if ('string' === typeof secret) {
    secret = JSON.parse(base64ToString(secret))
  }
  return match((secret as Secret).metadata.algorithm, [
    ['RSA-OAEP', async () => Rsa.decrypt(secret, privateKey, passphrase)],
    ['ECDH', async () => Ecc.decrypt(secret, privateKey, passphrase)],
    ['AES-CTR', async () => Aes.decrypt(secret, privateKey, passphrase)],
  ]) as unknown as Promise<string>
}

export const derivePublicKey = async (
  privateKey: MaybeSerializedKey,
  passphrase: string = ''
): Promise<WrappedKeyData> => {
  const wrappedKeyData: WrappedKeyData =
    typeof privateKey === 'string' ? unserializeKey(privateKey) : (privateKey as WrappedKeyData)

  // Import the private key using the appropriate algorithm
  const cryptoKey = (await match(wrappedKeyData.algorithm, [
    ['RSA-OAEP', () => Rsa.importPrivateKey(wrappedKeyData, passphrase)],
    ['ECDH', () => Ecc.importPrivateKey(wrappedKeyData, passphrase)],
    ['AES-CTR', () => Aes.importPrivateKey(wrappedKeyData, passphrase)],
  ])) as unknown as CryptoKey

  if ('AES-CTR' === wrappedKeyData.algorithm) {
    return wrappedKeyData
  }

  // Derive the public key using the appropriate algorithm
  const publicKey = (await match(wrappedKeyData.algorithm, [
    ['RSA-OAEP', () => Rsa.derivePublicKey(cryptoKey)],
    ['ECDH', () => Ecc.derivePublicKey(cryptoKey)],
    ['AES-CTR', () => Aes.derivePublicKey(cryptoKey)],
  ])) as unknown as CryptoKey

  // For RSA and ECC, we need to export the public key
  return wrapPublicKey(publicKey, wrappedKeyData.algorithm, wrappedKeyData.fingerprint, wrappedKeyData.namedCurve)
}
export type {
  KeyPairOptions,
  MaybeSerializedKey,
  Secret,
  SerializedKeyPair,
  WrappedCryptoKeyPair,
  WrappedKeyData,
} from './common'
