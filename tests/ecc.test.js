import {describe, expect, it} from 'vitest'
import {
  generateKeyPair,
  encrypt,
  checkPassphrase,
  exportKeyPair,
  decrypt,
  changePassphrase,
  serializeSecret,
  derivePublicKey,
} from '../src'
import {payload as sensitiveData} from './data'

describe.each([
  {sensitiveData},
  {sensitiveData, passphrase: 'May the 4th be with you'},
  {sensitiveData, eccCurve: 'P-384'},
  {sensitiveData, eccCurve: 'P-384', passphrase: 'May the 4th be with you'},
  {sensitiveData, eccCurve: 'P-521'},
  {sensitiveData, eccCurve: 'P-521', passphrase: 'May the 4th be with you'},
])('ECC keys with passphrase $passphrase', function ({sensitiveData, eccCurve, passphrase}) {
  let keyPair, serializedKeys, encryptedSecret, serializedSecret
  it('generates a key pair', async function () {
    keyPair = await generateKeyPair({
      algorithm: 'ECC',
      eccCurve,
      passphrase,
    })
    const {publicKey, privateKey, fingerprint} = keyPair
    expect(fingerprint).toBeDefined()
    expect(publicKey).toBeDefined()
    expect(publicKey.fingerprint).toEqual(fingerprint)
    expect(privateKey).toBeDefined()
    expect(privateKey.fingerprint).toEqual(fingerprint)
  })

  it('serializes the keys', async function () {
    serializedKeys = await exportKeyPair(keyPair)
    const {publicKey, privateKey, fingerprint} = serializedKeys
    expect(publicKey).toBeTypeOf('string')
    expect(privateKey).toBeTypeOf('string')
    expect(fingerprint).toBeTypeOf('string')
  })

  it('encrypts a secret', async function () {
    encryptedSecret = await encrypt(sensitiveData, serializedKeys.publicKey)
    expect(encryptedSecret.encryptedData).toBeTypeOf('string')
    expect(encryptedSecret.metadata.algorithm).toBe('ECDH')
    expect(encryptedSecret.metadata.keyFingerprint).toBe(keyPair.fingerprint)
    expect(encryptedSecret.metadata.publicKey).toBeDefined()
    expect(encryptedSecret.metadata.namedCurve).toBe(eccCurve ?? 'P-256')
    serializedSecret = serializeSecret(encryptedSecret)
  })

  it('decrypts a secret', async function () {
    let decrypted = await decrypt(serializedSecret, serializedKeys.privateKey, passphrase)
    expect(decrypted).toBe(sensitiveData)
  })

  it('cannot decrypt a secret with the wrong private key', async function () {
    const keyPair = await generateKeyPair({
      algorithm: 'ECC',
      eccCurve,
      passphrase,
    })
    const serializedKeys = await exportKeyPair(keyPair)
    const {privateKey} = serializedKeys
    try {
      await decrypt(serializedSecret, privateKey, passphrase)
      expect(true).toBe(false) // This line should not be reached
    } catch (e) {
      expect(e).toBeInstanceOf(Error)
    }
  })

  it('cannot decrypt a secret with the wrong passphrase', async function () {
    try {
      await decrypt(serializedSecret, serializedKeys.privateKey, 'wrong passphrase')
      expect(true).toBe(false) // This line should not be reached
    } catch (e) {
      expect(e).toBeInstanceOf(Error)
    }
  })

  it('changes the passphrase', async function () {
    const newPrivateKey = await changePassphrase(serializedKeys.privateKey, passphrase, 'C0vf3f3')
    let decrypted = await decrypt(serializedSecret, newPrivateKey, 'C0vf3f3')
    expect(decrypted).toBe(sensitiveData)
    expect(newPrivateKey.fingerprint).toEqual(keyPair.privateKey.fingerprint)
  })

  it('generates public key from private key', async function () {
    const publicKey = await derivePublicKey(serializedKeys.privateKey, passphrase)
    expect(publicKey.fingerprint).toBe(keyPair.fingerprint)
    expect(publicKey.algorithm).toBe('ECDH')
    expect(publicKey.namedCurve).toBe(eccCurve ?? 'P-256')

    // Verify the public key works for encryption
    const testSecret = await encrypt('test message', publicKey)
    const decrypted = await decrypt(testSecret, serializedKeys.privateKey, passphrase)
    expect(decrypted).toBe('test message')
  })

  it('validates correct passphrase', async function () {
    if (passphrase) {
      const isValid = await checkPassphrase(serializedKeys.privateKey, passphrase)
      expect(isValid).toBe(true)
    }
  })

  it('rejects incorrect passphrase', async function () {
    if (passphrase) {
      const isValid = await checkPassphrase(serializedKeys.privateKey, 'wrong passphrase')
      expect(isValid).toBe(false)
    }
  })

  it('accepts any passphrase for unprotected keys', async function () {
    const unprotectedKeyPair = await generateKeyPair({algorithm: 'ECC'})
    const {privateKey} = await exportKeyPair(unprotectedKeyPair)
    const isValid = await checkPassphrase(privateKey, 'any passphrase')
    expect(isValid).toBe(true)
  })
})
